"""Durable deployment-state primitives for transactional HomeOps promotion.

The Cozo database is derived data.  This module deliberately keeps deployment
selection small and boring: immutable candidate records plus one atomically
replaced schema-v2 state file.  It does not build or verify a database; callers
must perform those gates before invoking :func:`select_deployment`.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterator


DEPLOYMENT_SCHEMA_VERSION = 2
DEPLOYMENT_CONTRACT_VERSION = "homeops-deployment-v2"
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class DeploymentError(RuntimeError):
    """A deployment record or state transition is invalid."""


class PromotionConflict(DeploymentError):
    """The selected deployment changed after the candidate was prepared."""


def strict_json_loads(value: str | bytes) -> Any:
    """Decode JSON while rejecting duplicate object keys and non-finite numbers."""

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in items:
            if key in result:
                raise DeploymentError(f"JSON contains duplicate key: {key}")
            result[key] = item
        return result

    def invalid_constant(constant: str) -> Any:
        raise DeploymentError(f"JSON contains non-finite number: {constant}")

    try:
        return json.loads(
            value, object_pairs_hook=pairs, parse_constant=invalid_constant
        )
    except json.JSONDecodeError as error:
        raise DeploymentError(f"invalid JSON: {error}") from error


def canonical_json_bytes(value: Any) -> bytes:
    """Return the single canonical encoding used for content-derived IDs."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def durable_atomic_json(path: Path, value: Any, *, mode: int = 0o600) -> None:
    """Atomically replace JSON and durably commit both file and directory entry."""

    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(json.dumps(value, indent=2, sort_keys=True).encode("utf-8"))
            stream.write(b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def durable_atomic_canonical_json(
    path: Path, value: dict[str, Any], *, mode: int = 0o600
) -> None:
    """Atomically write compact insertion-ordered JSON for receiver protocols."""

    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    encoded = (
        json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def durable_create_json(path: Path, value: Any, *, mode: int = 0o600) -> None:
    """Create immutable JSON, accepting an identical idempotent retry only."""

    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    encoded = json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    except FileExistsError:
        if path.read_bytes() != encoded:
            raise DeploymentError(
                f"immutable record already exists with other bytes: {path}"
            )
        return
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        _fsync_directory(path.parent)
    except Exception:
        path.unlink(missing_ok=True)
        raise


@contextmanager
def _data_lock(
    data_dir: Path,
    name: str,
    *,
    blocking: bool = False,
    shared: bool = False,
    create: bool = True,
    record_owner: bool = False,
) -> Iterator[None]:
    if data_dir.is_symlink():
        raise DeploymentError("deployment data directory must not be a symlink")
    data = data_dir.resolve()
    if create:
        data.mkdir(parents=True, exist_ok=True, mode=0o700)
    elif not data.is_dir():
        raise DeploymentError(f"deployment data directory does not exist: {data}")
    lock_path = data / name
    flags = os.O_RDWR | os.O_CREAT if create else os.O_RDONLY
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as error:
        raise DeploymentError(f"cannot open deployment lock: {lock_path}") from error
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise DeploymentError(f"deployment lock is not a regular file: {lock_path}")
    operation = (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | (
        0 if blocking else fcntl.LOCK_NB
    )
    try:
        try:
            fcntl.flock(descriptor, operation)
        except BlockingIOError as error:
            raise DeploymentError(
                f"another HomeOps operation holds {lock_path}"
            ) from error
        if record_owner and not shared and create:
            os.ftruncate(descriptor, 0)
            os.write(descriptor, f"{os.getpid()}\n".encode("ascii"))
            os.fsync(descriptor)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


@contextmanager
def deployment_lock(
    data_dir: Path,
    *,
    blocking: bool = False,
    shared: bool = False,
    create: bool = True,
) -> Iterator[None]:
    """Hold the kernel-backed lock shared by deployment mutations."""

    with _data_lock(
        data_dir,
        "deployment.lock",
        blocking=blocking,
        shared=shared,
        create=create,
        record_owner=True,
    ):
        yield


@contextmanager
def retention_lock(
    data_dir: Path,
    *,
    blocking: bool = True,
    shared: bool = False,
    create: bool = True,
) -> Iterator[None]:
    """Serialize cleanup handoff without blocking build or promotion work.

    Readers take this lock shared only until their per-run shared lock is held.
    A future cleanup implementation must acquire locks in this order:
    retention exclusive, deployment exclusive, then run exclusive.
    """

    with _data_lock(
        data_dir,
        "retention.lock",
        blocking=blocking,
        shared=shared,
        create=create,
    ):
        yield


def run_pin_path(data_dir: Path, run_id: str) -> Path:
    """Return the fixed advisory-lock path for one immutable build run."""

    safe_id = validate_safe_id(run_id, "run_id")
    if data_dir.is_symlink():
        raise DeploymentError("deployment data directory must not be a symlink")
    data = data_dir.resolve()
    pins = data / "run-pins"
    try:
        pins_mode = pins.lstat().st_mode
    except FileNotFoundError:
        pass
    except OSError as error:
        raise DeploymentError(f"cannot inspect run pin directory: {pins}") from error
    else:
        if not stat.S_ISDIR(pins_mode):
            raise DeploymentError(f"run pin directory is not a directory: {pins}")
    return pins / f"{safe_id}.lock"


@contextmanager
def run_pin(
    data_dir: Path,
    run_id: str,
    *,
    exclusive: bool = False,
    blocking: bool = True,
) -> Iterator[None]:
    """Pin one run while it is being read, or exclusively reserve it for cleanup."""

    path = run_pin_path(data_dir, run_id)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise DeploymentError(f"run pin is not a regular file: {path}")
    operation = (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | (
        0 if blocking else fcntl.LOCK_NB
    )
    try:
        try:
            fcntl.flock(descriptor, operation)
        except BlockingIOError as error:
            raise DeploymentError(f"run is pinned: {run_id}") from error
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def run_is_pinned(data_dir: Path, run_id: str) -> bool:
    """Probe an existing run lock without creating retention state."""

    path = run_pin_path(data_dir, run_id)
    if not os.path.lexists(path):
        return False
    if path.is_symlink() or not path.is_file():
        raise DeploymentError(f"run pin is not a regular file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise DeploymentError(f"cannot inspect run pin: {path}") from error
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise DeploymentError(f"run pin is not a regular file: {path}")
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        return False
    finally:
        os.close(descriptor)


def validate_safe_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
        raise DeploymentError(f"{field} is not a safe identifier")
    return value


def _require_string(
    record: dict[str, Any], field: str, *, nullable: bool = False
) -> str | None:
    value = record.get(field)
    if nullable and value is None:
        return None
    if not isinstance(value, str) or not value:
        raise DeploymentError(f"deployment {field} must be a non-empty string")
    return value


_RECORD_FIELDS = {
    "deployment_schema_version",
    "deployment_contract_version",
    "deployment_id",
    "snapshot_id",
    "run_id",
    "source_fingerprint",
    "artifact_fingerprint",
    "logical_fingerprint",
    "snapshot_created_at",
    "snapshot_received_at",
    "build_completed_at",
    "build_verified_at",
    "promoted_at",
    "homeops_version",
    "source_revision",
    "image_digest",
    "snapshot_schema_version",
    "snapshot_contract_version",
    "build_schema_version",
    "build_contract_version",
    "result",
}


def deployment_identity(record: dict[str, Any]) -> dict[str, Any]:
    """Return immutable fields covered by ``deployment_id``."""

    return {
        "deployment_contract_version": record["deployment_contract_version"],
        "snapshot_id": record["snapshot_id"],
        "run_id": record["run_id"],
        "source_fingerprint": record["source_fingerprint"],
        "artifact_fingerprint": record["artifact_fingerprint"],
        "logical_fingerprint": record["logical_fingerprint"],
        "homeops_version": record["homeops_version"],
        "source_revision": record["source_revision"],
        "image_digest": record["image_digest"],
        "snapshot_schema_version": record["snapshot_schema_version"],
        "snapshot_contract_version": record["snapshot_contract_version"],
        "build_schema_version": record["build_schema_version"],
        "build_contract_version": record["build_contract_version"],
    }


def validate_deployment_record(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise DeploymentError("deployment record must be an object")
    unknown = set(record) - _RECORD_FIELDS
    missing = _RECORD_FIELDS - set(record)
    if unknown or missing:
        details = []
        if missing:
            details.append("missing " + ", ".join(sorted(missing)))
        if unknown:
            details.append("unknown " + ", ".join(sorted(unknown)))
        raise DeploymentError("invalid deployment record fields: " + "; ".join(details))
    if record["deployment_schema_version"] != DEPLOYMENT_SCHEMA_VERSION:
        raise DeploymentError("unsupported deployment schema version")
    if record["deployment_contract_version"] != DEPLOYMENT_CONTRACT_VERSION:
        raise DeploymentError("unsupported deployment contract version")
    for field in ("deployment_id", "snapshot_id", "run_id"):
        validate_safe_id(record[field], field)
    for field in ("source_fingerprint", "artifact_fingerprint", "logical_fingerprint"):
        value = _require_string(record, field)
        if not _SHA256.fullmatch(value or ""):
            raise DeploymentError(f"deployment {field} must be a lowercase SHA-256")
    for field in (
        "snapshot_created_at",
        "snapshot_received_at",
        "build_completed_at",
        "build_verified_at",
        "homeops_version",
        "source_revision",
        "image_digest",
        "snapshot_contract_version",
        "build_contract_version",
    ):
        _require_string(record, field)
    _require_string(record, "promoted_at", nullable=True)
    for field in ("snapshot_schema_version", "build_schema_version"):
        if (
            not isinstance(record[field], int)
            or isinstance(record[field], bool)
            or record[field] < 1
        ):
            raise DeploymentError(f"deployment {field} must be a positive integer")
    if record["result"] != "verified":
        raise DeploymentError("only verified deployments may be selected")
    expected_id = sha256_json(deployment_identity(record))
    if record["deployment_id"] != expected_id:
        raise DeploymentError("deployment_id does not match deployment identity")
    return deepcopy(record)


def create_deployment_record(
    *,
    snapshot: dict[str, Any],
    build: dict[str, Any],
    snapshot_received_at: str,
    homeops_version: str,
    source_revision: str,
    image_digest: str,
    promoted_at: str | None = None,
) -> dict[str, Any]:
    """Bind one verified build to the exact snapshot from which it was built."""

    for field in ("source_fingerprint", "artifact_fingerprint", "logical_fingerprint"):
        if snapshot.get(field) != build.get(field):
            raise DeploymentError(f"snapshot/build {field} mismatch")
    if build.get("result") != "verified":
        raise DeploymentError("candidate build is not verified")
    record: dict[str, Any] = {
        "deployment_schema_version": DEPLOYMENT_SCHEMA_VERSION,
        "deployment_contract_version": DEPLOYMENT_CONTRACT_VERSION,
        "deployment_id": "pending",
        "snapshot_id": snapshot["snapshot_id"],
        "run_id": build["run_id"],
        "source_fingerprint": snapshot["source_fingerprint"],
        "artifact_fingerprint": snapshot["artifact_fingerprint"],
        "logical_fingerprint": snapshot["logical_fingerprint"],
        "snapshot_created_at": snapshot["created_at"],
        "snapshot_received_at": snapshot_received_at,
        "build_completed_at": build["completed_at"],
        "build_verified_at": build["verified_at"],
        "promoted_at": promoted_at,
        "homeops_version": homeops_version,
        "source_revision": source_revision,
        "image_digest": image_digest,
        "snapshot_schema_version": snapshot["schema_version"],
        "snapshot_contract_version": snapshot["snapshot_contract_version"],
        "build_schema_version": build["schema_version"],
        "build_contract_version": build["build_contract_version"],
        "result": "verified",
    }
    record["deployment_id"] = sha256_json(deployment_identity(record))
    return validate_deployment_record(record)


def empty_state() -> dict[str, Any]:
    return {
        "schema_version": DEPLOYMENT_SCHEMA_VERSION,
        "current": None,
        "previous": None,
        "current_deployment": None,
        "previous_deployment": None,
        "promoted_at": None,
    }


_STATE_FIELDS = {
    "schema_version",
    "current",
    "previous",
    "current_deployment",
    "previous_deployment",
    "promoted_at",
}


def validate_state(state: Any, *, allow_legacy: bool = True) -> dict[str, Any]:
    if not isinstance(state, dict):
        raise DeploymentError("active deployment state must be an object")
    schema_version = state.get("schema_version")
    if schema_version == 1 and allow_legacy:
        allowed = {"schema_version", "current", "previous", "promoted_at"}
        if set(state) - allowed:
            raise DeploymentError("legacy active state has unknown fields")
        for field in ("current", "previous"):
            value = state.get(field)
            if value is not None:
                validate_safe_id(value, field)
        return deepcopy(state)
    if schema_version != DEPLOYMENT_SCHEMA_VERSION:
        raise DeploymentError("unsupported active deployment schema version")
    if set(state) != _STATE_FIELDS:
        raise DeploymentError("schema-v2 active state has missing or unknown fields")
    current_record = state["current_deployment"]
    previous_record = state["previous_deployment"]
    if current_record is None:
        if (
            state["current"] is not None
            or previous_record is not None
            or state["previous"] is not None
        ):
            raise DeploymentError("empty active state contains a selected deployment")
    else:
        current_record = validate_deployment_record(current_record)
        if state["current"] != current_record["run_id"]:
            raise DeploymentError(
                "legacy current run ID disagrees with current deployment"
            )
    if previous_record is None:
        if state["previous"] is not None:
            raise DeploymentError("previous run ID has no previous deployment")
    else:
        previous_record = validate_deployment_record(previous_record)
        if state["previous"] != previous_record["run_id"]:
            raise DeploymentError(
                "legacy previous run ID disagrees with previous deployment"
            )
    promoted_at = state["promoted_at"]
    if promoted_at is not None and not isinstance(promoted_at, str):
        raise DeploymentError("active promoted_at must be a string or null")
    result = deepcopy(state)
    result["current_deployment"] = current_record
    result["previous_deployment"] = previous_record
    return result


def load_state(data_dir: Path, *, allow_legacy: bool = True) -> dict[str, Any]:
    path = data_dir.resolve() / "active.json"
    if not path.is_file():
        return empty_state()
    try:
        parsed = strict_json_loads(path.read_text(encoding="utf-8"))
    except (OSError, DeploymentError) as error:
        raise DeploymentError(
            f"cannot read active deployment state: {error}"
        ) from error
    return validate_state(parsed, allow_legacy=allow_legacy)


def deployment_record_path(data_dir: Path, deployment_id: str) -> Path:
    safe_id = validate_safe_id(deployment_id, "deployment_id")
    return data_dir.resolve() / "deployments" / f"{safe_id}.json"


def store_deployment(data_dir: Path, record: dict[str, Any]) -> Path:
    checked = validate_deployment_record(record)
    path = deployment_record_path(data_dir, checked["deployment_id"])
    durable_create_json(path, checked)
    return path


def load_deployment(data_dir: Path, deployment_id: str) -> dict[str, Any]:
    path = deployment_record_path(data_dir, deployment_id)
    if not path.is_file():
        raise DeploymentError(f"deployment record does not exist: {deployment_id}")
    try:
        return validate_deployment_record(
            strict_json_loads(path.read_text(encoding="utf-8"))
        )
    except DeploymentError as error:
        raise DeploymentError(
            f"deployment record is invalid: {deployment_id}: {error}"
        ) from error


def select_deployment(
    state: dict[str, Any],
    candidate: dict[str, Any],
    *,
    expected_current_deployment_id: str | None,
    promoted_at: str,
) -> tuple[dict[str, Any], str]:
    """Pure compare-and-swap transition returning ``(state, result)``."""

    selected = validate_state(state, allow_legacy=False)
    checked = validate_deployment_record(candidate)
    current = selected["current_deployment"]
    if current and current["deployment_id"] == checked["deployment_id"]:
        return selected, "unchanged"
    actual = current["deployment_id"] if current else None
    if actual != expected_current_deployment_id:
        raise PromotionConflict(
            "active deployment changed: "
            f"expected {expected_current_deployment_id!r}, found {actual!r}"
        )
    promoted = deepcopy(checked)
    promoted["promoted_at"] = promoted_at
    next_state = {
        "schema_version": DEPLOYMENT_SCHEMA_VERSION,
        "current": promoted["run_id"],
        "previous": current["run_id"] if current else None,
        "current_deployment": promoted,
        "previous_deployment": deepcopy(current),
        "promoted_at": promoted_at,
    }
    return validate_state(next_state, allow_legacy=False), "promoted"


def rollback_transition(state: dict[str, Any], *, promoted_at: str) -> dict[str, Any]:
    selected = validate_state(state, allow_legacy=False)
    current = selected["current_deployment"]
    previous = selected["previous_deployment"]
    if current is None or previous is None:
        raise DeploymentError(
            "rollback requires current and previous verified deployments"
        )
    selected_previous = deepcopy(previous)
    selected_previous["promoted_at"] = promoted_at
    rolled_back = {
        "schema_version": DEPLOYMENT_SCHEMA_VERSION,
        "current": previous["run_id"],
        "previous": current["run_id"],
        "current_deployment": selected_previous,
        "previous_deployment": deepcopy(current),
        "promoted_at": promoted_at,
    }
    return validate_state(rolled_back, allow_legacy=False)


def deployment_for_run(
    data_dir: Path, run_id: str | None = None
) -> tuple[dict[str, Any] | None, str, str]:
    """Resolve one run and its active/previous/retained role at request start."""

    state = load_state(data_dir)
    selected_run = run_id or state.get("current")
    if not selected_run:
        raise DeploymentError("there is no active deployment")
    validate_safe_id(selected_run, "run_id")
    if state.get("schema_version") == DEPLOYMENT_SCHEMA_VERSION:
        current = state.get("current_deployment")
        previous = state.get("previous_deployment")
        if current and current["run_id"] == selected_run:
            return current, "active", selected_run
        if previous and previous["run_id"] == selected_run:
            return previous, "previous", selected_run
        deployments_dir = data_dir.resolve() / "deployments"
        if deployments_dir.is_dir():
            for path in sorted(deployments_dir.glob("*.json")):
                try:
                    record = validate_deployment_record(
                        strict_json_loads(path.read_text(encoding="utf-8"))
                    )
                except (DeploymentError, OSError):
                    continue
                if record["run_id"] == selected_run:
                    history = (
                        data_dir.resolve()
                        / "deployment-history"
                        / record["deployment_id"]
                    )
                    if history.is_dir():
                        events: list[dict[str, Any]] = []
                        for event_path in sorted(history.glob("*.json")):
                            try:
                                event = validate_deployment_record(
                                    strict_json_loads(
                                        event_path.read_text(encoding="utf-8")
                                    )
                                )
                            except (DeploymentError, OSError):
                                continue
                            if event["deployment_id"] == record["deployment_id"]:
                                events.append(event)
                        if events:
                            record = max(
                                events, key=lambda event: event["promoted_at"] or ""
                            )
                    return record, "retained", selected_run
    # A verified schema-v1 run remains queryable during the explicit adoption window.
    return (
        None,
        "active" if selected_run == state.get("current") else "retained",
        selected_run,
    )


def provenance(record: dict[str, Any] | None, role: str, run_id: str) -> dict[str, Any]:
    if record is None:
        return {
            "deployment_id": None,
            "snapshot_id": None,
            "run_id": run_id,
            "role": role,
            "active": role == "active",
            "retained": role != "active",
        }
    checked = validate_deployment_record(record)
    return {
        **checked,
        "role": role,
        "active": role == "active",
        "retained": role != "active",
    }


def current_projection(state: dict[str, Any]) -> dict[str, Any]:
    """Return the exact redacted receiver preflight/CAS projection."""

    checked = validate_state(state)
    if checked.get("schema_version") != DEPLOYMENT_SCHEMA_VERSION and checked.get(
        "current"
    ):
        raise DeploymentError(
            "cannot publish schema-v2 current projection for unadopted legacy state"
        )
    deployment = (
        checked.get("current_deployment")
        if checked.get("schema_version") == DEPLOYMENT_SCHEMA_VERSION
        else None
    )
    return {
        "schema_version": DEPLOYMENT_SCHEMA_VERSION,
        "current_deployment_id": deployment["deployment_id"] if deployment else "",
        "snapshot_id": deployment["snapshot_id"] if deployment else "",
        "run_id": deployment["run_id"] if deployment else "",
        "source_fingerprint": deployment["source_fingerprint"] if deployment else "",
        "artifact_fingerprint": deployment["artifact_fingerprint"]
        if deployment
        else "",
        "logical_fingerprint": deployment["logical_fingerprint"] if deployment else "",
        "homeops_version": deployment["homeops_version"] if deployment else "",
        "source_revision": deployment["source_revision"] if deployment else "",
        "image_digest": deployment["image_digest"] if deployment else "",
        "snapshot_contract_version": (
            deployment["snapshot_contract_version"] if deployment else ""
        ),
        "build_contract_version": (
            deployment["build_contract_version"] if deployment else ""
        ),
        "promoted_at": (deployment.get("promoted_at") or "") if deployment else "",
    }


def publish_current_projection(
    root: Path, state: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Durably publish the sole redacted identity exposed by receiver ``current``."""

    root = root.resolve()
    selected = state if state is not None else load_state(root / "data")
    projection = current_projection(selected)
    durable_atomic_canonical_json(
        root / "pipeline-state" / "current.json", projection, mode=0o640
    )
    return projection
