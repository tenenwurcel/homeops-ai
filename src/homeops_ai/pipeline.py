"""Transactional workstation coordinator and asynchronous remote processor."""

from __future__ import annotations

import fcntl
import os
import secrets
import shutil
import subprocess
import tempfile
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterator, Sequence

from homeops_ai.build import (
    BUILD_CONTRACT_VERSION,
    BUILD_SCHEMA_VERSION,
    BuildError,
    active_state,
    evaluate_candidate,
    inspect_vault,
    materialize_snapshot,
    promote,
    recover_pending_rollback,
    repair_selected_bookkeeping,
    rebuild,
    utc_now,
    validate_release_provenance,
    verify_run,
)
from homeops_ai.deployment import (
    DEPLOYMENT_SCHEMA_VERSION,
    DeploymentError,
    durable_atomic_json,
    publish_current_projection,
    sha256_json,
    strict_json_loads,
    validate_deployment_record,
    validate_safe_id,
)
from homeops_ai.evaluation import EvaluationError
from homeops_ai.source_contract import export_snapshot
from homeops_ai.snapshot import (
    RECEIVER_PROTOCOL,
    RECEIVER_SCHEMA_VERSION,
    SNAPSHOT_CONTRACT_VERSION,
    SNAPSHOT_SCHEMA_VERSION,
    SnapshotError,
    canonical_receiver_json,
    create_snapshot_manifest,
    file_sha256,
    read_manifest,
    safe_relative_path,
    validate_publisher_id,
    validate_request_message,
    verify_snapshot,
    write_manifest,
    write_submission_archive,
)


DEFAULT_PUBLISHER_ID = "workstation"
RESULT_SCHEMA_VERSION = 1
PENDING_ATTEMPT_SCHEMA_VERSION = 1
PROMOTION_POLICY_SCHEMA_VERSION = 1
_PENDING_ATTEMPT_NAME = "pending-attempt.json"
_PENDING_ARCHIVE_NAME = "pending-submission.tar"
TERMINAL_OUTCOMES = {
    "UNCHANGED",
    "PROMOTED",
    "LOCAL_VAULT_INVALID",
    "LOCAL_SOURCE_CHANGED",
    "PROMOTED_SOURCE_MOVED",
    "AUTHORIZATION_FAILED",
    "TRANSFER_FAILED",
    "REMOTE_SNAPSHOT_INVALID",
    "BUILD_FAILED",
    "EVALUATION_FAILED",
    "PROMOTION_CONFLICT",
    "POST_PROMOTION_MISMATCH",
    "HOMEOPS_UNAVAILABLE",
    "TIMEOUT",
    "INTERNAL_ERROR",
}
RETRYABLE_REMOTE_OUTCOMES = {
    "BUILD_FAILED",
    "EVALUATION_FAILED",
    "HOMEOPS_UNAVAILABLE",
    "TIMEOUT",
    "INTERNAL_ERROR",
}


class PipelineError(RuntimeError):
    def __init__(self, outcome: str, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.outcome = outcome
        self.retryable = retryable


def _result(outcome: str, **values: Any) -> dict[str, Any]:
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "protocol": RECEIVER_PROTOCOL,
        "outcome": outcome,
        "at": utc_now(),
        **values,
    }


def _redacted_failure(error: Exception) -> str:
    text = " ".join(str(error).split())
    return text[:500] or error.__class__.__name__


def _same_identity(first: dict[str, Any], second: dict[str, Any]) -> bool:
    return all(
        first.get(field) == second.get(field)
        for field in ("source_fingerprint", "artifact_fingerprint", "logical_fingerprint")
    )


def _package_version() -> str:
    from homeops_ai.build import _package_version as package_version

    return package_version()


def _released_identity(
    source_revision: str | None,
    image_digest: str | None,
) -> tuple[str, str, str]:
    if source_revision is None or image_digest is None:
        raise PipelineError(
            "INTERNAL_ERROR",
            "released pipeline requires HOMEOPS_SOURCE_REVISION and HOMEOPS_IMAGE_DIGEST",
        )
    try:
        return validate_release_provenance(
            _package_version(), source_revision, image_digest
        )
    except BuildError as error:
        raise PipelineError("INTERNAL_ERROR", str(error)) from error


def _release_policy(
    homeops_version: str,
    source_revision: str,
    image_digest: str,
    *,
    evaluation_cases: Sequence[Path] = (),
) -> dict[str, Any]:
    """Return the exact build/promotion policy for one processor invocation."""

    suite_digests: list[str] = []
    for case in evaluation_cases:
        resolved = case.resolve(strict=True)
        if not resolved.is_file() or resolved.is_symlink():
            raise PipelineError(
                "INTERNAL_ERROR", "promotion evaluation policy is not a regular file"
            )
        suite_digests.append(file_sha256(resolved))
    return {
        "schema_version": PROMOTION_POLICY_SCHEMA_VERSION,
        "homeops_version": homeops_version,
        "source_revision": source_revision,
        "image_digest": image_digest,
        "snapshot_schema_version": SNAPSHOT_SCHEMA_VERSION,
        "snapshot_contract_version": SNAPSHOT_CONTRACT_VERSION,
        "build_schema_version": BUILD_SCHEMA_VERSION,
        "build_contract_version": BUILD_CONTRACT_VERSION,
        "evaluation_suite_sha256": sorted(suite_digests),
    }


def _policy_id(policy: dict[str, Any]) -> str:
    return sha256_json(policy)


def _base_release_policy(policy: dict[str, Any]) -> dict[str, Any]:
    # The immutable image digest already binds the processor and evaluation-suite
    # bytes. The processor adds their individual hashes to the promotion policy.
    return {**policy, "evaluation_suite_sha256": []}


def _snapshot_identity(manifest: dict[str, Any]) -> dict[str, str]:
    return {
        field: manifest[field]
        for field in (
            "snapshot_id",
            "source_fingerprint",
            "artifact_fingerprint",
            "logical_fingerprint",
        )
    }


def _redact_result(value: dict[str, Any]) -> dict[str, Any]:
    """Remove capability material before writing user-visible local state."""

    def redact(item: Any) -> Any:
        if isinstance(item, dict):
            return {
                key: redact(child)
                for key, child in item.items()
                if key not in {"capability_token", "capability_sha256"}
                and not key.startswith("_")
            }
        if isinstance(item, list):
            return [redact(child) for child in item]
        return item

    redacted = redact(value)
    if not isinstance(redacted, dict):
        raise PipelineError("INTERNAL_ERROR", "pipeline result is not an object")
    return redacted


def _current_matches(
    current: dict[str, Any],
    manifest: dict[str, Any],
    *,
    homeops_version: str,
    source_revision: str,
    image_digest: str,
    deployment_id: str | None = None,
    run_id: str | None = None,
) -> bool:
    return bool(
        (deployment_id is None or current["current_deployment_id"] == deployment_id)
        and (run_id is None or current["run_id"] == run_id)
        and current["snapshot_id"] == manifest["snapshot_id"]
        and current["source_fingerprint"] == manifest["source_fingerprint"]
        and current["artifact_fingerprint"] == manifest["artifact_fingerprint"]
        and current["logical_fingerprint"] == manifest["logical_fingerprint"]
        and current["homeops_version"] == homeops_version
        and current["source_revision"] == source_revision
        and current["image_digest"] == image_digest
        and current["snapshot_contract_version"] == SNAPSHOT_CONTRACT_VERSION
        and current["build_contract_version"] == BUILD_CONTRACT_VERSION
    )


def export_candidate(
    vault: Path,
    destination: Path,
    *,
    source_revision: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate mutable source around an independently validated immutable export."""

    before = inspect_vault(vault)
    if before["validation"]["errors"]:
        raise PipelineError("LOCAL_VAULT_INVALID", "local vault validation failed")
    export_snapshot(vault, destination)
    candidate = inspect_vault(destination)
    if candidate["validation"]["errors"]:
        raise PipelineError("LOCAL_VAULT_INVALID", "exported candidate validation failed")
    after = inspect_vault(vault)
    if after["validation"]["errors"] or not (
        _same_identity(before, candidate) and _same_identity(candidate, after)
    ):
        raise PipelineError(
            "LOCAL_SOURCE_CHANGED", "vault changed during immutable candidate export", retryable=True
        )
    manifest = create_snapshot_manifest(
        destination,
        candidate,
        created_at=utc_now(),
        package_version=_package_version(),
        source_revision=source_revision,
    )
    verify_snapshot(destination, manifest)
    return manifest, before


def reconcile_local(
    vault: Path,
    root: Path,
    state_dir: Path,
    *,
    source_revision: str | None,
    image_digest: str | None,
    evaluation_cases: Sequence[Path] = (),
    quiescence_seconds: float = 10.0,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Build and promote a quiescent local synced vault without SSH ingress."""

    if not 0 <= quiescence_seconds <= 300:
        raise PipelineError(
            "INTERNAL_ERROR",
            "quiescence_seconds must be between 0 and 300",
        )
    root = root.resolve()
    state_dir = state_dir.resolve()
    result: dict[str, Any]
    try:
        with local_pipeline_lock(state_dir):
            homeops_version, released_revision, released_digest = _released_identity(
                source_revision,
                image_digest,
            )
            first = inspect_vault(vault)
            if first["validation"]["errors"]:
                raise PipelineError(
                    "LOCAL_VAULT_INVALID",
                    "synced vault validation failed",
                )
            if quiescence_seconds:
                sleep(quiescence_seconds)
            second = inspect_vault(vault)
            if second["validation"]["errors"] or not _same_identity(first, second):
                raise PipelineError(
                    "LOCAL_SOURCE_CHANGED",
                    "synced vault did not remain quiescent",
                    retryable=True,
                )

            candidates = state_dir / "candidates"
            candidates.mkdir(parents=True, exist_ok=True, mode=0o700)
            with tempfile.TemporaryDirectory(prefix="local.", dir=candidates) as temporary:
                exported = Path(temporary) / "vault"
                manifest, _ = export_candidate(
                    vault,
                    exported,
                    source_revision=released_revision,
                )
                if not _same_identity(second, manifest):
                    raise PipelineError(
                        "LOCAL_SOURCE_CHANGED",
                        "synced vault changed after the quiescence check",
                        retryable=True,
                    )
                state = active_state(root / "data")
                current = state.get("current_deployment")
                if current is not None and all(
                    current.get(field) == manifest[field]
                    for field in (
                        "snapshot_id",
                        "source_fingerprint",
                        "artifact_fingerprint",
                        "logical_fingerprint",
                    )
                ) and all(
                    current.get(field) == expected
                    for field, expected in (
                        ("homeops_version", homeops_version),
                        ("source_revision", released_revision),
                        ("image_digest", released_digest),
                    )
                ):
                    result = _result(
                        "UNCHANGED",
                        retryable=False,
                        deployment_id=current["deployment_id"],
                        snapshot_id=current["snapshot_id"],
                        run_id=current["run_id"],
                    )
                else:
                    expected_current = (
                        current["deployment_id"] if current is not None else None
                    )
                    try:
                        snapshot_dir = materialize_snapshot(root, exported, manifest)
                        built = rebuild(
                            snapshot_dir / "vault",
                            root / "data",
                            promote=False,
                            snapshot_manifest=manifest,
                            snapshot_received_at=utc_now(),
                            homeops_version=homeops_version,
                            source_revision=released_revision,
                            image_digest=released_digest,
                            expected_current_deployment_id=expected_current,
                        )
                    except (BuildError, DeploymentError, SnapshotError, OSError) as error:
                        raise PipelineError(
                            "BUILD_FAILED",
                            _redacted_failure(error),
                            retryable=True,
                        ) from error
                    deployment = built.get("deployment")
                    if not isinstance(deployment, dict):
                        raise PipelineError(
                            "BUILD_FAILED",
                            "local build did not produce a deployment record",
                        )
                    try:
                        evaluation = evaluate_candidate(
                            root / "data",
                            built["run_id"],
                            cases=list(evaluation_cases),
                        )
                    except (BuildError, EvaluationError, OSError, ValueError) as error:
                        raise PipelineError(
                            "EVALUATION_FAILED",
                            _redacted_failure(error),
                        ) from error
                    if not evaluation.get("passed"):
                        raise PipelineError(
                            "EVALUATION_FAILED",
                            "local candidate failed promotion-safe evaluation",
                        )

                    current_source = inspect_vault(vault)
                    if current_source["validation"]["errors"] or not _same_identity(
                        current_source,
                        manifest,
                    ):
                        raise PipelineError(
                            "PROMOTED_SOURCE_MOVED",
                            "synced vault moved before candidate promotion",
                            retryable=True,
                        )
                    selected = active_state(root / "data").get(
                        "current_deployment"
                    )
                    actual_current = (
                        selected["deployment_id"] if selected is not None else None
                    )
                    if actual_current != expected_current:
                        raise PipelineError(
                            "PROMOTION_CONFLICT",
                            "active deployment moved before local promotion",
                            retryable=True,
                        )
                    try:
                        promoted = promote(
                            root / "data",
                            deployment,
                            expected_current_deployment_id=expected_current,
                        )
                        verified = verify_active(root)
                    except (BuildError, DeploymentError, SnapshotError, OSError) as error:
                        raise PipelineError(
                            "POST_PROMOTION_MISMATCH",
                            _redacted_failure(error),
                        ) from error
                    result = _result(
                        "PROMOTED",
                        retryable=False,
                        deployment_id=deployment["deployment_id"],
                        snapshot_id=deployment["snapshot_id"],
                        run_id=deployment["run_id"],
                        promotion=promoted["result"],
                        verification=verified["outcome"],
                    )
    except PipelineError as error:
        result = _result(
            error.outcome,
            retryable=error.retryable,
            diagnostic=_redacted_failure(error),
        )
    except (
        BuildError,
        DeploymentError,
        EvaluationError,
        SnapshotError,
        OSError,
        ValueError,
    ) as error:
        result = _result(
            "INTERNAL_ERROR",
            retryable=True,
            diagnostic=_redacted_failure(error),
        )
    _write_last_result(state_dir, result)
    return result


@contextmanager
def local_pipeline_lock(state_dir: Path) -> Iterator[None]:
    state_dir = state_dir.resolve()
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(state_dir / "pipeline.lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise PipelineError("UNCHANGED", "publisher reconciliation is already running") from error
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


class TransportError(RuntimeError):
    pass


class ReceiverRejected(TransportError):
    def __init__(self, response: dict[str, Any]):
        self.response = response
        self.outcome = str(response.get("outcome") or "INTERNAL_ERROR")
        self.retryable = bool(response.get("retryable", False))
        super().__init__(
            f"receiver rejected request: {self.outcome}"
            + (f": {response['message']}" if response.get("message") else "")
        )


def _validate_receiver_envelope(response: Any) -> dict[str, Any]:
    if not isinstance(response, dict):
        raise TransportError("receiver response must be an object")
    if response.get("schema_version") != RECEIVER_SCHEMA_VERSION:
        raise TransportError("receiver response has unsupported schema version")
    if response.get("protocol") != RECEIVER_PROTOCOL:
        raise TransportError("receiver response has unsupported protocol")
    if not isinstance(response.get("outcome"), str) or not response["outcome"]:
        raise TransportError("receiver response lacks an outcome")
    if "retryable" in response and not isinstance(response["retryable"], bool):
        raise TransportError("receiver retryable flag is invalid")
    return response


def _pipeline_error_from_receiver(error: ReceiverRejected) -> PipelineError:
    if error.outcome in {"NOT_FOUND"}:
        outcome = "AUTHORIZATION_FAILED"
    elif error.outcome in {"COMMIT_MISMATCH", "COMMIT_CONFLICT"}:
        outcome = "PROMOTION_CONFLICT"
    elif error.outcome in {
        "PROTOCOL_REJECTED",
        "INVALID_REQUEST",
        "REQUEST_ID_CONFLICT",
        "ARCHIVE_LIMIT_EXCEEDED",
        "ARCHIVE_INVALID",
    }:
        outcome = "TRANSFER_FAILED"
    elif error.outcome == "COMMIT_NOT_READY":
        outcome = "TIMEOUT"
    elif error.outcome == "INTERNAL_ERROR":
        outcome = "HOMEOPS_UNAVAILABLE" if error.retryable else "INTERNAL_ERROR"
    else:
        outcome = "INTERNAL_ERROR"
    return PipelineError(outcome, str(error), retryable=error.retryable)


@dataclass(frozen=True)
class SSHTransport:
    target: str
    identity_file: Path
    known_hosts: Path
    control_socket: Path
    timeout_seconds: int = 60

    def _base(self) -> list[str]:
        return [
            "ssh",
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            f"IdentityFile={self.identity_file.resolve()}",
            "-o",
            "IdentityAgent=none",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={self.known_hosts.resolve()}",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "GSSAPIAuthentication=no",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "RequestTTY=no",
            "-o",
            f"ControlPath={self.control_socket.resolve()}",
            "-o",
            "ControlMaster=auto",
            "-o",
            "ControlPersist=120",
            self.target,
        ]

    def call(self, verb: str, body: bytes | BinaryIO) -> dict[str, Any]:
        if verb not in {"submit", "status", "commit", "current"}:
            raise TransportError("unsupported receiver verb")
        self.control_socket.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        command = [*self._base(), f"homeops-receiver-v1 {verb}"]
        try:
            completed = subprocess.run(
                command,
                input=body.read() if hasattr(body, "read") else body,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=self.timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise TransportError(str(error)) from error
        try:
            lines = completed.stdout.decode("utf-8", "strict").splitlines()
        except UnicodeDecodeError as error:
            raise TransportError("receiver returned non-UTF-8 output") from error
        if completed.returncode:
            if len(lines) == 1:
                try:
                    response = _validate_receiver_envelope(
                        strict_json_loads(lines[0])
                    )
                except DeploymentError:
                    response = None
                if isinstance(response, dict):
                    raise ReceiverRejected(response)
            diagnostic = completed.stderr.decode("utf-8", "replace")[:300].strip()
            raise TransportError(
                f"receiver exited {completed.returncode}" + (f": {diagnostic}" if diagnostic else "")
            )
        if len(lines) != 1:
            raise TransportError("receiver did not return exactly one JSON line")
        try:
            response = _validate_receiver_envelope(strict_json_loads(lines[0]))
        except DeploymentError as error:
            raise TransportError("receiver returned invalid JSON") from error
        return response

    def close(self) -> None:
        subprocess.run(
            [*self._base()[:-1], "-O", "exit", self.target],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
        )

    def current(self) -> dict[str, Any]:
        response = self.call("current", b"")
        if (
            tuple(response) != ("schema_version", "protocol", "outcome", "current")
            or response.get("outcome") != "CURRENT"
            or not isinstance(response.get("current"), dict)
        ):
            raise TransportError("receiver returned an invalid current envelope")
        current = response["current"]
        fields = (
            "schema_version",
            "current_deployment_id",
            "snapshot_id",
            "run_id",
            "source_fingerprint",
            "artifact_fingerprint",
            "logical_fingerprint",
            "homeops_version",
            "source_revision",
            "image_digest",
            "snapshot_contract_version",
            "build_contract_version",
            "promoted_at",
        )
        if tuple(current) != fields or current["schema_version"] != 2:
            raise TransportError("receiver returned an invalid current deployment schema")
        for field in (
            "current_deployment_id",
            "snapshot_id",
            "source_fingerprint",
            "artifact_fingerprint",
            "logical_fingerprint",
        ):
            value = current[field]
            if not isinstance(value, str) or (value and (len(value) != 64 or any(
                character not in "0123456789abcdef" for character in value
            ))):
                raise TransportError(f"receiver current {field} is invalid")
        if not all(
            isinstance(current[field], str)
            for field in (
                "run_id",
                "homeops_version",
                "source_revision",
                "image_digest",
                "snapshot_contract_version",
                "build_contract_version",
                "promoted_at",
            )
        ):
            raise TransportError("receiver current metadata is invalid")
        return current


def _status_body(request: dict[str, Any]) -> bytes:
    value = {
        "schema_version": RECEIVER_SCHEMA_VERSION,
        "protocol": RECEIVER_PROTOCOL,
        "request_id": request["request_id"],
        "publisher_id": request["publisher_id"],
        "capability_token": request["capability_token"],
    }
    return canonical_receiver_json(value, tuple(value))


def _commit_body(request: dict[str, Any], deployment_id: str) -> bytes:
    value = {
        "schema_version": RECEIVER_SCHEMA_VERSION,
        "protocol": RECEIVER_PROTOCOL,
        "request_id": request["request_id"],
        "publisher_id": request["publisher_id"],
        "capability_token": request["capability_token"],
        "candidate_deployment_id": deployment_id,
        "expected_current_deployment_id": request["expected_current_deployment_id"],
    }
    return canonical_receiver_json(value, tuple(value))


def _poll(
    transport: SSHTransport,
    request: dict[str, Any],
    *,
    deadline: float,
    terminal_only: bool = False,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    delay = 0.5
    while time.monotonic() < deadline:
        response = transport.call("status", _status_body(request))
        if response.get("request_id") != request["request_id"]:
            raise TransportError("receiver status does not match request")
        response_outcome = response.get("outcome")
        if not isinstance(response.get("commit_accepted"), bool):
            raise TransportError("receiver status lacks commit acceptance state")
        if response_outcome == "RESULT" and isinstance(response.get("result"), dict):
            result = response["result"]
            if (
                result.get("schema_version") != RESULT_SCHEMA_VERSION
                or result.get("protocol") != RECEIVER_PROTOCOL
                or result.get("request_id") != request["request_id"]
                or result.get("publisher_id") != request["publisher_id"]
                or not isinstance(result.get("outcome"), str)
                or not isinstance(result.get("retryable"), bool)
            ):
                raise TransportError("receiver result does not match request")
            if not terminal_only or result.get("outcome") in TERMINAL_OUTCOMES:
                return {
                    **result,
                    "_commit_accepted": response["commit_accepted"],
                }
            # The candidate result can remain visible until the remote worker
            # consumes the commit marker. Keep polling for the terminal result.
        elif response_outcome != "PENDING":
            raise TransportError("receiver returned an invalid status envelope")
        sleep(delay)
        delay = min(delay * 1.5, 5.0)
    raise PipelineError("TIMEOUT", "remote pipeline status timed out", retryable=True)


def _write_last_result(state_dir: Path, result: dict[str, Any]) -> None:
    durable_atomic_json(
        state_dir.resolve() / "last-result.json", _redact_result(result), mode=0o600
    )


_ATTEMPT_PHASES = {
    "PREPARED",
    "SUBMITTING",
    "SUBMITTED",
    "COMMITTING",
    "COMMIT_REQUESTED",
    "TERMINAL",
}
_ATTEMPT_FIELDS = {
    "schema_version",
    "protocol",
    "phase",
    "request",
    "snapshot",
    "release_policy",
    "archive_sha256",
    "candidate_deployment_id",
    "promotion_policy_id",
    "created_at",
    "updated_at",
    "terminal_result",
}


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_policy(policy: Any) -> dict[str, Any]:
    fields = {
        "schema_version",
        "homeops_version",
        "source_revision",
        "image_digest",
        "snapshot_schema_version",
        "snapshot_contract_version",
        "build_schema_version",
        "build_contract_version",
        "evaluation_suite_sha256",
    }
    if not isinstance(policy, dict) or set(policy) != fields:
        raise PipelineError("INTERNAL_ERROR", "promotion policy contract is invalid")
    if policy["schema_version"] != PROMOTION_POLICY_SCHEMA_VERSION:
        raise PipelineError("INTERNAL_ERROR", "promotion policy schema is unsupported")
    for field in (
        "homeops_version",
        "source_revision",
        "image_digest",
        "snapshot_contract_version",
        "build_contract_version",
    ):
        if not isinstance(policy[field], str) or not policy[field]:
            raise PipelineError("INTERNAL_ERROR", f"promotion policy {field} is invalid")
    for field in ("snapshot_schema_version", "build_schema_version"):
        if (
            not isinstance(policy[field], int)
            or isinstance(policy[field], bool)
            or policy[field] < 1
        ):
            raise PipelineError("INTERNAL_ERROR", f"promotion policy {field} is invalid")
    suites = policy["evaluation_suite_sha256"]
    if (
        not isinstance(suites, list)
        or suites != sorted(set(suites))
        or any(
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            for digest in suites
        )
    ):
        raise PipelineError("INTERNAL_ERROR", "promotion evaluation policy is invalid")
    return dict(policy)


def _validate_pending_attempt(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _ATTEMPT_FIELDS:
        raise PipelineError("INTERNAL_ERROR", "pending attempt contract is invalid")
    if (
        value["schema_version"] != PENDING_ATTEMPT_SCHEMA_VERSION
        or value["protocol"] != RECEIVER_PROTOCOL
        or value["phase"] not in _ATTEMPT_PHASES
    ):
        raise PipelineError("INTERNAL_ERROR", "pending attempt schema is unsupported")
    request = value["request"]
    request_fields = (
        "schema_version",
        "protocol",
        "request_id",
        "publisher_id",
        "capability_token",
        "release_policy_id",
        "snapshot_id",
        "expected_current_deployment_id",
        "snapshot_manifest_sha256",
    )
    if not isinstance(request, dict) or set(request) != set(request_fields):
        raise PipelineError("INTERNAL_ERROR", "pending request contract is invalid")
    try:
        checked_request = validate_request_message(
            {field: request[field] for field in request_fields}
        )
    except SnapshotError as error:
        raise PipelineError("INTERNAL_ERROR", f"pending request is invalid: {error}") from error
    snapshot = value["snapshot"]
    snapshot_fields = {
        "snapshot_id",
        "source_fingerprint",
        "artifact_fingerprint",
        "logical_fingerprint",
    }
    if not isinstance(snapshot, dict) or set(snapshot) != snapshot_fields:
        raise PipelineError("INTERNAL_ERROR", "pending snapshot identity is invalid")
    for field in snapshot_fields:
        item = snapshot[field]
        if (
            not isinstance(item, str)
            or len(item) != 64
            or any(character not in "0123456789abcdef" for character in item)
        ):
            raise PipelineError("INTERNAL_ERROR", f"pending snapshot {field} is invalid")
    if snapshot["snapshot_id"] != checked_request["snapshot_id"]:
        raise PipelineError("INTERNAL_ERROR", "pending snapshot and request disagree")
    release_policy = _validate_policy(value["release_policy"])
    if checked_request["release_policy_id"] != _policy_id(release_policy):
        raise PipelineError(
            "INTERNAL_ERROR", "pending request and release policy disagree"
        )
    archive_digest = value["archive_sha256"]
    if (
        not isinstance(archive_digest, str)
        or len(archive_digest) != 64
        or any(character not in "0123456789abcdef" for character in archive_digest)
    ):
        raise PipelineError("INTERNAL_ERROR", "pending archive digest is invalid")
    candidate = value["candidate_deployment_id"]
    if candidate is not None and (
        not isinstance(candidate, str)
        or len(candidate) != 64
        or any(character not in "0123456789abcdef" for character in candidate)
    ):
        raise PipelineError("INTERNAL_ERROR", "pending candidate deployment is invalid")
    if value["phase"] in {"COMMITTING", "COMMIT_REQUESTED"} and candidate is None:
        raise PipelineError("INTERNAL_ERROR", "pending commit lacks a candidate deployment")
    promotion_policy_id = value["promotion_policy_id"]
    if promotion_policy_id is not None and (
        not isinstance(promotion_policy_id, str)
        or len(promotion_policy_id) != 64
        or any(character not in "0123456789abcdef" for character in promotion_policy_id)
    ):
        raise PipelineError("INTERNAL_ERROR", "pending promotion policy is invalid")
    if value["phase"] in {"COMMITTING", "COMMIT_REQUESTED"} and promotion_policy_id is None:
        raise PipelineError("INTERNAL_ERROR", "pending commit lacks promotion policy identity")
    for field in ("created_at", "updated_at"):
        if not isinstance(value[field], str) or not value[field]:
            raise PipelineError("INTERNAL_ERROR", f"pending attempt {field} is invalid")
    terminal = value["terminal_result"]
    if value["phase"] == "TERMINAL":
        if not isinstance(terminal, dict) or terminal.get("outcome") not in TERMINAL_OUTCOMES:
            raise PipelineError("INTERNAL_ERROR", "pending terminal result is invalid")
    elif terminal is not None:
        raise PipelineError("INTERNAL_ERROR", "nonterminal attempt contains a terminal result")
    return {
        **value,
        "request": checked_request,
        "snapshot": dict(snapshot),
        "release_policy": release_policy,
        "terminal_result": _redact_result(terminal) if terminal is not None else None,
    }


def _pending_paths(state_dir: Path) -> tuple[Path, Path]:
    root = state_dir.resolve()
    return root / _PENDING_ATTEMPT_NAME, root / _PENDING_ARCHIVE_NAME


def _write_pending_attempt(state_dir: Path, attempt: dict[str, Any]) -> dict[str, Any]:
    checked = _validate_pending_attempt(attempt)
    state_dir = state_dir.resolve()
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(state_dir, 0o700)
    pending_path, _ = _pending_paths(state_dir)
    durable_atomic_json(pending_path, checked, mode=0o600)
    return checked


def _load_pending_attempt(state_dir: Path) -> dict[str, Any] | None:
    pending_path, archive_path = _pending_paths(state_dir)
    if not pending_path.exists():
        return None
    if pending_path.is_symlink() or pending_path.stat().st_mode & 0o077:
        raise PipelineError("INTERNAL_ERROR", "pending attempt permissions are not private")
    try:
        parsed = strict_json_loads(pending_path.read_text(encoding="utf-8"))
    except (OSError, DeploymentError) as error:
        raise PipelineError("INTERNAL_ERROR", f"pending attempt cannot be read: {error}") from error
    checked = _validate_pending_attempt(parsed)
    if checked["phase"] != "TERMINAL":
        if (
            not archive_path.is_file()
            or archive_path.is_symlink()
            or archive_path.stat().st_mode & 0o077
            or file_sha256(archive_path) != checked["archive_sha256"]
        ):
            raise PipelineError(
                "INTERNAL_ERROR", "pending submission archive is missing or invalid"
            )
    return checked


def _persist_pending_archive(state_dir: Path, archive: Path) -> str:
    state_dir = state_dir.resolve()
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(state_dir, 0o700)
    _, destination = _pending_paths(state_dir)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=state_dir, prefix=".pending-submission.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output, archive.open("rb") as source:
            shutil.copyfileobj(source, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
        _fsync_directory(state_dir)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return file_sha256(destination)


def _update_pending_attempt(
    state_dir: Path, attempt: dict[str, Any], **changes: Any
) -> dict[str, Any]:
    updated = {**attempt, **changes, "updated_at": utc_now()}
    return _write_pending_attempt(state_dir, updated)


def _retire_pending_attempt(state_dir: Path) -> None:
    pending_path, archive_path = _pending_paths(state_dir)
    archive_path.unlink(missing_ok=True)
    pending_path.unlink(missing_ok=True)
    _fsync_directory(state_dir.resolve())


def _resolve_pending_attempt(
    state_dir: Path, attempt: dict[str, Any], result: dict[str, Any]
) -> dict[str, Any]:
    redacted = _redact_result(result)
    terminal = _update_pending_attempt(
        state_dir, attempt, phase="TERMINAL", terminal_result=redacted
    )
    _write_last_result(state_dir, redacted)
    _retire_pending_attempt(state_dir)
    return terminal["terminal_result"]


def _pending_failure(
    state_dir: Path,
    attempt: dict[str, Any] | None,
    result: dict[str, Any],
) -> dict[str, Any]:
    """Record a bounded diagnostic while retaining every unresolved attempt."""

    redacted = _redact_result(result)
    _write_last_result(state_dir, redacted)
    # Exceptions are not proof of a resolved remote state. Keep the exact
    # capability/request/archive for a later deterministic recovery attempt.
    return redacted


def _terminal_matches_attempt(
    terminal: dict[str, Any], attempt: dict[str, Any]
) -> bool:
    snapshot = attempt["snapshot"]
    promotion_policy_id = attempt["promotion_policy_id"]
    return all(
        (
            terminal.get("snapshot_id") == snapshot["snapshot_id"],
            attempt["candidate_deployment_id"] is None
            or terminal.get("candidate_deployment_id")
            == attempt["candidate_deployment_id"],
            terminal.get("expected_current_deployment_id")
            == attempt["request"]["expected_current_deployment_id"],
            terminal.get("release_policy_id")
            == attempt["request"]["release_policy_id"],
            promotion_policy_id is None
            or terminal.get("promotion_policy_id") == promotion_policy_id,
        )
    )


def _source_matches_pending(vault: Path, attempt: dict[str, Any]) -> bool:
    inspected = inspect_vault(vault)
    return not inspected["validation"]["errors"] and _same_identity(
        inspected, attempt["snapshot"]
    )


def _validate_remote_terminal(
    transport: SSHTransport,
    attempt: dict[str, Any],
    terminal: dict[str, Any],
) -> None:
    if terminal.get("outcome") not in {"PROMOTED", "UNCHANGED"}:
        return
    if not _terminal_matches_attempt(terminal, attempt):
        raise PipelineError(
            "POST_PROMOTION_MISMATCH", "remote terminal result disagrees with pending attempt"
        )
    policy = attempt["release_policy"]
    if not _current_matches(
        transport.current(),
        attempt["snapshot"],
        homeops_version=policy["homeops_version"],
        source_revision=policy["source_revision"],
        image_digest=policy["image_digest"],
        deployment_id=terminal.get("candidate_deployment_id"),
        run_id=terminal.get("run_id"),
    ):
        raise PipelineError(
            "POST_PROMOTION_MISMATCH",
            "selected deployment does not exactly match pending attempt",
        )


def _resume_pending_attempt(
    *,
    vault: Path,
    state_dir: Path,
    transport: SSHTransport,
    attempt: dict[str, Any],
    release_policy: dict[str, Any],
    timeout_seconds: int,
) -> dict[str, Any]:
    if attempt["request"]["publisher_id"] != validate_publisher_id(
        attempt["request"]["publisher_id"]
    ):
        raise PipelineError("INTERNAL_ERROR", "pending publisher identity is invalid")
    if attempt["phase"] == "TERMINAL":
        return _resolve_pending_attempt(state_dir, attempt, attempt["terminal_result"])

    request = attempt["request"]
    deadline = time.monotonic() + timeout_seconds
    policy_matches = attempt["release_policy"] == release_policy
    source_matches = _source_matches_pending(vault, attempt)
    can_authorize = policy_matches and source_matches
    if not can_authorize and attempt["phase"] in {"PREPARED", "SUBMITTING", "SUBMITTED"}:
        return _resolve_pending_attempt(
            state_dir,
            attempt,
            _result(
                "LOCAL_SOURCE_CHANGED",
                request_id=request["request_id"],
                publisher_id=request["publisher_id"],
                snapshot_id=attempt["snapshot"]["snapshot_id"],
                retryable=True,
                diagnostic=(
                    "pending attempt belongs to a different HomeOps release policy"
                    if not policy_matches
                    else "local source changed before commit authorization"
                ),
            ),
        )
    if attempt["phase"] in {"PREPARED", "SUBMITTING"}:
        attempt = _update_pending_attempt(state_dir, attempt, phase="SUBMITTING")
        _, archive_path = _pending_paths(state_dir)
        with archive_path.open("rb") as stream:
            accepted = transport.call("submit", stream)
        if (
            accepted.get("outcome") != "ACCEPTED"
            or accepted.get("request_id") != request["request_id"]
            or accepted.get("archive_sha256") != attempt["archive_sha256"]
        ):
            raise TransportError("receiver did not accept pending submission")
        attempt = _update_pending_attempt(state_dir, attempt, phase="SUBMITTED")

    if attempt["phase"] == "SUBMITTED":
        ready = _poll(transport, request, deadline=deadline)
        if ready.get("outcome") in TERMINAL_OUTCOMES:
            _validate_remote_terminal(transport, attempt, ready)
            return _resolve_pending_attempt(state_dir, attempt, ready)
        if ready.get("outcome") != "CANDIDATE_READY":
            raise TransportError("remote processor returned an invalid candidate result")
        deployment_id = ready.get("candidate_deployment_id")
        if not isinstance(deployment_id, str):
            raise TransportError("candidate result lacks deployment ID")
        promotion_policy_id = ready.get("promotion_policy_id")
        if (
            ready.get("release_policy_id") != request["release_policy_id"]
            or not isinstance(promotion_policy_id, str)
            or len(promotion_policy_id) != 64
            or any(
                character not in "0123456789abcdef"
                for character in promotion_policy_id
            )
        ):
            raise TransportError("candidate result has invalid release policy identity")
        if not _source_matches_pending(vault, attempt):
            return _resolve_pending_attempt(
                state_dir,
                attempt,
                _result(
                    "LOCAL_SOURCE_CHANGED",
                    request_id=request["request_id"],
                    publisher_id=request["publisher_id"],
                    snapshot_id=attempt["snapshot"]["snapshot_id"],
                    retryable=True,
                    diagnostic="local source changed before commit authorization",
                ),
            )
        attempt = _update_pending_attempt(
            state_dir,
            attempt,
            phase="COMMITTING",
            candidate_deployment_id=deployment_id,
            promotion_policy_id=promotion_policy_id,
        )

    deployment_id = attempt["candidate_deployment_id"]
    if attempt["phase"] == "COMMITTING":
        status = _poll(transport, request, deadline=deadline)
        if status.get("outcome") in TERMINAL_OUTCOMES:
            _validate_remote_terminal(transport, attempt, status)
            if status.get("outcome") == "PROMOTED" and not (
                attempt["release_policy"] == release_policy
                and _source_matches_pending(vault, attempt)
            ):
                status = {
                    **status,
                    "outcome": "PROMOTED_SOURCE_MOVED",
                    "retryable": True,
                }
            return _resolve_pending_attempt(state_dir, attempt, status)
        if status.get("outcome") != "CANDIDATE_READY":
            raise TransportError("remote processor returned an invalid pending status")
        if status.get("_commit_accepted") is True:
            attempt = _update_pending_attempt(
                state_dir, attempt, phase="COMMIT_REQUESTED"
            )
        elif not (
            attempt["release_policy"] == release_policy
            and _source_matches_pending(vault, attempt)
        ):
            return _resolve_pending_attempt(
                state_dir,
                attempt,
                _result(
                    "LOCAL_SOURCE_CHANGED",
                    request_id=request["request_id"],
                    publisher_id=request["publisher_id"],
                    snapshot_id=attempt["snapshot"]["snapshot_id"],
                    retryable=True,
                    diagnostic="pending commit authorization is no longer current",
                ),
            )

    if attempt["phase"] == "COMMITTING":
        committed = transport.call("commit", _commit_body(request, deployment_id))
        if (
            committed.get("outcome") != "COMMIT_ACCEPTED"
            or committed.get("request_id") != request["request_id"]
        ):
            raise TransportError("receiver did not accept pending commit")
        attempt = _update_pending_attempt(
            state_dir, attempt, phase="COMMIT_REQUESTED"
        )

    terminal = _poll(transport, request, deadline=deadline, terminal_only=True)
    if terminal.get("outcome") not in TERMINAL_OUTCOMES:
        raise TransportError("remote processor did not return a terminal result")
    _validate_remote_terminal(transport, attempt, terminal)
    if terminal.get("outcome") == "PROMOTED" and not _source_matches_pending(vault, attempt):
        terminal = {
            **terminal,
            "outcome": "PROMOTED_SOURCE_MOVED",
            "retryable": True,
        }
    return _resolve_pending_attempt(state_dir, attempt, terminal)


def reconcile(
    *,
    vault: Path,
    state_dir: Path,
    transport: SSHTransport,
    publisher_id: str = DEFAULT_PUBLISHER_ID,
    source_revision: str | None,
    image_digest: str | None,
    timeout_seconds: int = 900,
) -> dict[str, Any]:
    """Perform one complete compare-and-swap publication attempt."""

    publisher_id = validate_publisher_id(publisher_id)
    state_dir = state_dir.resolve()
    homeops_version, released_revision, released_digest = _released_identity(
        source_revision, image_digest
    )
    release_policy = _release_policy(
        homeops_version, released_revision, released_digest
    )
    with local_pipeline_lock(state_dir):
        attempt: dict[str, Any] | None = None
        request_id: str | None = None
        try:
            attempt = _load_pending_attempt(state_dir)
            if attempt is not None:
                request_id = attempt["request"]["request_id"]
                if attempt["request"]["publisher_id"] != publisher_id:
                    raise PipelineError(
                        "INTERNAL_ERROR",
                        "pending attempt publisher differs from configured publisher",
                    )
                return _resume_pending_attempt(
                    vault=vault,
                    state_dir=state_dir,
                    transport=transport,
                    attempt=attempt,
                    release_policy=release_policy,
                    timeout_seconds=timeout_seconds,
                )

            request_id = str(uuid.uuid4())
            with tempfile.TemporaryDirectory(prefix="homeops-publish-") as temporary_name:
                temporary = Path(temporary_name)
                os.chmod(temporary, 0o700)
                snapshot_root = temporary / "vault"
                manifest, source_before = export_candidate(
                    vault, snapshot_root, source_revision=released_revision
                )
                current = transport.current()
                expected = current["current_deployment_id"]
                if _current_matches(
                    current,
                    manifest,
                    homeops_version=homeops_version,
                    source_revision=released_revision,
                    image_digest=released_digest,
                ):
                    result = _result(
                        "UNCHANGED",
                        request_id=request_id,
                        publisher_id=publisher_id,
                        deployment_id=expected or None,
                        snapshot_id=manifest["snapshot_id"],
                        run_id=current["run_id"] or None,
                        retryable=False,
                    )
                    _write_last_result(state_dir, result)
                    return result
                capability = secrets.token_hex(32)
                manifest_path = temporary / "snapshot.json"
                write_manifest(manifest_path, manifest)
                request = {
                    "schema_version": RECEIVER_SCHEMA_VERSION,
                    "protocol": RECEIVER_PROTOCOL,
                    "request_id": request_id,
                    "publisher_id": publisher_id,
                    "capability_token": capability,
                    "release_policy_id": _policy_id(release_policy),
                    "snapshot_id": manifest["snapshot_id"],
                    "expected_current_deployment_id": expected,
                    "snapshot_manifest_sha256": file_sha256(manifest_path),
                }
                validate_request_message(request)
                archive = temporary / "submission.tar"
                with archive.open("wb") as stream:
                    write_submission_archive(stream, request, manifest, snapshot_root)
                    stream.flush()
                    os.fsync(stream.fileno())
                archive_digest = _persist_pending_archive(state_dir, archive)
                now = utc_now()
                attempt = _write_pending_attempt(
                    state_dir,
                    {
                        "schema_version": PENDING_ATTEMPT_SCHEMA_VERSION,
                        "protocol": RECEIVER_PROTOCOL,
                        "phase": "PREPARED",
                    "request": request,
                        "snapshot": _snapshot_identity(manifest),
                        "release_policy": release_policy,
                        "archive_sha256": archive_digest,
                        "candidate_deployment_id": None,
                        "promotion_policy_id": None,
                        "created_at": now,
                        "updated_at": now,
                        "terminal_result": None,
                    },
                )
                return _resume_pending_attempt(
                    vault=vault,
                    state_dir=state_dir,
                    transport=transport,
                    attempt=attempt,
                    release_policy=release_policy,
                    timeout_seconds=timeout_seconds,
                )
        except PipelineError as error:
            result = _result(
                error.outcome,
                request_id=request_id or "unavailable",
                publisher_id=publisher_id,
                retryable=error.retryable,
                diagnostic=_redacted_failure(error),
            )
        except ReceiverRejected as error:
            mapped = _pipeline_error_from_receiver(error)
            result = _result(
                mapped.outcome,
                request_id=request_id or "unavailable",
                publisher_id=publisher_id,
                retryable=mapped.retryable,
                diagnostic=_redacted_failure(mapped),
            )
        except TransportError as error:
            result = _result(
                "HOMEOPS_UNAVAILABLE",
                request_id=request_id or "unavailable",
                publisher_id=publisher_id,
                retryable=True,
                diagnostic=_redacted_failure(error),
            )
        except (BuildError, SnapshotError, OSError, ValueError) as error:
            result = _result(
                "INTERNAL_ERROR",
                request_id=request_id or "unavailable",
                publisher_id=publisher_id,
                retryable=False,
                diagnostic=_redacted_failure(error),
            )
        finally:
            transport.close()
        return _pending_failure(state_dir, attempt, result)


_WIRE_REQUEST_FIELDS = (
    "schema_version",
    "protocol",
    "request_id",
    "publisher_id",
    "capability_token",
    "release_policy_id",
    "snapshot_id",
    "expected_current_deployment_id",
    "snapshot_manifest_sha256",
)
_QUEUED_REQUEST_FIELDS = (
    "schema_version",
    "protocol",
    "request_id",
    "publisher_id",
    "release_policy_id",
    "snapshot_id",
    "expected_current_deployment_id",
    "snapshot_manifest_sha256",
)


def _load_canonical_request(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    try:
        request = strict_json_loads(raw)
    except DeploymentError as error:
        raise SnapshotError("request.json is invalid JSON") from error
    if not isinstance(request, dict) or tuple(request) != _QUEUED_REQUEST_FIELDS:
        raise SnapshotError("queued request has missing, reordered, or unknown fields")
    if "capability_token" in request:
        raise SnapshotError("queued request persisted a raw capability token")
    checked_wire = validate_request_message(
        {
            "schema_version": request["schema_version"],
            "protocol": request["protocol"],
            "request_id": request["request_id"],
            "publisher_id": request["publisher_id"],
            "capability_token": "0" * 64,
            "release_policy_id": request["release_policy_id"],
            "snapshot_id": request["snapshot_id"],
            "expected_current_deployment_id": request[
                "expected_current_deployment_id"
            ],
            "snapshot_manifest_sha256": request["snapshot_manifest_sha256"],
        }
    )
    checked = {field: checked_wire[field] for field in _QUEUED_REQUEST_FIELDS}
    if raw != canonical_receiver_json(checked, _QUEUED_REQUEST_FIELDS):
        raise SnapshotError("request.json is not canonical")
    return checked


def _validate_untrusted_payload(payload: Path, receipt: Path) -> tuple[dict[str, Any], dict[str, Any], str]:
    """Revalidate receiver output immediately before copying/building it."""

    if payload.is_symlink() or receipt.is_symlink():
        raise SnapshotError("incoming request contains a symlink")
    request_path = payload / "request.json"
    manifest_path = payload / "snapshot.json"
    vault = payload / "vault"
    request = _load_canonical_request(request_path)
    manifest = read_manifest(manifest_path)
    if request["snapshot_id"] != manifest["snapshot_id"]:
        raise SnapshotError("request and manifest snapshot IDs disagree")
    if request["snapshot_manifest_sha256"] != file_sha256(manifest_path):
        raise SnapshotError("snapshot manifest hash disagrees with request")
    try:
        receipt_value = strict_json_loads(receipt.read_text(encoding="utf-8"))
    except DeploymentError as error:
        raise SnapshotError("receipt is invalid JSON") from error
    if not isinstance(receipt_value, dict):
        raise SnapshotError("receipt must be an object")
    receipt_fields = (
        "schema_version",
        "protocol",
        "request_id",
        "publisher_id",
        "capability_sha256",
        "release_policy_id",
        "snapshot_id",
        "expected_current_deployment_id",
        "snapshot_manifest_sha256",
        "archive_sha256",
        "archive_bytes",
        "extracted_bytes",
        "file_count",
        "vault_file_count",
        "files",
    )
    if tuple(receipt_value) != receipt_fields:
        raise SnapshotError("receipt has missing, reordered, or unknown fields")
    if (
        receipt_value["schema_version"] != RECEIVER_SCHEMA_VERSION
        or receipt_value["protocol"] != RECEIVER_PROTOCOL
    ):
        raise SnapshotError("receipt protocol is unsupported")
    archive_digest = receipt_value.get("archive_sha256")
    if not all(
        isinstance(receipt_value.get(field), str)
        and len(receipt_value[field]) == 64
        and all(character in "0123456789abcdef" for character in receipt_value[field])
        for field in (
            "capability_sha256",
            "release_policy_id",
            "snapshot_id",
            "snapshot_manifest_sha256",
            "archive_sha256",
        )
    ):
        raise SnapshotError("receipt lacks submission archive SHA-256")
    for field in (
        "request_id",
        "publisher_id",
        "release_policy_id",
        "snapshot_id",
        "expected_current_deployment_id",
        "snapshot_manifest_sha256",
    ):
        if receipt_value.get(field) != request[field]:
            raise SnapshotError(f"receipt {field} disagrees with request")
    proofs = receipt_value.get("files")
    if not isinstance(proofs, list):
        raise SnapshotError("receipt file proofs are invalid")
    proof_by_path: dict[str, dict[str, Any]] = {}
    for proof in proofs:
        if not isinstance(proof, dict) or tuple(proof) != ("path", "size", "sha256"):
            raise SnapshotError("receipt file proof contract is invalid")
        proof_path = safe_relative_path(proof["path"])
        if proof_path in proof_by_path:
            raise SnapshotError("receipt contains a duplicate file proof")
        if (
            not isinstance(proof.get("size"), int)
            or isinstance(proof.get("size"), bool)
            or proof["size"] < 0
            or not isinstance(proof.get("sha256"), str)
            or len(proof["sha256"]) != 64
            or any(
                character not in "0123456789abcdef"
                for character in proof["sha256"]
            )
        ):
            raise SnapshotError("receipt file proof value is invalid")
        proof_by_path[proof_path] = proof
    expected_paths = {
        "request.json",
        "snapshot.json",
        *(f"vault/{item['path']}" for item in manifest["inventory"]),
    }
    if set(proof_by_path) != expected_paths:
        raise SnapshotError("receipt file proofs do not exactly cover the submission")
    request_proof = proof_by_path["request.json"]
    # The proof binds the original wire request containing the secret.  Recreate
    # its byte count deterministically without storing or knowing the token.
    zero_token_wire = {
        "schema_version": request["schema_version"],
        "protocol": request["protocol"],
        "request_id": request["request_id"],
        "publisher_id": request["publisher_id"],
        "capability_token": "0" * 64,
        "release_policy_id": request["release_policy_id"],
        "snapshot_id": request["snapshot_id"],
        "expected_current_deployment_id": request[
            "expected_current_deployment_id"
        ],
        "snapshot_manifest_sha256": request["snapshot_manifest_sha256"],
    }
    if request_proof["size"] != len(
        canonical_receiver_json(zero_token_wire, _WIRE_REQUEST_FIELDS)
    ):
        raise SnapshotError("wire request proof has an impossible size")
    manifest_proof = proof_by_path.get("snapshot.json")
    if (
        manifest_proof is None
        or manifest_proof.get("size") != manifest_path.stat().st_size
        or manifest_proof.get("sha256") != file_sha256(manifest_path)
    ):
        raise SnapshotError("snapshot.json does not match receipt proof")
    for item in manifest["inventory"]:
        relative = f"vault/{item['path']}"
        proof = proof_by_path.get(relative)
        if (
            proof is None
            or proof.get("size") != item["size"]
            or proof.get("sha256") != item["sha256"]
        ):
            raise SnapshotError(
                f"vault file does not match receipt proof: {item['path']}"
            )
    if receipt_value["vault_file_count"] != manifest["file_count"]:
        raise SnapshotError("receipt vault file count disagrees with manifest")
    if receipt_value["file_count"] != len(proofs):
        raise SnapshotError("receipt file count disagrees with file proofs")
    if not all(
        isinstance(receipt_value[field], int)
        and not isinstance(receipt_value[field], bool)
        and receipt_value[field] >= 0
        for field in (
            "archive_bytes",
            "extracted_bytes",
            "file_count",
            "vault_file_count",
        )
    ):
        raise SnapshotError("receipt numeric bounds are invalid")
    proof_bytes = sum(proof["size"] for proof in proofs)
    if proof_bytes != receipt_value["extracted_bytes"]:
        raise SnapshotError("receipt extracted byte count disagrees with file proofs")
    if receipt_value["file_count"] != manifest["file_count"] + 2:
        raise SnapshotError("receipt file count disagrees with manifest inventory")
    if receipt_value["archive_bytes"] < receipt_value["extracted_bytes"]:
        raise SnapshotError("receipt archive size is smaller than extracted data")
    verify_snapshot(vault, manifest)
    return request, manifest, archive_digest


def _copy_verified_snapshot(source: Path, destination: Path, manifest: dict[str, Any]) -> None:
    if destination.exists():
        verify_snapshot(destination / "vault", read_manifest(destination / "snapshot.json"))
        if read_manifest(destination / "snapshot.json")["snapshot_id"] != manifest["snapshot_id"]:
            raise SnapshotError("snapshot ID collision in immutable store")
        return
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    temporary = destination.parent / f".{destination.name}.{uuid.uuid4()}.partial"
    temporary.mkdir(mode=0o750)
    try:
        target_vault = temporary / "vault"
        shutil.copytree(source, target_vault, symlinks=False)
        write_manifest(temporary / "snapshot.json", manifest)
        verify_snapshot(target_vault, manifest)
        for path in sorted(temporary.rglob("*"), reverse=True):
            if path.is_file():
                descriptor = os.open(path, os.O_RDONLY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            elif path.is_dir():
                descriptor = os.open(
                    path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                )
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        parent_descriptor = os.open(
            temporary, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
        os.replace(temporary, destination)
        destination_parent = os.open(
            destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(destination_parent)
        finally:
            os.close(destination_parent)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def _result_path(root: Path, publisher: str, request_id: str) -> Path:
    validate_publisher_id(publisher)
    validate_safe_id(request_id, "request_id")
    return root / "results" / publisher / f"{request_id}.json"


def _write_remote_result(root: Path, request: dict[str, Any], result: dict[str, Any]) -> None:
    # Capability material is intentionally absent even if callers pass it by mistake.
    sanitized = {
        key: value
        for key, value in result.items()
        if key not in {"capability_token", "capability_sha256"}
    }
    durable_atomic_json(
        _result_path(root, request["publisher_id"], request["request_id"]),
        sanitized,
        mode=0o640,
    )


def _ready_result(
    request: dict[str, Any], deployment: dict[str, Any], *, promotion_policy_id: str
) -> dict[str, Any]:
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "protocol": RECEIVER_PROTOCOL,
        "request_id": request["request_id"],
        "publisher_id": request["publisher_id"],
        "outcome": "CANDIDATE_READY",
        "candidate_deployment_id": deployment["deployment_id"],
        "expected_current_deployment_id": request["expected_current_deployment_id"],
        "snapshot_id": deployment["snapshot_id"],
        "run_id": deployment["run_id"],
        "release_policy_id": request["release_policy_id"],
        "promotion_policy_id": promotion_policy_id,
        "retryable": False,
    }


def _process_submission(
    root: Path,
    publisher: str,
    request_dir: Path,
    *,
    evaluation_cases: Sequence[Path],
    homeops_version: str,
    source_revision: str,
    image_digest: str,
    release_policy: dict[str, Any],
) -> dict[str, Any]:
    payload = request_dir / "payload"
    request, manifest, archive_digest = _validate_untrusted_payload(
        payload, request_dir / "receipt.json"
    )
    if request["publisher_id"] != publisher or request["request_id"] != request_dir.name:
        raise SnapshotError("incoming request path disagrees with request body")
    if request["release_policy_id"] != _policy_id(
        _base_release_policy(release_policy)
    ):
        raise PipelineError(
            "BUILD_FAILED", "queued request belongs to a different release policy"
        )
    if manifest["exporter"] != {
        "package_version": homeops_version,
        "source_revision": source_revision,
    }:
        raise PipelineError(
            "BUILD_FAILED", "queued snapshot exporter does not match this release policy"
        )
    if (
        manifest["schema_version"] != release_policy["snapshot_schema_version"]
        or manifest["snapshot_contract_version"]
        != release_policy["snapshot_contract_version"]
    ):
        raise PipelineError(
            "BUILD_FAILED", "queued snapshot contract does not match this release policy"
        )
    destination = root / "vault-snapshots" / manifest["snapshot_id"]
    _copy_verified_snapshot(payload / "vault", destination, manifest)
    # Validate processor-owned bytes again immediately before invoking the build.
    stored_manifest = read_manifest(destination / "snapshot.json")
    verify_snapshot(destination / "vault", stored_manifest)
    data = root / "data"
    build = rebuild(
        destination / "vault",
        data,
        force=False,
        promote=False,
        snapshot_manifest=stored_manifest,
        snapshot_received_at=utc_now(),
        homeops_version=homeops_version,
        source_revision=source_revision,
        image_digest=image_digest,
    )
    if build["result"] == "unchanged":
        state = active_state(data)
        current = state.get("current_deployment")
        if current and current.get("snapshot_id") == manifest["snapshot_id"]:
            return {
                "schema_version": RESULT_SCHEMA_VERSION,
                "protocol": RECEIVER_PROTOCOL,
                "request_id": request["request_id"],
                "publisher_id": publisher,
                "outcome": "UNCHANGED",
                "candidate_deployment_id": current["deployment_id"],
                "expected_current_deployment_id": request["expected_current_deployment_id"],
                "snapshot_id": current["snapshot_id"],
                "run_id": current["run_id"],
                "release_policy_id": request["release_policy_id"],
                "promotion_policy_id": _policy_id(release_policy),
                "submission_archive_sha256": archive_digest,
                "retryable": False,
            }
        raise BuildError("unchanged build does not match active deployment snapshot")
    try:
        evaluation = evaluate_candidate(
            data, build["run_id"], cases=list(evaluation_cases)
        )
    except Exception as error:
        raise PipelineError(
            "EVALUATION_FAILED", f"promotion-safe evaluation failed: {error}"
        ) from error
    if not evaluation["passed"]:
        raise PipelineError("EVALUATION_FAILED", "promotion-safe evaluation failed")
    evaluation = {**evaluation, "promotion_policy_id": _policy_id(release_policy)}
    durable_atomic_json(
        data / "builds" / build["run_id"] / "promotion-evaluation.json",
        evaluation,
        mode=0o600,
    )
    return {
        **_ready_result(
            request,
            build["deployment"],
            promotion_policy_id=_policy_id(release_policy),
        ),
        "submission_archive_sha256": archive_digest,
    }


def _validate_commit(
    marker: Path,
    ready: dict[str, Any],
    receipt_digest: str,
) -> dict[str, Any]:
    raw = marker.read_bytes()
    try:
        commit = strict_json_loads(raw)
    except DeploymentError as error:
        raise PipelineError("PROMOTION_CONFLICT", "commit marker is invalid JSON") from error
    ordered_fields = (
        "schema_version",
        "protocol",
        "request_id",
        "publisher_id",
        "candidate_deployment_id",
        "expected_current_deployment_id",
        "submission_archive_sha256",
    )
    if not isinstance(commit, dict) or tuple(commit) != ordered_fields:
        raise PipelineError("PROMOTION_CONFLICT", "commit marker contract is invalid")
    if raw != canonical_receiver_json(commit, ordered_fields):
        raise PipelineError("PROMOTION_CONFLICT", "commit marker is not canonical")
    for field in (
        "request_id",
        "publisher_id",
        "candidate_deployment_id",
        "expected_current_deployment_id",
    ):
        if commit.get(field) != ready.get(field):
            raise PipelineError("PROMOTION_CONFLICT", f"commit {field} disagrees with candidate")
    if commit.get("submission_archive_sha256") != receipt_digest:
        raise PipelineError("PROMOTION_CONFLICT", "commit archive digest disagrees with receipt")
    return commit


def _deployment_matches_policy(
    deployment: dict[str, Any], policy: dict[str, Any]
) -> bool:
    checked = validate_deployment_record(deployment)
    return all(
        (
            checked["homeops_version"] == policy["homeops_version"],
            checked["source_revision"] == policy["source_revision"],
            checked["image_digest"] == policy["image_digest"],
            checked["snapshot_schema_version"] == policy["snapshot_schema_version"],
            checked["snapshot_contract_version"]
            == policy["snapshot_contract_version"],
            checked["build_schema_version"] == policy["build_schema_version"],
            checked["build_contract_version"] == policy["build_contract_version"],
        )
    )


def _commit_journal_path(root: Path, publisher: str, request_id: str) -> Path:
    validate_publisher_id(publisher)
    validate_safe_id(request_id, "request_id")
    return root.resolve() / "pipeline-state" / "commit-journal" / publisher / f"{request_id}.json"


def _write_commit_journal(
    root: Path,
    publisher: str,
    request_id: str,
    *,
    candidate_deployment_id: str,
    expected_current_deployment_id: str,
    release_policy_id: str,
) -> dict[str, Any]:
    journal = {
        "schema_version": 1,
        "protocol": RECEIVER_PROTOCOL,
        "state": "APPLYING",
        "request_id": request_id,
        "publisher_id": publisher,
        "candidate_deployment_id": candidate_deployment_id,
        "expected_current_deployment_id": expected_current_deployment_id,
        "release_policy_id": release_policy_id,
        "started_at": utc_now(),
    }
    durable_atomic_json(
        _commit_journal_path(root, publisher, request_id), journal, mode=0o600
    )
    return journal


def _load_commit_journal(
    root: Path, publisher: str, request_id: str
) -> dict[str, Any] | None:
    path = _commit_journal_path(root, publisher, request_id)
    if not path.is_file():
        return None
    parsed = strict_json_loads(path.read_text(encoding="utf-8"))
    fields = {
        "schema_version",
        "protocol",
        "state",
        "request_id",
        "publisher_id",
        "candidate_deployment_id",
        "expected_current_deployment_id",
        "release_policy_id",
        "started_at",
    }
    if (
        not isinstance(parsed, dict)
        or set(parsed) != fields
        or parsed["schema_version"] != 1
        or parsed["protocol"] != RECEIVER_PROTOCOL
        or parsed["state"] != "APPLYING"
        or parsed["request_id"] != request_id
        or parsed["publisher_id"] != publisher
    ):
        raise PipelineError("PROMOTION_CONFLICT", "commit journal is invalid")
    return parsed


def _process_commit(
    root: Path,
    publisher: str,
    marker: Path,
    *,
    release_policy: dict[str, Any],
) -> dict[str, Any]:
    request_id = marker.stem
    result_path = _result_path(root, publisher, request_id)
    ready = strict_json_loads(result_path.read_text(encoding="utf-8"))
    if ready.get("outcome") in TERMINAL_OUTCOMES:
        return ready
    if ready.get("outcome") != "CANDIDATE_READY":
        raise PipelineError("PROMOTION_CONFLICT", "commit has no candidate-ready result")
    receipt = strict_json_loads(
        (root / "incoming" / publisher / request_id / "receipt.json").read_text(
            encoding="utf-8"
        )
    )
    _validate_commit(marker, ready, receipt["archive_sha256"])
    deployment_id = ready["candidate_deployment_id"]
    policy_id = _policy_id(release_policy)
    release_policy_id = _policy_id(_base_release_policy(release_policy))
    if (
        ready.get("release_policy_id") != release_policy_id
        or ready.get("promotion_policy_id") != policy_id
    ):
        raise PipelineError(
            "PROMOTION_CONFLICT", "candidate belongs to a different release policy"
        )
    deployment_path = root / "data" / "deployments" / f"{deployment_id}.json"
    deployment = strict_json_loads(deployment_path.read_text(encoding="utf-8"))
    if not _deployment_matches_policy(deployment, release_policy):
        raise PipelineError(
            "PROMOTION_CONFLICT", "candidate deployment does not match release policy"
        )
    evaluation_path = (
        root / "data" / "builds" / deployment["run_id"] / "promotion-evaluation.json"
    )
    evaluation = strict_json_loads(evaluation_path.read_text(encoding="utf-8"))
    if (
        not isinstance(evaluation, dict)
        or evaluation.get("passed") is not True
        or evaluation.get("promotion_policy_id") != policy_id
    ):
        raise PipelineError(
            "PROMOTION_CONFLICT", "candidate evaluation does not match release policy"
        )
    expected = ready["expected_current_deployment_id"] or None
    journal = _load_commit_journal(root, publisher, request_id)
    if journal is not None:
        if (
            journal["candidate_deployment_id"] != deployment_id
            or journal["expected_current_deployment_id"]
            != ready["expected_current_deployment_id"]
            or journal["release_policy_id"] != release_policy_id
        ):
            raise PipelineError("PROMOTION_CONFLICT", "commit journal disagrees with candidate")
        state = active_state(root / "data")
        current = state.get("current_deployment")
        if current and current.get("deployment_id") == deployment_id:
            repaired = repair_selected_bookkeeping(root / "data", deployment_id)
            current = repaired["current_deployment"]
            return {
                **ready,
                "outcome": "PROMOTED",
                "promoted_at": current["promoted_at"],
            }
        raise PipelineError(
            "PROMOTION_CONFLICT",
            "commit was already applied or interrupted and cannot be replayed",
        )
    _write_commit_journal(
        root,
        publisher,
        request_id,
        candidate_deployment_id=deployment_id,
        expected_current_deployment_id=ready["expected_current_deployment_id"],
        release_policy_id=release_policy_id,
    )
    try:
        promoted = promote(
            root / "data",
            deployment,
            expected_current_deployment_id=expected,
            require_evaluation=True,
        )
    except OSError:
        # An I/O failure may have happened after active.json was durably replaced.
        # Repair only when that exact candidate is selected; otherwise retain the
        # candidate-ready result and APPLYING journal for a later safe retry.
        state = active_state(root / "data")
        current = state.get("current_deployment")
        if not current or current.get("deployment_id") != deployment_id:
            raise
        repaired = repair_selected_bookkeeping(root / "data", deployment_id)
        promoted = {"result": "promoted", **repaired}
    except (BuildError, DeploymentError) as error:
        outcome = "PROMOTION_CONFLICT" if "changed" in str(error) else "BUILD_FAILED"
        raise PipelineError(outcome, str(error)) from error
    selected = promoted.get("current_deployment")
    if not selected or selected["deployment_id"] != deployment_id:
        raise PipelineError("POST_PROMOTION_MISMATCH", "selected deployment differs from commit")
    return {
        **ready,
        "outcome": "PROMOTED" if promoted["result"] == "promoted" else "UNCHANGED",
        "promoted_at": selected["promoted_at"],
    }


def process_remote(
    root: Path,
    *,
    publisher_id: str = DEFAULT_PUBLISHER_ID,
    evaluation_cases: Sequence[Path] = (),
    source_revision: str | None = None,
    image_digest: str | None = None,
) -> dict[str, Any]:
    """Idempotently scan immutable receiver requests and sanitized commit markers."""

    root = root.resolve()
    # A rollback journal is a durable, already-authorized intent. Boot/periodic
    # processing may finish it, but the absence of a journal never starts one.
    recover_pending_rollback(root / "data")
    publisher_id = validate_publisher_id(publisher_id)
    homeops_version, released_revision, released_digest = _released_identity(
        source_revision, image_digest
    )
    release_policy = _release_policy(
        homeops_version,
        released_revision,
        released_digest,
        evaluation_cases=evaluation_cases,
    )
    # Recover automatically from a crash after active.json replacement but before
    # its redacted projection became durable.
    publish_current_projection(root)
    processed: list[dict[str, Any]] = []
    incoming = root / "incoming" / publisher_id
    if incoming.is_dir():
        for request_dir in sorted(path for path in incoming.iterdir() if path.is_dir()):
            result_path = _result_path(root, publisher_id, request_dir.name)
            if result_path.is_file():
                existing = strict_json_loads(result_path.read_text(encoding="utf-8"))
                if not (
                    isinstance(existing, dict)
                    and existing.get("retryable") is True
                    and existing.get("outcome") in RETRYABLE_REMOTE_OUTCOMES
                ):
                    continue
            request_stub = {
                "publisher_id": publisher_id,
                "request_id": request_dir.name,
            }
            try:
                result = _process_submission(
                    root,
                    publisher_id,
                    request_dir,
                    evaluation_cases=evaluation_cases,
                    homeops_version=homeops_version,
                    source_revision=released_revision,
                    image_digest=released_digest,
                    release_policy=release_policy,
                )
            except PipelineError as error:
                result = {
                    "schema_version": RESULT_SCHEMA_VERSION,
                    "protocol": RECEIVER_PROTOCOL,
                    "request_id": request_dir.name,
                    "publisher_id": publisher_id,
                    "outcome": error.outcome,
                    "retryable": error.retryable,
                    "diagnostic": _redacted_failure(error),
                }
            except SnapshotError as error:
                result = {
                    "schema_version": RESULT_SCHEMA_VERSION,
                    "protocol": RECEIVER_PROTOCOL,
                    "request_id": request_dir.name,
                    "publisher_id": publisher_id,
                    "outcome": "REMOTE_SNAPSHOT_INVALID",
                    "retryable": False,
                    "diagnostic": _redacted_failure(error),
                }
            except (BuildError, OSError, ValueError) as error:
                result = {
                    "schema_version": RESULT_SCHEMA_VERSION,
                    "protocol": RECEIVER_PROTOCOL,
                    "request_id": request_dir.name,
                    "publisher_id": publisher_id,
                    "outcome": "BUILD_FAILED",
                    "retryable": False,
                    "diagnostic": _redacted_failure(error),
                }
            _write_remote_result(root, request_stub, result)
            processed.append(result)
    commits = root / "commits" / publisher_id
    if commits.is_dir():
        for marker in sorted(commits.glob("*.json")):
            result_path = _result_path(root, publisher_id, marker.stem)
            if not result_path.is_file():
                continue
            current = strict_json_loads(result_path.read_text(encoding="utf-8"))
            if current.get("outcome") != "CANDIDATE_READY":
                continue
            stub = {"publisher_id": publisher_id, "request_id": marker.stem}
            try:
                result = _process_commit(
                    root,
                    publisher_id,
                    marker,
                    release_policy=release_policy,
                )
            except PipelineError as error:
                result = {
                    **current,
                    "outcome": error.outcome,
                    "retryable": error.retryable,
                    "diagnostic": _redacted_failure(error),
                }
            _write_remote_result(root, stub, result)
            if result.get("outcome") in {"PROMOTED", "UNCHANGED"}:
                publish_current_status(root)
            processed.append(result)
    publish_current_projection(root)
    return {
        "schema_version": 1,
        "processed": len(processed),
        "outcomes": [item["outcome"] for item in processed],
    }


def verify_active(root: Path) -> dict[str, Any]:
    data = root.resolve() / "data"
    state = active_state(data)
    if state.get("schema_version") != DEPLOYMENT_SCHEMA_VERSION:
        raise PipelineError("INTERNAL_ERROR", "active deployment state is not schema v2")
    deployment = state.get("current_deployment")
    if deployment is None:
        raise PipelineError("INTERNAL_ERROR", "there is no active deployment")
    verification = verify_run(data, deployment["run_id"])
    snapshot_dir = root.resolve() / "vault-snapshots" / deployment["snapshot_id"]
    manifest = read_manifest(snapshot_dir / "snapshot.json")
    verify_snapshot(snapshot_dir / "vault", manifest)
    for field in ("source_fingerprint", "artifact_fingerprint", "logical_fingerprint"):
        if deployment[field] != manifest[field]:
            raise PipelineError("POST_PROMOTION_MISMATCH", f"active {field} mismatch")
    publish_current_status(root)
    return {
        "schema_version": 1,
        "outcome": "VERIFIED",
        "deployment_id": deployment["deployment_id"],
        "snapshot_id": deployment["snapshot_id"],
        "run_id": deployment["run_id"],
        "verification": verification,
    }


def publish_current_status(root: Path) -> dict[str, Any]:
    """Publish the exact redacted preflight/CAS identity consumed by the receiver."""

    return publish_current_projection(root)
