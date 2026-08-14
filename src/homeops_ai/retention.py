"""Fail-closed, read-only planning for immutable deployment retention."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from contextlib import ExitStack
from dataclasses import dataclass, field as dataclass_field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from homeops_ai.build import BUILD_CONTRACT_VERSION, BUILD_SCHEMA_VERSION
from homeops_ai.deployment import (
    DEPLOYMENT_SCHEMA_VERSION,
    DeploymentError,
    canonical_json_bytes,
    current_projection,
    deployment_lock,
    deployment_identity,
    retention_lock,
    run_is_pinned,
    strict_json_loads,
    validate_deployment_record,
    validate_safe_id,
    validate_state,
)
from homeops_ai.snapshot import (
    RECEIVER_PROTOCOL,
    RECEIVER_SCHEMA_VERSION,
    SnapshotError,
    read_manifest,
    validate_publisher_id,
    verify_snapshot,
)


RETENTION_PLAN_SCHEMA_VERSION = 1
COMMIT_JOURNAL_SCHEMA_VERSION = 1
FAILED_BUILD_RETENTION = timedelta(days=7)
INCOMPLETE_UPLOAD_RETENTION = timedelta(hours=24)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UUID4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_SOURCE_REVISION = re.compile(r"^[0-9a-f]{7,64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TERMINAL_OUTCOMES = {
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
_SUCCESS_OUTCOMES = {"UNCHANGED", "PROMOTED"}


class RetentionError(RuntimeError):
    """The retention inventory cannot be planned safely."""


@dataclass(frozen=True)
class RetentionPolicy:
    keep_additional_verified: int = 3

    def __post_init__(self) -> None:
        if (
            not isinstance(self.keep_additional_verified, int)
            or isinstance(self.keep_additional_verified, bool)
            or self.keep_additional_verified < 0
        ):
            raise RetentionError(
                "keep_additional_verified must be a non-negative integer"
            )


def validate_retention_output(root: Path, output: Path) -> Path:
    """Resolve a report path while refusing aliases into the inspected root."""

    try:
        resolved_root = root.resolve(strict=True)
    except OSError as error:
        raise RetentionError(f"pipeline root does not exist: {root}") from error
    requested = Path(os.path.abspath(output))
    current = Path(requested.anchor)
    for part in requested.parts[1:]:
        current /= part
        if not _path_exists(current):
            break
        try:
            mode = current.lstat().st_mode
        except OSError as error:
            raise RetentionError(
                f"cannot inspect retention output path: {current}"
            ) from error
        if stat.S_ISLNK(mode):
            raise RetentionError("retention output path must not traverse a symlink")
    resolved = requested.resolve(strict=False)
    if resolved == resolved_root or resolved.is_relative_to(resolved_root):
        raise RetentionError("retention output must be outside the inspected root")
    if _path_exists(requested) and not requested.is_file():
        raise RetentionError("retention output must be a regular file")
    return resolved


@dataclass
class _References:
    deployments: set[str] = dataclass_field(default_factory=set)
    runs: set[str] = dataclass_field(default_factory=set)
    snapshots: set[str] = dataclass_field(default_factory=set)
    failure_deployments: set[str] = dataclass_field(default_factory=set)
    failure_runs: set[str] = dataclass_field(default_factory=set)
    failure_snapshots: set[str] = dataclass_field(default_factory=set)
    identity_bundles: list[dict[str, str]] = dataclass_field(default_factory=list)
    unresolved: list[dict[str, str]] = dataclass_field(default_factory=list)
    blocks_all: bool = False


def _path_exists(path: Path) -> bool:
    """Return true for existing paths and dangling symlinks."""

    return os.path.lexists(path)


def _relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _unresolved(
    references: _References,
    root: Path,
    path: Path,
    code: str,
    *,
    detail: str,
    blocks_all: bool,
) -> None:
    references.unresolved.append(
        {"code": code, "path": _relative(root, path), "detail": detail}
    )
    references.blocks_all = references.blocks_all or blocks_all


def _resolve_input(root: Path, path: Path, field: str) -> Path:
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise RetentionError(f"{field} escapes the pipeline root") from error
    current = root
    for part in relative.parts:
        current /= part
        try:
            mode = current.lstat().st_mode
        except OSError as error:
            raise RetentionError(f"{field} is missing") from error
        if stat.S_ISLNK(mode):
            raise RetentionError(f"{field} traverses a symlink")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise RetentionError(f"{field} is missing") from error
    if not resolved.is_relative_to(root):
        raise RetentionError(f"{field} escapes the pipeline root")
    return resolved


def _read_object(root: Path, path: Path) -> dict[str, Any]:
    resolved = _resolve_input(root, path, "JSON path")
    if not resolved.is_file():
        raise RetentionError("path is not a regular file")
    try:
        value = strict_json_loads(resolved.read_text(encoding="utf-8"))
    except (OSError, DeploymentError) as error:
        raise RetentionError(str(error)) from error
    if not isinstance(value, dict):
        raise RetentionError("JSON value is not an object")
    return value


def _read_canonical_object(
    root: Path, path: Path, fields: tuple[str, ...]
) -> dict[str, Any]:
    resolved = _resolve_input(root, path, "canonical JSON path")
    if not resolved.is_file():
        raise RetentionError("canonical JSON path is not a regular file")
    try:
        raw = resolved.read_bytes()
        value = strict_json_loads(raw)
    except (OSError, DeploymentError) as error:
        raise RetentionError(str(error)) from error
    if not isinstance(value, dict) or tuple(value) != fields:
        raise RetentionError("canonical JSON has missing, reordered, or unknown fields")
    encoded = (
        json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )
    if raw != encoded:
        raise RetentionError("canonical JSON bytes are not canonical")
    return value


def _parse_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise RetentionError(f"{field} is not a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise RetentionError(f"{field} is not an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise RetentionError(f"{field} lacks a timezone")
    return parsed.astimezone(UTC)


def _safe_directory(root: Path, path: Path, field: str) -> None:
    resolved = _resolve_input(root, path, field)
    if not resolved.is_dir():
        raise RetentionError(f"{field} is not a real directory")


def _validate_build(root: Path, data: Path, record: dict[str, Any]) -> Path:
    run_id = record["run_id"]
    build_dir = data / "builds" / run_id
    _safe_directory(root, build_dir, "build directory")
    manifest = _read_object(root, build_dir / "manifest.json")
    expected = {
        "run_id": record["run_id"],
        "result": "verified",
        "source_fingerprint": record["source_fingerprint"],
        "artifact_fingerprint": record["artifact_fingerprint"],
        "logical_fingerprint": record["logical_fingerprint"],
        "completed_at": record["build_completed_at"],
        "verified_at": record["build_verified_at"],
        "schema_version": record["build_schema_version"],
        "build_contract_version": record["build_contract_version"],
        "homeops_version": record["homeops_version"],
        "source_revision": record["source_revision"],
        "image_digest": record["image_digest"],
    }
    for field, value in expected.items():
        if manifest.get(field) != value:
            raise RetentionError(f"build manifest {field} disagrees with deployment")
    database = build_dir / "cozo.db"
    _safe_directory(root, database, "Cozo database")
    return build_dir


def _validate_snapshot(root: Path, record: dict[str, Any]) -> Path:
    snapshot_dir = root / "vault-snapshots" / record["snapshot_id"]
    _safe_directory(root, snapshot_dir, "snapshot directory")
    try:
        manifest = read_manifest(
            _resolve_input(root, snapshot_dir / "snapshot.json", "snapshot manifest")
        )
    except (OSError, SnapshotError) as error:
        raise RetentionError(f"snapshot manifest is invalid: {error}") from error
    expected = {
        "snapshot_id": record["snapshot_id"],
        "source_fingerprint": record["source_fingerprint"],
        "artifact_fingerprint": record["artifact_fingerprint"],
        "logical_fingerprint": record["logical_fingerprint"],
        "created_at": record["snapshot_created_at"],
        "schema_version": record["snapshot_schema_version"],
        "snapshot_contract_version": record["snapshot_contract_version"],
    }
    for field, value in expected.items():
        if manifest.get(field) != value:
            raise RetentionError(f"snapshot manifest {field} disagrees with deployment")
    vault = snapshot_dir / "vault"
    _safe_directory(root, vault, "snapshot vault")
    try:
        verify_snapshot(vault, manifest)
    except SnapshotError as error:
        raise RetentionError(f"snapshot bytes are invalid: {error}") from error
    return snapshot_dir


def _validate_history(
    root: Path, data: Path, record: dict[str, Any]
) -> tuple[Path | None, list[str], datetime]:
    history_dir = data / "deployment-history" / record["deployment_id"]
    timestamps: list[tuple[datetime, str]] = []
    if _path_exists(history_dir):
        _safe_directory(root, history_dir, "deployment history")
        for path in sorted(history_dir.iterdir(), key=lambda item: item.name):
            if path.suffix != ".json":
                raise RetentionError("deployment history has an unexpected entry")
            event = validate_deployment_record(_read_object(root, path))
            if event["deployment_id"] != record["deployment_id"]:
                raise RetentionError(
                    "deployment history ID disagrees with its directory"
                )
            if deployment_identity(event) != deployment_identity(record):
                raise RetentionError(
                    "deployment history identity disagrees with record"
                )
            promoted_at = event.get("promoted_at")
            timestamps.append(
                (_parse_time(promoted_at, "history promoted_at"), str(promoted_at))
            )
    verified = _parse_time(record["build_verified_at"], "build_verified_at")
    effective = max([verified, *(item[0] for item in timestamps)])
    return (
        history_dir if _path_exists(history_dir) else None,
        [item[1] for item in timestamps],
        effective,
    )


def _inventory_deployments(
    root: Path, references: _References
) -> dict[str, dict[str, Any]]:
    data = root / "data"
    deployments_dir = data / "deployments"
    records: dict[str, dict[str, Any]] = {}
    if not deployments_dir.is_dir() or deployments_dir.is_symlink():
        _unresolved(
            references,
            root,
            deployments_dir,
            "deployment-store-invalid",
            detail="deployment store is not a real directory",
            blocks_all=True,
        )
        return records
    for path in sorted(deployments_dir.iterdir(), key=lambda item: item.name):
        if path.suffix != ".json":
            _unresolved(
                references,
                root,
                path,
                "unexpected-deployment-entry",
                detail="deployment store contains a non-record entry",
                blocks_all=True,
            )
            continue
        try:
            deployment_id = validate_safe_id(path.stem, "deployment_id")
            record = validate_deployment_record(_read_object(root, path))
            if deployment_id != record["deployment_id"]:
                raise RetentionError("deployment filename disagrees with deployment_id")
            build_dir = _validate_build(root, data, record)
            snapshot_dir = _validate_snapshot(root, record)
            history_dir, history, effective = _validate_history(root, data, record)
            records[deployment_id] = {
                "record": record,
                "record_path": path,
                "build_dir": build_dir,
                "snapshot_dir": snapshot_dir,
                "history_dir": history_dir,
                "history": history,
                "effective": effective,
            }
        except (DeploymentError, RetentionError) as error:
            _unresolved(
                references,
                root,
                path,
                "deployment-bundle-invalid",
                detail=str(error),
                blocks_all=True,
            )
    return records


def _validate_build_ownership(
    root: Path,
    records: dict[str, dict[str, Any]],
    references: _References,
) -> None:
    owners: dict[str, list[str]] = {}
    for deployment_id, item in records.items():
        owners.setdefault(item["record"]["run_id"], []).append(deployment_id)
    for run_id, deployment_ids in sorted(owners.items()):
        if len(deployment_ids) > 1:
            _unresolved(
                references,
                root,
                root / "data" / "builds" / run_id,
                "duplicate-build-ownership",
                detail=(
                    "one build run is owned by multiple deployment records: "
                    + ",".join(sorted(deployment_ids))
                ),
                blocks_all=True,
            )


def _validate_reference_integrity(
    root: Path,
    records: dict[str, dict[str, Any]],
    references: _References,
) -> None:
    for deployment_id in sorted(
        references.deployments | references.failure_deployments
    ):
        if deployment_id not in records:
            _unresolved(
                references,
                root,
                root / "data" / "deployments" / f"{deployment_id}.json",
                "referenced-deployment-missing",
                detail="pipeline state names no valid immutable deployment bundle",
                blocks_all=True,
            )

    runs = {
        item["record"]["run_id"]: deployment_id
        for deployment_id, item in records.items()
    }
    for run_id in sorted(references.runs | references.failure_runs):
        if run_id not in runs:
            _unresolved(
                references,
                root,
                root / "data" / "builds" / run_id,
                "referenced-build-missing",
                detail="pipeline state names no valid deployment-owned build",
                blocks_all=True,
            )

    for bundle in sorted(
        references.identity_bundles,
        key=lambda item: (
            item["deployment_id"],
            item["run_id"],
            item["snapshot_id"],
            item["kind"],
        ),
    ):
        item = records.get(bundle["deployment_id"])
        if item is None:
            continue
        record = item["record"]
        if (
            record["run_id"] != bundle["run_id"]
            or record["snapshot_id"] != bundle["snapshot_id"]
        ):
            _unresolved(
                references,
                root,
                item["record_path"],
                "pipeline-identity-mismatch",
                detail="pipeline deployment/run/snapshot identity is inconsistent",
                blocks_all=True,
            )


def _optional_sha256(value: Any, field: str) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise RetentionError(f"{field} is not a lowercase SHA-256")
    return value


def _required_sha256(value: Any, field: str) -> str:
    checked = _optional_sha256(value, field)
    if checked is None:
        raise RetentionError(f"{field} is required")
    return checked


def _expected_deployment_id(value: Any, field: str) -> str | None:
    if not isinstance(value, str) or (value and not _SHA256.fullmatch(value)):
        raise RetentionError(f"{field} must be empty or a lowercase SHA-256")
    return value or None


def _uuid4(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _UUID4.fullmatch(value):
        raise RetentionError(f"{field} must be a lowercase UUIDv4")
    return value


def _request_id(value: Any) -> str:
    return _uuid4(value, "request_id")


def _optional_run(value: Any) -> str | None:
    if value is None or value == "":
        return None
    return validate_safe_id(value, "run_id")


_RESULT_COMMON_FIELDS = {
    "schema_version",
    "protocol",
    "request_id",
    "publisher_id",
    "outcome",
    "retryable",
}
_RESULT_READY_FIELDS = {
    "candidate_deployment_id",
    "expected_current_deployment_id",
    "snapshot_id",
    "run_id",
    "release_policy_id",
    "promotion_policy_id",
}
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
_COMMIT_FIELDS = (
    "schema_version",
    "protocol",
    "request_id",
    "publisher_id",
    "candidate_deployment_id",
    "expected_current_deployment_id",
    "submission_archive_sha256",
)
_COMMIT_JOURNAL_FIELDS = {
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
_FAILED_BUILD_FIELDS = {
    "schema_version",
    "build_contract_version",
    "run_id",
    "profile",
    "vault_root",
    "database_path",
    "source_fingerprint",
    "artifact_fingerprint",
    "logical_fingerprint",
    "counts",
    "inventory",
    "unresolved_targets",
    "started_at",
    "completed_at",
    "result",
    "ingestion_result",
    "homeops_version",
    "source_revision",
    "image_digest",
    "failed_at",
    "failure",
}


def _validate_ready_references(value: dict[str, Any]) -> None:
    _required_sha256(value.get("candidate_deployment_id"), "candidate_deployment_id")
    _expected_deployment_id(
        value.get("expected_current_deployment_id"),
        "expected_current_deployment_id",
    )
    _required_sha256(value.get("snapshot_id"), "snapshot_id")
    if _optional_run(value.get("run_id")) is None:
        raise RetentionError("run_id is required")
    _required_sha256(value.get("release_policy_id"), "release_policy_id")
    _required_sha256(value.get("promotion_policy_id"), "promotion_policy_id")


def _validate_result_record(
    value: dict[str, Any], *, publisher_id: str, request_id: str
) -> dict[str, Any]:
    if (
        value.get("schema_version") != RECEIVER_SCHEMA_VERSION
        or value.get("protocol") != RECEIVER_PROTOCOL
        or value.get("publisher_id") != publisher_id
        or value.get("request_id") != request_id
    ):
        raise RetentionError("result protocol identity disagrees with its path")
    _request_id(request_id)
    outcome = value.get("outcome")
    retryable = value.get("retryable")
    if outcome not in _TERMINAL_OUTCOMES | {"CANDIDATE_READY"}:
        raise RetentionError("result outcome is unknown")
    if not isinstance(retryable, bool):
        raise RetentionError("result retryable flag is invalid")

    fields = frozenset(value)
    ready = _RESULT_COMMON_FIELDS | _RESULT_READY_FIELDS | {"submission_archive_sha256"}
    simple_failure = _RESULT_COMMON_FIELDS | {"diagnostic"}
    candidate_failure = ready | {"diagnostic"}
    if outcome == "CANDIDATE_READY":
        if retryable or fields != ready:
            raise RetentionError("candidate-ready result contract is invalid")
        _validate_ready_references(value)
        _required_sha256(
            value.get("submission_archive_sha256"), "submission_archive_sha256"
        )
    elif outcome in _SUCCESS_OUTCOMES:
        promoted = ready | {"promoted_at"}
        valid_fields = (
            {frozenset(promoted)}
            if outcome == "PROMOTED"
            else {frozenset(promoted), frozenset(ready)}
        )
        if retryable or fields not in valid_fields:
            raise RetentionError("successful result contract is invalid")
        _validate_ready_references(value)
        _required_sha256(
            value.get("submission_archive_sha256"), "submission_archive_sha256"
        )
        if "promoted_at" in value:
            _parse_time(value["promoted_at"], "result promoted_at")
    else:
        if fields not in {frozenset(simple_failure), frozenset(candidate_failure)}:
            raise RetentionError("failure result contract is invalid")
        diagnostic = value.get("diagnostic")
        if not isinstance(diagnostic, str) or not diagnostic or len(diagnostic) > 500:
            raise RetentionError("failure result diagnostic is invalid")
        if fields == candidate_failure:
            _validate_ready_references(value)
            _required_sha256(
                value.get("submission_archive_sha256"),
                "submission_archive_sha256",
            )
    return value


def _validate_queued_request(
    value: dict[str, Any], *, publisher_id: str, request_id: str
) -> dict[str, Any]:
    if tuple(value) != _QUEUED_REQUEST_FIELDS:
        raise RetentionError("queued request has missing or unknown fields")
    if (
        value.get("schema_version") != RECEIVER_SCHEMA_VERSION
        or value.get("protocol") != RECEIVER_PROTOCOL
        or value.get("publisher_id") != publisher_id
        or value.get("request_id") != request_id
    ):
        raise RetentionError("queued request protocol identity disagrees with its path")
    _required_sha256(value.get("release_policy_id"), "release_policy_id")
    _required_sha256(value.get("snapshot_id"), "snapshot_id")
    _request_id(request_id)
    _expected_deployment_id(
        value.get("expected_current_deployment_id"),
        "expected_current_deployment_id",
    )
    _required_sha256(value.get("snapshot_manifest_sha256"), "snapshot_manifest_sha256")
    return value


def _validate_commit_reference(
    value: dict[str, Any], *, publisher_id: str, request_id: str
) -> dict[str, Any]:
    if tuple(value) != _COMMIT_FIELDS:
        raise RetentionError("commit marker has missing or unknown fields")
    if (
        value.get("schema_version") != RECEIVER_SCHEMA_VERSION
        or value.get("protocol") != RECEIVER_PROTOCOL
        or value.get("publisher_id") != publisher_id
        or value.get("request_id") != request_id
    ):
        raise RetentionError("commit marker protocol identity disagrees with its path")
    _required_sha256(value.get("candidate_deployment_id"), "candidate_deployment_id")
    _request_id(request_id)
    _expected_deployment_id(
        value.get("expected_current_deployment_id"),
        "expected_current_deployment_id",
    )
    _required_sha256(
        value.get("submission_archive_sha256"), "submission_archive_sha256"
    )
    return value


def _validate_commit_journal_reference(
    value: dict[str, Any], *, publisher_id: str, request_id: str
) -> dict[str, Any]:
    if set(value) != _COMMIT_JOURNAL_FIELDS:
        raise RetentionError("commit journal has missing or unknown fields")
    if (
        value.get("schema_version") != COMMIT_JOURNAL_SCHEMA_VERSION
        or value.get("protocol") != RECEIVER_PROTOCOL
        or value.get("state") != "APPLYING"
        or value.get("publisher_id") != publisher_id
        or value.get("request_id") != request_id
    ):
        raise RetentionError("commit journal protocol identity disagrees with its path")
    _request_id(request_id)
    _required_sha256(value.get("candidate_deployment_id"), "candidate_deployment_id")
    _expected_deployment_id(
        value.get("expected_current_deployment_id"),
        "expected_current_deployment_id",
    )
    _required_sha256(value.get("release_policy_id"), "release_policy_id")
    _parse_time(value.get("started_at"), "commit journal started_at")
    return value


def _add_identity_references(
    value: dict[str, Any], references: _References, *, failure: bool = False
) -> None:
    runs = references.failure_runs if failure else references.runs
    snapshots = references.failure_snapshots if failure else references.snapshots
    candidate = _optional_sha256(
        value.get("candidate_deployment_id"), "candidate_deployment_id"
    )
    if candidate:
        (references.failure_deployments if failure else references.deployments).add(
            candidate
        )
    expected = _optional_sha256(
        value.get("expected_current_deployment_id"),
        "expected_current_deployment_id",
    )
    if expected:
        references.deployments.add(expected)
    snapshot_id = _optional_sha256(value.get("snapshot_id"), "snapshot_id")
    if snapshot_id:
        snapshots.add(snapshot_id)
    run_id = _optional_run(value.get("run_id"))
    if run_id:
        runs.add(run_id)
    if candidate and snapshot_id and run_id:
        references.identity_bundles.append(
            {
                "deployment_id": candidate,
                "run_id": run_id,
                "snapshot_id": snapshot_id,
                "kind": "failure" if failure else "unresolved",
            }
        )


def _pipeline_references(root: Path, references: _References) -> None:
    results: dict[tuple[str, str], dict[str, Any]] = {}
    results_root = root / "results"
    if _path_exists(results_root):
        try:
            _safe_directory(root, results_root, "results directory")
            for publisher_dir in sorted(
                results_root.iterdir(), key=lambda item: item.name
            ):
                _safe_directory(root, publisher_dir, "publisher results directory")
                validate_publisher_id(publisher_dir.name)
                for path in sorted(publisher_dir.iterdir(), key=lambda item: item.name):
                    if path.suffix != ".json":
                        raise RetentionError("result path is not a JSON record")
                    request_id = validate_safe_id(path.stem, "request_id")
                    result = _validate_result_record(
                        _read_object(root, path),
                        publisher_id=publisher_dir.name,
                        request_id=request_id,
                    )
                    outcome = result.get("outcome")
                    retryable = result.get("retryable")
                    results[(publisher_dir.name, request_id)] = result
                    if outcome == "CANDIDATE_READY" or retryable:
                        _add_identity_references(result, references)
                        _unresolved(
                            references,
                            root,
                            path,
                            "pipeline-attempt-unresolved",
                            detail=f"remote result remains {outcome}",
                            blocks_all=False,
                        )
                    elif outcome not in _SUCCESS_OUTCOMES:
                        candidate = _optional_sha256(
                            result.get("candidate_deployment_id"),
                            "candidate_deployment_id",
                        )
                        if candidate:
                            _add_identity_references(result, references, failure=True)
        except (DeploymentError, RetentionError, SnapshotError) as error:
            _unresolved(
                references,
                root,
                results_root,
                "results-inventory-invalid",
                detail=str(error),
                blocks_all=True,
            )

    incoming_root = root / "incoming"
    if _path_exists(incoming_root):
        try:
            _safe_directory(root, incoming_root, "incoming directory")
            for publisher_dir in sorted(
                incoming_root.iterdir(), key=lambda item: item.name
            ):
                if publisher_dir.name.startswith(".upload-"):
                    continue
                _safe_directory(root, publisher_dir, "publisher incoming directory")
                validate_publisher_id(publisher_dir.name)
                for request_dir in sorted(
                    publisher_dir.iterdir(), key=lambda item: item.name
                ):
                    _safe_directory(root, request_dir, "incoming request directory")
                    request_id = validate_safe_id(request_dir.name, "request_id")
                    request = _validate_queued_request(
                        _read_canonical_object(
                            root,
                            request_dir / "payload" / "request.json",
                            _QUEUED_REQUEST_FIELDS,
                        ),
                        publisher_id=publisher_dir.name,
                        request_id=request_id,
                    )
                    result = results.get((publisher_dir.name, request_id))
                    if (
                        result is None
                        or result.get("outcome") == "CANDIDATE_READY"
                        or result.get("retryable") is True
                    ):
                        _add_identity_references(request, references)
                        _unresolved(
                            references,
                            root,
                            request_dir,
                            "incoming-request-unresolved",
                            detail="incoming request has no final non-retryable result",
                            blocks_all=False,
                        )
        except (DeploymentError, RetentionError, SnapshotError) as error:
            _unresolved(
                references,
                root,
                incoming_root,
                "incoming-inventory-invalid",
                detail=str(error),
                blocks_all=True,
            )

    for namespace, label in (
        (root / "commits", "commit"),
        (root / "pipeline-state" / "commit-journal", "commit-journal"),
    ):
        if not _path_exists(namespace):
            continue
        try:
            _safe_directory(root, namespace, f"{label} directory")
            for publisher_dir in sorted(
                namespace.iterdir(), key=lambda item: item.name
            ):
                _safe_directory(root, publisher_dir, f"publisher {label} directory")
                validate_publisher_id(publisher_dir.name)
                for path in sorted(publisher_dir.iterdir(), key=lambda item: item.name):
                    if path.suffix != ".json":
                        raise RetentionError(f"{label} path is not a JSON record")
                    request_id = validate_safe_id(path.stem, "request_id")
                    if label == "commit":
                        value = _validate_commit_reference(
                            _read_canonical_object(root, path, _COMMIT_FIELDS),
                            publisher_id=publisher_dir.name,
                            request_id=request_id,
                        )
                    else:
                        value = _validate_commit_journal_reference(
                            _read_object(root, path),
                            publisher_id=publisher_dir.name,
                            request_id=request_id,
                        )
                    result = results.get((publisher_dir.name, request_id))
                    if (
                        result is None
                        or result.get("outcome") == "CANDIDATE_READY"
                        or result.get("retryable") is True
                    ):
                        _add_identity_references(value, references)
                        _unresolved(
                            references,
                            root,
                            path,
                            f"{label}-unresolved",
                            detail=f"{label} has no final non-retryable result",
                            blocks_all=False,
                        )
        except (DeploymentError, RetentionError, SnapshotError) as error:
            _unresolved(
                references,
                root,
                namespace,
                f"{label}-inventory-invalid",
                detail=str(error),
                blocks_all=True,
            )

    rollback = root / "data" / "pipeline-transactions" / "rollback.json"
    if _path_exists(rollback):
        try:
            value = _read_object(root, rollback)
            for field in ("source_state", "target_state"):
                state = validate_state(value.get(field), allow_legacy=False)
                for role in ("current_deployment", "previous_deployment"):
                    deployment = state.get(role)
                    if deployment:
                        references.deployments.add(deployment["deployment_id"])
                        references.runs.add(deployment["run_id"])
                        references.snapshots.add(deployment["snapshot_id"])
                        references.identity_bundles.append(
                            {
                                "deployment_id": deployment["deployment_id"],
                                "run_id": deployment["run_id"],
                                "snapshot_id": deployment["snapshot_id"],
                                "kind": "rollback",
                            }
                        )
            _unresolved(
                references,
                root,
                rollback,
                "rollback-transaction-unresolved",
                detail="a durable rollback transaction must finish before cleanup",
                blocks_all=True,
            )
        except (DeploymentError, RetentionError) as error:
            _unresolved(
                references,
                root,
                rollback,
                "rollback-transaction-invalid",
                detail=str(error),
                blocks_all=True,
            )

    quarantine = root / "quarantine"
    if _path_exists(quarantine):
        try:
            _safe_directory(root, quarantine, "quarantine directory")
            entries = sorted(quarantine.iterdir(), key=lambda item: item.name)
            if entries:
                _unresolved(
                    references,
                    root,
                    quarantine,
                    "quarantine-not-empty",
                    detail="quarantined input may contain unresolved deployment references",
                    blocks_all=True,
                )
        except RetentionError as error:
            _unresolved(
                references,
                root,
                quarantine,
                "quarantine-invalid",
                detail=str(error),
                blocks_all=True,
            )


def _validate_active_state(
    root: Path,
    records: dict[str, dict[str, Any]],
    references: _References,
) -> tuple[dict[str, Any] | None, str | None, str | None]:
    data = root / "data"
    try:
        state = validate_state(
            _read_object(root, data / "active.json"), allow_legacy=False
        )
        if state.get("schema_version") != DEPLOYMENT_SCHEMA_VERSION:
            raise RetentionError("retention requires schema-v2 active state")
        current = state.get("current_deployment")
        previous = state.get("previous_deployment")
        if current is None:
            raise RetentionError("retention requires an active deployment")
        for role, deployment in (("current", current), ("previous", previous)):
            if deployment is None:
                continue
            stored = records.get(deployment["deployment_id"])
            if stored is None:
                raise RetentionError(f"{role} deployment has no valid immutable bundle")
            if deployment_identity(stored["record"]) != deployment_identity(deployment):
                raise RetentionError(
                    f"{role} deployment identity disagrees with its record"
                )
        projection_path = root / "pipeline-state" / "current.json"
        if _read_object(root, projection_path) != current_projection(state):
            raise RetentionError(
                "published current projection disagrees with active state"
            )
        return (
            state,
            current["deployment_id"],
            previous["deployment_id"] if previous else None,
        )
    except (DeploymentError, RetentionError) as error:
        _unresolved(
            references,
            root,
            data / "active.json",
            "active-state-invalid",
            detail=str(error),
            blocks_all=True,
        )
        return None, None, None


def _validate_failed_build_manifest(path: Path, manifest: dict[str, Any]) -> datetime:
    if set(manifest) != _FAILED_BUILD_FIELDS:
        raise RetentionError("failed build manifest has missing or unknown fields")
    run_id = _uuid4(manifest.get("run_id"), "failed build run_id")
    if run_id != path.name:
        raise RetentionError("failed build run_id disagrees with its directory")
    if (
        manifest.get("schema_version") != BUILD_SCHEMA_VERSION
        or manifest.get("build_contract_version") != BUILD_CONTRACT_VERSION
        or manifest.get("result") != "failed"
        or manifest.get("ingestion_result") not in {"candidate", "verified"}
    ):
        raise RetentionError("failed build schema or state is invalid")
    for field_name in (
        "profile",
        "vault_root",
        "homeops_version",
        "failure",
    ):
        value = manifest.get(field_name)
        if not isinstance(value, str) or not value:
            raise RetentionError(f"failed build {field_name} is invalid")
    if not Path(manifest["vault_root"]).is_absolute():
        raise RetentionError("failed build vault_root is not absolute")
    expected_database = str((path / "cozo.db").resolve(strict=False))
    if manifest.get("database_path") != expected_database:
        raise RetentionError("failed build database_path disagrees with its directory")
    for field_name in (
        "source_fingerprint",
        "artifact_fingerprint",
        "logical_fingerprint",
    ):
        _required_sha256(manifest.get(field_name), f"failed build {field_name}")
    source_revision = manifest.get("source_revision")
    if not isinstance(source_revision, str) or not _SOURCE_REVISION.fullmatch(
        source_revision
    ):
        raise RetentionError("failed build source_revision is invalid")
    image_digest = manifest.get("image_digest")
    if not isinstance(image_digest, str) or not _IMAGE_DIGEST.fullmatch(image_digest):
        raise RetentionError("failed build image_digest is invalid")
    counts = manifest.get("counts")
    if not isinstance(counts, dict) or not all(
        isinstance(key, str)
        and isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 0
        for key, value in counts.items()
    ):
        raise RetentionError("failed build counts are invalid")
    inventory = manifest.get("inventory")
    if (
        not isinstance(inventory, dict)
        or set(inventory) != {"included", "excluded"}
        or not all(isinstance(inventory[field], list) for field in inventory)
    ):
        raise RetentionError("failed build inventory is invalid")
    if not isinstance(manifest.get("unresolved_targets"), list):
        raise RetentionError("failed build unresolved_targets is invalid")
    started_at = _parse_time(manifest.get("started_at"), "failed build started_at")
    completed_value = manifest.get("completed_at")
    completed_at = (
        _parse_time(completed_value, "failed build completed_at")
        if completed_value is not None
        else None
    )
    failed_at = _parse_time(manifest.get("failed_at"), "failed build failed_at")
    if failed_at < started_at or (
        completed_at is not None
        and (completed_at < started_at or completed_at > failed_at)
    ):
        raise RetentionError("failed build timestamps are inconsistent")
    return failed_at


def _inventory_orphans(
    root: Path,
    records: dict[str, dict[str, Any]],
    references: _References,
    *,
    as_of: datetime,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    evidence: list[dict[str, Any]] = []
    age_targets: list[dict[str, str]] = []
    data = root / "data"
    known_runs = {item["record"]["run_id"] for item in records.values()}
    builds = data / "builds"
    if builds.is_dir() and not builds.is_symlink():
        for path in sorted(builds.iterdir(), key=lambda item: item.name):
            if path.name in known_runs:
                continue
            try:
                _safe_directory(root, path, "unassociated build")
                manifest = _read_object(root, path / "manifest.json")
                failed_at = _validate_failed_build_manifest(path, manifest)
                if failed_at > as_of:
                    raise RetentionError("failed build timestamp is in the future")
                eligible_at = failed_at + FAILED_BUILD_RETENTION
                stale = eligible_at <= as_of
                referenced = path.name in (references.runs | references.failure_runs)
                evidence.append(
                    {
                        "kind": "failed-build",
                        "decision": (
                            "retain-pipeline-reference"
                            if referenced
                            else (
                                "remove-stale" if stale else "retain-failure-evidence"
                            )
                        ),
                        "path": _relative(root, path),
                        "observed_at": failed_at.isoformat(),
                        "eligible_at": eligible_at.isoformat(),
                    }
                )
                if stale and not referenced:
                    age_targets.append(_target(root, path, "failed-build"))
            except RetentionError as error:
                _unresolved(
                    references,
                    root,
                    path,
                    "unassociated-build",
                    detail=str(error),
                    blocks_all=True,
                )

    known_snapshots = {item["record"]["snapshot_id"] for item in records.values()}
    snapshots = root / "vault-snapshots"
    if snapshots.is_dir() and not snapshots.is_symlink():
        for path in sorted(snapshots.iterdir(), key=lambda item: item.name):
            if path.name in known_snapshots:
                continue
            if path.name in references.snapshots:
                evidence.append(
                    {
                        "decision": "retain-unresolved-pipeline",
                        "path": _relative(root, path),
                    }
                )
                continue
            _unresolved(
                references,
                root,
                path,
                "unassociated-snapshot",
                detail="snapshot has no validated deployment record",
                blocks_all=True,
            )

    known_deployments = set(records)
    history = data / "deployment-history"
    if history.is_dir() and not history.is_symlink():
        for path in sorted(history.iterdir(), key=lambda item: item.name):
            if path.name not in known_deployments:
                _unresolved(
                    references,
                    root,
                    path,
                    "unassociated-deployment-history",
                    detail="history has no validated deployment record",
                    blocks_all=True,
                )
    incoming = root / "incoming"
    if _path_exists(incoming):
        try:
            _safe_directory(root, incoming, "incoming directory")
            for path in sorted(incoming.iterdir(), key=lambda item: item.name):
                if not path.name.startswith(".upload-"):
                    continue
                if not re.fullmatch(
                    r"\.upload-[a-z][a-z0-9-]{0,62}-[0-9a-f]{32}", path.name
                ):
                    raise RetentionError("incomplete upload name is invalid")
                _safe_directory(root, path, "incomplete upload")
                observed_at = datetime.fromtimestamp(path.lstat().st_mtime, UTC)
                if observed_at > as_of:
                    raise RetentionError("incomplete upload timestamp is in the future")
                eligible_at = observed_at + INCOMPLETE_UPLOAD_RETENTION
                stale = eligible_at <= as_of
                evidence.append(
                    {
                        "kind": "incomplete-upload",
                        "decision": "remove-stale" if stale else "retain-incomplete",
                        "path": _relative(root, path),
                        "observed_at": observed_at.isoformat(),
                        "eligible_at": eligible_at.isoformat(),
                    }
                )
                if stale:
                    age_targets.append(_target(root, path, "incomplete-upload"))
        except RetentionError as error:
            _unresolved(
                references,
                root,
                incoming,
                "incomplete-upload-inventory-invalid",
                detail=str(error),
                blocks_all=True,
            )
    return evidence, age_targets


def _target(root: Path, path: Path, kind: str) -> dict[str, str]:
    if path.is_symlink() or not path.exists():
        raise RetentionError(f"retention target is missing or a symlink: {path}")
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(root):
        raise RetentionError(f"retention target escapes pipeline root: {path}")
    relative = resolved.relative_to(root).as_posix()
    allowed = {
        "deployment-record": re.compile(r"^data/deployments/[0-9a-f]{64}\.json$"),
        "deployment-history": re.compile(r"^data/deployment-history/[0-9a-f]{64}$"),
        "build": re.compile(r"^data/builds/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"),
        "snapshot": re.compile(r"^vault-snapshots/[0-9a-f]{64}$"),
        "failed-build": re.compile(r"^data/builds/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"),
        "incomplete-upload": re.compile(
            r"^incoming/\.upload-[a-z][a-z0-9-]{0,62}-[0-9a-f]{32}$"
        ),
    }
    if kind not in allowed or not allowed[kind].fullmatch(relative):
        raise RetentionError(f"retention target is not allowlisted: {relative}")
    return {"kind": kind, "path": relative, "resolved_path": str(resolved)}


def plan_deployment_retention(
    root: Path,
    *,
    policy: RetentionPolicy = RetentionPolicy(),
    as_of: datetime | None = None,
) -> dict[str, Any]:
    """Return a deterministic dry-run plan; never remove or rename any path."""

    if as_of is None:
        as_of = datetime.now(UTC).replace(microsecond=0)
    if not isinstance(as_of, datetime) or as_of.tzinfo is None:
        raise RetentionError("as_of must be a timezone-aware datetime")
    as_of = as_of.astimezone(UTC)
    requested_root = root.absolute()
    if root.is_symlink():
        raise RetentionError("pipeline root must not be a symlink")
    try:
        resolved_root = root.resolve(strict=True)
    except OSError as error:
        raise RetentionError(f"pipeline root does not exist: {root}") from error
    if resolved_root != requested_root:
        raise RetentionError("pipeline root must not traverse a symlink")
    _safe_directory(resolved_root, resolved_root, "pipeline root")
    data = resolved_root / "data"
    _safe_directory(resolved_root, data, "data directory")
    references = _References()

    try:
        # The deployed wrapper also owns the host pipeline lock. This shared
        # in-data lock is opened without creation or writes so all inputs may be
        # mounted read-only.
        with ExitStack() as locks:
            locks.enter_context(
                retention_lock(data, blocking=True, shared=True, create=False)
            )
            locks.enter_context(
                deployment_lock(data, blocking=True, shared=True, create=False)
            )
            records = _inventory_deployments(resolved_root, references)
            _validate_build_ownership(resolved_root, records, references)
            _pipeline_references(resolved_root, references)
            _validate_reference_integrity(resolved_root, records, references)
            state, current_id, previous_id = _validate_active_state(
                resolved_root, records, references
            )
            evidence, age_targets = _inventory_orphans(
                resolved_root, records, references, as_of=as_of
            )

            live: set[str] = set()
            for deployment_id, item in records.items():
                try:
                    if run_is_pinned(data, item["record"]["run_id"]):
                        live.add(deployment_id)
                except DeploymentError as error:
                    _unresolved(
                        references,
                        resolved_root,
                        data / "run-pins" / f"{item['record']['run_id']}.lock",
                        "run-pin-invalid",
                        detail=str(error),
                        blocks_all=True,
                    )

            unpromoted = {
                deployment_id
                for deployment_id, item in records.items()
                if not item["history"]
                and deployment_id not in {current_id, previous_id}
            }
            failure_evidence = references.failure_deployments | unpromoted
            reserved = {
                item
                for item in (
                    current_id,
                    previous_id,
                    *live,
                    *references.deployments,
                    *failure_evidence,
                )
                if item is not None
            }
            additional_candidates = sorted(
                (
                    (deployment_id, item)
                    for deployment_id, item in records.items()
                    if deployment_id not in reserved
                ),
                key=lambda pair: (-pair[1]["effective"].timestamp(), pair[0]),
            )
            additional = {
                deployment_id
                for deployment_id, _ in additional_candidates[
                    : policy.keep_additional_verified
                ]
            }

            deployment_output: list[dict[str, Any]] = []
            removable_ids: set[str] = set()
            for deployment_id in sorted(records):
                item = records[deployment_id]
                record = item["record"]
                reasons: list[str] = []
                if deployment_id == current_id:
                    reasons.append("current")
                if deployment_id == previous_id:
                    reasons.append("previous")
                if deployment_id in live:
                    reasons.append("live-pinned")
                if (
                    deployment_id in references.deployments
                    or record["run_id"] in references.runs
                    or record["snapshot_id"] in references.snapshots
                ):
                    reasons.append("unresolved-pipeline")
                if (
                    deployment_id in failure_evidence
                    or record["run_id"] in references.failure_runs
                    or record["snapshot_id"] in references.failure_snapshots
                ):
                    reasons.append("failure-evidence")
                if deployment_id in additional:
                    reasons.append("additional-verified")
                decision = "retain" if reasons else "remove"
                if decision == "remove":
                    removable_ids.add(deployment_id)
                deployment_output.append(
                    {
                        "deployment_id": deployment_id,
                        "run_id": record["run_id"],
                        "snapshot_id": record["snapshot_id"],
                        "effective_at": item["effective"].isoformat(),
                        "decision": decision,
                        "reasons": reasons,
                    }
                )

            delete_targets: list[dict[str, str]] = (
                list(age_targets) if not references.blocks_all else []
            )
            if not references.blocks_all:
                for deployment_id in sorted(removable_ids):
                    item = records[deployment_id]
                    delete_targets.append(
                        _target(resolved_root, item["record_path"], "deployment-record")
                    )
                    if item["history_dir"] is not None:
                        delete_targets.append(
                            _target(
                                resolved_root,
                                item["history_dir"],
                                "deployment-history",
                            )
                        )
                    delete_targets.append(
                        _target(resolved_root, item["build_dir"], "build")
                    )

                snapshot_references: dict[str, set[str]] = {}
                for deployment_id, item in records.items():
                    snapshot_references.setdefault(
                        item["record"]["snapshot_id"], set()
                    ).add(deployment_id)
                for snapshot_id in sorted(snapshot_references):
                    owners = snapshot_references[snapshot_id]
                    if (
                        owners
                        and owners <= removable_ids
                        and snapshot_id not in references.snapshots
                        and snapshot_id not in references.failure_snapshots
                    ):
                        delete_targets.append(
                            _target(
                                resolved_root,
                                resolved_root / "vault-snapshots" / snapshot_id,
                                "snapshot",
                            )
                        )
            delete_targets.sort(key=lambda item: (item["kind"], item["path"]))
    except DeploymentError as error:
        raise RetentionError(str(error)) from error

    references.unresolved.sort(
        key=lambda item: (item["code"], item["path"], item["detail"])
    )
    body: dict[str, Any] = {
        "schema_version": RETENTION_PLAN_SCHEMA_VERSION,
        "kind": "homeops-deployment-retention-plan",
        "mode": "dry-run",
        "deletion_enabled": False,
        "root": str(resolved_root),
        "as_of": as_of.isoformat(),
        "policy": {
            "keep_current": True,
            "keep_previous": True,
            "keep_additional_verified": policy.keep_additional_verified,
            "keep_live_pinned": True,
            "keep_unresolved": True,
            "failed_build_retention_seconds": int(
                FAILED_BUILD_RETENTION.total_seconds()
            ),
            "incomplete_upload_retention_seconds": int(
                INCOMPLETE_UPLOAD_RETENTION.total_seconds()
            ),
            "quarantine_cleanup_supported": False,
        },
        "active": {
            "schema_version": state.get("schema_version") if state else None,
            "current_deployment_id": current_id,
            "previous_deployment_id": previous_id,
        },
        "summary": {
            "deployment_count": len(deployment_output),
            "retained_count": sum(
                item["decision"] == "retain" for item in deployment_output
            ),
            "removable_count": sum(
                item["decision"] == "remove" for item in deployment_output
            ),
            "delete_target_count": len(delete_targets),
            "unresolved_count": len(references.unresolved),
            "blocked": references.blocks_all,
        },
        "deployments": deployment_output,
        "evidence": sorted(evidence, key=lambda item: (item["decision"], item["path"])),
        "unresolved": references.unresolved,
        "delete_targets": delete_targets,
    }
    body["inventory_digest"] = hashlib.sha256(canonical_json_bytes(body)).hexdigest()
    body["plan_id"] = hashlib.sha256(canonical_json_bytes(body)).hexdigest()
    return body
