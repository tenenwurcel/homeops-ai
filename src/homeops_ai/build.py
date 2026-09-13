import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from collections import Counter
from contextlib import contextmanager
from dataclasses import asdict
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path, PurePosixPath
from typing import Any, Iterator

from homeops_ai.database import open_database
from homeops_ai.loader import (
    _resolve_link,
    _title_index,
    _title_key,
    load_documents,
    load_ingestion_run,
)
from homeops_ai.markdown_parser import parse_sources
from homeops_ai.models import ParsedSourceDocument
from homeops_ai.source_contract import discover_sources, inventory_paths
from homeops_ai.deployment import (
    DEPLOYMENT_SCHEMA_VERSION,
    DeploymentError,
    PromotionConflict,
    create_deployment_record,
    deployment_lock,
    durable_atomic_json,
    durable_create_json,
    load_state,
    publish_current_projection,
    rollback_transition,
    select_deployment,
    store_deployment,
    strict_json_loads,
    validate_deployment_record,
    validate_safe_id,
    validate_state,
)
from homeops_ai.snapshot import (
    SnapshotError,
    create_snapshot_manifest,
    read_manifest,
    validate_snapshot_manifest,
    verify_snapshot,
    write_manifest,
)


BUILD_SCHEMA_VERSION = 1
INGESTION_CONTRACT_VERSION = "homeops-v1"
BUILD_CONTRACT_VERSION = "homeops-build-v1"
_SOURCE_REVISION = re.compile(r"^[0-9a-f]{7,64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class BuildError(RuntimeError):
    pass


class VerificationError(BuildError):
    def __init__(self, report: dict[str, Any]):
        super().__init__("candidate verification failed")
        self.report = report


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _sha256_json(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _atomic_json(path: Path, value: Any) -> None:
    durable_atomic_json(path, value)


def _excluded_markdown_titles(inventory: dict[str, list[dict[str, Any]]]) -> list[str]:
    return [
        PurePosixPath(item["source_path"]).stem
        for item in inventory["excluded"]
        if PurePosixPath(item["source_path"]).suffix.lower() == ".md"
    ]


def _document_fingerprint(document: ParsedSourceDocument) -> dict[str, Any]:
    data = asdict(document)
    data["warnings"] = sorted(
        data["warnings"], key=lambda item: (item["source_path"], item["code"])
    )
    return data


def _validate_documents(
    documents: list[ParsedSourceDocument],
    known_source_titles: list[str],
) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    warnings = [
        asdict(warning) for document in documents for warning in document.warnings
    ]
    ids: dict[str, str] = {}
    title_paths: dict[tuple[str, str], list[str]] = {}
    categories = {
        _title_key(document.title): document
        for document in documents
        if document.source_kind == "category"
    }

    for document in documents:
        if not document.document_id:
            errors.append(
                {
                    "code": "missing-document-id",
                    "source_path": document.source_path,
                    "message": "eligible source is missing an immutable document ID",
                }
            )
        elif document.document_id in ids:
            errors.append(
                {
                    "code": "duplicate-document-id",
                    "source_path": document.source_path,
                    "message": f"document ID duplicates {ids[document.document_id]}",
                }
            )
        else:
            ids[document.document_id] = document.source_path
        title_paths.setdefault(
            (document.source_kind, _title_key(document.title)), []
        ).append(
            document.source_path
        )

    for paths in title_paths.values():
        if len(paths) > 1:
            errors.append(
                {
                    "code": "ambiguous-document-title",
                    "source_path": paths[0],
                    "message": "case-folded title within one source kind is shared by: "
                    + ", ".join(paths),
                }
            )

    selected_titles = _title_index(documents)
    known_titles = {_title_key(title) for title in known_source_titles}
    resolutions: Counter[str] = Counter()
    unresolved_targets: Counter[str] = Counter()
    ambiguous_targets: Counter[str] = Counter()

    for document in documents:
        for assignment in document.categories:
            if _title_key(assignment.target_title) not in categories:
                errors.append(
                    {
                        "code": "unresolved-category",
                        "source_path": document.source_path,
                        "message": f"category does not resolve: {assignment.raw_target}",
                    }
                )
        for link in document.links:
            resolution = _resolve_link(link, document, selected_titles, known_titles)
            resolutions[resolution.state] += 1
            target = link.target_title or link.raw_target
            if resolution.state == "unresolved":
                unresolved_targets[target] += 1
            elif resolution.state == "ambiguous":
                ambiguous_targets[target] += 1

    for target, count in sorted(ambiguous_targets.items()):
        errors.append(
            {
                "code": "ambiguous-link-target",
                "source_path": "",
                "message": f"{target} is ambiguous in {count} link occurrence(s)",
            }
        )

    return {
        "errors": errors,
        "warnings": warnings,
        "link_resolution_counts": dict(sorted(resolutions.items())),
        "unresolved_targets": [
            {"target": target, "occurrences": count}
            for target, count in unresolved_targets.most_common()
        ],
    }


def _counts(
    documents: list[ParsedSourceDocument], validation: dict[str, Any]
) -> dict[str, int]:
    category_titles = {
        _title_key(document.title)
        for document in documents
        if document.source_kind == "category"
    }
    counts = {
        "ingestion_run": 1,
        "source_document": len(documents),
        "knowledge_document": sum(
            document.source_kind == "knowledge" for document in documents
        ),
        "category": sum(document.source_kind == "category" for document in documents),
        "document_content": len(documents),
        "document_tag": sum(len(document.tags) for document in documents),
        "document_category": sum(
            _title_key(assignment.target_title) in category_titles
            for document in documents
            for assignment in document.categories
        ),
        "section": sum(len(document.sections) for document in documents),
        "link_occurrence": sum(len(document.links) for document in documents),
    }
    for state, count in validation["link_resolution_counts"].items():
        counts[f"links_{state}"] = count
    return counts


def inspect_vault(vault_root: Path) -> dict[str, Any]:
    root = vault_root.resolve()
    inventory = inventory_paths(root, include_uppercase_markdown=True)
    sources = discover_sources(root, include_uppercase_markdown=True)
    documents = parse_sources(root, sources)
    known_titles = _excluded_markdown_titles(inventory)
    validation = _validate_documents(documents, known_titles)
    source_records = [
        {
            "source_path": document.source_path,
            "kind": document.source_kind,
            "content_hash": document.content_hash,
        }
        for document in documents
    ]
    source_fingerprint = _sha256_json(
        {
            "ingestion_contract_version": INGESTION_CONTRACT_VERSION,
            "profile": "knowledge",
            "sources": source_records,
        }
    )
    artifact_fingerprint = _sha256_json(inventory["excluded"])

    selected_titles = _title_index(documents)
    known_title_keys = {_title_key(title) for title in known_titles}
    resolutions = []
    for document in documents:
        for link in document.links:
            resolved = _resolve_link(link, document, selected_titles, known_title_keys)
            resolutions.append(
                {
                    "source_path": document.source_path,
                    "ordinal": link.ordinal,
                    "state": resolved.state,
                    "target_id": resolved.target_id,
                    "target_path": resolved.target_path,
                }
            )
    logical_fingerprint = _sha256_json(
        {
            "documents": [_document_fingerprint(document) for document in documents],
            "resolutions": resolutions,
        }
    )
    return {
        "vault_root": str(root),
        "profile": "knowledge",
        "source_fingerprint": source_fingerprint,
        "artifact_fingerprint": artifact_fingerprint,
        "logical_fingerprint": logical_fingerprint,
        "counts": _counts(documents, validation),
        "validation": validation,
        "inventory": inventory,
        "_documents": documents,
        "_known_source_titles": known_titles,
    }


def validation_report(vault_root: Path) -> dict[str, Any]:
    inspected = inspect_vault(vault_root)
    return {key: value for key, value in inspected.items() if not key.startswith("_")}


@contextmanager
def _rebuild_lock(data_dir: Path) -> Iterator[None]:
    """Compatibility wrapper around the shared crash-safe kernel lock."""

    try:
        with deployment_lock(data_dir):
            yield
    except DeploymentError as error:
        raise BuildError(str(error)) from error


def _manifest_path(data_dir: Path, run_id: str) -> Path:
    validate_safe_id(run_id, "run_id")
    return data_dir.resolve() / "builds" / run_id / "manifest.json"


def _load_json(path: Path) -> dict[str, Any]:
    parsed = strict_json_loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise BuildError(f"JSON document is not an object: {path}")
    return parsed


def active_state(data_dir: Path) -> dict[str, Any]:
    try:
        return load_state(data_dir)
    except DeploymentError as error:
        raise BuildError(str(error)) from error


def _invoke_verifier(build_dir: Path) -> dict[str, Any]:
    command = [
        sys.executable,
        "-m",
        "homeops_ai.verifier",
        "--build-dir",
        str(build_dir.resolve()),
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if not completed.stdout.strip():
        raise BuildError(
            f"verifier produced no JSON output (exit {completed.returncode}): "
            f"{completed.stderr.strip()}"
        )
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise BuildError(f"verifier produced invalid JSON: {completed.stdout}") from error
    if completed.returncode or not report.get("valid"):
        raise VerificationError(report)
    return report


def verify_run(data_dir: Path, run_id: str | None = None) -> dict[str, Any]:
    if run_id is None:
        run_id = active_state(data_dir).get("current")
    if not run_id:
        raise BuildError("there is no active build to verify")
    validate_safe_id(run_id, "run_id")
    return _invoke_verifier(data_dir.resolve() / "builds" / run_id)


def _package_version() -> str:
    try:
        return version("homeops-ai")
    except PackageNotFoundError:
        return "0+unknown"


def validate_release_provenance(
    homeops_version: str,
    source_revision: str,
    image_digest: str,
) -> tuple[str, str, str]:
    """Validate immutable release identity used by unattended publication."""

    if not isinstance(homeops_version, str) or not homeops_version.strip():
        raise BuildError("HomeOps package version is required")
    if not isinstance(source_revision, str) or not _SOURCE_REVISION.fullmatch(
        source_revision
    ):
        raise BuildError("HomeOps source revision must be 7-64 lowercase hex characters")
    if not isinstance(image_digest, str) or not _IMAGE_DIGEST.fullmatch(image_digest):
        raise BuildError("HomeOps image digest must be sha256:<64 lowercase hex>")
    return homeops_version, source_revision, image_digest


def _fsync_path(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | (getattr(os, "O_DIRECTORY", 0) if path.is_dir() else 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _materialize_snapshot(
    root: Path,
    source_vault: Path,
    manifest: dict[str, Any],
) -> Path:
    """Durably publish a verified vault under the canonical immutable layout."""

    root = root.resolve()
    source = source_vault.resolve(strict=True)
    checked = validate_snapshot_manifest(manifest)
    verify_snapshot(source, checked)
    snapshots = root / "vault-snapshots"
    destination = snapshots / checked["snapshot_id"]
    if destination.exists():
        existing = read_manifest(destination / "snapshot.json")
        if existing["snapshot_id"] != checked["snapshot_id"]:
            raise BuildError("snapshot ID collision in immutable snapshot store")
        verify_snapshot(destination / "vault", existing)
        return destination

    snapshots.mkdir(parents=True, exist_ok=True, mode=0o750)
    temporary = snapshots / f".{checked['snapshot_id']}.{uuid.uuid4()}.partial"
    temporary.mkdir(mode=0o750)
    try:
        copied = temporary / "vault"
        shutil.copytree(source, copied, symlinks=False)
        write_manifest(temporary / "snapshot.json", checked)
        verify_snapshot(copied, checked)
        for path in sorted(temporary.rglob("*"), reverse=True):
            _fsync_path(path)
        _fsync_path(temporary)
        os.replace(temporary, destination)
        _fsync_path(snapshots)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return destination


def materialize_snapshot(
    root: Path,
    source_vault: Path,
    manifest: dict[str, Any],
) -> Path:
    """Durably publish one verified immutable snapshot under ``root``."""

    return _materialize_snapshot(root, source_vault, manifest)


def _legacy_record(
    data: Path,
    run_id: str,
    vault_root: Path,
    *,
    promoted_at: str | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Independently bind one legacy verified run to its actual snapshot bytes."""

    manifest = _load_json(_manifest_path(data, run_id))
    if manifest.get("result") != "verified":
        raise BuildError(f"legacy active build is not verified: {run_id}")
    verify_run(data, run_id)
    inspected = inspect_vault(vault_root)
    if inspected["validation"]["errors"]:
        raise BuildError(f"legacy snapshot validation failed: {vault_root}")
    for field in ("source_fingerprint", "artifact_fingerprint", "logical_fingerprint"):
        if inspected[field] != manifest.get(field):
            raise BuildError(f"legacy snapshot/build {field} mismatch for {run_id}")
    try:
        snapshot = create_snapshot_manifest(
            vault_root,
            inspected,
            created_at=manifest.get("started_at") or utc_now(),
            package_version=manifest.get("homeops_version", "legacy"),
            source_revision=manifest.get("source_revision", "legacy"),
        )
        verify_snapshot(vault_root, snapshot)
    except SnapshotError as error:
        raise BuildError(f"legacy snapshot verification failed: {error}") from error
    build = {
        **manifest,
        "schema_version": manifest.get("schema_version", BUILD_SCHEMA_VERSION),
        "build_contract_version": manifest.get(
            "build_contract_version", BUILD_CONTRACT_VERSION
        ),
        "completed_at": manifest.get("completed_at") or manifest.get("verified_at"),
        "verified_at": manifest.get("verified_at") or manifest.get("completed_at"),
    }
    deployment = create_deployment_record(
        snapshot=snapshot,
        build=build,
        snapshot_received_at=snapshot["created_at"],
        homeops_version=manifest.get("homeops_version", "legacy"),
        source_revision=manifest.get("source_revision", "legacy"),
        image_digest=manifest.get("image_digest", "legacy-unrecorded"),
        promoted_at=promoted_at,
    )
    return deployment, snapshot


def adopt_legacy_state(
    data_dir: Path,
    current_vault: Path,
    *,
    previous_vault: Path | None = None,
) -> dict[str, Any]:
    """One-time fail-closed adoption using actual retained snapshot bytes."""

    data = data_dir.resolve()
    with _rebuild_lock(data):
        state = active_state(data)
        if state.get("schema_version") == DEPLOYMENT_SCHEMA_VERSION:
            if state.get("current_deployment") is None:
                raise BuildError("there is no legacy deployment state to adopt")
            for deployment in (
                state["current_deployment"],
                state.get("previous_deployment"),
            ):
                if deployment is None:
                    continue
                snapshot_dir = data.parent / "vault-snapshots" / deployment["snapshot_id"]
                manifest = read_manifest(snapshot_dir / "snapshot.json")
                verify_snapshot(snapshot_dir / "vault", manifest)
            publish_current_projection(data.parent, state)
            return state
        current_id = state.get("current")
        previous_id = state.get("previous")
        if not current_id:
            raise BuildError("legacy state has no current verified build")
        if previous_id and previous_vault is None:
            raise BuildError(
                "legacy state has a previous build; --previous-vault is required "
                "to preserve exact-pair rollback"
            )
        current, current_snapshot = _legacy_record(
            data, current_id, current_vault, promoted_at=state.get("promoted_at")
        )
        previous: dict[str, Any] | None = None
        previous_snapshot: dict[str, Any] | None = None
        if previous_id and previous_vault is not None:
            previous, previous_snapshot = _legacy_record(
                data, previous_id, previous_vault, promoted_at=None
            )
        adopted = {
            "schema_version": DEPLOYMENT_SCHEMA_VERSION,
            "current": current["run_id"],
            "previous": previous["run_id"] if previous else None,
            "current_deployment": current,
            "previous_deployment": previous,
            "promoted_at": state.get("promoted_at"),
        }
        # Persist all immutable evidence before selecting the new state.
        _materialize_snapshot(data.parent, current_vault, current_snapshot)
        store_deployment(data, current)
        if previous and previous_snapshot:
            assert previous_vault is not None
            _materialize_snapshot(data.parent, previous_vault, previous_snapshot)
            store_deployment(data, previous)
        _atomic_json(data / "active.json", adopted)
        publish_current_projection(data.parent, adopted)
        return adopted


def _candidate_matches_build(data: Path, candidate: dict[str, Any]) -> dict[str, Any]:
    checked = validate_deployment_record(candidate)
    manifest = _load_json(_manifest_path(data, checked["run_id"]))
    if manifest.get("result") != "verified":
        raise BuildError("candidate build manifest is not verified")
    if manifest.get("run_id") != checked["run_id"]:
        raise BuildError("candidate deployment/build run ID mismatch")
    if manifest.get("schema_version") != checked["build_schema_version"]:
        raise BuildError("candidate deployment/build schema version mismatch")

    legacy = (
        checked["homeops_version"] == "legacy"
        and checked["source_revision"] == "legacy"
        and checked["image_digest"] == "legacy-unrecorded"
    )
    provenance = {
        "build_contract_version": manifest.get("build_contract_version"),
        "homeops_version": manifest.get("homeops_version"),
        "source_revision": manifest.get("source_revision"),
        "image_digest": manifest.get("image_digest"),
    }
    if legacy:
        provenance = {
            "build_contract_version": provenance["build_contract_version"]
            or BUILD_CONTRACT_VERSION,
            "homeops_version": provenance["homeops_version"] or "legacy",
            "source_revision": provenance["source_revision"] or "legacy",
            "image_digest": provenance["image_digest"] or "legacy-unrecorded",
        }
    for field, actual in provenance.items():
        if actual != checked[field]:
            raise BuildError(f"candidate deployment/build {field} mismatch")
    if manifest.get("completed_at") != checked["build_completed_at"]:
        raise BuildError("candidate deployment/build completion timestamp mismatch")
    if manifest.get("verified_at") != checked["build_verified_at"]:
        raise BuildError("candidate deployment/build verification timestamp mismatch")
    for field in ("source_fingerprint", "artifact_fingerprint", "logical_fingerprint"):
        if manifest.get(field) != checked[field]:
            raise BuildError(f"candidate deployment/build {field} mismatch")

    snapshot_dir = data.parent / "vault-snapshots" / checked["snapshot_id"]
    try:
        snapshot = read_manifest(snapshot_dir / "snapshot.json")
        verify_snapshot(snapshot_dir / "vault", snapshot)
    except (OSError, SnapshotError) as error:
        raise BuildError(f"candidate snapshot verification failed: {error}") from error
    if snapshot["snapshot_id"] != checked["snapshot_id"]:
        raise BuildError("candidate deployment/snapshot ID mismatch")
    if snapshot["schema_version"] != checked["snapshot_schema_version"]:
        raise BuildError("candidate deployment/snapshot schema version mismatch")
    if (
        snapshot["snapshot_contract_version"]
        != checked["snapshot_contract_version"]
    ):
        raise BuildError("candidate deployment/snapshot contract version mismatch")
    if snapshot["created_at"] != checked["snapshot_created_at"]:
        raise BuildError("candidate deployment/snapshot creation timestamp mismatch")
    for field in ("source_fingerprint", "artifact_fingerprint", "logical_fingerprint"):
        if snapshot[field] != checked[field]:
            raise BuildError(f"candidate deployment/snapshot {field} mismatch")
    verify_run(data, checked["run_id"])
    return manifest


def _store_promoted_record(data: Path, record: dict[str, Any]) -> None:
    """Persist immutable promotion provenance separately from candidate identity."""

    checked = validate_deployment_record(record)
    promoted_at = checked.get("promoted_at")
    if not promoted_at:
        raise BuildError("promoted deployment record lacks promotion timestamp")
    durable_create_json(
        data
        / "deployment-history"
        / checked["deployment_id"]
        / f"{hashlib.sha256(promoted_at.encode()).hexdigest()}.json",
        checked,
    )


def _repair_selected_bookkeeping_locked(
    data: Path, expected_deployment_id: str
) -> dict[str, Any]:
    """Idempotently finish history/projection writes after an active-state CAS."""

    expected_deployment_id = validate_safe_id(
        expected_deployment_id, "deployment_id"
    )
    state = active_state(data)
    if state.get("schema_version") != DEPLOYMENT_SCHEMA_VERSION:
        raise BuildError("selected deployment bookkeeping requires schema-v2 state")
    current = state.get("current_deployment")
    if current is None or current["deployment_id"] != expected_deployment_id:
        raise BuildError("selected deployment changed before bookkeeping repair")
    # Also closes the case where active.json replacement succeeded but fsync of
    # its parent directory was the operation that reported failure.
    _fsync_path(data)
    _store_promoted_record(data, current)
    publish_current_projection(data.parent, state)
    return state


def repair_selected_bookkeeping(
    data_dir: Path, expected_deployment_id: str
) -> dict[str, Any]:
    """Repair idempotent post-CAS bookkeeping for the exact active deployment."""

    data = data_dir.resolve()
    with _rebuild_lock(data):
        return _repair_selected_bookkeeping_locked(data, expected_deployment_id)


_ROLLBACK_JOURNAL_FIELDS = {
    "schema_version",
    "operation",
    "source_state",
    "target_state",
    "started_at",
}


def _rollback_journal_path(data: Path) -> Path:
    return data.resolve() / "pipeline-transactions" / "rollback.json"


def _load_rollback_journal(data: Path) -> dict[str, Any] | None:
    path = _rollback_journal_path(data)
    if not path.is_file():
        return None
    parsed = strict_json_loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(parsed, dict)
        or set(parsed) != _ROLLBACK_JOURNAL_FIELDS
        or parsed["schema_version"] != 1
        or parsed["operation"] != "rollback"
        or not isinstance(parsed["started_at"], str)
        or not parsed["started_at"]
    ):
        raise BuildError("rollback transaction journal is invalid")
    try:
        source = validate_state(parsed["source_state"], allow_legacy=False)
        target = validate_state(parsed["target_state"], allow_legacy=False)
    except DeploymentError as error:
        raise BuildError(f"rollback transaction journal is invalid: {error}") from error
    source_current = source.get("current_deployment")
    source_previous = source.get("previous_deployment")
    target_current = target.get("current_deployment")
    target_previous = target.get("previous_deployment")
    if (
        source_current is None
        or source_previous is None
        or target_current is None
        or target_previous is None
        or target_current["deployment_id"] != source_previous["deployment_id"]
        or target_current
        != {**source_previous, "promoted_at": parsed["started_at"]}
        or target_previous != source_current
        or target_current["promoted_at"] != parsed["started_at"]
        or target["promoted_at"] != parsed["started_at"]
    ):
        raise BuildError("rollback transaction journal transition is invalid")
    return {**parsed, "source_state": source, "target_state": target}


def _write_rollback_journal(
    data: Path, source: dict[str, Any], target: dict[str, Any]
) -> dict[str, Any]:
    journal = {
        "schema_version": 1,
        "operation": "rollback",
        "source_state": validate_state(source, allow_legacy=False),
        "target_state": validate_state(target, allow_legacy=False),
        "started_at": target["promoted_at"],
    }
    _atomic_json(_rollback_journal_path(data), journal)
    return journal


def _clear_rollback_journal(data: Path) -> None:
    path = _rollback_journal_path(data)
    path.unlink(missing_ok=True)
    if path.parent.is_dir():
        _fsync_path(path.parent)


def _finish_rollback_locked(data: Path, journal: dict[str, Any]) -> dict[str, Any]:
    source = journal["source_state"]
    target = journal["target_state"]
    actual = active_state(data)
    if actual == source:
        _atomic_json(data / "active.json", target)
    elif actual != target:
        raise BuildError("active deployment changed during rollback recovery")
    current = target["current_deployment"]
    _repair_selected_bookkeeping_locked(data, current["deployment_id"])
    _clear_rollback_journal(data)
    return target


def recover_pending_rollback(data_dir: Path) -> dict[str, Any] | None:
    """Finish one durable rollback intent; never initiate a new rollback."""

    data = data_dir.resolve()
    with _rebuild_lock(data):
        pending = _load_rollback_journal(data)
        if pending is None:
            return None
        return _finish_rollback_locked(data, pending)


def _promote_locked(
    data: Path,
    candidate: dict[str, Any],
    *,
    expected_current_deployment_id: str | None,
    promoted_at: str,
    require_evaluation: bool,
) -> dict[str, Any]:
    if _rollback_journal_path(data).is_file():
        raise BuildError("unfinished rollback transaction must be recovered first")
    _candidate_matches_build(data, candidate)
    if require_evaluation:
        evaluation_path = (
            data / "builds" / candidate["run_id"] / "promotion-evaluation.json"
        )
        if not evaluation_path.is_file() or not _load_json(evaluation_path).get("passed"):
            raise BuildError("candidate has no passing promotion-safe evaluation")
    state = active_state(data)
    if state.get("schema_version") != DEPLOYMENT_SCHEMA_VERSION:
        raise BuildError("legacy active state must be explicitly adopted before v2 promotion")
    try:
        selected, result = select_deployment(
            state,
            candidate,
            expected_current_deployment_id=expected_current_deployment_id,
            promoted_at=promoted_at,
        )
    except PromotionConflict:
        raise
    if result == "promoted":
        store_deployment(data, candidate)
        _atomic_json(data / "active.json", selected)
    repaired = _repair_selected_bookkeeping_locked(
        data, selected["current_deployment"]["deployment_id"]
    )
    return {"result": result, **repaired}


def promote(
    data_dir: Path,
    deployment: dict[str, Any],
    *,
    expected_current_deployment_id: str | None,
    require_evaluation: bool = True,
) -> dict[str, Any]:
    data = data_dir.resolve()
    with _rebuild_lock(data):
        try:
            return _promote_locked(
                data,
                deployment,
                expected_current_deployment_id=expected_current_deployment_id,
                promoted_at=utc_now(),
                require_evaluation=require_evaluation,
            )
        except DeploymentError as error:
            raise BuildError(str(error)) from error


def rebuild(
    vault_root: Path,
    data_dir: Path,
    *,
    force: bool = False,
    promote: bool = True,
    snapshot_manifest: dict[str, Any] | None = None,
    snapshot_received_at: str | None = None,
    homeops_version: str | None = None,
    source_revision: str | None = None,
    image_digest: str | None = None,
    expected_current_deployment_id: str | None = None,
) -> dict[str, Any]:
    data = data_dir.resolve()
    with _rebuild_lock(data):
        requested_homeops_version = homeops_version or _package_version()
        if snapshot_manifest is not None:
            if source_revision is None or image_digest is None:
                raise BuildError(
                    "strict snapshot builds require source_revision and image_digest"
                )
            (
                requested_homeops_version,
                requested_source_revision,
                requested_image_digest,
            ) = validate_release_provenance(
                requested_homeops_version, source_revision, image_digest
            )
        else:
            requested_source_revision = source_revision or os.environ.get(
                "HOMEOPS_SOURCE_REVISION", "development"
            )
            requested_image_digest = image_digest or os.environ.get(
                "HOMEOPS_IMAGE_DIGEST", "development-unpinned"
            )
        inspected = inspect_vault(vault_root)
        if inspected["validation"]["errors"]:
            raise BuildError("vault validation failed; run `homeops-ai vault validate`")

        state = active_state(data)
        strict_snapshot: dict[str, Any] | None = None
        if snapshot_manifest is not None:
            try:
                strict_snapshot = validate_snapshot_manifest(snapshot_manifest)
                verify_snapshot(vault_root, strict_snapshot)
            except SnapshotError as error:
                raise BuildError(f"snapshot verification failed: {error}") from error
        current_id = state.get("current")
        if current_id and not force:
            current_manifest_path = _manifest_path(data, current_id)
            if current_manifest_path.is_file():
                current = _load_json(current_manifest_path)
                same_build = (
                    current.get("result") == "verified"
                    and current.get("source_fingerprint")
                    == inspected["source_fingerprint"]
                    and current.get("artifact_fingerprint")
                    == inspected["artifact_fingerprint"]
                    and current.get("logical_fingerprint")
                    == inspected["logical_fingerprint"]
                )
                if strict_snapshot is not None:
                    selected = state.get("current_deployment")
                    same_build = bool(
                        same_build
                        and state.get("schema_version") == DEPLOYMENT_SCHEMA_VERSION
                        and selected
                        and selected["run_id"] == current_id
                        and selected["snapshot_id"] == strict_snapshot["snapshot_id"]
                        and selected["homeops_version"] == requested_homeops_version
                        and selected["source_revision"] == requested_source_revision
                        and selected["image_digest"] == requested_image_digest
                        and selected["build_contract_version"]
                        == BUILD_CONTRACT_VERSION
                        and selected["snapshot_contract_version"]
                        == strict_snapshot["snapshot_contract_version"]
                        and current.get("build_contract_version")
                        == BUILD_CONTRACT_VERSION
                        and current.get("homeops_version")
                        == requested_homeops_version
                        and current.get("source_revision")
                        == requested_source_revision
                        and current.get("image_digest") == requested_image_digest
                    )
                else:
                    same_build = bool(
                        same_build
                        and current.get(
                            "build_contract_version", BUILD_CONTRACT_VERSION
                        )
                        == BUILD_CONTRACT_VERSION
                        and current.get(
                            "homeops_version", requested_homeops_version
                        )
                        == requested_homeops_version
                        and current.get(
                            "source_revision", requested_source_revision
                        )
                        == requested_source_revision
                        and current.get("image_digest", requested_image_digest)
                        == requested_image_digest
                    )
                if same_build:
                    return {
                        "result": "unchanged",
                        "run_id": current_id,
                        "deployment_id": (
                            state.get("current_deployment") or {}
                        ).get("deployment_id"),
                        "source_fingerprint": inspected["source_fingerprint"],
                        "artifact_fingerprint": inspected["artifact_fingerprint"],
                        "logical_fingerprint": inspected["logical_fingerprint"],
                    }

        run_id = str(uuid.uuid4())
        build_dir = data / "builds" / run_id
        database_path = build_dir / "cozo.db"
        started_at = utc_now()
        build_dir.mkdir(parents=True)
        manifest = {
            "schema_version": BUILD_SCHEMA_VERSION,
            "build_contract_version": BUILD_CONTRACT_VERSION,
            "run_id": run_id,
            "profile": inspected["profile"],
            "vault_root": inspected["vault_root"],
            "database_path": str(database_path),
            "source_fingerprint": inspected["source_fingerprint"],
            "artifact_fingerprint": inspected["artifact_fingerprint"],
            "logical_fingerprint": inspected["logical_fingerprint"],
            "counts": inspected["counts"],
            "inventory": inspected["inventory"],
            "unresolved_targets": inspected["validation"]["unresolved_targets"],
            "started_at": started_at,
            "completed_at": None,
            "result": "building",
            "ingestion_result": "candidate",
            "homeops_version": requested_homeops_version,
            "source_revision": requested_source_revision,
            "image_digest": requested_image_digest,
        }
        _atomic_json(build_dir / "manifest.json", manifest)

        try:
            with open_database(database_path) as client:
                load_documents(
                    client,
                    inspected["_documents"],
                    known_source_titles=inspected["_known_source_titles"],
                )
                load_ingestion_run(
                    client,
                    run_id=run_id,
                    source_root=inspected["vault_root"],
                    source_fingerprint=inspected["source_fingerprint"],
                    logical_fingerprint=inspected["logical_fingerprint"],
                    started_at=started_at,
                    completed_at=utc_now(),
                    result="candidate",
                    counts=inspected["counts"],
                )

            manifest["result"] = "candidate"
            manifest["completed_at"] = utc_now()
            _atomic_json(build_dir / "manifest.json", manifest)
            _invoke_verifier(build_dir)

            with open_database(database_path) as client:
                load_ingestion_run(
                    client,
                    run_id=run_id,
                    source_root=inspected["vault_root"],
                    source_fingerprint=inspected["source_fingerprint"],
                    logical_fingerprint=inspected["logical_fingerprint"],
                    started_at=started_at,
                    completed_at=manifest["completed_at"],
                    result="verified",
                    counts=inspected["counts"],
                )
            manifest["ingestion_result"] = "verified"
            _atomic_json(build_dir / "manifest.json", manifest)
            validation = _invoke_verifier(build_dir)
            _atomic_json(build_dir / "validation.json", validation)
            manifest["result"] = "verified"
            manifest["verified_at"] = utc_now()
            _atomic_json(build_dir / "manifest.json", manifest)
            deployment: dict[str, Any] | None = None
            promoted: dict[str, Any] | None = None
            if strict_snapshot is not None:
                for field in (
                    "source_fingerprint",
                    "artifact_fingerprint",
                    "logical_fingerprint",
                ):
                    if strict_snapshot.get(field) != manifest[field]:
                        raise BuildError(f"snapshot/build {field} mismatch")
                deployment = create_deployment_record(
                    snapshot=strict_snapshot,
                    build=manifest,
                    snapshot_received_at=snapshot_received_at or started_at,
                    homeops_version=manifest["homeops_version"],
                    source_revision=manifest["source_revision"],
                    image_digest=manifest["image_digest"],
                )
                store_deployment(data, deployment)
                if promote:
                    if state.get("schema_version") != DEPLOYMENT_SCHEMA_VERSION:
                        raise BuildError(
                            "legacy active state must be explicitly adopted before v2 promotion"
                        )
                    promoted = _promote_locked(
                        data,
                        deployment,
                        expected_current_deployment_id=expected_current_deployment_id,
                        promoted_at=utc_now(),
                        require_evaluation=False,
                    )
            elif promote:
                active_path = data / "active.json"
                if active_path.is_file() and state.get("schema_version") != BUILD_SCHEMA_VERSION:
                    raise BuildError(
                        "direct rebuild cannot replace schema-v2 deployment state; "
                        "provide a strict snapshot manifest"
                    )
                promoted = {
                    "schema_version": BUILD_SCHEMA_VERSION,
                    "current": run_id,
                    "previous": state.get("current"),
                    "promoted_at": utc_now(),
                }
                _atomic_json(active_path, promoted)
            return {
                "result": "verified",
                "run_id": run_id,
                "deployment_id": deployment["deployment_id"] if deployment else None,
                "deployment": deployment,
                "promoted": bool(promote),
                "active": promoted,
                "counts": inspected["counts"],
                "validation": validation,
            }
        except Exception as error:
            if isinstance(error, VerificationError):
                _atomic_json(build_dir / "validation.json", error.report)
            if manifest.get("result") != "verified":
                manifest["result"] = "failed"
                manifest["failed_at"] = utc_now()
                manifest["failure"] = str(error)
                _atomic_json(build_dir / "manifest.json", manifest)
            raise


def list_builds(data_dir: Path) -> list[dict[str, Any]]:
    builds_dir = data_dir.resolve() / "builds"
    if not builds_dir.is_dir():
        return []
    builds = []
    for manifest_path in sorted(builds_dir.glob("*/manifest.json")):
        manifest = _load_json(manifest_path)
        builds.append(
            {
                "run_id": manifest["run_id"],
                "result": manifest["result"],
                "started_at": manifest["started_at"],
                "verified_at": manifest.get("verified_at"),
                "source_fingerprint": manifest["source_fingerprint"],
            }
        )
    return builds


def rollback(data_dir: Path) -> dict[str, Any]:
    data = data_dir.resolve()
    with _rebuild_lock(data):
        pending = _load_rollback_journal(data)
        if pending is not None:
            return _finish_rollback_locked(data, pending)
        state = active_state(data)
        if state.get("schema_version") == BUILD_SCHEMA_VERSION:
            current = state.get("current")
            previous = state.get("previous")
            if not current or not previous:
                raise BuildError("rollback requires current and previous verified builds")
            verify_run(data, previous)
            rolled_back = {
                "schema_version": BUILD_SCHEMA_VERSION,
                "current": previous,
                "previous": current,
                "promoted_at": utc_now(),
            }
            _atomic_json(data / "active.json", rolled_back)
            return rolled_back
        if state.get("schema_version") != DEPLOYMENT_SCHEMA_VERSION:
            raise BuildError("unsupported active state schema for rollback")
        previous = state.get("previous_deployment")
        if previous is None:
            raise BuildError("rollback requires current and previous verified deployments")
        _candidate_matches_build(data, previous)
        try:
            rolled_back = rollback_transition(state, promoted_at=utc_now())
        except DeploymentError as error:
            raise BuildError(str(error)) from error
        journal = _write_rollback_journal(data, state, rolled_back)
        return _finish_rollback_locked(data, journal)


def cleanup_failed(data_dir: Path) -> list[str]:
    data = data_dir.resolve()
    with _rebuild_lock(data):
        cleaned = []
        for build in list_builds(data):
            if build["result"] != "failed":
                continue
            database_path = data / "builds" / build["run_id"] / "cozo.db"
            if database_path.exists():
                shutil.rmtree(database_path)
                cleaned.append(build["run_id"])
        return cleaned


def evaluate_candidate(
    data_dir: Path,
    run_id: str,
    *,
    cases: list[Path] | None = None,
) -> dict[str, Any]:
    """Run promotion-safe smoke queries and optional versioned suites."""

    validate_safe_id(run_id, "run_id")
    verify_run(data_dir, run_id)
    # Delayed imports avoid the query -> build dependency at module import time.
    from homeops_ai.evaluation import evaluate_suite
    from homeops_ai.query import execute_query

    smoke = {}
    for name in ("canonical-current", "link-inventory", "missing-lifecycle"):
        result = execute_query(data_dir, name, run_id=run_id)
        smoke[name] = result["summary"]
    suites = []
    for suite in cases or []:
        report = evaluate_suite(suite, data_dir, run_id=run_id)
        suites.append(
            {
                "path": str(suite.resolve()),
                "suite_id": report["suite_id"],
                "passed": report["passed"],
                "summary": report["summary"],
            }
        )
    report = {
        "schema_version": 1,
        "run_id": run_id,
        "evaluated_at": utc_now(),
        "passed": all(item["passed"] for item in suites),
        "smoke_queries": smoke,
        "suites": suites,
    }
    _atomic_json(
        data_dir.resolve() / "builds" / run_id / "promotion-evaluation.json",
        report,
    )
    return report
