import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from collections import Counter
from contextlib import contextmanager
from dataclasses import asdict
from datetime import UTC, datetime
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


BUILD_SCHEMA_VERSION = 1
INGESTION_CONTRACT_VERSION = "homeops-v1"


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
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


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
    lock_path = data_dir.resolve() / "rebuild.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as error:
        raise BuildError(f"another rebuild holds the lock: {lock_path}") from error
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(f"{os.getpid()}\n")
        yield
    finally:
        lock_path.unlink(missing_ok=True)


def _manifest_path(data_dir: Path, run_id: str) -> Path:
    return data_dir.resolve() / "builds" / run_id / "manifest.json"


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def active_state(data_dir: Path) -> dict[str, Any]:
    path = data_dir.resolve() / "active.json"
    if not path.is_file():
        return {"schema_version": BUILD_SCHEMA_VERSION, "current": None, "previous": None}
    return _load_json(path)


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
    return _invoke_verifier(data_dir.resolve() / "builds" / run_id)


def _promote(data_dir: Path, run_id: str) -> dict[str, Any]:
    state = active_state(data_dir)
    promoted = {
        "schema_version": BUILD_SCHEMA_VERSION,
        "current": run_id,
        "previous": state.get("current"),
        "promoted_at": utc_now(),
    }
    _atomic_json(data_dir.resolve() / "active.json", promoted)
    return promoted


def rebuild(
    vault_root: Path,
    data_dir: Path,
    *,
    force: bool = False,
    promote: bool = True,
) -> dict[str, Any]:
    data = data_dir.resolve()
    with _rebuild_lock(data):
        inspected = inspect_vault(vault_root)
        if inspected["validation"]["errors"]:
            raise BuildError("vault validation failed; run `homeops-ai vault validate`")

        state = active_state(data)
        current_id = state.get("current")
        if current_id and not force:
            current_manifest_path = _manifest_path(data, current_id)
            if current_manifest_path.is_file():
                current = _load_json(current_manifest_path)
                if (
                    current.get("result") == "verified"
                    and current.get("source_fingerprint")
                    == inspected["source_fingerprint"]
                    and current.get("artifact_fingerprint")
                    == inspected["artifact_fingerprint"]
                ):
                    return {
                        "result": "unchanged",
                        "run_id": current_id,
                        "source_fingerprint": inspected["source_fingerprint"],
                        "logical_fingerprint": inspected["logical_fingerprint"],
                    }

        run_id = str(uuid.uuid4())
        build_dir = data / "builds" / run_id
        database_path = build_dir / "cozo.db"
        started_at = utc_now()
        build_dir.mkdir(parents=True)
        manifest = {
            "schema_version": BUILD_SCHEMA_VERSION,
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
            promoted = _promote(data, run_id) if promote else None
            return {
                "result": "verified",
                "run_id": run_id,
                "promoted": bool(promote),
                "active": promoted,
                "counts": inspected["counts"],
                "validation": validation,
            }
        except Exception as error:
            if isinstance(error, VerificationError):
                _atomic_json(build_dir / "validation.json", error.report)
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
        state = active_state(data)
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


def cleanup_failed(data_dir: Path) -> list[str]:
    cleaned = []
    for build in list_builds(data_dir):
        if build["result"] != "failed":
            continue
        database_path = data_dir.resolve() / "builds" / build["run_id"] / "cozo.db"
        if database_path.exists():
            shutil.rmtree(database_path)
            cleaned.append(build["run_id"])
    return cleaned
