import hashlib
import json
import os
import shutil
import tempfile
import uuid
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ruamel.yaml.comments import CommentedSeq

from homeops_ai.frontmatter import FrontmatterError, parse_markdown, render_markdown
from homeops_ai.models import (
    FileMigration,
    MigrationReport,
    SourceFile,
    ValidationIssue,
)
from homeops_ai.source_contract import discover_sources


REPORT_SCHEMA_VERSION = 1
LIFECYCLE_TAGS = {"current", "planned", "done", "reference"}
STATUS_MAPPING = {
    "active": "current",
    "implemented": "done",
    "reference": "current",
    "current": "current",
    "planned": "planned",
    "in-progress": "in-progress",
    "done": "done",
    "superseded": "superseded",
    "abandoned": "abandoned",
    "historical": "historical",
}


class MigrationError(RuntimeError):
    pass


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _is_canonical_uuid4(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return False
    return parsed.version == 4 and str(parsed) == value


def _change(
    changes: list[dict[str, Any]],
    field: str,
    action: str,
    before: Any,
    after: Any,
) -> None:
    changes.append(
        {"field": field, "action": action, "before": before, "after": after}
    )


def _migrate_tags(
    source: SourceFile,
    frontmatter: dict[str, Any],
    canonical_status: str | None,
    changes: list[dict[str, Any]],
    warnings: list[ValidationIssue],
) -> str | None:
    tags = frontmatter.get("tags")
    if tags is None:
        return canonical_status
    if not isinstance(tags, list):
        warnings.append(
            ValidationIssue(
                "warning",
                "tags-not-list",
                source.source_path,
                "tags is not a YAML list; lifecycle tags were not migrated",
            )
        )
        return canonical_status

    lifecycle = [str(tag) for tag in tags if str(tag) in LIFECYCLE_TAGS]
    lifecycle_statuses = {STATUS_MAPPING[tag] for tag in lifecycle}
    if canonical_status is None and len(lifecycle_statuses) == 1:
        canonical_status = lifecycle_statuses.pop()
        frontmatter["status"] = canonical_status
        _change(changes, "status", "seed-from-tag", None, canonical_status)

    if not lifecycle:
        return canonical_status

    if canonical_status is not None and all(
        STATUS_MAPPING[tag] == canonical_status for tag in lifecycle
    ):
        filtered = CommentedSeq(tag for tag in tags if str(tag) not in LIFECYCLE_TAGS)
        frontmatter["tags"] = filtered
        _change(changes, "tags", "remove-lifecycle-tags", lifecycle, list(filtered))
    else:
        warnings.append(
            ValidationIssue(
                "warning",
                "lifecycle-tag-conflict",
                source.source_path,
                "lifecycle tags conflict with status or are ambiguous; tags were preserved",
            )
        )
    return canonical_status


def _transform(
    vault_root: Path,
    source: SourceFile,
    *,
    proposed_id: str | None = None,
) -> tuple[FileMigration | None, list[ValidationIssue], bytes | None]:
    path = vault_root / source.source_path
    original = path.read_bytes()
    issues: list[ValidationIssue] = []
    try:
        text = original.decode("utf-8")
    except UnicodeDecodeError:
        return (
            None,
            [
                ValidationIssue(
                    "error",
                    "invalid-utf8",
                    source.source_path,
                    "source is not valid UTF-8",
                )
            ],
            None,
        )

    try:
        document = parse_markdown(text)
    except FrontmatterError as error:
        return (
            None,
            [
                ValidationIssue(
                    "error",
                    "malformed-frontmatter",
                    source.source_path,
                    str(error),
                )
            ],
            None,
        )

    changes: list[dict[str, Any]] = []
    warnings: list[ValidationIssue] = []
    frontmatter = document.frontmatter

    existing_id = frontmatter.get("id")
    if existing_id is None:
        document_id = proposed_id or str(uuid.uuid4())
        frontmatter.insert(0, "id", document_id)
        _change(changes, "id", "add", None, document_id)
    elif not _is_canonical_uuid4(existing_id):
        issues.append(
            ValidationIssue(
                "error",
                "invalid-id",
                source.source_path,
                "id must be a canonical lowercase UUIDv4",
            )
        )
        return None, issues, None
    else:
        document_id = existing_id

    if source.kind == "category":
        if frontmatter.get("type") is None:
            frontmatter["type"] = "category"
            _change(changes, "type", "add-category-default", None, "category")
        if frontmatter.get("status") is None:
            frontmatter["status"] = "current"
            _change(changes, "status", "add-category-default", None, "current")

    raw_status = frontmatter.get("status")
    canonical_status: str | None = None
    if raw_status is not None:
        if not isinstance(raw_status, str) or raw_status not in STATUS_MAPPING:
            warnings.append(
                ValidationIssue(
                    "warning",
                    "unknown-status",
                    source.source_path,
                    "status is not an approved lifecycle value and was preserved",
                )
            )
        else:
            canonical_status = STATUS_MAPPING[raw_status]
            if canonical_status != raw_status:
                frontmatter["status"] = canonical_status
                _change(changes, "status", "normalize", raw_status, canonical_status)

    canonical_status = _migrate_tags(
        source, frontmatter, canonical_status, changes, warnings
    )

    if frontmatter.get("authority") == "historical":
        frontmatter["authority"] = "supporting"
        _change(changes, "authority", "normalize", "historical", "supporting")

    if source.kind == "knowledge":
        for field in ("type", "status", "authority"):
            if frontmatter.get(field) is None:
                warnings.append(
                    ValidationIssue(
                        "warning",
                        f"missing-{field}",
                        source.source_path,
                        f"legacy knowledge document is missing {field}",
                    )
                )

    rendered = render_markdown(document).encode("utf-8") if changes else original
    return (
        FileMigration(
            source_path=source.source_path,
            source_kind=source.kind,
            before_sha256=sha256_bytes(original),
            after_sha256=sha256_bytes(rendered),
            proposed_id=document_id,
            changes=changes,
            warnings=warnings,
        ),
        issues,
        rendered,
    )


def plan_migration(
    vault_root: Path,
    *,
    include_uppercase_markdown: bool = False,
    proposed_ids: dict[str, str] | None = None,
    migration_id: str | None = None,
) -> MigrationReport:
    root = vault_root.resolve()
    files: list[FileMigration] = []
    issues: list[ValidationIssue] = []
    seen_ids: dict[str, str] = {}

    for source in discover_sources(
        root, include_uppercase_markdown=include_uppercase_markdown
    ):
        item, item_issues, _ = _transform(
            root, source, proposed_id=(proposed_ids or {}).get(source.source_path)
        )
        issues.extend(item_issues)
        if item is None:
            continue
        if item.proposed_id in seen_ids:
            issues.append(
                ValidationIssue(
                    "error",
                    "duplicate-id",
                    source.source_path,
                    f"id duplicates {seen_ids[item.proposed_id]}",
                )
            )
        else:
            seen_ids[item.proposed_id] = source.source_path
        files.append(item)

    return MigrationReport(
        schema_version=REPORT_SCHEMA_VERSION,
        migration_id=migration_id or str(uuid.uuid4()),
        created_at=utc_now(),
        vault_root=str(root),
        include_uppercase_markdown=include_uppercase_markdown,
        files=files,
        issues=issues,
    )


def write_report(report: MigrationReport, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(output, json.dumps(report.to_dict(), indent=2).encode() + b"\n")


def load_report(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(file_descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _replan_from_report(report: dict[str, Any], vault_root: Path) -> MigrationReport:
    proposed_ids = {
        item["source_path"]: item["proposed_id"] for item in report["files"]
    }
    return plan_migration(
        vault_root,
        include_uppercase_markdown=report["include_uppercase_markdown"],
        proposed_ids=proposed_ids,
        migration_id=report["migration_id"],
    )


def apply_migration(report_path: Path, vault_root: Path, data_dir: Path) -> Path:
    reviewed = load_report(report_path)
    if reviewed["schema_version"] != REPORT_SCHEMA_VERSION:
        raise MigrationError("unsupported migration report schema")
    if Path(reviewed["vault_root"]).resolve() != vault_root.resolve():
        raise MigrationError("migration report belongs to a different vault")
    if reviewed["summary"]["errors"]:
        raise MigrationError("migration report contains errors")

    current = _replan_from_report(reviewed, vault_root)
    if current.errors:
        raise MigrationError("vault validation now fails; regenerate the report")
    current_by_path = {item.source_path: item for item in current.files}
    for expected in reviewed["files"]:
        actual = current_by_path.get(expected["source_path"])
        if actual is None:
            raise MigrationError(f"source disappeared: {expected['source_path']}")
        if actual.before_sha256 != expected["before_sha256"]:
            raise MigrationError(f"source changed since review: {expected['source_path']}")
        if actual.after_sha256 != expected["after_sha256"]:
            raise MigrationError(
                f"migration result differs from reviewed report: {expected['source_path']}"
            )

    migration_dir = data_dir.resolve() / "migrations" / reviewed["migration_id"]
    if migration_dir.exists():
        raise MigrationError(f"migration snapshot already exists: {migration_dir}")
    originals = migration_dir / "originals"
    originals.mkdir(parents=True)

    changed = [item for item in current.files if item.changed]
    for item in changed:
        source = vault_root / item.source_path
        snapshot = originals / item.source_path
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, snapshot)

    manifest = {
        **reviewed,
        "applied_at": utc_now(),
        "snapshot_root": str(originals),
    }
    _atomic_write(
        migration_dir / "manifest.json",
        json.dumps(manifest, indent=2).encode() + b"\n",
    )

    written: list[FileMigration] = []
    try:
        sources = {
            item.source_path: item
            for item in discover_sources(
                vault_root,
                include_uppercase_markdown=reviewed["include_uppercase_markdown"],
            )
        }
        proposed_ids = {
            item["source_path"]: item["proposed_id"] for item in reviewed["files"]
        }
        for item in changed:
            _, issues, rendered = _transform(
                vault_root,
                sources[item.source_path],
                proposed_id=proposed_ids[item.source_path],
            )
            if issues or rendered is None:
                raise MigrationError(f"failed to render {item.source_path}")
            _atomic_write(vault_root / item.source_path, rendered)
            written.append(item)
    except Exception:
        for item in written:
            _atomic_write(
                vault_root / item.source_path,
                (originals / item.source_path).read_bytes(),
            )
        raise

    return migration_dir


def restore_migration(migration_id: str, vault_root: Path, data_dir: Path) -> None:
    migration_dir = data_dir.resolve() / "migrations" / migration_id
    manifest_path = migration_dir / "manifest.json"
    if not manifest_path.is_file():
        raise MigrationError(f"migration manifest not found: {manifest_path}")
    manifest = load_report(manifest_path)
    if Path(manifest["vault_root"]).resolve() != vault_root.resolve():
        raise MigrationError("migration snapshot belongs to a different vault")
    originals = migration_dir / "originals"

    changed = [item for item in manifest["files"] if item["changed"]]
    conflicts = []
    for item in changed:
        current = vault_root / item["source_path"]
        if not current.is_file() or sha256_bytes(current.read_bytes()) != item["after_sha256"]:
            conflicts.append(item["source_path"])
    if conflicts:
        raise MigrationError(
            "restore refused because migrated files changed afterward: "
            + ", ".join(conflicts)
        )

    for item in changed:
        _atomic_write(
            vault_root / item["source_path"],
            (originals / item["source_path"]).read_bytes(),
        )
