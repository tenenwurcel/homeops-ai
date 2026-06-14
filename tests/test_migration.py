import json
import uuid
from pathlib import Path

import pytest

from homeops_ai.migration import (
    MigrationError,
    apply_migration,
    plan_migration,
    restore_migration,
    write_report,
)


def _note(frontmatter: str, body: str = "\n## What\n\nBody\n") -> str:
    return f"---\n{frontmatter}---\n{body}"


def test_migration_plans_ids_statuses_categories_and_warnings(tmp_path: Path) -> None:
    (tmp_path / "Active.md").write_text(
        _note("tags:\n  - current\n  - network\nstatus: active\nauthority: canonical\ntype: reference\n")
    )
    (tmp_path / "Legacy.md").write_text("# Legacy\n")
    (tmp_path / "Categories").mkdir()
    (tmp_path / "Categories" / "AI.md").write_text("![[AI.base]]")

    report = plan_migration(tmp_path)

    assert not report.errors
    assert len(report.files) == 3
    by_path = {item.source_path: item for item in report.files}
    assert uuid.UUID(by_path["Active.md"].proposed_id).version == 4
    assert {
        (change["field"], change["action"])
        for change in by_path["Active.md"].changes
    } >= {
        ("id", "add"),
        ("status", "normalize"),
        ("tags", "remove-lifecycle-tags"),
    }
    assert {warning.code for warning in by_path["Legacy.md"].warnings} == {
        "missing-type",
        "missing-status",
        "missing-authority",
    }
    assert {
        (change["field"], change["after"])
        for change in by_path["Categories/AI.md"].changes
    } >= {("type", "category"), ("status", "current")}


def test_migration_reports_malformed_frontmatter_and_duplicate_ids(
    tmp_path: Path,
) -> None:
    duplicate = str(uuid.uuid4())
    (tmp_path / "Broken.md").write_text("---\ntags:\n  - bad\n")
    (tmp_path / "One.md").write_text(_note(f'id: "{duplicate}"\n'))
    (tmp_path / "Two.md").write_text(_note(f'id: "{duplicate}"\n'))

    report = plan_migration(tmp_path)

    assert {issue.code for issue in report.errors} == {
        "malformed-frontmatter",
        "duplicate-id",
    }


def test_apply_snapshots_and_restore_returns_exact_original_bytes(
    tmp_path: Path,
) -> None:
    vault = tmp_path / "vault"
    data = tmp_path / "data"
    vault.mkdir()
    source = vault / "Note.md"
    original = _note("tags:\n  - current\nstatus: active\ntype: reference\nauthority: historical\n").encode()
    source.write_bytes(original)

    report = plan_migration(vault)
    report_path = tmp_path / "report.json"
    write_report(report, report_path)

    migration_dir = apply_migration(report_path, vault, data)
    migrated = source.read_bytes()
    assert migrated != original
    assert (migration_dir / "originals" / "Note.md").read_bytes() == original
    assert "status: current" in migrated.decode()
    assert "authority: supporting" in migrated.decode()
    assert plan_migration(vault).to_dict()["summary"]["changed_files"] == 0

    restore_migration(report.migration_id, vault, data)
    assert source.read_bytes() == original


def test_apply_refuses_source_changed_after_review(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    vault.mkdir()
    source = vault / "Note.md"
    source.write_text("# Original\n")
    report = plan_migration(vault)
    report_path = tmp_path / "report.json"
    write_report(report, report_path)
    source.write_text("# Changed\n")

    with pytest.raises(MigrationError, match="source changed since review"):
        apply_migration(report_path, vault, tmp_path / "data")


def test_report_contains_no_source_content(tmp_path: Path) -> None:
    secret_like_text = "do-not-copy-this-value"
    (tmp_path / "Note.md").write_text(f"# Note\n\n{secret_like_text}\n")
    report = plan_migration(tmp_path)

    assert secret_like_text not in json.dumps(report.to_dict())


def test_migration_preserves_existing_frontmatter_list_indentation(
    tmp_path: Path,
) -> None:
    source = tmp_path / "Note.md"
    source.write_text(
        _note(
            'categories:\n  - "[[AI]]"\ntags:\n  - network\n'
            "status: current\ntype: reference\nauthority: supporting\n"
        )
    )

    report = plan_migration(tmp_path)
    report_path = tmp_path / "report.json"
    write_report(report, report_path)
    apply_migration(report_path, tmp_path, tmp_path / "data")

    migrated = source.read_text()
    assert 'categories:\n  - "[[AI]]"\n' in migrated
    assert "tags:\n  - network\n" in migrated
