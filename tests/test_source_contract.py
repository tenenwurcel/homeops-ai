from pathlib import Path

import pytest

from homeops_ai.source_contract import discover_sources, export_snapshot, inventory_paths


def test_discovery_includes_root_and_categories_only(tmp_path: Path) -> None:
    (tmp_path / "Note.md").write_text("note")
    (tmp_path / "Upper.MD").write_text("upper")
    (tmp_path / "Templates").mkdir()
    (tmp_path / "Templates" / "Plan.md").write_text("template")
    (tmp_path / ".claude" / "commands").mkdir(parents=True)
    (tmp_path / ".claude" / "commands" / "mode.md").write_text("command")
    (tmp_path / "Categories").mkdir()
    (tmp_path / "Categories" / "AI.md").write_text("category")

    sources = discover_sources(tmp_path)
    assert [(item.source_path, item.kind) for item in sources] == [
        ("Categories/AI.md", "category"),
        ("Note.md", "knowledge"),
    ]

    sources_with_uppercase = discover_sources(
        tmp_path, include_uppercase_markdown=True
    )
    assert [item.source_path for item in sources_with_uppercase] == [
        "Categories/AI.md",
        "Note.md",
        "Upper.MD",
    ]

    inventory = inventory_paths(tmp_path)
    excluded = {item["source_path"]: item["reason"] for item in inventory["excluded"]}
    assert excluded["Templates/Plan.md"] == "template"
    assert excluded[".claude/commands/mode.md"] == "hidden-or-trash"


def test_snapshot_exports_source_bytes_and_path_only_artifacts(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "Note.md").write_bytes(b"approved source\n")
    (vault / "Categories").mkdir()
    (vault / "Categories" / "AI.md").write_bytes(b"category source\n")
    (vault / ".hidden").mkdir()
    (vault / ".hidden" / "secret.txt").write_bytes(b"must not be exported\n")
    (vault / "artifact.log").write_bytes(b"artifact contents\n")

    snapshot = tmp_path / "snapshot"
    report = export_snapshot(vault, snapshot)

    assert report["included_sources"] == 2
    assert report["excluded_path_placeholders"] == 2
    assert (snapshot / "Note.md").read_bytes() == b"approved source\n"
    assert (snapshot / "Categories" / "AI.md").read_bytes() == b"category source\n"
    assert (snapshot / ".hidden" / "secret.txt").read_bytes() == b""
    assert (snapshot / "artifact.log").read_bytes() == b""
    assert (vault / ".hidden" / "secret.txt").read_bytes() == b"must not be exported\n"

    with pytest.raises(ValueError, match="already exists"):
        export_snapshot(vault, snapshot)


def test_snapshot_rejects_destination_inside_vault(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    vault.mkdir()

    with pytest.raises(ValueError, match="outside"):
        export_snapshot(vault, vault / "snapshot")
