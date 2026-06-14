import json
from pathlib import Path

import pytest

import homeops_ai.build as build_module
from homeops_ai.build import (
    BuildError,
    VerificationError,
    active_state,
    rebuild,
    rollback,
    validation_report,
    verify_run,
)


def _write_vault(vault: Path, body: str = "Links to [[Missing]].\n") -> None:
    (vault / "Categories").mkdir(parents=True)
    (vault / "Categories" / "AI.md").write_text(
        """---
id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
type: category
status: current
---
"""
    )
    (vault / "AI Context.md").write_text(
        f"""---
id: "11111111-1111-4111-8111-111111111111"
categories:
  - "[[AI]]"
type: current-state
status: current
authority: canonical
---
{body}"""
    )


def test_validation_preserves_unresolved_links_as_warnings(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    vault.mkdir()
    _write_vault(vault)

    report = validation_report(vault)

    assert not report["validation"]["errors"]
    assert report["validation"]["link_resolution_counts"]["unresolved"] == 1
    assert report["validation"]["unresolved_targets"] == [
        {"target": "Missing", "occurrences": 1}
    ]


def test_rebuild_verify_unchanged_and_rollback(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    data = tmp_path / "data"
    vault.mkdir()
    _write_vault(vault)

    first = rebuild(vault, data)
    assert first["result"] == "verified"
    assert verify_run(data)["valid"]
    assert rebuild(vault, data)["result"] == "unchanged"

    (vault / "AI Context.md").write_text(
        (vault / "AI Context.md").read_text() + "\nChanged.\n"
    )
    second = rebuild(vault, data)
    assert second["run_id"] != first["run_id"]
    assert active_state(data)["previous"] == first["run_id"]

    rolled_back = rollback(data)
    assert rolled_back["current"] == first["run_id"]
    assert rolled_back["previous"] == second["run_id"]

    manifest = json.loads(
        (data / "builds" / first["run_id"] / "manifest.json").read_text()
    )
    assert manifest["result"] == "verified"


def test_rebuild_rejects_unresolved_category(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    vault.mkdir()
    _write_vault(vault)
    note = vault / "AI Context.md"
    note.write_text(note.read_text().replace("[[AI]]", "[[Missing Category]]"))

    with pytest.raises(BuildError, match="vault validation failed"):
        rebuild(vault, tmp_path / "data")


def test_failed_candidate_retains_validation_and_does_not_promote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = tmp_path / "vault"
    data = tmp_path / "data"
    vault.mkdir()
    _write_vault(vault)
    first = rebuild(vault, data)
    (vault / "AI Context.md").write_text(
        (vault / "AI Context.md").read_text() + "\nChanged.\n"
    )

    report = {"valid": False, "errors": ["intentional verifier failure"]}

    def fail_verification(build_dir: Path) -> dict:
        raise VerificationError(report)

    monkeypatch.setattr(build_module, "_invoke_verifier", fail_verification)
    with pytest.raises(VerificationError):
        rebuild(vault, data)

    assert active_state(data)["current"] == first["run_id"]
    failed = [item for item in build_module.list_builds(data) if item["result"] == "failed"]
    assert len(failed) == 1
    validation_path = data / "builds" / failed[0]["run_id"] / "validation.json"
    assert json.loads(validation_path.read_text()) == report
