from pathlib import Path

from homeops_ai.build import active_state
import homeops_ai.pipeline as pipeline
from homeops_ai.pipeline import reconcile_local, verify_active


REVISION = "a" * 40
IMAGE_DIGEST = "sha256:" + ("b" * 64)


def _write_vault(vault: Path) -> None:
    (vault / "Categories").mkdir(parents=True)
    (vault / "Categories" / "AI.md").write_text(
        """---
id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
type: category
status: current
authority: canonical
---
""",
        encoding="utf-8",
    )
    (vault / "Knowledge.md").write_text(
        """---
id: "11111111-1111-4111-8111-111111111111"
categories: ["[[AI]]"]
type: reference
status: current
authority: supporting
---
## Observation

Initial knowledge.
""",
        encoding="utf-8",
    )


def _reconcile(vault: Path, root: Path, state: Path) -> dict[str, object]:
    return reconcile_local(
        vault,
        root,
        state,
        source_revision=REVISION,
        image_digest=IMAGE_DIGEST,
        quiescence_seconds=0,
    )


def test_local_pipeline_promotes_verifies_and_retains_previous(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    root = tmp_path / "homeops"
    state = tmp_path / "state"
    vault.mkdir()
    root.mkdir()
    _write_vault(vault)

    first = _reconcile(vault, root, state)
    assert first["outcome"] == "PROMOTED"
    assert first["promotion"] == "promoted"
    assert first["verification"] == "VERIFIED"
    selected = active_state(root / "data")
    assert selected["schema_version"] == 2
    assert selected["current_deployment"]["deployment_id"] == first["deployment_id"]
    assert selected["previous_deployment"] is None
    assert verify_active(root)["outcome"] == "VERIFIED"

    unchanged = _reconcile(vault, root, state)
    assert unchanged["outcome"] == "UNCHANGED"
    assert unchanged["deployment_id"] == first["deployment_id"]

    knowledge = vault / "Knowledge.md"
    knowledge.write_text(
        knowledge.read_text(encoding="utf-8") + "\nSecond observation.\n",
        encoding="utf-8",
    )
    second = _reconcile(vault, root, state)
    assert second["outcome"] == "PROMOTED"
    assert second["deployment_id"] != first["deployment_id"]
    selected = active_state(root / "data")
    assert selected["current_deployment"]["deployment_id"] == second["deployment_id"]
    assert selected["previous_deployment"]["deployment_id"] == first["deployment_id"]
    assert (state / "last-result.json").is_file()


def test_local_pipeline_does_not_promote_a_moving_source(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    root = tmp_path / "homeops"
    state = tmp_path / "state"
    vault.mkdir()
    root.mkdir()
    _write_vault(vault)

    def mutate(_: float) -> None:
        knowledge = vault / "Knowledge.md"
        knowledge.write_text(
            knowledge.read_text(encoding="utf-8") + "\nMoved during quiet check.\n",
            encoding="utf-8",
        )

    result = reconcile_local(
        vault,
        root,
        state,
        source_revision=REVISION,
        image_digest=IMAGE_DIGEST,
        quiescence_seconds=1,
        sleep=mutate,
    )
    assert result["outcome"] == "LOCAL_SOURCE_CHANGED"
    assert result["retryable"] is True
    assert active_state(root / "data")["current_deployment"] is None


def test_local_pipeline_rejects_change_after_quiescence(
    tmp_path: Path, monkeypatch
) -> None:
    vault = tmp_path / "vault"
    root = tmp_path / "homeops"
    state = tmp_path / "state"
    vault.mkdir()
    root.mkdir()
    _write_vault(vault)
    real_export = pipeline.export_candidate

    def export_after_change(*args, **kwargs):
        knowledge = vault / "Knowledge.md"
        knowledge.write_text(
            knowledge.read_text(encoding="utf-8")
            + "\nMoved immediately after the quiet interval.\n",
            encoding="utf-8",
        )
        return real_export(*args, **kwargs)

    monkeypatch.setattr(pipeline, "export_candidate", export_after_change)
    result = _reconcile(vault, root, state)

    assert result["outcome"] == "LOCAL_SOURCE_CHANGED"
    assert result["retryable"] is True
    assert active_state(root / "data")["current_deployment"] is None


def test_local_pipeline_rejects_invalid_vault(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    root = tmp_path / "homeops"
    state = tmp_path / "state"
    vault.mkdir()
    root.mkdir()
    (vault / "Broken.md").write_text("no immutable document id\n", encoding="utf-8")

    result = _reconcile(vault, root, state)
    assert result["outcome"] == "LOCAL_VAULT_INVALID"
    assert result["retryable"] is False
    assert active_state(root / "data")["current_deployment"] is None


def test_local_pipeline_records_invalid_evaluation_suite(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    root = tmp_path / "homeops"
    state = tmp_path / "state"
    suite = tmp_path / "invalid-suite.yaml"
    vault.mkdir()
    root.mkdir()
    _write_vault(vault)
    suite.write_text("schema_version: 1\n", encoding="utf-8")

    result = reconcile_local(
        vault,
        root,
        state,
        source_revision=REVISION,
        image_digest=IMAGE_DIGEST,
        evaluation_cases=[suite],
        quiescence_seconds=0,
    )

    assert result["outcome"] == "EVALUATION_FAILED"
    assert result["retryable"] is False
    assert active_state(root / "data")["current_deployment"] is None
    assert (state / "last-result.json").is_file()

    retry = _reconcile(vault, root, state)
    assert retry["outcome"] == "PROMOTED"
    assert verify_active(root)["outcome"] == "VERIFIED"
