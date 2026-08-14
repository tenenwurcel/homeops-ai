from contextlib import contextmanager
from datetime import UTC, datetime
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
from typing import Any

import pytest

from homeops_ai import cli as cli_module
from homeops_ai import context_compiler as context_module
from homeops_ai import mcp_server as mcp_module
from homeops_ai import pipeline as pipeline_module
from homeops_ai import query as query_module
from homeops_ai import retention as retention_module
from homeops_ai.cli import build_parser, main
from homeops_ai.context_compiler import compile_context
from homeops_ai.deployment import (
    deployment_lock,
    deployment_identity,
    durable_create_json,
    empty_state,
    publish_current_projection,
    retention_lock,
    run_is_pinned,
    run_pin,
    select_deployment,
    sha256_json,
    store_deployment,
)
from homeops_ai.build import BUILD_CONTRACT_VERSION, inspect_vault
from homeops_ai.deployment import create_deployment_record
from homeops_ai.retention import (
    RetentionError,
    RetentionPolicy,
    plan_deployment_retention,
)
from homeops_ai.mcp_server import get_build_status
from homeops_ai.pipeline import PipelineError, process_remote
from homeops_ai.query import execute_query
from homeops_ai.snapshot import (
    create_snapshot_manifest,
    write_manifest,
)


AS_OF = datetime(2026, 8, 14, 12, 0, tzinfo=UTC)
_SNAPSHOT_FILES: dict[str, dict[str, bytes]] = {}


def _fingerprint(seed: str) -> str:
    return sha256_json({"seed": seed})


def _snapshot(seed: str) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as temporary:
        vault = Path(temporary)
        (vault / "Categories").mkdir()
        (vault / "Categories" / "AI.md").write_text(
            """---
id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
type: category
status: current
---
""",
            encoding="utf-8",
        )
        (vault / "AI Context.md").write_text(
            f"""---
id: "11111111-1111-4111-8111-111111111111"
categories: ["[[AI]]"]
type: current-state
status: current
authority: canonical
---
Synthetic {seed} evidence.
""",
            encoding="utf-8",
        )
        manifest = create_snapshot_manifest(
            vault,
            inspect_vault(vault),
            created_at="2026-08-13T12:00:00+00:00",
            package_version="0.4.1",
            source_revision="a" * 40,
        )
        _SNAPSHOT_FILES[manifest["snapshot_id"]] = {
            item["path"]: (vault / item["path"]).read_bytes()
            for item in manifest["inventory"]
        }
        return manifest


def _create_deployment(
    root: Path,
    index: int,
    *,
    shared_snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    data = root / "data"
    run_id = f"run-{index}"
    snapshot = shared_snapshot or _snapshot(f"deployment-{index}")
    snapshot_dir = root / "vault-snapshots" / snapshot["snapshot_id"]
    if not snapshot_dir.exists():
        (snapshot_dir / "vault").mkdir(parents=True)
        for relative, content in _SNAPSHOT_FILES[snapshot["snapshot_id"]].items():
            target = snapshot_dir / "vault" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        write_manifest(snapshot_dir / "snapshot.json", snapshot)
    build = {
        "schema_version": 1,
        "build_contract_version": BUILD_CONTRACT_VERSION,
        "run_id": run_id,
        "profile": "test",
        "counts": {},
        "started_at": f"2026-08-13T12:{index:02d}:00+00:00",
        "completed_at": f"2026-08-13T12:{index:02d}:00+00:00",
        "verified_at": f"2026-08-13T12:{index:02d}:30+00:00",
        "result": "verified",
        "source_fingerprint": snapshot["source_fingerprint"],
        "artifact_fingerprint": snapshot["artifact_fingerprint"],
        "logical_fingerprint": snapshot["logical_fingerprint"],
    }
    deployment = create_deployment_record(
        snapshot=snapshot,
        build=build,
        snapshot_received_at="2026-08-13T12:00:30+00:00",
        homeops_version="0.4.1",
        source_revision="a" * 40,
        image_digest="sha256:" + "b" * 64,
    )
    build_dir = data / "builds" / run_id
    (build_dir / "cozo.db").mkdir(parents=True)
    (build_dir / "manifest.json").write_text(
        json.dumps(
            {
                **build,
                "homeops_version": deployment["homeops_version"],
                "source_revision": deployment["source_revision"],
                "image_digest": deployment["image_digest"],
            }
        ),
        encoding="utf-8",
    )
    store_deployment(data, deployment)
    return deployment


def _pipeline_root(tmp_path: Path, count: int) -> tuple[Path, list[dict[str, Any]]]:
    root = tmp_path / "pipeline"
    (root / "data" / "deployments").mkdir(parents=True)
    records = [_create_deployment(root, index) for index in range(1, count + 1)]
    state = empty_state()
    for index, record in enumerate(records, start=1):
        current = state.get("current_deployment")
        state, _ = select_deployment(
            state,
            record,
            expected_current_deployment_id=(
                current["deployment_id"] if current is not None else None
            ),
            promoted_at=f"2026-08-13T13:{index:02d}:00+00:00",
        )
        promoted = state["current_deployment"]
        durable_create_json(
            root
            / "data"
            / "deployment-history"
            / record["deployment_id"]
            / f"event-{index}.json",
            promoted,
        )
    (root / "data" / "active.json").write_text(json.dumps(state), encoding="utf-8")
    publish_current_projection(root, state)
    with deployment_lock(root / "data"):
        pass
    with retention_lock(root / "data"):
        pass
    return root, records


def _queue_request(
    root: Path, deployment: dict[str, Any], request_id: str
) -> dict[str, Any]:
    request = {
        "schema_version": 1,
        "protocol": "homeops.receiver/v1",
        "request_id": request_id,
        "publisher_id": "workstation",
        "release_policy_id": "c" * 64,
        "snapshot_id": deployment["snapshot_id"],
        "expected_current_deployment_id": "",
        "snapshot_manifest_sha256": "d" * 64,
    }
    path = root / "incoming" / "workstation" / request_id / "payload" / "request.json"
    path.parent.mkdir(parents=True)
    _write_canonical_json(path, request)
    return request


def _write_canonical_json(path: Path, value: dict[str, Any]) -> None:
    path.write_bytes(
        json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def _write_failed_manifest(path: Path, *, failed_at: str) -> None:
    path.mkdir(parents=True)
    manifest = {
        "schema_version": 1,
        "build_contract_version": BUILD_CONTRACT_VERSION,
        "run_id": path.name,
        "profile": "knowledge",
        "vault_root": str((path.parent.parent.parent / "source-vault").resolve()),
        "database_path": str((path / "cozo.db").resolve()),
        "source_fingerprint": "a" * 64,
        "artifact_fingerprint": "b" * 64,
        "logical_fingerprint": "c" * 64,
        "counts": {},
        "inventory": {"included": [], "excluded": []},
        "unresolved_targets": [],
        "started_at": failed_at,
        "completed_at": None,
        "result": "failed",
        "ingestion_result": "candidate",
        "homeops_version": "0.4.1",
        "source_revision": "d" * 40,
        "image_digest": "sha256:" + "e" * 64,
        "failed_at": failed_at,
        "failure": "synthetic failure",
    }
    (path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def _decision(plan: dict[str, Any], deployment_id: str) -> dict[str, Any]:
    return next(
        item for item in plan["deployments"] if item["deployment_id"] == deployment_id
    )


def _hold_run_pin(
    data_dir: str,
    run_id: str,
    ready: Any,
    release: Any,
) -> None:
    with run_pin(Path(data_dir), run_id):
        ready.set()
        release.wait(10)


def test_plan_retains_current_previous_and_three_additional_deterministically(
    tmp_path: Path,
) -> None:
    root, records = _pipeline_root(tmp_path, 6)

    first = plan_deployment_retention(root, as_of=AS_OF)
    second = plan_deployment_retention(root, as_of=AS_OF)

    assert first == second
    assert first["mode"] == "dry-run"
    assert first["deletion_enabled"] is False
    assert first["summary"] == {
        "deployment_count": 6,
        "retained_count": 5,
        "removable_count": 1,
        "delete_target_count": 4,
        "unresolved_count": 0,
        "blocked": False,
    }
    assert _decision(first, records[-1]["deployment_id"])["reasons"] == ["current"]
    assert _decision(first, records[-2]["deployment_id"])["reasons"] == ["previous"]
    for record in records[1:4]:
        assert _decision(first, record["deployment_id"])["reasons"] == [
            "additional-verified"
        ]
    assert _decision(first, records[0]["deployment_id"])["decision"] == "remove"
    targets = first["delete_targets"]
    assert {item["kind"] for item in targets} == {
        "deployment-record",
        "deployment-history",
        "build",
        "snapshot",
    }
    assert all(Path(item["resolved_path"]).is_relative_to(root) for item in targets)
    assert first["plan_id"] == second["plan_id"]


def test_shared_snapshot_is_not_targeted_while_a_retained_deployment_uses_it(
    tmp_path: Path,
) -> None:
    root = tmp_path / "pipeline"
    (root / "data" / "deployments").mkdir(parents=True)
    shared = _snapshot("shared")
    oldest = _create_deployment(root, 1, shared_snapshot=shared)
    previous = _create_deployment(root, 2)
    current = _create_deployment(root, 3, shared_snapshot=shared)
    state = empty_state()
    for index, record in enumerate((oldest, previous, current), start=1):
        selected = state.get("current_deployment")
        state, _ = select_deployment(
            state,
            record,
            expected_current_deployment_id=(
                selected["deployment_id"] if selected else None
            ),
            promoted_at=f"2026-08-13T13:0{index}:00+00:00",
        )
        durable_create_json(
            root
            / "data"
            / "deployment-history"
            / record["deployment_id"]
            / f"event-{index}.json",
            state["current_deployment"],
        )
    (root / "data" / "active.json").write_text(json.dumps(state), encoding="utf-8")
    publish_current_projection(root, state)
    with deployment_lock(root / "data"):
        pass
    with retention_lock(root / "data"):
        pass

    plan = plan_deployment_retention(
        root, policy=RetentionPolicy(keep_additional_verified=0), as_of=AS_OF
    )

    assert _decision(plan, oldest["deployment_id"])["decision"] == "remove"
    assert not any(item["kind"] == "snapshot" for item in plan["delete_targets"])


def test_live_run_pin_excludes_an_otherwise_removable_deployment(
    tmp_path: Path,
) -> None:
    root, records = _pipeline_root(tmp_path, 3)
    oldest = records[0]
    context = multiprocessing.get_context("fork")
    ready = context.Event()
    release = context.Event()
    process = context.Process(
        target=_hold_run_pin,
        args=(str(root / "data"), oldest["run_id"], ready, release),
    )
    process.start()
    try:
        assert ready.wait(5)
        pinned = plan_deployment_retention(
            root, policy=RetentionPolicy(keep_additional_verified=0), as_of=AS_OF
        )
        assert "live-pinned" in _decision(pinned, oldest["deployment_id"])["reasons"]
        assert not any(
            oldest["run_id"] in item["path"] for item in pinned["delete_targets"]
        )
    finally:
        release.set()
        process.join(5)
        if process.is_alive():
            process.kill()
            process.join()
    assert process.exitcode == 0

    unpinned = plan_deployment_retention(
        root, policy=RetentionPolicy(keep_additional_verified=0), as_of=AS_OF
    )
    assert _decision(unpinned, oldest["deployment_id"])["decision"] == "remove"


def test_unresolved_candidate_ready_result_is_retained(tmp_path: Path) -> None:
    root, records = _pipeline_root(tmp_path, 3)
    candidate = records[0]
    request_id = "11111111-1111-4111-8111-111111111111"
    result_path = root / "results" / "workstation" / f"{request_id}.json"
    result_path.parent.mkdir(parents=True)
    result_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "protocol": "homeops.receiver/v1",
                "request_id": request_id,
                "publisher_id": "workstation",
                "outcome": "CANDIDATE_READY",
                "candidate_deployment_id": candidate["deployment_id"],
                "expected_current_deployment_id": "",
                "snapshot_id": candidate["snapshot_id"],
                "run_id": candidate["run_id"],
                "release_policy_id": "c" * 64,
                "promotion_policy_id": "d" * 64,
                "submission_archive_sha256": "e" * 64,
                "retryable": False,
            }
        ),
        encoding="utf-8",
    )

    plan = plan_deployment_retention(
        root, policy=RetentionPolicy(keep_additional_verified=0), as_of=AS_OF
    )

    assert (
        "unresolved-pipeline" in _decision(plan, candidate["deployment_id"])["reasons"]
    )
    assert plan["summary"]["unresolved_count"] == 1
    assert not plan["summary"]["blocked"]
    assert plan["delete_targets"] == []


def test_terminal_failure_candidate_is_retained_as_failure_evidence(
    tmp_path: Path,
) -> None:
    root, _ = _pipeline_root(tmp_path, 2)
    candidate = _create_deployment(root, 3)
    request_id = "11111111-1111-4111-8111-111111111111"
    result_path = root / "results" / "workstation" / f"{request_id}.json"
    result_path.parent.mkdir(parents=True)
    result_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "protocol": "homeops.receiver/v1",
                "request_id": request_id,
                "publisher_id": "workstation",
                "outcome": "EVALUATION_FAILED",
                "retryable": False,
                "diagnostic": "promotion-safe evaluation failed",
            }
        ),
        encoding="utf-8",
    )

    plan = plan_deployment_retention(
        root, policy=RetentionPolicy(keep_additional_verified=0), as_of=AS_OF
    )

    assert _decision(plan, candidate["deployment_id"])["reasons"] == [
        "failure-evidence"
    ]
    assert plan["delete_targets"] == []


@pytest.mark.parametrize(
    ("outcome", "raises"),
    [
        ("CANDIDATE_READY", False),
        ("UNCHANGED", False),
        ("EVALUATION_FAILED", True),
    ],
)
def test_planner_accepts_process_remote_submission_result_contracts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    outcome: str,
    raises: bool,
) -> None:
    root, records = _pipeline_root(tmp_path, 3)
    candidate = records[-1]
    request_id = "11111111-1111-4111-8111-111111111111"
    request = _queue_request(root, candidate, request_id)

    def submission(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        if raises:
            raise PipelineError(outcome, "synthetic pre-candidate failure")
        ready = {
            **pipeline_module._ready_result(
                request, candidate, promotion_policy_id="d" * 64
            ),
            "submission_archive_sha256": "e" * 64,
        }
        return {**ready, "outcome": outcome}

    monkeypatch.setattr(pipeline_module, "_process_submission", submission)
    processed = process_remote(
        root,
        source_revision="a" * 40,
        image_digest="sha256:" + "b" * 64,
    )

    result = json.loads(
        (root / "results" / "workstation" / f"{request_id}.json").read_text(
            encoding="utf-8"
        )
    )
    assert processed["outcomes"] == [outcome]
    assert result["outcome"] == outcome
    plan = plan_deployment_retention(
        root, policy=RetentionPolicy(keep_additional_verified=0), as_of=AS_OF
    )
    assert plan["summary"]["blocked"] is False


@pytest.mark.parametrize("outcome", ["PROMOTED", "PROMOTION_CONFLICT"])
def test_planner_accepts_process_remote_commit_result_contracts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    outcome: str,
) -> None:
    root, records = _pipeline_root(tmp_path, 3)
    candidate = records[-1]
    request_id = "11111111-1111-4111-8111-111111111111"
    request = _queue_request(root, candidate, request_id)
    ready = {
        **pipeline_module._ready_result(
            request, candidate, promotion_policy_id="d" * 64
        ),
        "submission_archive_sha256": "e" * 64,
    }
    monkeypatch.setattr(
        pipeline_module,
        "_process_submission",
        lambda *_args, **_kwargs: ready,
    )
    process_remote(
        root,
        source_revision="a" * 40,
        image_digest="sha256:" + "b" * 64,
    )
    marker = root / "commits" / "workstation" / f"{request_id}.json"
    marker.parent.mkdir(parents=True)
    _write_canonical_json(
        marker,
        {
            "schema_version": 1,
            "protocol": "homeops.receiver/v1",
            "request_id": request_id,
            "publisher_id": "workstation",
            "candidate_deployment_id": candidate["deployment_id"],
            "expected_current_deployment_id": "",
            "submission_archive_sha256": "e" * 64,
        },
    )

    def commit(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        if outcome == "PROMOTION_CONFLICT":
            raise PipelineError(outcome, "synthetic commit failure")
        return {
            **ready,
            "outcome": "PROMOTED",
            "promoted_at": "2026-08-14T11:00:00+00:00",
        }

    monkeypatch.setattr(pipeline_module, "_process_commit", commit)
    processed = process_remote(
        root,
        source_revision="a" * 40,
        image_digest="sha256:" + "b" * 64,
    )

    result = json.loads(
        (root / "results" / "workstation" / f"{request_id}.json").read_text(
            encoding="utf-8"
        )
    )
    assert processed["outcomes"] == [outcome]
    assert result["outcome"] == outcome
    plan = plan_deployment_retention(
        root, policy=RetentionPolicy(keep_additional_verified=0), as_of=AS_OF
    )
    assert plan["summary"]["blocked"] is False


def test_malformed_or_symlinked_inventory_blocks_all_targets(tmp_path: Path) -> None:
    root, records = _pipeline_root(tmp_path, 3)
    bad = root / "data" / "deployments" / ("f" * 64 + ".json")
    bad.symlink_to(
        root / "data" / "deployments" / f"{records[0]['deployment_id']}.json"
    )

    plan = plan_deployment_retention(
        root, policy=RetentionPolicy(keep_additional_verified=0), as_of=AS_OF
    )

    assert plan["summary"]["blocked"] is True
    assert plan["delete_targets"] == []
    assert any(
        item["code"] == "deployment-bundle-invalid" for item in plan["unresolved"]
    )


def test_failed_unassociated_build_is_reported_but_not_a_deployment_target(
    tmp_path: Path,
) -> None:
    root, _ = _pipeline_root(tmp_path, 2)
    run_id = "22222222-2222-4222-8222-222222222222"
    _write_failed_manifest(
        root / "data" / "builds" / run_id,
        failed_at="2026-08-13T12:00:00+00:00",
    )

    plan = plan_deployment_retention(root, as_of=AS_OF)

    assert plan["evidence"] == [
        {
            "kind": "failed-build",
            "decision": "retain-failure-evidence",
            "path": f"data/builds/{run_id}",
            "observed_at": "2026-08-13T12:00:00+00:00",
            "eligible_at": "2026-08-20T12:00:00+00:00",
        }
    ]
    assert plan["summary"]["blocked"] is False


def test_partial_failed_build_manifest_blocks_all_targets(tmp_path: Path) -> None:
    root, _ = _pipeline_root(tmp_path, 3)
    run_id = "55555555-5555-4555-8555-555555555555"
    failed = root / "data" / "builds" / run_id
    failed.mkdir()
    (failed / "manifest.json").write_text(
        json.dumps(
            {
                "run_id": run_id,
                "result": "failed",
                "failed_at": "2026-08-01T00:00:00+00:00",
                "failure": "synthetic failure",
            }
        ),
        encoding="utf-8",
    )

    plan = plan_deployment_retention(
        root, policy=RetentionPolicy(keep_additional_verified=0), as_of=AS_OF
    )

    assert plan["summary"]["blocked"] is True
    assert plan["delete_targets"] == []
    assert any(item["code"] == "unassociated-build" for item in plan["unresolved"])


def test_retention_cli_has_only_a_dry_run_plan_surface() -> None:
    parsed = build_parser().parse_args(
        [
            "pipeline",
            "retention-plan",
            "--root",
            "/tmp/pipeline",
            "--keep-additional-verified",
            "4",
            "--output",
            "/tmp/plan.json",
        ]
    )
    assert parsed.pipeline_command == "retention-plan"
    assert parsed.keep_additional_verified == 4
    assert parsed.output == Path("/tmp/plan.json")
    with pytest.raises(SystemExit):
        build_parser().parse_args(["pipeline", "retention-apply"])


def test_retention_policy_rejects_negative_count() -> None:
    with pytest.raises(RetentionError, match="non-negative"):
        RetentionPolicy(keep_additional_verified=-1)


def test_missing_deployment_lock_fails_closed_without_creating_it(
    tmp_path: Path,
) -> None:
    root, _ = _pipeline_root(tmp_path, 2)
    lock = root / "data" / "deployment.lock"
    lock.unlink()

    with pytest.raises(RetentionError, match="cannot open deployment lock"):
        plan_deployment_retention(root, as_of=AS_OF)

    assert not lock.exists()


def test_missing_retention_lock_fails_closed_without_creating_it(
    tmp_path: Path,
) -> None:
    root, _ = _pipeline_root(tmp_path, 2)
    lock = root / "data" / "retention.lock"
    lock.unlink()

    with pytest.raises(RetentionError, match="retention.lock"):
        plan_deployment_retention(root, as_of=AS_OF)

    assert not lock.exists()


@pytest.mark.parametrize("lock_name", ["deployment.lock", "retention.lock"])
def test_symlinked_lock_file_is_rejected(tmp_path: Path, lock_name: str) -> None:
    root, _ = _pipeline_root(tmp_path, 2)
    lock = root / "data" / lock_name
    real = lock.with_name(lock.name + ".real")
    lock.rename(real)
    lock.symlink_to(real)

    with pytest.raises(RetentionError, match="lock"):
        plan_deployment_retention(root, as_of=AS_OF)

    assert not (root / "data" / "run-pins").exists()


@pytest.mark.parametrize("lock_name", ["deployment.lock", "retention.lock"])
def test_fifo_lock_file_is_rejected_without_blocking(
    tmp_path: Path, lock_name: str
) -> None:
    root, _ = _pipeline_root(tmp_path, 2)
    lock = root / "data" / lock_name
    lock.unlink()
    os.mkfifo(lock)

    with pytest.raises(RetentionError, match="lock"):
        plan_deployment_retention(root, as_of=AS_OF)

    assert not (root / "data" / "run-pins").exists()


@pytest.mark.parametrize("kind", ["file", "fifo"])
def test_invalid_run_pin_namespace_blocks_all_targets(
    tmp_path: Path, kind: str
) -> None:
    root, _ = _pipeline_root(tmp_path, 3)
    pins = root / "data" / "run-pins"
    if kind == "file":
        pins.write_text("not a directory", encoding="utf-8")
    else:
        os.mkfifo(pins)

    plan = plan_deployment_retention(
        root, policy=RetentionPolicy(keep_additional_verified=0), as_of=AS_OF
    )

    assert plan["summary"]["blocked"] is True
    assert plan["delete_targets"] == []
    assert any(item["code"] == "run-pin-invalid" for item in plan["unresolved"])


@pytest.mark.parametrize(
    "relative",
    ["data/active.json", "data/builds", "vault-snapshots", "pipeline-state"],
)
def test_critical_symlinked_file_or_parent_blocks_all_targets(
    tmp_path: Path, relative: str
) -> None:
    root, _ = _pipeline_root(tmp_path, 3)
    path = root / relative
    real = path.with_name(path.name + "-real")
    path.rename(real)
    path.symlink_to(real, target_is_directory=real.is_dir())

    plan = plan_deployment_retention(
        root, policy=RetentionPolicy(keep_additional_verified=0), as_of=AS_OF
    )

    assert plan["summary"]["blocked"] is True
    assert plan["delete_targets"] == []


def test_malformed_candidate_ready_result_blocks_all_targets(tmp_path: Path) -> None:
    root, records = _pipeline_root(tmp_path, 3)
    request_id = "11111111-1111-4111-8111-111111111111"
    path = root / "results" / "workstation" / f"{request_id}.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "protocol": "homeops.receiver/v1",
                "request_id": request_id,
                "publisher_id": "workstation",
                "outcome": "CANDIDATE_READY",
                "candidate_deployment_id": records[0]["deployment_id"],
                "retryable": False,
            }
        ),
        encoding="utf-8",
    )

    plan = plan_deployment_retention(
        root, policy=RetentionPolicy(keep_additional_verified=0), as_of=AS_OF
    )

    assert plan["summary"]["blocked"] is True
    assert plan["delete_targets"] == []
    assert any(
        item["code"] == "results-inventory-invalid" for item in plan["unresolved"]
    )


@pytest.mark.parametrize("malformation", ["null-expected", "promoted-without-time"])
def test_result_schema_rejects_exactness_gaps(
    tmp_path: Path, malformation: str
) -> None:
    root, records = _pipeline_root(tmp_path, 3)
    candidate = records[-1]
    request_id = "11111111-1111-4111-8111-111111111111"
    result: dict[str, Any] = {
        "schema_version": 1,
        "protocol": "homeops.receiver/v1",
        "request_id": request_id,
        "publisher_id": "workstation",
        "outcome": "CANDIDATE_READY",
        "candidate_deployment_id": candidate["deployment_id"],
        "expected_current_deployment_id": "",
        "snapshot_id": candidate["snapshot_id"],
        "run_id": candidate["run_id"],
        "release_policy_id": "c" * 64,
        "promotion_policy_id": "d" * 64,
        "submission_archive_sha256": "e" * 64,
        "retryable": False,
    }
    if malformation == "null-expected":
        result["expected_current_deployment_id"] = None
    else:
        result["outcome"] = "PROMOTED"
    path = root / "results" / "workstation" / f"{request_id}.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(result), encoding="utf-8")

    plan = plan_deployment_retention(root, as_of=AS_OF)

    assert plan["summary"]["blocked"] is True
    assert plan["delete_targets"] == []
    assert any(
        item["code"] == "results-inventory-invalid" for item in plan["unresolved"]
    )


def test_queued_request_requires_lowercase_uuid4_path_and_identity(
    tmp_path: Path,
) -> None:
    root, records = _pipeline_root(tmp_path, 3)
    _queue_request(root, records[-1], "not-a-uuid")

    plan = plan_deployment_retention(root, as_of=AS_OF)

    assert plan["summary"]["blocked"] is True
    assert plan["delete_targets"] == []
    assert any(
        item["code"] == "incoming-inventory-invalid" for item in plan["unresolved"]
    )


def test_missing_referenced_candidate_blocks_and_protects_stale_failed_run(
    tmp_path: Path,
) -> None:
    root, records = _pipeline_root(tmp_path, 3)
    request_id = "11111111-1111-4111-8111-111111111111"
    failed_run_id = "33333333-3333-4333-8333-333333333333"
    _write_failed_manifest(
        root / "data" / "builds" / failed_run_id,
        failed_at="2026-08-01T00:00:00+00:00",
    )
    result = {
        "schema_version": 1,
        "protocol": "homeops.receiver/v1",
        "request_id": request_id,
        "publisher_id": "workstation",
        "outcome": "CANDIDATE_READY",
        "candidate_deployment_id": "f" * 64,
        "expected_current_deployment_id": "",
        "snapshot_id": records[0]["snapshot_id"],
        "run_id": failed_run_id,
        "release_policy_id": "c" * 64,
        "promotion_policy_id": "d" * 64,
        "submission_archive_sha256": "e" * 64,
        "retryable": False,
    }
    path = root / "results" / "workstation" / f"{request_id}.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(result), encoding="utf-8")

    plan = plan_deployment_retention(
        root, policy=RetentionPolicy(keep_additional_verified=0), as_of=AS_OF
    )

    assert plan["summary"]["blocked"] is True
    assert plan["delete_targets"] == []
    assert any(
        item["code"] == "referenced-deployment-missing" for item in plan["unresolved"]
    )
    assert (
        next(
            item
            for item in plan["evidence"]
            if item["path"] == f"data/builds/{failed_run_id}"
        )["decision"]
        == "retain-pipeline-reference"
    )


@pytest.mark.parametrize("namespace", ["commit", "journal"])
def test_malformed_commit_or_journal_blocks_all_targets(
    tmp_path: Path, namespace: str
) -> None:
    root, records = _pipeline_root(tmp_path, 3)
    request_id = "11111111-1111-4111-8111-111111111111"
    if namespace == "commit":
        path = root / "commits" / "workstation" / f"{request_id}.json"
        value = {
            "schema_version": 1,
            "protocol": "homeops.receiver/v1",
            "request_id": request_id,
            "publisher_id": "workstation",
            "candidate_deployment_id": records[0]["deployment_id"],
            "expected_current_deployment_id": None,
            "submission_archive_sha256": "e" * 64,
        }
    else:
        path = (
            root
            / "pipeline-state"
            / "commit-journal"
            / "workstation"
            / f"{request_id}.json"
        )
        value = {
            "schema_version": 1,
            "protocol": "homeops.receiver/v1",
            "state": "APPLYING",
            "request_id": request_id,
            "publisher_id": "workstation",
            "candidate_deployment_id": records[0]["deployment_id"],
            "expected_current_deployment_id": None,
            "release_policy_id": "c" * 64,
            "started_at": "2026-08-14T11:00:00+00:00",
        }
    path.parent.mkdir(parents=True)
    if namespace == "commit":
        _write_canonical_json(path, value)
    else:
        path.write_text(json.dumps(value), encoding="utf-8")

    plan = plan_deployment_retention(
        root, policy=RetentionPolicy(keep_additional_verified=0), as_of=AS_OF
    )

    assert plan["summary"]["blocked"] is True
    assert plan["delete_targets"] == []
    assert any(
        item["code"]
        == f"{namespace if namespace == 'commit' else 'commit-journal'}-inventory-invalid"
        for item in plan["unresolved"]
    )


def test_duplicate_run_ownership_blocks_shared_build_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, records = _pipeline_root(tmp_path, 3)
    original = records[0]
    duplicate = {**original, "deployment_id": "pending", "snapshot_id": "f" * 64}
    duplicate["deployment_id"] = sha256_json(deployment_identity(duplicate))
    store_deployment(root / "data", duplicate)
    validate_snapshot = retention_module._validate_snapshot

    def accept_synthetic_snapshot(pipeline_root: Path, record: dict[str, Any]) -> Path:
        if record["snapshot_id"] == "f" * 64:
            return pipeline_root / "vault-snapshots" / original["snapshot_id"]
        return validate_snapshot(pipeline_root, record)

    monkeypatch.setattr(
        retention_module, "_validate_snapshot", accept_synthetic_snapshot
    )

    plan = plan_deployment_retention(
        root, policy=RetentionPolicy(keep_additional_verified=0), as_of=AS_OF
    )

    assert plan["summary"]["blocked"] is True
    assert plan["delete_targets"] == []
    assert any(
        item["code"] == "duplicate-build-ownership" for item in plan["unresolved"]
    )


def test_age_policy_targets_only_stale_failed_build_and_incomplete_upload(
    tmp_path: Path,
) -> None:
    root, _ = _pipeline_root(tmp_path, 2)
    failed_run_id = "44444444-4444-4444-8444-444444444444"
    _write_failed_manifest(
        root / "data" / "builds" / failed_run_id,
        failed_at="2026-08-01T00:00:00+00:00",
    )
    stale_upload = root / "incoming" / (".upload-workstation-" + "a" * 32)
    fresh_upload = root / "incoming" / (".upload-workstation-" + "b" * 32)
    stale_upload.mkdir(parents=True)
    fresh_upload.mkdir()
    stale_time = datetime(2026, 8, 12, 0, 0, tzinfo=UTC).timestamp()
    fresh_time = datetime(2026, 8, 14, 6, 0, tzinfo=UTC).timestamp()
    os.utime(stale_upload, (stale_time, stale_time))
    os.utime(fresh_upload, (fresh_time, fresh_time))

    plan = plan_deployment_retention(root, as_of=AS_OF)

    assert {(item["kind"], item["path"]) for item in plan["delete_targets"]} == {
        ("failed-build", f"data/builds/{failed_run_id}"),
        ("incomplete-upload", stale_upload.relative_to(root).as_posix()),
    }
    assert (
        next(item for item in plan["evidence"] if item["path"].endswith("b" * 32))[
            "decision"
        ]
        == "retain-incomplete"
    )
    assert plan["policy"]["failed_build_retention_seconds"] == 7 * 24 * 60 * 60
    assert plan["policy"]["incomplete_upload_retention_seconds"] == 24 * 60 * 60


def test_nonempty_quarantine_blocks_every_age_and_deployment_target(
    tmp_path: Path,
) -> None:
    root, _ = _pipeline_root(tmp_path, 3)
    quarantine = root / "quarantine"
    quarantine.mkdir()
    (quarantine / "unknown.json").write_text("{}", encoding="utf-8")

    plan = plan_deployment_retention(
        root, policy=RetentionPolicy(keep_additional_verified=0), as_of=AS_OF
    )

    assert plan["policy"]["quarantine_cleanup_supported"] is False
    assert plan["summary"]["blocked"] is True
    assert plan["delete_targets"] == []


def test_planner_reads_fully_read_only_inputs_without_mutating_tree(
    tmp_path: Path,
) -> None:
    root, _ = _pipeline_root(tmp_path, 3)
    paths = [root, *root.rglob("*")]
    for path in paths:
        path.chmod(0o555 if path.is_dir() else 0o444)

    def signature() -> list[tuple[str, int, int, int, str | None]]:
        result = []
        for path in sorted([root, *root.rglob("*")], key=lambda item: str(item)):
            info = path.lstat()
            digest = (
                hashlib.sha256(path.read_bytes()).hexdigest()
                if path.is_file()
                else None
            )
            result.append(
                (
                    path.relative_to(root).as_posix() if path != root else ".",
                    stat.S_IMODE(info.st_mode),
                    info.st_size,
                    info.st_mtime_ns,
                    digest,
                )
            )
        return result

    try:
        before = signature()
        plan = plan_deployment_retention(
            root, policy=RetentionPolicy(keep_additional_verified=0), as_of=AS_OF
        )
        after = signature()
    finally:
        for path in [root, *root.rglob("*")]:
            path.chmod(0o755 if path.is_dir() else 0o644)

    assert plan["summary"]["blocked"] is False
    assert before == after
    assert not (root / "data" / "run-pins").exists()


def test_query_holds_real_run_pin_for_planner_lifetime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, records = _pipeline_root(tmp_path, 3)
    oldest = records[0]
    entered = threading.Event()
    release = threading.Event()
    failures: list[BaseException] = []

    @contextmanager
    def fake_database(_: Path) -> Any:
        yield object()

    def blocking_query(_: Any, __: dict[str, str]) -> dict[str, Any]:
        assert run_is_pinned(root / "data", oldest["run_id"])
        entered.set()
        assert release.wait(5)
        return {"rows": [], "summary": {"row_count": 0}}

    monkeypatch.setattr(query_module, "open_database", fake_database)
    monkeypatch.setitem(query_module.QUERY_HANDLERS, "pin-lifetime", blocking_query)

    def run_query() -> None:
        try:
            execute_query(root / "data", "pin-lifetime", {}, run_id=oldest["run_id"])
        except BaseException as error:
            failures.append(error)

    thread = threading.Thread(target=run_query)
    thread.start()
    try:
        assert entered.wait(2)
        plan = plan_deployment_retention(
            root, policy=RetentionPolicy(keep_additional_verified=0), as_of=AS_OF
        )
        assert "live-pinned" in _decision(plan, oldest["deployment_id"])["reasons"]
    finally:
        release.set()
        thread.join(5)
    assert not thread.is_alive()
    assert failures == []


def test_query_pin_handoff_does_not_wait_for_deployment_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, records = _pipeline_root(tmp_path, 2)
    completed = threading.Event()
    failures: list[BaseException] = []

    @contextmanager
    def fake_database(_: Path) -> Any:
        yield object()

    monkeypatch.setattr(query_module, "open_database", fake_database)
    monkeypatch.setitem(
        query_module.QUERY_HANDLERS,
        "writer-concurrency",
        lambda _client, _params: {"rows": [], "summary": {"row_count": 0}},
    )

    def run_query() -> None:
        try:
            execute_query(
                root / "data",
                "writer-concurrency",
                {},
                run_id=records[-1]["run_id"],
            )
        except BaseException as error:
            failures.append(error)
        finally:
            completed.set()

    with deployment_lock(root / "data"):
        thread = threading.Thread(target=run_query)
        thread.start()
        assert completed.wait(2)
    thread.join(5)
    assert failures == []


def test_mcp_build_status_holds_run_pin_through_active_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, records = _pipeline_root(tmp_path, 3)
    oldest = records[0]
    observed = threading.Event()

    def active_while_pinned(data: Path) -> dict[str, Any]:
        assert run_is_pinned(data, oldest["run_id"])
        observed.set()
        return json.loads((data / "active.json").read_text(encoding="utf-8"))

    monkeypatch.setattr(mcp_module, "active_state", active_while_pinned)

    status = get_build_status(root / "data", run_id=oldest["run_id"])

    assert observed.is_set()
    assert status["run_id"] == oldest["run_id"]


def test_context_compiler_holds_run_pin_through_database_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, records = _pipeline_root(tmp_path, 2)
    selected = records[-1]
    observed = threading.Event()
    retrieval = {
        "rows": [
            {
                "document_id": "doc-1",
                "source_path": "AI Context.md",
                "title": "AI Context",
                "document_type": "current-state",
                "status": "current",
                "authority": "canonical",
                "score": 10,
                "evidence": [
                    {
                        "ordinal": 1,
                        "heading": "Current State",
                        "score": 10,
                        "matched_terms": ["homeops"],
                    }
                ],
            }
        ],
        "summary": {"row_count": 1},
    }

    monkeypatch.setattr(
        context_module,
        "execute_query_for_manifest",
        lambda _manifest, _name, _params: retrieval,
    )

    def bodies_while_pinned(_: dict[str, Any]) -> dict[tuple[str, int], str]:
        assert run_is_pinned(root / "data", selected["run_id"])
        observed.set()
        return {("doc-1", 1): "Current HomeOps evidence."}

    monkeypatch.setattr(context_module, "_section_bodies", bodies_while_pinned)

    bundle = compile_context(
        root / "data", "HomeOps status", risk_level="normal", run_id=selected["run_id"]
    )

    assert observed.is_set()
    assert bundle["build"]["run_id"] == selected["run_id"]


def test_cli_report_is_atomic_private_and_outside_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root, _ = _pipeline_root(tmp_path, 2)
    output = tmp_path / "reports" / "retention-plan.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "homeops-ai",
            "pipeline",
            "retention-plan",
            "--root",
            str(root),
            "--output",
            str(output),
        ],
    )

    main()

    printed = json.loads(capsys.readouterr().out)
    assert json.loads(output.read_text(encoding="utf-8")) == printed
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert list(output.parent.glob(".retention-plan.json.*.tmp")) == []


@pytest.mark.parametrize("alias", [False, True])
def test_cli_refuses_output_within_or_symlinked_into_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, alias: bool
) -> None:
    root, _ = _pipeline_root(tmp_path, 2)
    output = root / "data" / "active.json"
    if alias:
        output = tmp_path / "active-alias.json"
        output.symlink_to(root / "data" / "active.json")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "homeops-ai",
            "pipeline",
            "retention-plan",
            "--root",
            str(root),
            "--output",
            str(output),
        ],
    )

    with pytest.raises(SystemExit, match="retention output"):
        main()


def test_cli_revalidates_output_after_parent_is_swapped_to_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _ = _pipeline_root(tmp_path, 2)
    output_parent = tmp_path / "reports"
    output_parent.mkdir()
    output = output_parent / "retention-plan.json"
    active_before = (root / "data" / "active.json").read_bytes()
    real_plan = cli_module.plan_deployment_retention

    def plan_then_swap(*args: Any, **kwargs: Any) -> dict[str, Any]:
        result = real_plan(*args, **kwargs)
        output_parent.rmdir()
        output_parent.symlink_to(root / "data", target_is_directory=True)
        return result

    monkeypatch.setattr(cli_module, "plan_deployment_retention", plan_then_swap)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "homeops-ai",
            "pipeline",
            "retention-plan",
            "--root",
            str(root),
            "--output",
            str(output),
        ],
    )

    with pytest.raises(SystemExit, match="retention output"):
        main()

    assert (root / "data" / "active.json").read_bytes() == active_before
    assert not (root / "data" / "retention-plan.json").exists()
