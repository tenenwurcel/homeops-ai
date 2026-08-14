import hashlib
import io
import json
import tarfile
from pathlib import Path
from typing import Any

import pytest

from homeops_ai import build as build_module
from homeops_ai.build import (
    BuildError,
    active_state,
    adopt_legacy_state,
    inspect_vault,
    rebuild,
    rollback,
)
from homeops_ai.cli import _pipeline_result_failed, build_parser
from homeops_ai.deployment import (
    DeploymentError,
    PromotionConflict,
    create_deployment_record,
    current_projection,
    empty_state,
    publish_current_projection,
    rollback_transition,
    select_deployment,
    strict_json_loads,
)
from homeops_ai.pipeline import (
    SSHTransport,
    TransportError,
    _commit_journal_path,
    _current_matches,
    _load_pending_attempt,
    _policy_id,
    _release_policy,
    _resume_pending_attempt,
    _write_commit_journal,
    process_remote,
    reconcile,
    verify_active,
)
from homeops_ai.query import execute_query
from homeops_ai.snapshot import (
    RECEIVER_PROTOCOL,
    RECEIVER_SCHEMA_VERSION,
    SnapshotError,
    canonical_receiver_json,
    create_snapshot_manifest,
    file_sha256,
    safe_relative_path,
    submission_archive_bytes,
    validate_request_message,
    verify_snapshot,
    write_manifest,
)
from homeops_ai.source_contract import export_snapshot


def _write_vault(vault: Path, text: str = "Current HomeOps evidence.\n") -> None:
    (vault / "Categories").mkdir(parents=True)
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
{text}""",
        encoding="utf-8",
    )
    (vault / "artifact.bin").write_bytes(b"not exported")


def _snapshot(
    source: Path,
    destination: Path,
    revision: str = "test-revision",
    package_version: str = "0.4.0-test",
) -> dict:
    export_snapshot(source, destination)
    inspected = inspect_vault(destination)
    return create_snapshot_manifest(
        destination,
        inspected,
        created_at="2026-08-13T12:00:00+00:00",
        package_version=package_version,
        source_revision=revision,
    )


def _request(manifest: dict, manifest_path: Path) -> dict:
    return {
        "schema_version": RECEIVER_SCHEMA_VERSION,
        "protocol": RECEIVER_PROTOCOL,
        "request_id": "11111111-1111-4111-8111-111111111111",
        "publisher_id": "workstation",
        "capability_token": "a" * 64,
        "release_policy_id": _policy_id(
            _release_policy("0.4.1", "a" * 40, "sha256:" + "b" * 64)
        ),
        "snapshot_id": manifest["snapshot_id"],
        "expected_current_deployment_id": "",
        "snapshot_manifest_sha256": file_sha256(manifest_path),
    }


def _record(
    seed: str,
    *,
    run_id: str,
    source_revision: str = "abc123",
    image_digest: str = "sha256:" + "b" * 64,
) -> dict:
    fingerprint = hashlib.sha256(seed.encode()).hexdigest()
    snapshot = {
        "schema_version": 1,
        "snapshot_contract_version": "homeops-snapshot-v1",
        "snapshot_id": hashlib.sha256(f"snapshot-{seed}".encode()).hexdigest(),
        "created_at": "2026-08-13T12:00:00+00:00",
        "source_fingerprint": fingerprint,
        "artifact_fingerprint": fingerprint,
        "logical_fingerprint": fingerprint,
    }
    build = {
        "schema_version": 1,
        "build_contract_version": "homeops-build-v1",
        "run_id": run_id,
        "completed_at": "2026-08-13T12:01:00+00:00",
        "verified_at": "2026-08-13T12:02:00+00:00",
        "result": "verified",
        "source_fingerprint": fingerprint,
        "artifact_fingerprint": fingerprint,
        "logical_fingerprint": fingerprint,
    }
    return create_deployment_record(
        snapshot=snapshot,
        build=build,
        snapshot_received_at="2026-08-13T12:00:30+00:00",
        homeops_version="0.4.1",
        source_revision=source_revision,
        image_digest=image_digest,
    )


def test_snapshot_manifest_and_ustar_are_strict_and_deterministic(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    vault.mkdir()
    _write_vault(vault)
    snapshot = tmp_path / "snapshot"
    manifest = _snapshot(vault, snapshot)
    manifest_path = tmp_path / "snapshot.json"
    write_manifest(manifest_path, manifest)
    request = _request(manifest, manifest_path)

    first = submission_archive_bytes(request, manifest, snapshot)
    second = submission_archive_bytes(request, manifest, snapshot)

    assert first == second
    with tarfile.open(fileobj=io.BytesIO(first), mode="r:") as archive:
        members = archive.getmembers()
        assert [item.name for item in members[:2]] == ["request.json", "snapshot.json"]
        assert [item.name for item in members[2:]] == sorted(
            f"vault/{item['path']}" for item in manifest["inventory"]
        )
        assert all(item.isfile() for item in members)
        assert all(item.mode == 0o600 for item in members)
        assert all(item.uid == item.gid == item.mtime == 0 for item in members)
        assert all(item.uname == item.gname == "" for item in members)

    (snapshot / "AI Context.md").write_text("tampered", encoding="utf-8")
    with pytest.raises(SnapshotError, match="does not match manifest"):
        verify_snapshot(snapshot, manifest)


@pytest.mark.parametrize(
    "path",
    ["/absolute", "../escape", "a/../b", "a\\b", "./a", "\u00c1 Evidence.md", "control\nname.md"],
)
def test_snapshot_paths_fail_closed(path: str) -> None:
    with pytest.raises(SnapshotError):
        safe_relative_path(path)


def test_publisher_id_uses_the_protocol_pattern() -> None:
    request = {
        "schema_version": RECEIVER_SCHEMA_VERSION,
        "protocol": RECEIVER_PROTOCOL,
        "request_id": "11111111-1111-4111-8111-111111111111",
        "publisher_id": "edge-node",
        "capability_token": "a" * 64,
        "release_policy_id": "d" * 64,
        "snapshot_id": "b" * 64,
        "expected_current_deployment_id": "",
        "snapshot_manifest_sha256": "c" * 64,
    }
    assert validate_request_message(request)["publisher_id"] == "edge-node"
    for publisher_id in ("Edge-node", "-edge", "edge_node", "e" * 64):
        with pytest.raises(SnapshotError, match="publisher_id"):
            validate_request_message({**request, "publisher_id": publisher_id})

    parsed = build_parser().parse_args(
        [
            "pipeline",
            "reconcile",
            "--vault",
            "vault",
            "--state-dir",
            "state",
            "--target",
            "example.invalid",
            "--identity-file",
            "identity",
            "--known-hosts",
            "known-hosts",
            "--control-socket",
            "control.sock",
            "--publisher-id",
            "edge-node",
        ]
    )
    assert parsed.publisher_id == "edge-node"


def test_deployment_compare_and_swap_rollback_and_projection(tmp_path: Path) -> None:
    first = _record("first", run_id="11111111-1111-4111-8111-111111111111")
    second = _record("second", run_id="22222222-2222-4222-8222-222222222222")

    selected, outcome = select_deployment(
        empty_state(),
        first,
        expected_current_deployment_id=None,
        promoted_at="2026-08-13T12:03:00+00:00",
    )
    assert outcome == "promoted"
    with pytest.raises(PromotionConflict):
        select_deployment(
            selected,
            second,
            expected_current_deployment_id=None,
            promoted_at="2026-08-13T12:04:00+00:00",
        )
    selected_second, _ = select_deployment(
        selected,
        second,
        expected_current_deployment_id=first["deployment_id"],
        promoted_at="2026-08-13T12:04:00+00:00",
    )
    rolled_back = rollback_transition(
        selected_second, promoted_at="2026-08-13T12:05:00+00:00"
    )
    assert rolled_back["current_deployment"]["deployment_id"] == first["deployment_id"]
    assert rolled_back["previous_deployment"]["deployment_id"] == second["deployment_id"]

    projection = publish_current_projection(tmp_path, selected_second)
    assert projection == current_projection(selected_second)
    assert projection["current_deployment_id"] == second["deployment_id"]
    assert tuple(projection) == (
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
    assert (tmp_path / "pipeline-state" / "current.json").stat().st_mode & 0o777 == 0o640


def test_rollback_recovers_history_and_projection_after_active_cas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = tmp_path / "data"
    first = _record("first", run_id="11111111-1111-4111-8111-111111111111")
    second = _record("second", run_id="22222222-2222-4222-8222-222222222222")
    selected_first, _ = select_deployment(
        empty_state(),
        first,
        expected_current_deployment_id=None,
        promoted_at="2026-08-13T12:03:00+00:00",
    )
    selected_second, _ = select_deployment(
        selected_first,
        second,
        expected_current_deployment_id=first["deployment_id"],
        promoted_at="2026-08-13T12:04:00+00:00",
    )
    data.mkdir()
    (data / "active.json").write_text(json.dumps(selected_second), encoding="utf-8")
    monkeypatch.setattr(build_module, "_candidate_matches_build", lambda *args: None)
    original_store = build_module._store_promoted_record
    calls = 0

    def fail_once(data_dir: Path, record: dict[str, Any]) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("injected failure after rollback active-state CAS")
        original_store(data_dir, record)

    monkeypatch.setattr(build_module, "_store_promoted_record", fail_once)

    with pytest.raises(OSError, match="after rollback active-state CAS"):
        rollback(data)

    selected_after_crash = active_state(data)
    assert selected_after_crash["current_deployment"]["deployment_id"] == first[
        "deployment_id"
    ]
    journal = data / "pipeline-transactions" / "rollback.json"
    assert journal.is_file()
    assert not (tmp_path / "pipeline-state" / "current.json").exists()

    recovered_result = process_remote(
        tmp_path,
        source_revision="a" * 40,
        image_digest="sha256:" + "b" * 64,
    )
    assert recovered_result["outcomes"] == []
    recovered = active_state(data)
    assert recovered == selected_after_crash
    assert recovered["current_deployment"]["deployment_id"] == first["deployment_id"]
    assert recovered["previous_deployment"]["deployment_id"] == second["deployment_id"]
    assert not journal.exists()
    history = list(
        (data / "deployment-history" / first["deployment_id"]).glob("*.json")
    )
    assert len(history) == 1
    assert json.loads(history[0].read_text(encoding="utf-8")) == recovered[
        "current_deployment"
    ]
    assert json.loads(
        (tmp_path / "pipeline-state" / "current.json").read_text(encoding="utf-8")
    ) == current_projection(recovered)


def test_process_entry_without_rollback_journal_never_toggles_state(
    tmp_path: Path,
) -> None:
    data = tmp_path / "data"
    first = _record("first", run_id="11111111-1111-4111-8111-111111111111")
    second = _record("second", run_id="22222222-2222-4222-8222-222222222222")
    selected_first, _ = select_deployment(
        empty_state(),
        first,
        expected_current_deployment_id=None,
        promoted_at="2026-08-13T12:03:00+00:00",
    )
    selected_second, _ = select_deployment(
        selected_first,
        second,
        expected_current_deployment_id=first["deployment_id"],
        promoted_at="2026-08-13T12:04:00+00:00",
    )
    data.mkdir()
    (data / "active.json").write_text(json.dumps(selected_second), encoding="utf-8")

    first_run = process_remote(
        tmp_path,
        source_revision="a" * 40,
        image_digest="sha256:" + "b" * 64,
    )
    second_run = process_remote(
        tmp_path,
        source_revision="a" * 40,
        image_digest="sha256:" + "b" * 64,
    )

    assert first_run["outcomes"] == second_run["outcomes"] == []
    assert active_state(data) == selected_second
    assert not (data / "pipeline-transactions" / "rollback.json").exists()


def test_process_entry_finishes_rollback_journal_written_before_active_cas(
    tmp_path: Path,
) -> None:
    data = tmp_path / "data"
    first = _record("first", run_id="11111111-1111-4111-8111-111111111111")
    second = _record("second", run_id="22222222-2222-4222-8222-222222222222")
    selected_first, _ = select_deployment(
        empty_state(),
        first,
        expected_current_deployment_id=None,
        promoted_at="2026-08-13T12:03:00+00:00",
    )
    source, _ = select_deployment(
        selected_first,
        second,
        expected_current_deployment_id=first["deployment_id"],
        promoted_at="2026-08-13T12:04:00+00:00",
    )
    target = rollback_transition(
        source, promoted_at="2026-08-13T12:05:00+00:00"
    )
    data.mkdir()
    (data / "active.json").write_text(json.dumps(source), encoding="utf-8")
    build_module._write_rollback_journal(data, source, target)

    processed = process_remote(
        tmp_path,
        source_revision="a" * 40,
        image_digest="sha256:" + "b" * 64,
    )

    assert processed["outcomes"] == []
    assert active_state(data) == target
    assert not (data / "pipeline-transactions" / "rollback.json").exists()
    assert json.loads(
        (tmp_path / "pipeline-state" / "current.json").read_text(encoding="utf-8")
    ) == current_projection(target)


def test_strict_json_rejects_duplicates_and_legacy_projection_fails_closed() -> None:
    with pytest.raises(DeploymentError, match="duplicate"):
        strict_json_loads('{"schema_version":2,"schema_version":2}')
    with pytest.raises(DeploymentError, match="unadopted legacy"):
        current_projection(
            {"schema_version": 1, "current": "run", "previous": None, "promoted_at": None}
        )


def test_legacy_adoption_requires_actual_matching_snapshot_bytes(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    vault.mkdir()
    _write_vault(vault, "First state.\n")
    data = tmp_path / "data"
    first = rebuild(vault, data)
    first_snapshot = tmp_path / "first-snapshot"
    _snapshot(vault, first_snapshot)

    (vault / "AI Context.md").write_text(
        (vault / "AI Context.md").read_text(encoding="utf-8") + "Second state.\n",
        encoding="utf-8",
    )
    second = rebuild(vault, data)
    second_snapshot = tmp_path / "second-snapshot"
    _snapshot(vault, second_snapshot)

    with pytest.raises(BuildError, match="fingerprint mismatch"):
        adopt_legacy_state(
            data, first_snapshot, previous_vault=first_snapshot
        )
    assert active_state(data)["schema_version"] == 1
    assert not (tmp_path / "pipeline-state" / "current.json").exists()

    adopted = adopt_legacy_state(
        data, second_snapshot, previous_vault=first_snapshot
    )
    assert adopted["schema_version"] == 2
    assert adopted["current"] == second["run_id"]
    assert adopted["previous"] == first["run_id"]
    projection = json.loads(
        (tmp_path / "pipeline-state" / "current.json").read_text(encoding="utf-8")
    )
    assert projection["current_deployment_id"] == adopted["current_deployment"][
        "deployment_id"
    ]
    current_dir = tmp_path / "vault-snapshots" / adopted["current_deployment"][
        "snapshot_id"
    ]
    previous_dir = tmp_path / "vault-snapshots" / adopted["previous_deployment"][
        "snapshot_id"
    ]
    assert (current_dir / "snapshot.json").is_file()
    assert (previous_dir / "snapshot.json").is_file()
    assert verify_active(tmp_path)["run_id"] == second["run_id"]

    (tmp_path / "pipeline-state" / "current.json").unlink()
    readopted = adopt_legacy_state(
        data, second_snapshot, previous_vault=first_snapshot
    )
    assert readopted == adopted
    assert json.loads(
        (tmp_path / "pipeline-state" / "current.json").read_text(encoding="utf-8")
    )["run_id"] == second["run_id"]

    rolled_back = rollback(data)
    assert rolled_back["current"] == first["run_id"]
    assert json.loads(
        (tmp_path / "pipeline-state" / "current.json").read_text(encoding="utf-8")
    )["run_id"] == first["run_id"]
    assert verify_active(tmp_path)["run_id"] == first["run_id"]


def test_remote_processor_builds_evaluates_commits_and_exposes_provenance(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_vault(source)
    exported = tmp_path / "exported"
    revision = "a" * 40
    digest = "sha256:" + "b" * 64
    manifest = _snapshot(source, exported, revision=revision, package_version="0.4.1")
    root = tmp_path / "remote"
    request_id = "11111111-1111-4111-8111-111111111111"
    request_dir = root / "incoming" / "workstation" / request_id
    payload = request_dir / "payload"
    shutil_target = payload / "vault"
    shutil_target.parent.mkdir(parents=True)
    import shutil

    shutil.copytree(exported, shutil_target)
    manifest_path = payload / "snapshot.json"
    write_manifest(manifest_path, manifest)
    wire = _request(manifest, manifest_path)
    queued = {
        key: value for key, value in wire.items() if key != "capability_token"
    }
    queued_fields = tuple(queued)
    (payload / "request.json").write_bytes(
        canonical_receiver_json(queued, queued_fields)
    )
    wire_bytes = canonical_receiver_json(wire, tuple(wire))
    proofs = [
        {
            "path": "request.json",
            "size": len(wire_bytes),
            "sha256": hashlib.sha256(wire_bytes).hexdigest(),
        },
        {
            "path": "snapshot.json",
            "size": manifest_path.stat().st_size,
            "sha256": file_sha256(manifest_path),
        },
    ]
    proofs.extend(
        {
            "path": f"vault/{item['path']}",
            "size": item["size"],
            "sha256": item["sha256"],
        }
        for item in manifest["inventory"]
    )
    receipt = {
        "schema_version": 1,
        "protocol": RECEIVER_PROTOCOL,
        "request_id": request_id,
        "publisher_id": "workstation",
        "capability_sha256": hashlib.sha256(bytes.fromhex("a" * 64)).hexdigest(),
        "release_policy_id": wire["release_policy_id"],
        "snapshot_id": manifest["snapshot_id"],
        "expected_current_deployment_id": "",
        "snapshot_manifest_sha256": file_sha256(manifest_path),
        "archive_sha256": "b" * 64,
        "archive_bytes": 10240,
        "extracted_bytes": sum(item["size"] for item in proofs),
        "file_count": len(proofs),
        "vault_file_count": manifest["file_count"],
        "files": proofs,
    }
    (request_dir / "receipt.json").write_text(
        json.dumps(receipt, separators=(",", ":")) + "\n", encoding="utf-8"
    )

    evaluation = Path(__file__).parents[1] / "evaluation" / "promotion-safe-v1.yaml"
    prepared = process_remote(
        root,
        evaluation_cases=[evaluation],
        source_revision=revision,
        image_digest=digest,
    )
    assert prepared["outcomes"] == ["CANDIDATE_READY"]
    result_path = root / "results" / "workstation" / f"{request_id}.json"
    ready = json.loads(result_path.read_text(encoding="utf-8"))
    assert ready["outcome"] == "CANDIDATE_READY"
    assert "capability_token" not in result_path.read_text(encoding="utf-8")
    assert active_state(root / "data")["current_deployment"] is None

    commit = {
        "schema_version": 1,
        "protocol": RECEIVER_PROTOCOL,
        "request_id": request_id,
        "publisher_id": "workstation",
        "candidate_deployment_id": ready["candidate_deployment_id"],
        "expected_current_deployment_id": "",
        "submission_archive_sha256": receipt["archive_sha256"],
    }
    marker = root / "commits" / "workstation" / f"{request_id}.json"
    marker.parent.mkdir(parents=True)
    marker.write_bytes(canonical_receiver_json(commit, tuple(commit)))

    committed = process_remote(
        root,
        evaluation_cases=[evaluation],
        source_revision=revision,
        image_digest=digest,
    )
    assert committed["outcomes"] == ["PROMOTED"]
    selected = active_state(root / "data")["current_deployment"]
    assert selected["deployment_id"] == ready["candidate_deployment_id"]
    projection = json.loads(
        (root / "pipeline-state" / "current.json").read_text(encoding="utf-8")
    )
    assert projection["current_deployment_id"] == selected["deployment_id"]

    query = execute_query(root / "data", "canonical-current")
    assert query["deployment"]["role"] == "active"
    assert query["deployment"]["snapshot_id"] == manifest["snapshot_id"]


def test_candidate_ready_is_rejected_after_release_policy_change(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_vault(source)
    exported = tmp_path / "exported"
    revision = "a" * 40
    first_digest = "sha256:" + "b" * 64
    second_digest = "sha256:" + "c" * 64
    manifest = _snapshot(source, exported, revision=revision, package_version="0.4.1")
    root = tmp_path / "remote"
    request_id = "11111111-1111-4111-8111-111111111111"
    request_dir = root / "incoming" / "workstation" / request_id
    payload = request_dir / "payload"
    import shutil

    shutil.copytree(exported, payload / "vault")
    manifest_path = payload / "snapshot.json"
    write_manifest(manifest_path, manifest)
    wire = {
        **_request(manifest, manifest_path),
        "release_policy_id": _policy_id(
            _release_policy("0.4.1", revision, first_digest)
        ),
    }
    queued = {key: value for key, value in wire.items() if key != "capability_token"}
    (payload / "request.json").write_bytes(
        canonical_receiver_json(queued, tuple(queued))
    )
    wire_bytes = canonical_receiver_json(wire, tuple(wire))
    proofs = [
        {
            "path": "request.json",
            "size": len(wire_bytes),
            "sha256": hashlib.sha256(wire_bytes).hexdigest(),
        },
        {
            "path": "snapshot.json",
            "size": manifest_path.stat().st_size,
            "sha256": file_sha256(manifest_path),
        },
        *(
            {
                "path": f"vault/{item['path']}",
                "size": item["size"],
                "sha256": item["sha256"],
            }
            for item in manifest["inventory"]
        ),
    ]
    receipt_digest = "e" * 64
    receipt = {
        "schema_version": 1,
        "protocol": RECEIVER_PROTOCOL,
        "request_id": request_id,
        "publisher_id": "workstation",
        "capability_sha256": hashlib.sha256(bytes.fromhex("a" * 64)).hexdigest(),
        "release_policy_id": wire["release_policy_id"],
        "snapshot_id": manifest["snapshot_id"],
        "expected_current_deployment_id": "",
        "snapshot_manifest_sha256": file_sha256(manifest_path),
        "archive_sha256": receipt_digest,
        "archive_bytes": 10240,
        "extracted_bytes": sum(item["size"] for item in proofs),
        "file_count": len(proofs),
        "vault_file_count": manifest["file_count"],
        "files": proofs,
    }
    (request_dir / "receipt.json").write_text(
        json.dumps(receipt, separators=(",", ":")) + "\n", encoding="utf-8"
    )
    evaluation = Path(__file__).parents[1] / "evaluation" / "promotion-safe-v1.yaml"
    prepared = process_remote(
        root,
        evaluation_cases=[evaluation],
        source_revision=revision,
        image_digest=first_digest,
    )
    assert prepared["outcomes"] == ["CANDIDATE_READY"]
    ready_path = root / "results" / "workstation" / f"{request_id}.json"
    ready = json.loads(ready_path.read_text(encoding="utf-8"))
    commit = {
        "schema_version": 1,
        "protocol": RECEIVER_PROTOCOL,
        "request_id": request_id,
        "publisher_id": "workstation",
        "candidate_deployment_id": ready["candidate_deployment_id"],
        "expected_current_deployment_id": "",
        "submission_archive_sha256": receipt_digest,
    }
    marker = root / "commits" / "workstation" / f"{request_id}.json"
    marker.parent.mkdir(parents=True)
    marker.write_bytes(canonical_receiver_json(commit, tuple(commit)))

    changed = process_remote(
        root,
        evaluation_cases=[evaluation],
        source_revision=revision,
        image_digest=second_digest,
    )
    assert changed["outcomes"] == ["PROMOTION_CONFLICT"]
    assert active_state(root / "data")["current_deployment"] is None


def test_current_match_includes_released_image_digest() -> None:
    fingerprint = "a" * 64
    manifest = {
        "snapshot_id": "b" * 64,
        "source_fingerprint": fingerprint,
        "artifact_fingerprint": fingerprint,
        "logical_fingerprint": fingerprint,
    }
    current = {
        "current_deployment_id": "c" * 64,
        "snapshot_id": manifest["snapshot_id"],
        "run_id": "11111111-1111-4111-8111-111111111111",
        "source_fingerprint": fingerprint,
        "artifact_fingerprint": fingerprint,
        "logical_fingerprint": fingerprint,
        "homeops_version": "0.4.1",
        "source_revision": "d" * 40,
        "image_digest": "sha256:" + "e" * 64,
        "snapshot_contract_version": "homeops-snapshot-v1",
        "build_contract_version": "homeops-build-v1",
    }
    assert _current_matches(
        current,
        manifest,
        homeops_version="0.4.1",
        source_revision="d" * 40,
        image_digest="sha256:" + "e" * 64,
    )
    assert not _current_matches(
        current,
        manifest,
        homeops_version="0.4.1",
        source_revision="d" * 40,
        image_digest="sha256:" + "f" * 64,
    )


def test_ssh_transport_and_process_exit_contract_are_fail_closed(
    tmp_path: Path,
) -> None:
    transport = SSHTransport(
        target="example.invalid",
        identity_file=tmp_path / "identity",
        known_hosts=tmp_path / "known-hosts",
        control_socket=tmp_path / "control.sock",
    )
    command = transport._base()
    for option in (
        "GlobalKnownHostsFile=/dev/null",
        "PasswordAuthentication=no",
        "KbdInteractiveAuthentication=no",
        "GSSAPIAuthentication=no",
        "ForwardAgent=no",
        "ClearAllForwardings=yes",
    ):
        assert option in command

    assert _pipeline_result_failed({"processed": 1, "outcomes": ["BUILD_FAILED"]})
    assert _pipeline_result_failed({"outcome": "PROMOTED_SOURCE_MOVED"})
    assert not _pipeline_result_failed(
        {"processed": 1, "outcomes": ["CANDIDATE_READY"]}
    )


def test_reconcile_reads_back_exact_promoted_release_identity(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    vault.mkdir()
    _write_vault(vault)
    revision = "a" * 40
    digest = "sha256:" + "b" * 64

    class FakeTransport:
        def __init__(self) -> None:
            self.request: dict[str, Any] | None = None
            self.manifest: dict[str, Any] | None = None
            self.committed = False
            self.current_calls = 0
            self.deployment_id = "c" * 64
            self.run_id = "11111111-1111-4111-8111-111111111111"

        def current(self) -> dict[str, Any]:
            self.current_calls += 1
            if not self.committed:
                return {
                    "schema_version": 2,
                    "current_deployment_id": "",
                    "snapshot_id": "",
                    "run_id": "",
                    "source_fingerprint": "",
                    "artifact_fingerprint": "",
                    "logical_fingerprint": "",
                    "homeops_version": "",
                    "source_revision": "",
                    "image_digest": "",
                    "snapshot_contract_version": "",
                    "build_contract_version": "",
                    "promoted_at": "",
                }
            assert self.manifest is not None
            return {
                "schema_version": 2,
                "current_deployment_id": self.deployment_id,
                "snapshot_id": self.manifest["snapshot_id"],
                "run_id": self.run_id,
                "source_fingerprint": self.manifest["source_fingerprint"],
                "artifact_fingerprint": self.manifest["artifact_fingerprint"],
                "logical_fingerprint": self.manifest["logical_fingerprint"],
                "homeops_version": "0.4.1",
                "source_revision": revision,
                "image_digest": digest,
                "snapshot_contract_version": "homeops-snapshot-v1",
                "build_contract_version": "homeops-build-v1",
                "promoted_at": "2026-08-13T12:05:00+00:00",
            }

        def call(self, verb: str, body: Any) -> dict[str, Any]:
            if verb == "submit":
                payload = body.read()
                with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
                    self.request = json.loads(
                        archive.extractfile("request.json").read()
                    )
                    self.manifest = json.loads(
                        archive.extractfile("snapshot.json").read()
                    )
                return {
                    "schema_version": 1,
                    "protocol": RECEIVER_PROTOCOL,
                    "outcome": "ACCEPTED",
                    "request_id": self.request["request_id"],
                    "retryable": False,
                    "archive_sha256": hashlib.sha256(payload).hexdigest(),
                }
            assert self.request is not None
            if verb == "commit":
                self.committed = True
                return {
                    "schema_version": 1,
                    "protocol": RECEIVER_PROTOCOL,
                    "outcome": "COMMIT_ACCEPTED",
                    "request_id": self.request["request_id"],
                    "retryable": False,
                }
            assert verb == "status"
            outcome = "PROMOTED" if self.committed else "CANDIDATE_READY"
            return {
                "schema_version": 1,
                "protocol": RECEIVER_PROTOCOL,
                "outcome": "RESULT",
                "request_id": self.request["request_id"],
                "retryable": False,
                "commit_accepted": self.committed,
                "result": {
                    "schema_version": 1,
                    "protocol": RECEIVER_PROTOCOL,
                    "request_id": self.request["request_id"],
                    "publisher_id": self.request["publisher_id"],
                    "outcome": outcome,
                    "candidate_deployment_id": self.deployment_id,
                    "expected_current_deployment_id": "",
                    "snapshot_id": self.request["snapshot_id"],
                    "run_id": self.run_id,
                    "release_policy_id": self.request["release_policy_id"],
                    "promotion_policy_id": hashlib.sha256(
                        json.dumps(
                            {
                                "build_contract_version": "homeops-build-v1",
                                "build_schema_version": 1,
                                "evaluation_suite_sha256": [],
                                "homeops_version": "0.4.1",
                                "image_digest": digest,
                                "schema_version": 1,
                                "snapshot_contract_version": "homeops-snapshot-v1",
                                "snapshot_schema_version": 1,
                                "source_revision": revision,
                            },
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode()
                    ).hexdigest(),
                    "retryable": False,
                },
            }

        def close(self) -> None:
            pass

    transport = FakeTransport()
    result = reconcile(
        vault=vault,
        state_dir=tmp_path / "state",
        transport=transport,  # type: ignore[arg-type]
        publisher_id="test-publisher",
        source_revision=revision,
        image_digest=digest,
        timeout_seconds=5,
    )

    assert result["outcome"] == "PROMOTED"
    assert result["publisher_id"] == "test-publisher"
    assert transport.request["publisher_id"] == "test-publisher"
    assert transport.current_calls == 2


def test_reconcile_resumes_exact_private_attempt_after_ambiguous_submit(
    tmp_path: Path,
) -> None:
    vault = tmp_path / "vault"
    vault.mkdir()
    _write_vault(vault)
    state = tmp_path / "state"
    revision = "a" * 40
    digest = "sha256:" + "b" * 64

    class ResumeTransport:
        request: dict[str, Any] | None = None
        manifest: dict[str, Any] | None = None
        submits = 0
        committed = False
        fail_first_submit = True
        deployment_id = "c" * 64
        run_id = "11111111-1111-4111-8111-111111111111"

        def current(self) -> dict[str, Any]:
            if not self.committed:
                return {
                    "schema_version": 2,
                    "current_deployment_id": "",
                    "snapshot_id": "",
                    "run_id": "",
                    "source_fingerprint": "",
                    "artifact_fingerprint": "",
                    "logical_fingerprint": "",
                    "homeops_version": "",
                    "source_revision": "",
                    "image_digest": "",
                    "snapshot_contract_version": "",
                    "build_contract_version": "",
                    "promoted_at": "",
                }
            assert self.manifest is not None
            return {
                "schema_version": 2,
                "current_deployment_id": self.deployment_id,
                "snapshot_id": self.manifest["snapshot_id"],
                "run_id": self.run_id,
                "source_fingerprint": self.manifest["source_fingerprint"],
                "artifact_fingerprint": self.manifest["artifact_fingerprint"],
                "logical_fingerprint": self.manifest["logical_fingerprint"],
                "homeops_version": "0.4.1",
                "source_revision": revision,
                "image_digest": digest,
                "snapshot_contract_version": "homeops-snapshot-v1",
                "build_contract_version": "homeops-build-v1",
                "promoted_at": "2026-08-13T12:05:00+00:00",
            }

        def call(self, verb: str, body: Any) -> dict[str, Any]:
            if verb == "submit":
                payload = body.read()
                self.submits += 1
                with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
                    self.request = json.loads(archive.extractfile("request.json").read())
                    self.manifest = json.loads(archive.extractfile("snapshot.json").read())
                if self.fail_first_submit:
                    self.fail_first_submit = False
                    raise TransportError("response lost after durable submit")
                return {
                    "schema_version": 1,
                    "protocol": RECEIVER_PROTOCOL,
                    "outcome": "ACCEPTED",
                    "request_id": self.request["request_id"],
                    "retryable": False,
                    "archive_sha256": hashlib.sha256(payload).hexdigest(),
                }
            assert self.request is not None
            if verb == "commit":
                self.committed = True
                return {
                    "schema_version": 1,
                    "protocol": RECEIVER_PROTOCOL,
                    "outcome": "COMMIT_ACCEPTED",
                    "request_id": self.request["request_id"],
                    "retryable": False,
                }
            assert verb == "status"
            policy = _release_policy("0.4.1", revision, digest)
            outcome = "PROMOTED" if self.committed else "CANDIDATE_READY"
            return {
                "schema_version": 1,
                "protocol": RECEIVER_PROTOCOL,
                "outcome": "RESULT",
                "request_id": self.request["request_id"],
                "retryable": False,
                "commit_accepted": self.committed,
                "result": {
                    "schema_version": 1,
                    "protocol": RECEIVER_PROTOCOL,
                    "request_id": self.request["request_id"],
                    "publisher_id": self.request["publisher_id"],
                    "outcome": outcome,
                    "candidate_deployment_id": self.deployment_id,
                    "expected_current_deployment_id": "",
                    "snapshot_id": self.request["snapshot_id"],
                    "run_id": self.run_id,
                    "release_policy_id": self.request["release_policy_id"],
                    "promotion_policy_id": _policy_id(policy),
                    "retryable": False,
                },
            }

        def close(self) -> None:
            pass

    transport = ResumeTransport()
    first = reconcile(
        vault=vault,
        state_dir=state,
        transport=transport,  # type: ignore[arg-type]
        source_revision=revision,
        image_digest=digest,
        timeout_seconds=2,
    )
    assert first["outcome"] == "HOMEOPS_UNAVAILABLE"
    pending = _load_pending_attempt(state)
    assert pending is not None
    original_request_id = pending["request"]["request_id"]
    capability = pending["request"]["capability_token"]
    assert (state / "pending-attempt.json").stat().st_mode & 0o777 == 0o600
    assert (state / "pending-submission.tar").stat().st_mode & 0o777 == 0o600
    assert capability not in (state / "last-result.json").read_text(encoding="utf-8")

    second = reconcile(
        vault=vault,
        state_dir=state,
        transport=transport,  # type: ignore[arg-type]
        source_revision=revision,
        image_digest=digest,
        timeout_seconds=2,
    )
    assert second["outcome"] == "PROMOTED"
    assert second["request_id"] == original_request_id
    assert transport.submits == 2
    assert not (state / "pending-attempt.json").exists()
    assert not (state / "pending-submission.tar").exists()
    assert capability not in (state / "last-result.json").read_text(encoding="utf-8")


def test_commit_requested_with_source_move_polls_terminal_without_reauthorizing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = tmp_path / "vault"
    vault.mkdir()
    _write_vault(vault)
    state = tmp_path / "state"
    revision = "a" * 40
    digest = "sha256:" + "b" * 64

    class DelayedCommitTransport:
        request: dict[str, Any] | None = None
        ready_calls = 0
        commit_calls = 0
        current_calls = 0

        def current(self) -> dict[str, Any]:
            self.current_calls += 1
            if self.current_calls > 1:
                raise AssertionError("current must not be reread before a terminal result")
            return {
                "schema_version": 2,
                "current_deployment_id": "",
                "snapshot_id": "",
                "run_id": "",
                "source_fingerprint": "",
                "artifact_fingerprint": "",
                "logical_fingerprint": "",
                "homeops_version": "",
                "source_revision": "",
                "image_digest": "",
                "snapshot_contract_version": "",
                "build_contract_version": "",
                "promoted_at": "",
            }

        def call(self, verb: str, body: Any) -> dict[str, Any]:
            if verb == "submit":
                payload = body.read()
                with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
                    self.request = json.loads(archive.extractfile("request.json").read())
                return {
                    "schema_version": 1,
                    "protocol": RECEIVER_PROTOCOL,
                    "outcome": "ACCEPTED",
                    "request_id": self.request["request_id"],
                    "retryable": False,
                    "archive_sha256": hashlib.sha256(payload).hexdigest(),
                }
            assert self.request is not None
            if verb == "commit":
                self.commit_calls += 1
                return {
                    "schema_version": 1,
                    "protocol": RECEIVER_PROTOCOL,
                    "outcome": "COMMIT_ACCEPTED",
                    "request_id": self.request["request_id"],
                    "retryable": False,
                }
            assert verb == "status"
            self.ready_calls += 1
            return {
                "schema_version": 1,
                "protocol": RECEIVER_PROTOCOL,
                "outcome": "RESULT",
                "request_id": self.request["request_id"],
                "retryable": False,
                "commit_accepted": True,
                "result": {
                    "schema_version": 1,
                    "protocol": RECEIVER_PROTOCOL,
                    "request_id": self.request["request_id"],
                    "publisher_id": self.request["publisher_id"],
                    "outcome": "CANDIDATE_READY",
                    "candidate_deployment_id": "c" * 64,
                    "expected_current_deployment_id": "",
                    "snapshot_id": self.request["snapshot_id"],
                    "run_id": "11111111-1111-4111-8111-111111111111",
                    "release_policy_id": self.request["release_policy_id"],
                    "promotion_policy_id": _policy_id(
                        _release_policy("0.4.1", revision, digest)
                    ),
                    "retryable": False,
                },
            }

        def close(self) -> None:
            pass

    class StopPolling(RuntimeError):
        pass

    transport = DelayedCommitTransport()
    original_poll = __import__("homeops_ai.pipeline", fromlist=["_poll"])._poll
    stop_terminal = False

    def stop_terminal_poll(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal stop_terminal
        if kwargs.get("terminal_only") and stop_terminal:
            raise StopPolling("observed terminal-only recovery poll")
        if kwargs.get("terminal_only"):
            stop_terminal = True
            raise TransportError("terminal response was lost after commit acceptance")
        return original_poll(*args, **kwargs)

    monkeypatch.setattr("homeops_ai.pipeline._poll", stop_terminal_poll)
    initial = reconcile(
        vault=vault,
        state_dir=state,
        transport=transport,  # type: ignore[arg-type]
        source_revision=revision,
        image_digest=digest,
        timeout_seconds=2,
    )
    assert initial["outcome"] == "HOMEOPS_UNAVAILABLE"
    pending = _load_pending_attempt(state)
    assert pending is not None and pending["phase"] == "COMMIT_REQUESTED"
    transport.request = pending["request"]
    (vault / "AI Context.md").write_text("changed after commit acceptance", encoding="utf-8")
    stop_terminal = True

    with pytest.raises(StopPolling):
        _resume_pending_attempt(
            vault=vault,
            state_dir=state,
            transport=transport,  # type: ignore[arg-type]
            attempt=pending,
            release_policy=_release_policy("0.4.1", revision, digest),
            timeout_seconds=2,
        )
    assert transport.commit_calls == 0
    assert _load_pending_attempt(state)["phase"] == "COMMIT_REQUESTED"


def test_applying_commit_journal_cannot_repromote_after_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "remote"
    data = root / "data"
    publisher = "workstation"
    request_id = "11111111-1111-4111-8111-111111111111"
    expected = _record("expected", run_id="22222222-2222-4222-8222-222222222222")
    candidate = _record("candidate", run_id="33333333-3333-4333-8333-333333333333")
    revision = "a" * 40
    digest = "sha256:" + "b" * 64
    for record in (expected, candidate):
        record["source_revision"] = revision
        record["image_digest"] = digest
        record["deployment_id"] = hashlib.sha256(
            json.dumps(
                {
                    key: value
                    for key, value in record.items()
                    if key
                    in {
                        "deployment_contract_version",
                        "snapshot_id",
                        "run_id",
                        "source_fingerprint",
                        "artifact_fingerprint",
                        "logical_fingerprint",
                        "homeops_version",
                        "source_revision",
                        "image_digest",
                        "snapshot_schema_version",
                        "snapshot_contract_version",
                        "build_schema_version",
                        "build_contract_version",
                    }
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
    policy = _release_policy(
        candidate["homeops_version"],
        candidate["source_revision"],
        candidate["image_digest"],
    )
    policy_id = _policy_id(policy)

    deployment_path = data / "deployments" / f"{candidate['deployment_id']}.json"
    deployment_path.parent.mkdir(parents=True)
    deployment_path.write_text(json.dumps(candidate), encoding="utf-8")
    build_dir = data / "builds" / candidate["run_id"]
    build_dir.mkdir(parents=True)
    (build_dir / "promotion-evaluation.json").write_text(
        json.dumps({"passed": True, "promotion_policy_id": policy_id}),
        encoding="utf-8",
    )
    rolled_back = {
        "schema_version": 2,
        "current": expected["run_id"],
        "previous": candidate["run_id"],
        "current_deployment": expected,
        "previous_deployment": candidate,
        "promoted_at": "2026-08-13T13:00:00+00:00",
    }
    data.mkdir(exist_ok=True)
    (data / "active.json").write_text(json.dumps(rolled_back), encoding="utf-8")

    incoming = root / "incoming" / publisher / request_id
    incoming.mkdir(parents=True)
    receipt_digest = "e" * 64
    (incoming / "receipt.json").write_text(
        json.dumps({"archive_sha256": receipt_digest}), encoding="utf-8"
    )
    results = root / "results" / publisher
    results.mkdir(parents=True)
    ready = {
        "schema_version": 1,
        "protocol": RECEIVER_PROTOCOL,
        "request_id": request_id,
        "publisher_id": publisher,
        "outcome": "CANDIDATE_READY",
        "candidate_deployment_id": candidate["deployment_id"],
        "expected_current_deployment_id": expected["deployment_id"],
        "snapshot_id": candidate["snapshot_id"],
        "run_id": candidate["run_id"],
        "release_policy_id": policy_id,
        "promotion_policy_id": policy_id,
        "submission_archive_sha256": receipt_digest,
        "retryable": False,
    }
    (results / f"{request_id}.json").write_text(json.dumps(ready), encoding="utf-8")
    commits = root / "commits" / publisher
    commits.mkdir(parents=True)
    marker = commits / f"{request_id}.json"
    commit = {
        "schema_version": 1,
        "protocol": RECEIVER_PROTOCOL,
        "request_id": request_id,
        "publisher_id": publisher,
        "candidate_deployment_id": candidate["deployment_id"],
        "expected_current_deployment_id": expected["deployment_id"],
        "submission_archive_sha256": receipt_digest,
    }
    marker.write_bytes(canonical_receiver_json(commit, tuple(commit)))
    _write_commit_journal(
        root,
        publisher,
        request_id,
        candidate_deployment_id=candidate["deployment_id"],
        expected_current_deployment_id=expected["deployment_id"],
        release_policy_id=policy_id,
    )
    monkeypatch.setattr(
        "homeops_ai.pipeline.promote",
        lambda *args, **kwargs: pytest.fail("stale journal replay called promote"),
    )

    result = process_remote(
        root,
        source_revision=candidate["source_revision"],
        image_digest=candidate["image_digest"],
    )
    assert result["outcomes"] == ["PROMOTION_CONFLICT"]
    assert active_state(data)["current_deployment"]["deployment_id"] == expected[
        "deployment_id"
    ]
    assert _commit_journal_path(root, publisher, request_id).is_file()


def test_commit_journal_repairs_bookkeeping_after_active_cas_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "remote"
    data = root / "data"
    publisher = "workstation"
    request_id = "11111111-1111-4111-8111-111111111111"
    revision = "a" * 40
    digest = "sha256:" + "b" * 64
    expected = _record(
        "expected",
        run_id="22222222-2222-4222-8222-222222222222",
        source_revision=revision,
        image_digest=digest,
    )
    candidate = _record(
        "candidate",
        run_id="33333333-3333-4333-8333-333333333333",
        source_revision=revision,
        image_digest=digest,
    )
    selected_expected, _ = select_deployment(
        empty_state(),
        expected,
        expected_current_deployment_id=None,
        promoted_at="2026-08-13T12:03:00+00:00",
    )
    data.mkdir(parents=True)
    (data / "active.json").write_text(json.dumps(selected_expected), encoding="utf-8")
    deployment_path = data / "deployments" / f"{candidate['deployment_id']}.json"
    assert build_module.store_deployment(data, candidate) == deployment_path
    policy = _release_policy("0.4.1", revision, digest)
    policy_id = _policy_id(policy)
    build_dir = data / "builds" / candidate["run_id"]
    build_dir.mkdir(parents=True)
    (build_dir / "promotion-evaluation.json").write_text(
        json.dumps({"passed": True, "promotion_policy_id": policy_id}),
        encoding="utf-8",
    )

    receipt_digest = "e" * 64
    incoming = root / "incoming" / publisher / request_id
    incoming.mkdir(parents=True)
    (incoming / "receipt.json").write_text(
        json.dumps({"archive_sha256": receipt_digest}), encoding="utf-8"
    )
    ready = {
        "schema_version": 1,
        "protocol": RECEIVER_PROTOCOL,
        "request_id": request_id,
        "publisher_id": publisher,
        "outcome": "CANDIDATE_READY",
        "candidate_deployment_id": candidate["deployment_id"],
        "expected_current_deployment_id": expected["deployment_id"],
        "snapshot_id": candidate["snapshot_id"],
        "run_id": candidate["run_id"],
        "release_policy_id": policy_id,
        "promotion_policy_id": policy_id,
        "submission_archive_sha256": receipt_digest,
        "retryable": False,
    }
    result_path = root / "results" / publisher / f"{request_id}.json"
    result_path.parent.mkdir(parents=True)
    result_path.write_text(json.dumps(ready), encoding="utf-8")
    commit = {
        "schema_version": 1,
        "protocol": RECEIVER_PROTOCOL,
        "request_id": request_id,
        "publisher_id": publisher,
        "candidate_deployment_id": candidate["deployment_id"],
        "expected_current_deployment_id": expected["deployment_id"],
        "submission_archive_sha256": receipt_digest,
    }
    marker = root / "commits" / publisher / f"{request_id}.json"
    marker.parent.mkdir(parents=True)
    marker.write_bytes(canonical_receiver_json(commit, tuple(commit)))

    monkeypatch.setattr(build_module, "_candidate_matches_build", lambda *args: None)
    original_store = build_module._store_promoted_record

    def fail_store(*args: Any) -> None:
        raise OSError("injected failure after promotion active-state CAS")

    monkeypatch.setattr(build_module, "_store_promoted_record", fail_store)
    with pytest.raises(OSError, match="after promotion active-state CAS"):
        process_remote(root, source_revision=revision, image_digest=digest)

    selected_after_crash = active_state(data)["current_deployment"]
    assert selected_after_crash["deployment_id"] == candidate["deployment_id"]
    assert json.loads(result_path.read_text(encoding="utf-8"))["outcome"] == (
        "CANDIDATE_READY"
    )
    assert _commit_journal_path(root, publisher, request_id).is_file()
    assert not (data / "deployment-history" / candidate["deployment_id"]).exists()

    monkeypatch.setattr(build_module, "_store_promoted_record", original_store)
    recovered = process_remote(root, source_revision=revision, image_digest=digest)
    assert recovered["outcomes"] == ["PROMOTED"]
    terminal = json.loads(result_path.read_text(encoding="utf-8"))
    assert terminal["outcome"] == "PROMOTED"
    history = list(
        (data / "deployment-history" / candidate["deployment_id"]).glob("*.json")
    )
    assert len(history) == 1
    assert json.loads(history[0].read_text(encoding="utf-8")) == active_state(data)[
        "current_deployment"
    ]
    projection = json.loads(
        (root / "pipeline-state" / "current.json").read_text(encoding="utf-8")
    )
    assert projection["current_deployment_id"] == candidate["deployment_id"]


def test_query_ignores_untrusted_manifest_database_path(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    vault.mkdir()
    _write_vault(vault)
    data = tmp_path / "data"
    build = rebuild(vault, data)
    manifest_path = data / "builds" / build["run_id"] / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["database_path"] = "/tmp/not-the-selected-database"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = execute_query(data, "canonical-current")
    assert result["rows"][0]["source_path"] == "AI Context.md"
