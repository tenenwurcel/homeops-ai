from pathlib import Path

import anyio
import pytest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from homeops_ai.build import active_state, inspect_vault, rebuild
from homeops_ai.mcp_server import (
    MAX_MCP_ROWS,
    MCPToolError,
    compile_context_bundle,
    get_build_status,
    run_stable_query,
)
from homeops_ai.snapshot import create_snapshot_manifest, write_manifest
from homeops_ai.source_contract import export_snapshot


def _write_vault(vault: Path) -> None:
    (vault / "Categories").mkdir()
    (vault / "Categories" / "AI.md").write_text(
        """---
id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
type: category
status: current
---
"""
    )
    (vault / "AI Context.md").write_text(
        """---
id: "11111111-1111-4111-8111-111111111111"
categories: ["[[AI]]"]
type: context-index
status: current
authority: canonical
---
Current priorities link to [[Heavy VM]] and [[AI Plan]].
"""
    )
    (vault / "Heavy VM.md").write_text(
        """---
id: "22222222-2222-4222-8222-222222222222"
categories: ["[[AI]]"]
type: current-state
status: current
authority: canonical
---
## Services

The Heavy VM currently runs HomeOps. See [[Missing]].
"""
    )
    (vault / "AI Plan.md").write_text(
        """---
id: "33333333-3333-4333-8333-333333333333"
categories: ["[[AI]]"]
type: plan
status: in-progress
authority: supporting
---
The active AI plan links to [[Heavy VM]].
"""
    )
    (vault / "Legacy.md").write_text(
        """---
id: "44444444-4444-4444-8444-444444444444"
categories: ["[[AI]]"]
type: plan
status: historical
authority: supporting
---
Legacy guidance links to [[AI Context]].
"""
    )
    (vault / "Missing Lifecycle.md").write_text(
        """---
id: "55555555-5555-4555-8555-555555555555"
---
Incomplete legacy metadata.
"""
    )


def _build_data(tmp_path: Path) -> Path:
    vault = tmp_path / "vault"
    data = tmp_path / "data"
    vault.mkdir()
    _write_vault(vault)
    rebuild(vault, data)
    return data


def _promote_versioned_build(
    tmp_path: Path,
    vault: Path,
    data: Path,
    *,
    sequence: int,
    expected_deployment_id: str | None,
) -> tuple[str, str]:
    revision = "a" * 40
    digest = "sha256:" + "b" * 64
    staging = tmp_path / f"snapshot-staging-{sequence}"
    export_snapshot(vault, staging / "vault")
    inspected = inspect_vault(staging / "vault")
    manifest = create_snapshot_manifest(
        staging / "vault",
        inspected,
        created_at=f"2026-08-13T12:0{sequence}:00+00:00",
        package_version="0.4.1",
        source_revision=revision,
    )
    snapshot = tmp_path / "vault-snapshots" / manifest["snapshot_id"]
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    staging.rename(snapshot)
    write_manifest(snapshot / "snapshot.json", manifest)
    build = rebuild(
        snapshot / "vault",
        data,
        snapshot_manifest=manifest,
        snapshot_received_at=f"2026-08-13T12:0{sequence}:30+00:00",
        homeops_version="0.4.1",
        source_revision=revision,
        image_digest=digest,
        expected_current_deployment_id=expected_deployment_id,
    )
    return build["run_id"], build["deployment_id"]


def test_build_status_reports_verified_read_only_contract(tmp_path: Path) -> None:
    data = _build_data(tmp_path)

    status = get_build_status(data)

    assert status["result"] == "verified"
    assert status["active"]["current"] == status["run_id"]
    assert status["counts"]["source_document"] == 6
    assert status["validation"]["valid"] is True
    assert status["trust_policy"] == {
        "read_only": True,
        "generated_answer": False,
        "live_discovery_performed": False,
    }
    assert "context" in status["available_queries"]


def test_explicit_previous_and_retained_runs_report_mcp_provenance(
    tmp_path: Path,
) -> None:
    vault = tmp_path / "vault"
    data = tmp_path / "data"
    vault.mkdir()
    _write_vault(vault)

    first_run, first_deployment = _promote_versioned_build(
        tmp_path,
        vault,
        data,
        sequence=1,
        expected_deployment_id=None,
    )
    context = vault / "AI Context.md"
    context.write_text(
        context.read_text(encoding="utf-8") + "\nSecond deployment.\n",
        encoding="utf-8",
    )
    second_run, second_deployment = _promote_versioned_build(
        tmp_path,
        vault,
        data,
        sequence=2,
        expected_deployment_id=first_deployment,
    )
    context.write_text(
        context.read_text(encoding="utf-8") + "\nThird deployment.\n",
        encoding="utf-8",
    )
    third_run, third_deployment = _promote_versioned_build(
        tmp_path,
        vault,
        data,
        sequence=3,
        expected_deployment_id=second_deployment,
    )

    previous = get_build_status(data, run_id=second_run)
    assert previous["deployment"]["role"] == "previous"
    assert previous["deployment"]["active"] is False
    assert previous["deployment"]["retained"] is True
    assert previous["deployment"]["deployment_id"] == second_deployment

    retained = get_build_status(data, run_id=first_run)
    assert retained["deployment"]["role"] == "retained"
    assert retained["deployment"]["active"] is False
    assert retained["deployment"]["retained"] is True
    assert retained["deployment"]["deployment_id"] == first_deployment

    query = run_stable_query(data, "canonical-current", run_id=first_run)
    assert query["run_id"] == first_run
    assert query["deployment"]["role"] == "retained"
    bundle = compile_context_bundle(data, "What currently runs?", run_id=second_run)
    assert bundle["build"]["run_id"] == second_run
    assert bundle["build"]["deployment"]["role"] == "previous"

    selected_before = active_state(data)
    assert selected_before["current"] == third_run
    assert selected_before["current_deployment"]["deployment_id"] == third_deployment

    async def run_explicit_mcp_calls() -> None:
        server = StdioServerParameters(
            command="homeops-ai",
            args=["mcp", "--data-dir", str(data)],
        )
        async with stdio_client(server) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                previous_result = await session.call_tool(
                    "build_status", {"run_id": second_run}
                )
                assert previous_result.isError is False
                assert previous_result.structuredContent["deployment"]["role"] == (
                    "previous"
                )
                retained_result = await session.call_tool(
                    "build_status", {"run_id": first_run}
                )
                assert retained_result.isError is False
                assert retained_result.structuredContent["deployment"]["role"] == (
                    "retained"
                )

    anyio.run(run_explicit_mcp_calls)
    assert active_state(data) == selected_before


def test_query_tool_uses_stable_queries_and_bounds_rows(tmp_path: Path) -> None:
    data = _build_data(tmp_path)

    result = run_stable_query(data, "link-inventory", max_rows=2)

    assert result["query"] == "link-inventory"
    assert len(result["rows"]) == 2
    assert result["mcp"]["returned_rows"] == 2
    assert result["mcp"]["truncated"] is True


def test_query_tool_rejects_invalid_params_and_row_limits(tmp_path: Path) -> None:
    data = _build_data(tmp_path)

    with pytest.raises(MCPToolError, match="params must be an object"):
        run_stable_query(data, "canonical-current", params=["not", "an", "object"])
    with pytest.raises(MCPToolError, match=f"between 1 and {MAX_MCP_ROWS}"):
        run_stable_query(data, "canonical-current", max_rows=0)


def test_context_bundle_tool_preserves_risk_policy(tmp_path: Path) -> None:
    data = _build_data(tmp_path)

    bundle = compile_context_bundle(
        data,
        "Change the Heavy VM",
        risk_level="risky",
        max_documents=2,
        max_sections=2,
        max_chars=1000,
    )

    assert bundle["bundle_kind"] == "homeops-context-bundle"
    assert bundle["live_verification"]["required"]
    assert bundle["trust_policy"]["generated_answer"] is False
    assert bundle["selection"]["document_count"] <= 2


def test_stdio_mcp_server_exposes_read_only_tools(tmp_path: Path) -> None:
    data = _build_data(tmp_path)

    async def run_smoke() -> None:
        server = StdioServerParameters(
            command="homeops-ai",
            args=["mcp", "--data-dir", str(data)],
        )
        async with stdio_client(server) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                tools = await session.list_tools()
                assert {tool.name for tool in tools.tools} == {
                    "build_status",
                    "context_bundle",
                    "query",
                }

                result = await session.call_tool("build_status", {})
                assert result.isError is False
                assert result.structuredContent["result"] == "verified"
                assert (
                    result.structuredContent["active"]["current"]
                    == active_state(data)["current"]
                )

    anyio.run(run_smoke)
