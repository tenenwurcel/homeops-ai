from pathlib import Path

import anyio
import pytest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from homeops_ai.build import active_state, rebuild
from homeops_ai.mcp_server import (
    MAX_MCP_ROWS,
    MCPToolError,
    compile_context_bundle,
    get_build_status,
    run_stable_query,
)


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
                assert result.structuredContent["active"]["current"] == active_state(data)[
                    "current"
                ]

    anyio.run(run_smoke)
