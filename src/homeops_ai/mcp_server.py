import argparse
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from homeops_ai.build import active_state
from homeops_ai.context_compiler import ContextCompilerError, compile_context
from homeops_ai.query import QueryError, build_manifest, execute_query, query_names


DEFAULT_DATA_DIR = Path("data")
MAX_MCP_ROWS = 1000


class MCPToolError(RuntimeError):
    pass


def _clean_params(params: dict[str, Any] | None) -> dict[str, str]:
    if params is None:
        return {}
    if not isinstance(params, dict):
        raise MCPToolError("params must be an object")
    cleaned = {}
    for key, value in params.items():
        if not isinstance(key, str):
            raise MCPToolError("params keys must be strings")
        if value is None:
            continue
        cleaned[key] = str(value)
    return cleaned


def _bounded_rows(result: dict[str, Any], max_rows: int) -> dict[str, Any]:
    if not 1 <= max_rows <= MAX_MCP_ROWS:
        raise MCPToolError(f"max_rows must be between 1 and {MAX_MCP_ROWS}")
    rows = result.get("rows")
    if not isinstance(rows, list):
        return result
    returned = rows[:max_rows]
    return {
        **result,
        "rows": returned,
        "mcp": {
            "returned_rows": len(returned),
            "truncated": len(rows) > len(returned),
            "max_rows": max_rows,
            "available_queries": query_names(),
        },
    }


def get_build_status(data_dir: Path, run_id: str | None = None) -> dict[str, Any]:
    manifest = build_manifest(data_dir, run_id=run_id)
    validation_path = (
        data_dir.resolve() / "builds" / manifest["run_id"] / "validation.json"
    )
    validation = None
    if validation_path.is_file():
        import json

        validation = json.loads(validation_path.read_text(encoding="utf-8"))
    return {
        "schema_version": 1,
        "run_id": manifest["run_id"],
        "active": active_state(data_dir.resolve()),
        "result": manifest["result"],
        "profile": manifest["profile"],
        "started_at": manifest["started_at"],
        "completed_at": manifest["completed_at"],
        "verified_at": manifest.get("verified_at"),
        "source_fingerprint": manifest["source_fingerprint"],
        "logical_fingerprint": manifest["logical_fingerprint"],
        "artifact_fingerprint": manifest["artifact_fingerprint"],
        "counts": manifest["counts"],
        "validation": validation,
        "available_queries": query_names(),
        "trust_policy": {
            "read_only": True,
            "generated_answer": False,
            "live_discovery_performed": False,
        },
    }


def run_stable_query(
    data_dir: Path,
    name: str,
    params: dict[str, Any] | None = None,
    run_id: str | None = None,
    max_rows: int = 100,
) -> dict[str, Any]:
    try:
        result = execute_query(data_dir, name, _clean_params(params), run_id=run_id)
    except QueryError as error:
        raise MCPToolError(str(error)) from error
    return _bounded_rows(result, max_rows)


def compile_context_bundle(
    data_dir: Path,
    question: str,
    risk_level: str = "normal",
    max_documents: int = 5,
    max_sections: int = 8,
    max_chars: int = 6000,
    run_id: str | None = None,
) -> dict[str, Any]:
    try:
        return compile_context(
            data_dir,
            question,
            risk_level=risk_level,
            max_documents=max_documents,
            max_sections=max_sections,
            max_chars=max_chars,
            run_id=run_id,
        )
    except (ContextCompilerError, QueryError) as error:
        raise MCPToolError(str(error)) from error


def create_server(data_dir: Path = DEFAULT_DATA_DIR) -> FastMCP:
    resolved_data_dir = data_dir.resolve()
    mcp = FastMCP("HomeOps AI", json_response=True)

    @mcp.tool()
    def build_status(run_id: str | None = None) -> dict[str, Any]:
        """Return metadata for the active verified HomeOps build."""
        return get_build_status(resolved_data_dir, run_id=run_id)

    @mcp.tool()
    def query(
        name: str,
        params: dict[str, Any] | None = None,
        run_id: str | None = None,
        max_rows: int = 100,
    ) -> dict[str, Any]:
        """Run one stable read-only HomeOps query against a verified build."""
        return run_stable_query(
            resolved_data_dir,
            name,
            params=params,
            run_id=run_id,
            max_rows=max_rows,
        )

    @mcp.tool()
    def context_bundle(
        question: str,
        risk_level: str = "normal",
        max_documents: int = 5,
        max_sections: int = 8,
        max_chars: int = 6000,
        run_id: str | None = None,
    ) -> dict[str, Any]:
        """Compile a deterministic evidence bundle without generating an answer."""
        return compile_context_bundle(
            resolved_data_dir,
            question,
            risk_level=risk_level,
            max_documents=max_documents,
            max_sections=max_sections,
            max_chars=max_chars,
            run_id=run_id,
        )

    return mcp


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the read-only HomeOps MCP server")
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--transport", choices=("stdio",), default="stdio")
    args = parser.parse_args()

    create_server(args.data_dir).run(transport=args.transport)
