from pathlib import Path

from homeops_ai.build import rebuild
from homeops_ai.context_compiler import ContextCompilerError, compile_context
from homeops_ai.evaluation import evaluate_suite
from homeops_ai.query import execute_query
import pytest


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


def test_stable_queries_cover_graph_and_context(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    data = tmp_path / "data"
    vault.mkdir()
    _write_vault(vault)
    rebuild(vault, data)

    canonical = execute_query(data, "canonical-current")
    assert {row["source_path"] for row in canonical["rows"]} == {
        "AI Context.md",
        "Heavy VM.md",
    }

    links = execute_query(data, "links-to", {"title": "Heavy VM"})
    assert {row["source_path"] for row in links["rows"]} == {
        "AI Context.md",
        "AI Plan.md",
    }

    reachable = execute_query(data, "reachable-from", {"title": "AI Context"})
    assert {row["source_path"] for row in reachable["rows"]} >= {
        "AI Context.md",
        "AI Plan.md",
        "Heavy VM.md",
    }

    inventory = execute_query(data, "link-inventory")
    assert inventory["summary"]["by_resolution_state"]["unresolved"] == 1
    assert execute_query(data, "missing-lifecycle")["rows"][0]["source_path"] == "Missing Lifecycle.md"
    assert execute_query(data, "guidance-conflicts")["rows"][0]["source_path"] == "Legacy.md"

    context = execute_query(data, "context", {"question": "What currently runs on the Heavy VM?"})
    assert context["rows"][0]["source_path"] == "Heavy VM.md"
    assert context["rows"][0]["evidence"]


def test_evaluation_suite_reports_queries_and_expected_gaps(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    data = tmp_path / "data"
    vault.mkdir()
    _write_vault(vault)
    rebuild(vault, data)
    cases = tmp_path / "cases.yaml"
    cases.write_text(
        """schema_version: 1
suite_id: test-suite
suite_version: 1
cases:
  - id: canonical
    question: Which documents are canonical and current?
    capability_class: deterministic-graph
    query:
      name: canonical-current
    expected:
      row_count: 2
      required_source_paths: [AI Context.md, Heavy VM.md]
      forbidden_statuses: [historical]
    live_verification_required: false
    reviewer_notes: Test oracle.
  - id: expected-gap
    question: Query an external AI client.
    capability_class: expected-gap
    expected_gap:
      classification: read-only-mcp
      reason: No external interface exists.
    live_verification_required: false
    reviewer_notes: Test gap.
  - id: compiled
    question: Compile risky Heavy VM context.
    capability_class: context-compiler
    compile:
      question: Change the Heavy VM
      risk_level: risky
      max_documents: 2
      max_sections: 2
      max_chars: 1000
    expected:
      required_source_paths: [Heavy VM.md]
      forbidden_statuses: [historical]
      live_verification_required: true
      max_document_count: 2
      max_section_count: 2
      max_evidence_chars: 1000
    reviewer_notes: Test compiler.
"""
    )

    report = evaluate_suite(cases, data)

    assert report["passed"]
    assert report["summary"] == {"total": 3, "expected-gap": 1, "passed": 2}
    assert report["cases"][1]["expected_gap"]["classification"] == "read-only-mcp"


def test_context_compiler_is_deterministic_budgeted_and_risk_explicit(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    data = tmp_path / "data"
    vault.mkdir()
    _write_vault(vault)
    rebuild(vault, data)

    options = {
        "risk_level": "risky",
        "max_documents": 2,
        "max_sections": 2,
        "max_chars": 1000,
    }
    first = compile_context(data, "Change the Heavy VM", **options)
    second = compile_context(data, "Change the Heavy VM", **options)

    assert first == second
    assert first["live_verification"]["required"]
    assert first["trust_policy"]["live_discovery_performed"] is False
    assert first["selection"]["document_count"] <= 2
    assert first["selection"]["section_count"] <= 2
    assert first["selection"]["evidence_chars"] <= 1000
    assert all(
        document["status"] not in {"historical", "superseded", "abandoned"}
        for document in first["documents"]
    )
    assert all(section["body"] for document in first["documents"] for section in document["sections"])


def test_context_compiler_rejects_impossible_budget(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    data = tmp_path / "data"
    vault.mkdir()
    _write_vault(vault)
    (vault / "Heavy VM.md").write_text(
        (vault / "Heavy VM.md").read_text()
        + "\n## Oversized\n\nUniqueCompilerTarget "
        + ("evidence " * 80)
        + "\n"
    )
    rebuild(vault, data)

    with pytest.raises(ContextCompilerError, match="cannot fit any"):
        compile_context(
            data,
            "UniqueCompilerTarget",
            risk_level="normal",
            max_chars=200,
        )
