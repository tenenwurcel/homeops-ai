import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from homeops_ai.context_compiler import ContextCompilerError, compile_context
from homeops_ai.query import QueryError, execute_query


class EvaluationError(RuntimeError):
    pass


def _load_suite(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise EvaluationError(f"evaluation suite does not exist: {path}")
    parsed = YAML(typ="safe").load(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict) or not isinstance(parsed.get("cases"), list):
        raise EvaluationError("evaluation suite must be a mapping with a cases list")
    if parsed.get("schema_version") != 1 or not parsed.get("suite_id"):
        raise EvaluationError("evaluation suite requires schema_version 1 and suite_id")
    return parsed


def _nested(value: dict[str, Any], dotted_path: str) -> Any:
    current: Any = value
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _check(name: str, passed: bool, expected: Any, actual: Any) -> dict[str, Any]:
    return {"name": name, "passed": passed, "expected": expected, "actual": actual}


def _failure_classification(case: dict[str, Any], *, query_error: bool = False) -> str:
    if query_error:
        return "query-error"
    return case.get("failure_classification") or {
        "deterministic-graph": "graph-correctness",
        "context-retrieval": "retrieval-policy",
    }.get(case.get("capability_class"), "unclassified")


def _evaluate_expected(result: dict[str, Any], expected: dict[str, Any]) -> list[dict[str, Any]]:
    rows = result["rows"]
    checks = []
    if "row_count" in expected:
        checks.append(_check("row_count", len(rows) == expected["row_count"], expected["row_count"], len(rows)))
    if "min_rows" in expected:
        checks.append(_check("min_rows", len(rows) >= expected["min_rows"], expected["min_rows"], len(rows)))
    if "max_rows" in expected:
        checks.append(_check("max_rows", len(rows) <= expected["max_rows"], expected["max_rows"], len(rows)))

    paths = {row.get("source_path") for row in rows if row.get("source_path")}
    for path in expected.get("required_source_paths", []):
        checks.append(_check(f"required_source_path:{path}", path in paths, path, sorted(paths)))
    for path in expected.get("forbidden_source_paths", []):
        checks.append(_check(f"forbidden_source_path:{path}", path not in paths, f"not {path}", sorted(paths)))

    forbidden_statuses = set(expected.get("forbidden_statuses", []))
    if forbidden_statuses:
        actual = sorted({row.get("status") for row in rows if row.get("status") in forbidden_statuses})
        checks.append(_check("forbidden_statuses", not actual, [], actual))
    for dotted_path, value in expected.get("summary_equals", {}).items():
        actual = _nested(result["summary"], dotted_path)
        checks.append(_check(f"summary_equals:{dotted_path}", actual == value, value, actual))
    return checks


def _evaluate_compiler_expected(bundle: dict[str, Any], expected: dict[str, Any]) -> list[dict[str, Any]]:
    documents = bundle["documents"]
    selection = bundle["selection"]
    checks = []
    paths = {document["source_path"] for document in documents}
    for path in expected.get("required_source_paths", []):
        checks.append(_check(f"required_source_path:{path}", path in paths, path, sorted(paths)))
    forbidden_statuses = set(expected.get("forbidden_statuses", []))
    if forbidden_statuses:
        actual = sorted({document["status"] for document in documents if document["status"] in forbidden_statuses})
        checks.append(_check("forbidden_statuses", not actual, [], actual))
    if "live_verification_required" in expected:
        actual = bundle["live_verification"]["required"]
        checks.append(_check("live_verification_required", actual == expected["live_verification_required"], expected["live_verification_required"], actual))
    for field in ("document_count", "section_count", "evidence_chars"):
        maximum = expected.get(f"max_{field}")
        if maximum is not None:
            checks.append(_check(f"max_{field}", selection[field] <= maximum, maximum, selection[field]))
    return checks


def evaluate_suite(
    cases_path: Path,
    data_dir: Path,
    *,
    run_id: str | None = None,
) -> dict[str, Any]:
    suite = _load_suite(cases_path.resolve())
    case_reports = []
    selected_run_id = run_id

    for case in suite["cases"]:
        if not isinstance(case, dict) or not case.get("id") or not case.get("question"):
            raise EvaluationError("every evaluation case requires id and question")
        if "expected_gap" in case:
            gap = case["expected_gap"]
            case_reports.append(
                {
                    "id": case["id"],
                    "question": case["question"],
                    "capability_class": case.get("capability_class"),
                    "status": "expected-gap",
                    "passed": True,
                    "expected_gap": gap,
                    "live_verification_required": bool(case.get("live_verification_required")),
                    "reviewer_notes": case.get("reviewer_notes"),
                }
            )
            continue

        if "compile" in case:
            request = case["compile"]
            expected = case.get("expected")
            if not isinstance(request, dict) or not isinstance(expected, dict):
                raise EvaluationError(f"case {case['id']} requires compile and expected mappings")
            try:
                bundle = compile_context(
                    data_dir,
                    request["question"],
                    risk_level=request["risk_level"],
                    max_documents=request.get("max_documents", 5),
                    max_sections=request.get("max_sections", 8),
                    max_chars=request.get("max_chars", 6000),
                    run_id=selected_run_id,
                )
                selected_run_id = bundle["build"]["run_id"]
                checks = _evaluate_compiler_expected(bundle, expected)
                passed = all(check["passed"] for check in checks)
                case_reports.append(
                    {
                        "id": case["id"],
                        "question": case["question"],
                        "capability_class": case.get("capability_class"),
                        "status": "passed" if passed else "failed",
                        "passed": passed,
                        "checks": checks,
                        "result": bundle,
                        "failure_classification": None if passed else "context-compiler",
                        "live_verification_required": bundle["live_verification"]["required"],
                        "reviewer_notes": case.get("reviewer_notes"),
                    }
                )
            except ContextCompilerError as error:
                case_reports.append(
                    {
                        "id": case["id"],
                        "question": case["question"],
                        "capability_class": case.get("capability_class"),
                        "status": "error",
                        "passed": False,
                        "error": str(error),
                        "failure_classification": "context-compiler",
                        "live_verification_required": bool(case.get("live_verification_required")),
                        "reviewer_notes": case.get("reviewer_notes"),
                    }
                )
            continue

        query = case.get("query")
        expected = case.get("expected")
        if not isinstance(query, dict) or not query.get("name") or not isinstance(expected, dict):
            raise EvaluationError(f"case {case['id']} requires query and expected mappings")
        try:
            result = execute_query(data_dir, query["name"], query.get("params", {}), run_id=selected_run_id)
            selected_run_id = result["run_id"]
            checks = _evaluate_expected(result, expected)
            passed = all(check["passed"] for check in checks)
            case_reports.append(
                {
                    "id": case["id"],
                    "question": case["question"],
                    "capability_class": case.get("capability_class"),
                    "status": "passed" if passed else "failed",
                    "passed": passed,
                    "checks": checks,
                    "result": result,
                    "failure_classification": None if passed else _failure_classification(case),
                    "live_verification_required": bool(case.get("live_verification_required")),
                    "reviewer_notes": case.get("reviewer_notes"),
                }
            )
        except QueryError as error:
            case_reports.append(
                {
                    "id": case["id"],
                    "question": case["question"],
                    "capability_class": case.get("capability_class"),
                    "status": "error",
                    "passed": False,
                    "error": str(error),
                    "failure_classification": _failure_classification(case, query_error=True),
                    "live_verification_required": bool(case.get("live_verification_required")),
                    "reviewer_notes": case.get("reviewer_notes"),
                }
            )

    counts = Counter(report["status"] for report in case_reports)
    return {
        "schema_version": 1,
        "suite_id": suite["suite_id"],
        "suite_version": suite.get("suite_version"),
        "run_id": selected_run_id,
        "evaluated_at": datetime.now(UTC).isoformat(),
        "passed": all(report["passed"] for report in case_reports),
        "summary": {"total": len(case_reports), **dict(sorted(counts.items()))},
        "cases": case_reports,
    }


def write_report(report: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
