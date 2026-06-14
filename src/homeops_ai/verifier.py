import argparse
import json
from pathlib import Path
from typing import Any

from homeops_ai.database import open_database
from homeops_ai.schema import RELATION_SCHEMAS, relation_names


def _rows(client: Any, query: str) -> list[list[Any]]:
    return client.run(query, immutable=True)["rows"]


def verify(build_dir: Path) -> dict[str, Any]:
    manifest = json.loads((build_dir / "manifest.json").read_text(encoding="utf-8"))
    database_path = Path(manifest["database_path"])
    errors: list[str] = []
    checks: dict[str, Any] = {}

    with open_database(database_path) as client:
        actual_relations = relation_names(client)
        expected_relations = set(RELATION_SCHEMAS)
        checks["relations"] = sorted(actual_relations)
        if actual_relations != expected_relations:
            errors.append(
                f"schema mismatch: expected {sorted(expected_relations)}, "
                f"found {sorted(actual_relations)}"
            )

        source = _rows(
            client,
            "?[document_id, source_path, source_kind, title] := "
            "*source_document{document_id, source_path, source_kind, title}",
        )
        knowledge = _rows(
            client, "?[document_id] := *knowledge_document{document_id}"
        )
        categories = _rows(client, "?[category_id] := *category{category_id}")
        content = _rows(client, "?[document_id] := *document_content{document_id}")
        tags = _rows(client, "?[document_id, tag] := *document_tag{document_id, tag}")
        assignments = _rows(
            client,
            "?[document_id, category_id] := "
            "*document_category{document_id, category_id}",
        )
        sections = _rows(
            client,
            "?[document_id, ordinal, parent_ordinal] := "
            "*section{document_id, ordinal, parent_ordinal}",
        )
        links = _rows(
            client,
            "?[source_document_id, ordinal, link_kind, resolution_state, "
            "resolved_target_id] := *link_occurrence{source_document_id, ordinal, "
            "link_kind, resolution_state, resolved_target_id}",
        )
        runs = _rows(
            client,
            "?[run_id, source_root, source_fingerprint, logical_fingerprint, result] := "
            "*ingestion_run{run_id, source_root, source_fingerprint, "
            "logical_fingerprint, result}",
        )

        actual_counts = {
            "ingestion_run": len(runs),
            "source_document": len(source),
            "knowledge_document": len(knowledge),
            "category": len(categories),
            "document_content": len(content),
            "document_tag": len(tags),
            "document_category": len(assignments),
            "section": len(sections),
            "link_occurrence": len(links),
        }
        for state in ("resolved", "unresolved", "ambiguous", "excluded"):
            actual_counts[f"links_{state}"] = sum(row[3] == state for row in links)
        checks["counts"] = actual_counts
        for key, expected in manifest["counts"].items():
            if actual_counts.get(key, 0) != expected:
                errors.append(
                    f"count mismatch for {key}: expected {expected}, "
                    f"found {actual_counts.get(key, 0)}"
                )

        source_ids = {row[0] for row in source}
        source_paths = [row[1] for row in source]
        source_titles = [(str(row[2]), str(row[3]).casefold()) for row in source]
        knowledge_ids = {row[0] for row in knowledge}
        category_ids = {row[0] for row in categories}
        if len(source_paths) != len(set(source_paths)):
            errors.append("source paths are not unique")
        if len(source_titles) != len(set(source_titles)):
            errors.append("case-folded source titles within one source kind are not unique")
        if not knowledge_ids <= source_ids:
            errors.append("knowledge_document contains unknown document IDs")
        if not category_ids <= source_ids:
            errors.append("category contains unknown document IDs")
        if {row[0] for row in content} != source_ids:
            errors.append("document_content does not exactly cover source documents")
        if not {row[0] for row in tags} <= source_ids:
            errors.append("document_tag contains unknown document IDs")
        if not all(row[0] in source_ids and row[1] in category_ids for row in assignments):
            errors.append("document_category contains invalid references")

        section_keys = {(row[0], row[1]) for row in sections}
        if not all(row[0] in source_ids for row in sections):
            errors.append("section contains unknown document IDs")
        if not all(
            row[2] is None or (row[0], row[2]) in section_keys for row in sections
        ):
            errors.append("section contains invalid parent references")
        if not all(row[0] in source_ids for row in links):
            errors.append("link_occurrence contains unknown source document IDs")
        for source_id, _, link_kind, state, target_id in links:
            if state == "ambiguous":
                errors.append("ambiguous link occurrence reached a verified build")
            if target_id is not None and target_id not in source_ids:
                errors.append("link_occurrence resolved target is unknown")
            if (
                state == "resolved"
                and link_kind in {"internal", "same-document"}
                and target_id is None
            ):
                errors.append("resolved internal link is missing a target ID")
            if state in {"unresolved", "ambiguous", "excluded"} and target_id is not None:
                errors.append(f"{state} link unexpectedly has a target ID")
            if link_kind == "same-document" and target_id not in {None, source_id}:
                errors.append("same-document link resolves to another document")

        if len(runs) != 1:
            errors.append("expected exactly one ingestion_run")
        else:
            run = runs[0]
            expected_run = (
                manifest["run_id"],
                manifest["vault_root"],
                manifest["source_fingerprint"],
                manifest["logical_fingerprint"],
                manifest["ingestion_result"],
            )
            if tuple(str(value) for value in run) != tuple(
                str(value) for value in expected_run
            ):
                errors.append("ingestion_run does not match manifest")

        try:
            reachable = _rows(
                client,
                'root[id] := *source_document{document_id: id, title: "AI Context"}\n'
                "edge[from, to] := *link_occurrence{source_document_id: from, "
                'resolved_target_id: to, resolution_state: "resolved"}, '
                "*source_document{document_id: to}\n"
                "reachable[to] := root[to]\n"
                "reachable[to] := reachable[from], edge[from, to]\n"
                "?[count(id)] := reachable[id]",
            )
            checks["ai_context_reachable_documents"] = reachable[0][0] if reachable else 0
        except Exception as error:
            errors.append(f"recursive AI Context query failed: {error}")

    return {
        "schema_version": 1,
        "run_id": manifest["run_id"],
        "verified_at": __import__("datetime").datetime.now(
            __import__("datetime").UTC
        ).isoformat(),
        "valid": not errors,
        "errors": errors,
        "checks": checks,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Constrained HomeOps build verifier")
    parser.add_argument("--build-dir", type=Path, required=True)
    args = parser.parse_args()
    report = verify(args.build_dir.resolve())
    print(json.dumps(report, indent=2, default=str))
    raise SystemExit(0 if report["valid"] else 2)


if __name__ == "__main__":
    main()
