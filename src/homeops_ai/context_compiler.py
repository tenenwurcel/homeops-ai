import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from homeops_ai.database import open_database
from homeops_ai.query import (
    FORBIDDEN_GUIDANCE_STATUSES,
    QueryError,
    STOPWORDS,
    build_manifest,
    execute_query,
)


DEFAULT_MAX_DOCUMENTS = 5
DEFAULT_MAX_SECTIONS = 8
DEFAULT_MAX_CHARS = 6000
RISK_LEVELS = {"normal", "risky"}
COMPILER_WRAPPER_TERMS = {
    "bundle",
    "change",
    "changing",
    "context",
    "prepare",
    "smallest",
    "trustworthy",
}
LOW_INFORMATION_TERMS = {"current", "currently", "implemented", "running", "verified"}


class ContextCompilerError(RuntimeError):
    pass


def _validate_budgets(max_documents: int, max_sections: int, max_chars: int) -> None:
    if not 1 <= max_documents <= 25:
        raise ContextCompilerError("max_documents must be between 1 and 25")
    if not 1 <= max_sections <= 50:
        raise ContextCompilerError("max_sections must be between 1 and 50")
    if max_chars < 200:
        raise ContextCompilerError("max_chars must be at least 200")


def _section_bodies(manifest: dict[str, Any]) -> dict[tuple[str, int], str]:
    with open_database(Path(manifest["database_path"])) as client:
        rows = client.run(
            "?[document_id, ordinal, body] := *section{document_id, ordinal, body}",
            immutable=True,
        )["rows"]
    return {(str(document_id), ordinal): body for document_id, ordinal, body in rows}


def _candidate_sections(
    rows: list[dict[str, Any]],
    bodies: dict[tuple[str, int], str],
) -> list[dict[str, Any]]:
    candidates = []
    for document_rank, row in enumerate(rows, start=1):
        for section_rank, section in enumerate(row["evidence"], start=1):
            key = (row["document_id"], section["ordinal"])
            body = bodies.get(key)
            if body is None:
                raise ContextCompilerError(
                    f"section body missing for {row['source_path']} ordinal {section['ordinal']}"
                )
            candidates.append(
                {
                    "document_rank": document_rank,
                    "section_rank": section_rank,
                    "document": row,
                    "section": section,
                    "body": body,
                    "char_count": len(body),
                }
            )
    return candidates


def _selection_order(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # Select one best section per document before considering additional sections.
    return sorted(
        candidates,
        key=lambda item: (
            item["section_rank"] != 1,
            item["document_rank"],
            item["section_rank"],
            item["section"]["ordinal"],
        ),
    )


def _retrieval_question(question: str) -> str:
    words = re.findall(r"[A-Za-z0-9]+(?:[_.-][A-Za-z0-9]+)*", question)
    filtered = [
        word
        for word in words
        if word.casefold() not in COMPILER_WRAPPER_TERMS
        and word.casefold() not in STOPWORDS
    ]
    return " ".join(filtered) or question


def compile_context(
    data_dir: Path,
    question: str,
    *,
    risk_level: str,
    max_documents: int = DEFAULT_MAX_DOCUMENTS,
    max_sections: int = DEFAULT_MAX_SECTIONS,
    max_chars: int = DEFAULT_MAX_CHARS,
    run_id: str | None = None,
) -> dict[str, Any]:
    if not question.strip():
        raise ContextCompilerError("question must not be empty")
    if risk_level not in RISK_LEVELS:
        raise ContextCompilerError("risk_level must be normal or risky")
    _validate_budgets(max_documents, max_sections, max_chars)

    retrieval_question = _retrieval_question(question)
    manifest = build_manifest(data_dir, run_id)
    try:
        retrieval = execute_query(
            data_dir,
            "context",
            {"question": retrieval_question, "limit": "25"},
            run_id=manifest["run_id"],
        )
    except QueryError as error:
        raise ContextCompilerError(str(error)) from error
    candidates = _candidate_sections(retrieval["rows"], _section_bodies(manifest))

    selected = []
    selected_documents: set[str] = set()
    selected_terms: set[str] = set()
    has_canonical_current_state = False
    evidence_chars = 0
    omitted = defaultdict(int)
    for candidate in _selection_order(candidates):
        document = candidate["document"]
        document_id = document["document_id"]
        if document["status"] in FORBIDDEN_GUIDANCE_STATUSES:
            omitted["forbidden-lifecycle"] += 1
            continue
        matched_terms = {
            term
            for term in candidate["section"]["matched_terms"]
            if term not in LOW_INFORMATION_TERMS
        }
        adds_terms = bool(matched_terms - selected_terms)
        exact_title_anchor = (
            document_id not in selected_documents
            and document["title"].casefold() in retrieval_question.casefold()
        )
        canonical_current_state = (
            document["authority"] == "canonical"
            and document["status"] == "current"
            and document["document_type"] == "current-state"
        )
        required_for_trust = canonical_current_state and not has_canonical_current_state
        if selected and not adds_terms and not required_for_trust and not exact_title_anchor:
            omitted["redundant-evidence"] += 1
            continue
        if document_id not in selected_documents and len(selected_documents) >= max_documents:
            omitted["document-budget"] += 1
            continue
        if len(selected) >= max_sections:
            omitted["section-budget"] += 1
            continue
        if evidence_chars + candidate["char_count"] > max_chars:
            omitted["character-budget"] += 1
            continue
        selection_reasons = []
        if not selected:
            selection_reasons.append("highest-ranked evidence")
        if adds_terms:
            selection_reasons.append(
                "adds task terms: " + ", ".join(sorted(matched_terms - selected_terms))
            )
        if required_for_trust:
            selection_reasons.append("adds required canonical current-state evidence")
        if exact_title_anchor:
            selection_reasons.append("adds exact-title anchor evidence")
        candidate["selection_reasons"] = selection_reasons
        selected.append(candidate)
        selected_documents.add(document_id)
        selected_terms.update(matched_terms)
        has_canonical_current_state = has_canonical_current_state or canonical_current_state
        evidence_chars += candidate["char_count"]

    if not selected:
        raise ContextCompilerError(
            "budgets cannot fit any retrieved evidence section; increase max_chars"
        )

    by_document: dict[str, dict[str, Any]] = {}
    for candidate in selected:
        document = candidate["document"]
        entry = by_document.setdefault(
            document["document_id"],
            {
                "document_id": document["document_id"],
                "source_path": document["source_path"],
                "title": document["title"],
                "document_type": document["document_type"],
                "status": document["status"],
                "authority": document["authority"],
                "document_rank": candidate["document_rank"],
                "document_score": document["score"],
                "selection_reasons": list(candidate["selection_reasons"]),
                "sections": [],
            },
        )
        for reason in candidate["selection_reasons"]:
            if reason not in entry["selection_reasons"]:
                entry["selection_reasons"].append(reason)
        section = candidate["section"]
        entry["sections"].append(
            {
                "ordinal": section["ordinal"],
                "heading": section["heading"],
                "section_score": section["score"],
                "matched_terms": section["matched_terms"],
                "selection_reasons": candidate["selection_reasons"],
                "char_count": candidate["char_count"],
                "body": candidate["body"],
            }
        )

    documents = sorted(by_document.values(), key=lambda item: item["document_rank"])
    warnings = ["Compiled evidence is documented state; no live verification was performed."]
    if risk_level == "risky":
        warnings.append("Fresh live read-only discovery is required before mutation.")
    if any(document["authority"] != "canonical" for document in documents):
        warnings.append("Supporting evidence is included and does not override canonical state.")
    if omitted:
        warnings.append("Some ranked evidence was omitted by explicit bundle budgets.")

    known_gaps = []
    for document in documents:
        for section in document["sections"]:
            if (section["heading"] or "").casefold() == "known verification gaps":
                known_gaps.append(
                    {
                        "source_path": document["source_path"],
                        "ordinal": section["ordinal"],
                        "body": section["body"],
                    }
                )
    if risk_level == "risky" and not known_gaps:
        warnings.append(
            "No task-specific documented verification gap was selected; fresh discovery remains required."
        )

    return {
        "schema_version": 1,
        "bundle_kind": "homeops-context-bundle",
        "build": {
            "run_id": manifest["run_id"],
            "source_fingerprint": manifest["source_fingerprint"],
            "logical_fingerprint": manifest["logical_fingerprint"],
        },
        "request": {
            "question": question,
            "retrieval_question": retrieval_question,
            "risk_level": risk_level,
            "budgets": {
                "max_documents": max_documents,
                "max_sections": max_sections,
                "max_chars": max_chars,
            },
        },
        "trust_policy": {
            "authoritative_sources": "Markdown and verified live discovery",
            "excluded_lifecycle_states": sorted(FORBIDDEN_GUIDANCE_STATUSES),
            "generated_answer": False,
            "live_discovery_performed": False,
        },
        "live_verification": {
            "required": risk_level == "risky",
            "status": "required-before-mutation" if risk_level == "risky" else "not-required-by-request",
            "known_verification_gaps": known_gaps,
        },
        "selection": {
            "document_count": len(documents),
            "section_count": len(selected),
            "evidence_chars": evidence_chars,
            "retrieved_document_candidates": len(retrieval["rows"]),
            "retrieved_section_candidates": len(candidates),
            "omitted": dict(sorted(omitted.items())),
        },
        "documents": documents,
        "warnings": warnings,
    }


def write_bundle(bundle: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
