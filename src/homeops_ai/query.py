import json
import re
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any, Callable

from homeops_ai.build import active_state
from homeops_ai.database import open_database


FORBIDDEN_GUIDANCE_STATUSES = {"historical", "superseded", "abandoned"}
STOPWORDS = {
    "all",
    "and",
    "are",
    "before",
    "does",
    "for",
    "from",
    "into",
    "its",
    "that",
    "the",
    "this",
    "what",
    "where",
    "which",
    "with",
}
LOW_SIGNAL_HEADINGS = {
    "ai sessions",
    "initial evaluation set",
    "links",
    "prompt",
    "sources",
}
CURRENT_INTENT_TERMS = {"current", "currently", "implemented", "running", "verified"}


class QueryError(RuntimeError):
    pass


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def build_manifest(data_dir: Path, run_id: str | None = None) -> dict[str, Any]:
    data = data_dir.resolve()
    selected = run_id or active_state(data).get("current")
    if not selected:
        raise QueryError("there is no active build to query")
    path = data / "builds" / selected / "manifest.json"
    if not path.is_file():
        raise QueryError(f"build manifest does not exist: {path}")
    manifest = _load_json(path)
    if manifest.get("result") != "verified":
        raise QueryError(f"build is not verified: {selected}")
    return manifest


def _select(client: Any, query: str, columns: list[str]) -> list[dict[str, Any]]:
    rows = client.run(query, immutable=True)["rows"]
    return [
        {column: str(value) if column.endswith("_id") and value is not None else value
         for column, value in zip(columns, row, strict=True)}
        for row in rows
    ]


def _documents(client: Any) -> list[dict[str, Any]]:
    return _select(
        client,
        "?[document_id, source_path, title, document_type, status, authority] := "
        "*source_document{document_id, source_path, title}, "
        "*knowledge_document{document_id, document_type, status, authority}",
        ["document_id", "source_path", "title", "document_type", "status", "authority"],
    )


def _sources(client: Any) -> list[dict[str, Any]]:
    return _select(
        client,
        "?[document_id, source_path, source_kind, title] := "
        "*source_document{document_id, source_path, source_kind, title}",
        ["document_id", "source_path", "source_kind", "title"],
    )


def _links(client: Any) -> list[dict[str, Any]]:
    return _select(
        client,
        "?[source_document_id, ordinal, link_kind, raw_target, resolution_state, "
        "resolved_target_id, resolved_target_path] := "
        "*link_occurrence{source_document_id, ordinal, link_kind, raw_target, "
        "resolution_state, resolved_target_id, resolved_target_path}",
        [
            "source_document_id",
            "ordinal",
            "link_kind",
            "raw_target",
            "resolution_state",
            "resolved_target_id",
            "resolved_target_path",
        ],
    )


def _sections(client: Any) -> list[dict[str, Any]]:
    return _select(
        client,
        "?[document_id, ordinal, heading, body] := "
        "*section{document_id, ordinal, heading, body}",
        ["document_id", "ordinal", "heading", "body"],
    )


def _content(client: Any) -> dict[str, str]:
    rows = _select(
        client,
        "?[document_id, raw_markdown] := *document_content{document_id, raw_markdown}",
        ["document_id", "raw_markdown"],
    )
    return {row["document_id"]: row["raw_markdown"] for row in rows}


def _result(rows: list[dict[str, Any]], summary: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"rows": rows, "summary": summary or {"row_count": len(rows)}}


def _canonical_current(client: Any, _: dict[str, str]) -> dict[str, Any]:
    rows = [
        document
        for document in _documents(client)
        if document["authority"] == "canonical" and document["status"] == "current"
    ]
    return _result(sorted(rows, key=lambda row: row["source_path"].casefold()))


def _links_to(client: Any, params: dict[str, str]) -> dict[str, Any]:
    title = params.get("title")
    if not title:
        raise QueryError("links-to requires parameter: title")
    sources = _sources(client)
    targets = [source for source in sources if source["title"].casefold() == title.casefold()]
    if len(targets) != 1:
        raise QueryError(f"expected exactly one source titled {title!r}, found {len(targets)}")
    target_id = targets[0]["document_id"]
    documents = {document["document_id"]: document for document in _documents(client)}
    linked = {
        link["source_document_id"]
        for link in _links(client)
        if link["resolution_state"] == "resolved" and link["resolved_target_id"] == target_id
    }
    rows = [documents[document_id] for document_id in linked if document_id in documents]
    return _result(sorted(rows, key=lambda row: row["source_path"].casefold()))


def _reachable_from(client: Any, params: dict[str, str]) -> dict[str, Any]:
    title = params.get("title")
    if not title:
        raise QueryError("reachable-from requires parameter: title")
    sources = _sources(client)
    roots = [source for source in sources if source["title"].casefold() == title.casefold()]
    if len(roots) != 1:
        raise QueryError(f"expected exactly one source titled {title!r}, found {len(roots)}")

    edges: dict[str, set[str]] = defaultdict(set)
    for link in _links(client):
        if link["resolution_state"] == "resolved" and link["resolved_target_id"]:
            edges[link["source_document_id"]].add(link["resolved_target_id"])
    reachable = {roots[0]["document_id"]}
    pending = deque(reachable)
    while pending:
        for target in edges[pending.popleft()]:
            if target not in reachable:
                reachable.add(target)
                pending.append(target)

    by_id = {source["document_id"]: source for source in sources}
    rows = [by_id[document_id] for document_id in reachable if document_id in by_id]
    return _result(sorted(rows, key=lambda row: row["source_path"].casefold()))


def _link_inventory(client: Any, _: dict[str, str]) -> dict[str, Any]:
    sources = {source["document_id"]: source for source in _sources(client)}
    rows = []
    for link in _links(client):
        source = sources[link["source_document_id"]]
        rows.append({"source_path": source["source_path"], "source_title": source["title"], **link})
    rows.sort(key=lambda row: (row["source_path"].casefold(), row["ordinal"]))
    by_resolution_state = Counter(row["resolution_state"] for row in rows)
    by_link_kind = Counter(row["link_kind"] for row in rows)
    return _result(
        rows,
        {
            "row_count": len(rows),
            "by_resolution_state": {
                state: by_resolution_state[state]
                for state in ("resolved", "unresolved", "ambiguous", "excluded")
            },
            "by_link_kind": {
                kind: by_link_kind[kind]
                for kind in ("internal", "same-document", "external", "attachment")
            },
        },
    )


def _missing_lifecycle(client: Any, _: dict[str, str]) -> dict[str, Any]:
    rows = [
        document
        for document in _documents(client)
        if any(document[field] is None for field in ("document_type", "status", "authority"))
    ]
    return _result(sorted(rows, key=lambda row: row["source_path"].casefold()))


def _guidance_conflicts(client: Any, _: dict[str, str]) -> dict[str, Any]:
    documents = {document["document_id"]: document for document in _documents(client)}
    canonical_current = {
        document_id
        for document_id, document in documents.items()
        if document["authority"] == "canonical" and document["status"] == "current"
    }
    connections: dict[str, set[str]] = defaultdict(set)
    for link in _links(client):
        source_id = link["source_document_id"]
        target_id = link["resolved_target_id"]
        if link["resolution_state"] != "resolved" or not target_id:
            continue
        if source_id in canonical_current:
            connections[target_id].add(source_id)
        if target_id in canonical_current:
            connections[source_id].add(target_id)

    rows = []
    for document_id, connected_ids in connections.items():
        document = documents.get(document_id)
        if not document or document["status"] not in FORBIDDEN_GUIDANCE_STATUSES:
            continue
        rows.append(
            {
                **document,
                "connected_current_paths": sorted(documents[item]["source_path"] for item in connected_ids),
            }
        )
    return _result(sorted(rows, key=lambda row: row["source_path"].casefold()))


def _terms(question: str) -> list[str]:
    words = re.findall(r"[a-z0-9]+(?:[_.-][a-z0-9]+)*", question.casefold())
    return sorted({word for word in words if (len(word) >= 3 or word == "not") and word not in STOPWORDS})


def _excerpt(body: str, terms: list[str], limit: int = 360) -> str:
    compact = " ".join(body.split())
    positions = [compact.casefold().find(term) for term in terms]
    positions = [position for position in positions if position >= 0]
    start = max(0, (min(positions) if positions else 0) - 80)
    excerpt = compact[start : start + limit]
    if start:
        excerpt = "..." + excerpt
    if start + limit < len(compact):
        excerpt += "..."
    return excerpt


def _context(client: Any, params: dict[str, str]) -> dict[str, Any]:
    question = params.get("question")
    if not question:
        raise QueryError("context requires parameter: question")
    try:
        limit = int(params.get("limit", "5"))
    except ValueError as error:
        raise QueryError("context limit must be an integer") from error
    if limit < 1 or limit > 25:
        raise QueryError("context limit must be between 1 and 25")

    terms = _terms(question)
    if not terms:
        raise QueryError("context question contains no searchable terms")
    current_intent = bool(CURRENT_INTENT_TERMS.intersection(terms))
    contents = _content(client)
    sections: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for section in _sections(client):
        sections[section["document_id"]].append(section)

    ranked = []
    for document in _documents(client):
        if document["status"] in FORBIDDEN_GUIDANCE_STATUSES:
            continue
        title = document["title"].casefold()
        raw = contents.get(document["document_id"], "").casefold()
        matched = [term for term in terms if term in title or term in raw]
        if not matched:
            continue
        title_score = sum(18 for term in terms if term in title)
        evidence = []
        for section in sections.get(document["document_id"], []):
            heading = (section["heading"] or "").casefold()
            if heading in LOW_SIGNAL_HEADINGS:
                continue
            text = f"{heading} {section['body']}".casefold()
            section_matches = [term for term in terms if term in text]
            if section_matches:
                section_score = (
                    len(section_matches) * 4
                    + sum(8 for term in terms if term in heading)
                    + min(sum(text.count(term) for term in section_matches), 6)
                )
                evidence.append(
                    {
                        "ordinal": section["ordinal"],
                        "heading": section["heading"],
                        "matched_terms": section_matches,
                        "excerpt": _excerpt(section["body"], section_matches),
                        "score": section_score,
                    }
                )
        evidence.sort(key=lambda item: (-item["score"], item["ordinal"]))
        authority_score = (
            10
            if document["authority"] == "canonical"
            else 2 if document["authority"] == "supporting" else 0
        )
        status_score = {
            "current": 8,
            "in-progress": 4,
            "planned": 2,
            "done": -4,
        }.get(document["status"], 0)
        current_intent_score = 0
        if current_intent:
            if document["document_type"] == "current-state":
                current_intent_score += 24
            if document["document_type"] in {"plan", "runbook"}:
                current_intent_score -= 12
            if document["status"] == "done":
                current_intent_score -= 8
        section_score = evidence[0]["score"] if evidence else 0
        score = title_score + section_score + authority_score + status_score + current_intent_score
        ranked.append(
            {
                **document,
                "score": score,
                "score_components": {
                    "title": title_score,
                    "best_section": section_score,
                    "authority": authority_score,
                    "status": status_score,
                    "current_intent": current_intent_score,
                },
                "matched_terms": matched,
                "evidence": evidence[:3],
            }
        )

    ranked.sort(key=lambda row: (-row["score"], row["source_path"].casefold()))
    return _result(ranked[:limit], {"row_count": min(len(ranked), limit), "search_terms": terms, "candidate_count": len(ranked)})


QUERY_HANDLERS: dict[str, Callable[[Any, dict[str, str]], dict[str, Any]]] = {
    "canonical-current": _canonical_current,
    "context": _context,
    "guidance-conflicts": _guidance_conflicts,
    "link-inventory": _link_inventory,
    "links-to": _links_to,
    "missing-lifecycle": _missing_lifecycle,
    "reachable-from": _reachable_from,
}


def query_names() -> list[str]:
    return sorted(QUERY_HANDLERS)


def execute_query(
    data_dir: Path,
    name: str,
    params: dict[str, str] | None = None,
    *,
    run_id: str | None = None,
) -> dict[str, Any]:
    if name not in QUERY_HANDLERS:
        raise QueryError(f"unknown query {name!r}; choose from: {', '.join(query_names())}")
    manifest = build_manifest(data_dir, run_id)
    with open_database(Path(manifest["database_path"])) as client:
        result = QUERY_HANDLERS[name](client, params or {})
    return {
        "schema_version": 1,
        "run_id": manifest["run_id"],
        "query": name,
        "parameters": params or {},
        **result,
    }
