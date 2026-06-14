from collections import defaultdict
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Iterable

from pycozo.client import Client

from homeops_ai.models import LinkOccurrence, ParsedSourceDocument
from homeops_ai.schema import ensure_schema


class LoadError(ValueError):
    pass


@dataclass(frozen=True)
class ResolvedLink:
    state: str
    target_id: str | None
    target_path: str | None


def _put(
    client: Client,
    *,
    relation: str,
    columns: list[str],
    keys: list[str],
    rows: list[list[Any]],
    uuid_columns: set[str] = frozenset(),
    nullable_uuid_columns: set[str] = frozenset(),
) -> None:
    if not rows:
        return
    raw_columns = [
        f"raw_{column}" if column in uuid_columns else column for column in columns
    ]
    assignments = []
    for column in columns:
        if column in nullable_uuid_columns:
            assignments.append(
                f"{column} = if(is_null(raw_{column}), null, to_uuid(raw_{column}))"
            )
        elif column in uuid_columns:
            assignments.append(f"{column} = to_uuid(raw_{column})")
    rule_body = f"input[{', '.join(raw_columns)}]"
    if assignments:
        rule_body += ", " + ", ".join(assignments)
    values = ", ".join(columns)
    non_keys = [column for column in columns if column not in keys]
    put_shape = ", ".join(keys)
    if non_keys:
        put_shape += " => " + ", ".join(non_keys)
    query = (
        f"input[{', '.join(raw_columns)}] <- $rows\n"
        f"?[{values}] := {rule_body}\n"
        f":put {relation} {{{put_shape}}}"
    )
    client.run(query, {"rows": rows})


def _validate_documents(documents: list[ParsedSourceDocument]) -> None:
    missing_ids = [document.source_path for document in documents if not document.document_id]
    if missing_ids:
        raise LoadError("documents are missing IDs: " + ", ".join(missing_ids))

    by_id: dict[str, str] = {}
    by_path: set[str] = set()
    for document in documents:
        assert document.document_id is not None
        if document.document_id in by_id:
            raise LoadError(
                f"duplicate document ID in {document.source_path} and "
                f"{by_id[document.document_id]}"
            )
        if document.source_path in by_path:
            raise LoadError(f"duplicate source path: {document.source_path}")
        by_id[document.document_id] = document.source_path
        by_path.add(document.source_path)


def _title_key(value: str) -> str:
    title = PurePosixPath(value).name
    if title.lower().endswith(".md"):
        title = title[:-3]
    return title.casefold()


def _title_index(
    documents: Iterable[ParsedSourceDocument],
) -> dict[str, list[ParsedSourceDocument]]:
    index: dict[str, list[ParsedSourceDocument]] = defaultdict(list)
    for document in documents:
        index[_title_key(document.title)].append(document)
    return index


def _resolve_link(
    link: LinkOccurrence,
    source: ParsedSourceDocument,
    selected_titles: dict[str, list[ParsedSourceDocument]],
    known_titles: set[str],
) -> ResolvedLink:
    if link.link_kind == "external":
        return ResolvedLink("resolved", None, None)
    if link.link_kind == "attachment":
        return ResolvedLink("excluded", None, None)
    if link.link_kind == "same-document":
        return ResolvedLink("resolved", source.document_id, source.source_path)
    if link.target_title is None:
        return ResolvedLink("unresolved", None, None)

    matches = selected_titles.get(_title_key(link.target_title), [])
    knowledge_matches = [
        document for document in matches if document.source_kind == "knowledge"
    ]
    if len(knowledge_matches) == 1:
        target = knowledge_matches[0]
        return ResolvedLink("resolved", target.document_id, target.source_path)
    if len(knowledge_matches) > 1:
        return ResolvedLink("ambiguous", None, None)
    if len(matches) == 1:
        target = matches[0]
        return ResolvedLink("resolved", target.document_id, target.source_path)
    if len(matches) > 1:
        return ResolvedLink("ambiguous", None, None)
    if _title_key(link.target_title) in known_titles:
        return ResolvedLink("excluded", None, None)
    return ResolvedLink("unresolved", None, None)


def load_documents(
    client: Client,
    documents: Iterable[ParsedSourceDocument],
    *,
    known_source_titles: Iterable[str] = (),
) -> None:
    selected = list(documents)
    _validate_documents(selected)
    ensure_schema(client)
    title_index = _title_index(selected)
    known_titles = {_title_key(title) for title in known_source_titles}

    _put(
        client,
        relation="source_document",
        columns=[
            "document_id",
            "source_path",
            "source_kind",
            "title",
            "content_hash",
            "raw_frontmatter",
        ],
        keys=["document_id"],
        uuid_columns={"document_id"},
        rows=[
            [
                document.document_id,
                document.source_path,
                document.source_kind,
                document.title,
                document.content_hash,
                document.raw_frontmatter,
            ]
            for document in selected
        ],
    )
    _put(
        client,
        relation="document_content",
        columns=["document_id", "raw_markdown"],
        keys=["document_id"],
        uuid_columns={"document_id"},
        rows=[[document.document_id, document.raw_markdown] for document in selected],
    )
    _put(
        client,
        relation="knowledge_document",
        columns=[
            "document_id",
            "document_type",
            "status",
            "authority",
            "created_at",
            "updated_at",
            "last_verified_at",
        ],
        keys=["document_id"],
        uuid_columns={"document_id"},
        rows=[
            [
                document.document_id,
                document.document_type,
                document.status,
                document.authority,
                document.created_at,
                document.updated_at,
                document.last_verified_at,
            ]
            for document in selected
            if document.source_kind == "knowledge"
        ],
    )
    _put(
        client,
        relation="category",
        columns=["category_id", "name", "status"],
        keys=["category_id"],
        uuid_columns={"category_id"},
        rows=[
            [document.document_id, document.title, document.status]
            for document in selected
            if document.source_kind == "category"
        ],
    )
    _put(
        client,
        relation="document_tag",
        columns=["document_id", "tag"],
        keys=["document_id", "tag"],
        uuid_columns={"document_id"},
        rows=[
            [document.document_id, tag]
            for document in selected
            for tag in document.tags
        ],
    )

    category_index = {
        _title_key(document.title): document
        for document in selected
        if document.source_kind == "category"
    }
    _put(
        client,
        relation="document_category",
        columns=["document_id", "category_id", "raw_target"],
        keys=["document_id", "category_id"],
        uuid_columns={"document_id", "category_id"},
        rows=[
            [
                document.document_id,
                category_index[_title_key(assignment.target_title)].document_id,
                assignment.raw_target,
            ]
            for document in selected
            for assignment in document.categories
            if _title_key(assignment.target_title) in category_index
        ],
    )
    _put(
        client,
        relation="section",
        columns=[
            "document_id",
            "ordinal",
            "parent_ordinal",
            "heading_level",
            "heading",
            "body",
            "content_hash",
        ],
        keys=["document_id", "ordinal"],
        uuid_columns={"document_id"},
        rows=[
            [
                document.document_id,
                section.ordinal,
                section.parent_ordinal,
                section.heading_level,
                section.heading,
                section.body,
                section.content_hash,
            ]
            for document in selected
            for section in document.sections
        ],
    )

    link_rows = []
    for document in selected:
        for link in document.links:
            resolution = _resolve_link(link, document, title_index, known_titles)
            link_rows.append(
                [
                    document.document_id,
                    link.ordinal,
                    link.source_section_ordinal,
                    link.syntax,
                    link.link_kind,
                    link.raw_target,
                    link.target_title,
                    link.target_heading,
                    link.target_block_id,
                    link.display_text,
                    link.is_embed,
                    resolution.state,
                    resolution.target_id,
                    resolution.target_path,
                ]
            )
    _put(
        client,
        relation="link_occurrence",
        columns=[
            "source_document_id",
            "ordinal",
            "source_section_ordinal",
            "syntax",
            "link_kind",
            "raw_target",
            "target_title",
            "target_heading",
            "target_block_id",
            "display_text",
            "is_embed",
            "resolution_state",
            "resolved_target_id",
            "resolved_target_path",
        ],
        keys=["source_document_id", "ordinal"],
        uuid_columns={"source_document_id", "resolved_target_id"},
        nullable_uuid_columns={"resolved_target_id"},
        rows=link_rows,
    )


def load_ingestion_run(
    client: Client,
    *,
    run_id: str,
    source_root: str,
    source_fingerprint: str,
    logical_fingerprint: str,
    started_at: str,
    completed_at: str,
    result: str,
    counts: dict[str, Any],
) -> None:
    ensure_schema(client)
    _put(
        client,
        relation="ingestion_run",
        columns=[
            "run_id",
            "source_root",
            "source_fingerprint",
            "logical_fingerprint",
            "started_at",
            "completed_at",
            "result",
            "counts",
        ],
        keys=["run_id"],
        uuid_columns={"run_id"},
        rows=[
            [
                run_id,
                source_root,
                source_fingerprint,
                logical_fingerprint,
                started_at,
                completed_at,
                result,
                counts,
            ]
        ],
    )
