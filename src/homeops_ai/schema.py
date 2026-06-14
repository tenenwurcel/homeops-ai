from pycozo.client import Client


RELATION_SCHEMAS = {
    "ingestion_run": (
        ":create ingestion_run {"
        "run_id: Uuid => source_root: String, source_fingerprint: String, "
        "logical_fingerprint: String?, started_at: String, completed_at: String?, "
        "result: String, counts: Json"
        "}"
    ),
    "source_document": (
        ":create source_document {"
        "document_id: Uuid => source_path: String, source_kind: String, "
        "title: String, content_hash: String, raw_frontmatter: Json"
        "}"
    ),
    "knowledge_document": (
        ":create knowledge_document {"
        "document_id: Uuid => document_type: String?, status: String?, "
        "authority: String?, created_at: String?, updated_at: String?, "
        "last_verified_at: String?"
        "}"
    ),
    "category": (
        ":create category {"
        "category_id: Uuid => name: String, status: String?"
        "}"
    ),
    "document_content": (
        ":create document_content {document_id: Uuid => raw_markdown: String}"
    ),
    "document_tag": (
        ":create document_tag {document_id: Uuid, tag: String =>}"
    ),
    "document_category": (
        ":create document_category {"
        "document_id: Uuid, category_id: Uuid => raw_target: String"
        "}"
    ),
    "section": (
        ":create section {"
        "document_id: Uuid, ordinal: Int => parent_ordinal: Int?, "
        "heading_level: Int, heading: String?, body: String, content_hash: String"
        "}"
    ),
    "link_occurrence": (
        ":create link_occurrence {"
        "source_document_id: Uuid, ordinal: Int => source_section_ordinal: Int?, "
        "syntax: String, link_kind: String, raw_target: String, "
        "target_title: String?, target_heading: String?, target_block_id: String?, "
        "display_text: String?, is_embed: Bool, resolution_state: String, "
        "resolved_target_id: Uuid?, resolved_target_path: String?"
        "}"
    ),
}


def relation_names(client: Client) -> set[str]:
    return {row[0] for row in client.run("::relations")["rows"]}


def ensure_schema(client: Client) -> None:
    existing = relation_names(client)
    for name, statement in RELATION_SCHEMAS.items():
        if name not in existing:
            client.run(statement)
