from pathlib import Path

import pytest

from homeops_ai.database import open_database
from homeops_ai.loader import LoadError, load_documents
from homeops_ai.markdown_parser import parse_sources
from homeops_ai.models import SourceFile
from homeops_ai.schema import RELATION_SCHEMAS, ensure_schema, relation_names


def _write_sources(vault: Path) -> list[SourceFile]:
    (vault / "Categories").mkdir()
    (vault / "Categories" / "AI.md").write_text(
        """---
id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
type: category
status: current
---
![[AI.base]]
"""
    )
    (vault / "Alpha.md").write_text(
        """---
id: "11111111-1111-4111-8111-111111111111"
categories:
  - "[[AI]]"
tags:
  - cozo
type: reference
status: current
authority: canonical
---
## Alpha

Links to [[Beta]], [[Known Outside]], and [[Missing]].
"""
    )
    (vault / "Beta.md").write_text(
        """---
id: "22222222-2222-4222-8222-222222222222"
type: reference
status: current
authority: supporting
---
## Beta

Backlink target.
"""
    )
    return [
        SourceFile("Alpha.md", "knowledge"),
        SourceFile("Beta.md", "knowledge"),
        SourceFile("Categories/AI.md", "category"),
    ]


def test_schema_creation_is_idempotent() -> None:
    with open_database() as client:
        ensure_schema(client)
        ensure_schema(client)
        assert relation_names(client) == set(RELATION_SCHEMAS)


def test_loader_populates_relations_resolves_links_and_is_idempotent(
    tmp_path: Path,
) -> None:
    documents = parse_sources(tmp_path, _write_sources(tmp_path))

    with open_database() as client:
        load_documents(client, documents, known_source_titles=["Known Outside"])
        load_documents(client, documents, known_source_titles=["Known Outside"])

        assert client.run("?[count(document_id)] := *source_document{document_id}")[
            "rows"
        ] == [[3]]
        assert client.run("?[count(document_id)] := *document_category{document_id}")[
            "rows"
        ] == [[1]]
        assert client.run(
            "?[raw_target, resolution_state] := "
            "*link_occurrence{raw_target, resolution_state}"
        )["rows"] == [
            ["AI.base", "excluded"],
            ["Beta", "resolved"],
            ["Known Outside", "excluded"],
            ["Missing", "unresolved"],
        ]


def test_loader_requires_document_ids(tmp_path: Path) -> None:
    (tmp_path / "No ID.md").write_text("# No ID\n")
    documents = parse_sources(
        tmp_path, [SourceFile("No ID.md", "knowledge")]
    )

    with open_database() as client, pytest.raises(LoadError, match="missing IDs"):
        load_documents(client, documents)


def test_links_prefer_knowledge_note_over_same_named_category(tmp_path: Path) -> None:
    (tmp_path / "Categories").mkdir()
    (tmp_path / "Categories" / "Home Assistant.md").write_text(
        """---
id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
type: category
status: current
---
"""
    )
    (tmp_path / "Home Assistant.md").write_text(
        """---
id: "11111111-1111-4111-8111-111111111111"
type: reference
status: current
authority: canonical
---
"""
    )
    (tmp_path / "Source.md").write_text(
        """---
id: "22222222-2222-4222-8222-222222222222"
categories:
  - "[[Home Assistant]]"
type: reference
status: current
authority: supporting
---
Links to [[Home Assistant]].
"""
    )
    documents = parse_sources(
        tmp_path,
        [
            SourceFile("Categories/Home Assistant.md", "category"),
            SourceFile("Home Assistant.md", "knowledge"),
            SourceFile("Source.md", "knowledge"),
        ],
    )

    with open_database() as client:
        load_documents(client, documents)
        assert client.run(
            "?[resolved_target_path] := *link_occurrence{resolved_target_path}"
        )["rows"] == [["Home Assistant.md"]]
