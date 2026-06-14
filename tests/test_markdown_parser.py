from pathlib import Path

from homeops_ai.markdown_parser import parse_source
from homeops_ai.models import SourceFile


def test_parser_builds_sections_metadata_and_categories(tmp_path: Path) -> None:
    (tmp_path / "Note.md").write_text(
        """---
id: "11111111-1111-4111-8111-111111111111"
categories:
  - "[[AI]]"
tags:
  - cozo
type: reference
status: current
authority: supporting
---
Preamble.

## Parent

Parent body.

### Child

Child body.
"""
    )

    parsed = parse_source(tmp_path, SourceFile("Note.md", "knowledge"))

    assert parsed.document_id == "11111111-1111-4111-8111-111111111111"
    assert parsed.raw_frontmatter["categories"] == ["[[AI]]"]
    assert parsed.tags == ["cozo"]
    assert [item.target_title for item in parsed.categories] == ["AI"]
    assert [(section.heading, section.parent_ordinal) for section in parsed.sections] == [
        (None, None),
        ("Parent", None),
        ("Child", 1),
    ]


def test_parser_classifies_links_and_ignores_code_and_comments(tmp_path: Path) -> None:
    (tmp_path / "Note.md").write_text(
        """---
id: "11111111-1111-4111-8111-111111111111"
---
## Links

The [[Application Host|application host]] runs `[[not a link]]`.
The [[Mikrotik Router\\|RB5009]] routes traffic.
See [[#Local heading]], ![[image.png]], and [Cozo](https://www.cozodb.org/).
See [config](ventisol-rf-gateway.yaml) and [local](Other.md).
%% [[commented link]] %%
<!-- [[html commented link]] -->

```text
[[fenced link]]
```
"""
    )

    parsed = parse_source(tmp_path, SourceFile("Note.md", "knowledge"))

    assert [
        (
            link.syntax,
            link.link_kind,
            link.target_title,
            link.target_heading,
            link.display_text,
            link.is_embed,
        )
        for link in parsed.links
    ] == [
        ("wikilink", "internal", "Application Host", None, "application host", False),
        ("wikilink", "internal", "Mikrotik Router", None, "RB5009", False),
        ("wikilink", "same-document", None, "Local heading", None, False),
        ("wikilink", "attachment", "image.png", None, None, True),
        ("markdown", "external", None, None, "Cozo", False),
        ("markdown", "attachment", None, None, "config", False),
        ("markdown", "internal", "Other.md", None, "local", False),
    ]


def test_duplicate_headings_preserve_distinct_section_order(tmp_path: Path) -> None:
    (tmp_path / "Note.md").write_text(
        "## Repeat\n\nFirst.\n\n## Repeat\n\nSecond.\n"
    )

    parsed = parse_source(tmp_path, SourceFile("Note.md", "knowledge"))

    assert [(item.ordinal, item.heading, item.body) for item in parsed.sections] == [
        (0, "Repeat", "\nFirst.\n\n"),
        (1, "Repeat", "\nSecond.\n"),
    ]


def test_legacy_bare_categories_are_preserved_with_warning(tmp_path: Path) -> None:
    (tmp_path / "Note.md").write_text(
        """---
categories:
  - Smarthome
---
# Note
"""
    )

    parsed = parse_source(tmp_path, SourceFile("Note.md", "knowledge"))

    assert [item.target_title for item in parsed.categories] == ["Smarthome"]
    assert [warning.code for warning in parsed.warnings] == ["legacy-bare-category"]
