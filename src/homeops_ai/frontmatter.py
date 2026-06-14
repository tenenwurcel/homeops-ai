from dataclasses import dataclass
from io import StringIO
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap


class FrontmatterError(ValueError):
    pass


@dataclass
class MarkdownDocument:
    frontmatter: CommentedMap
    body: str
    had_frontmatter: bool


def _yaml() -> YAML:
    parser = YAML(typ="rt")
    parser.preserve_quotes = True
    parser.width = 4096
    parser.indent(mapping=2, sequence=4, offset=2)
    return parser


def parse_markdown(text: str) -> MarkdownDocument:
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].rstrip("\r\n") != "---":
        return MarkdownDocument(CommentedMap(), text, had_frontmatter=False)

    closing_index = next(
        (
            index
            for index, line in enumerate(lines[1:], start=1)
            if line.rstrip("\r\n") == "---"
        ),
        None,
    )
    if closing_index is None:
        raise FrontmatterError("frontmatter starts with '---' but has no closing '---'")

    raw_yaml = "".join(lines[1:closing_index])
    try:
        parsed: Any = _yaml().load(raw_yaml)
    except Exception as error:
        raise FrontmatterError(f"invalid YAML frontmatter: {error}") from error

    if parsed is None:
        frontmatter = CommentedMap()
    elif isinstance(parsed, CommentedMap):
        frontmatter = parsed
    elif isinstance(parsed, dict):
        frontmatter = CommentedMap(parsed)
    else:
        raise FrontmatterError("frontmatter must be a YAML mapping")

    return MarkdownDocument(frontmatter, "".join(lines[closing_index + 1 :]), True)


def render_markdown(document: MarkdownDocument) -> str:
    stream = StringIO()
    _yaml().dump(document.frontmatter, stream)
    rendered_yaml = stream.getvalue()
    return f"---\n{rendered_yaml}---\n{document.body}"
