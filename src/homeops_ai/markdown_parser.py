import hashlib
import re
from pathlib import Path, PurePosixPath
from typing import Any, Iterable
from urllib.parse import urlparse

from markdown_it import MarkdownIt
from markdown_it.rules_inline import StateInline
from markdown_it.token import Token

from homeops_ai.frontmatter import FrontmatterError, parse_markdown
from homeops_ai.models import (
    CategoryAssignment,
    LinkKind,
    LinkOccurrence,
    ParsedSourceDocument,
    SectionRecord,
    SourceFile,
    ValidationIssue,
)


ATTACHMENT_EXTENSIONS = {
    ".base",
    ".bmp",
    ".csv",
    ".gif",
    ".h",
    ".ino",
    ".jpeg",
    ".jpg",
    ".json",
    ".log",
    ".pdf",
    ".png",
    ".svg",
    ".webp",
    ".yaml",
    ".yml",
}


def _sha256_text(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _comment_rule(state: StateInline, silent: bool) -> bool:
    if not state.src.startswith("%%", state.pos):
        return False
    end = state.src.find("%%", state.pos + 2)
    if end < 0:
        end = state.posMax - 2
    if not silent:
        token = state.push("obsidian_comment", "", 0)
        token.content = state.src[state.pos : end + 2]
    state.pos = min(end + 2, state.posMax)
    return True


def _wikilink_rule(state: StateInline, silent: bool) -> bool:
    start = state.pos
    is_embed = state.src.startswith("![[", start)
    prefix_length = 3 if is_embed else 2
    if not is_embed and not state.src.startswith("[[", start):
        return False

    end = state.src.find("]]", start + prefix_length)
    if end < 0:
        return False
    if not silent:
        token = state.push("wikilink", "", 0)
        token.content = state.src[start + prefix_length : end]
        token.meta = {"is_embed": is_embed}
    state.pos = end + 2
    return True


def create_markdown_parser() -> MarkdownIt:
    parser = MarkdownIt("commonmark", {"html": True})
    parser.inline.ruler.before("backticks", "obsidian_comment", _comment_rule)
    parser.inline.ruler.after("backticks", "wikilink", _wikilink_rule)
    return parser


def _plain_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _plain_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_plain_json(item) for item in value]
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return str(value)


def _string_list(value: Any, field: str, source_path: str) -> tuple[list[str], list[ValidationIssue]]:
    if value is None:
        return [], []
    if not isinstance(value, list):
        return (
            [],
            [
                ValidationIssue(
                    "warning",
                    f"{field}-not-list",
                    source_path,
                    f"{field} is not a YAML list and was not expanded",
                )
            ],
        )
    return [str(item) for item in value], []


def _split_alias(raw: str) -> tuple[str, str | None]:
    match = re.search(r"\\?\|", raw)
    if match is None:
        return raw, None
    target = raw[: match.start()]
    display = raw[match.end() :]
    return target, display or None


def _split_wiki_target(
    raw: str,
) -> tuple[str | None, str | None, str | None, str | None]:
    target, display = _split_alias(raw)
    title = target
    heading = None
    block_id = None
    if "#^" in target:
        title, block_id = target.split("#^", 1)
    elif "#" in target:
        title, heading = target.split("#", 1)
    return title or None, heading or None, block_id or None, display


def _classify_target(target: str | None, syntax: str) -> LinkKind:
    if target is None or target.startswith("#"):
        return "same-document"
    parsed = urlparse(target)
    if parsed.scheme in {"http", "https"}:
        return "external"
    suffix = PurePosixPath(target.split("#", 1)[0]).suffix.lower()
    if suffix == ".md" or not suffix:
        return "internal"
    if suffix in ATTACHMENT_EXTENSIONS or syntax == "markdown":
        return "attachment"
    return "attachment"


def _inline_links(
    source_path: str,
    section_ordinal: int | None,
    children: list[Token],
    starting_ordinal: int,
) -> list[LinkOccurrence]:
    links: list[LinkOccurrence] = []
    active_href: str | None = None
    active_text: list[str] = []
    for token in children:
        if token.type == "link_open":
            active_href = token.attrGet("href")
            active_text = []
        elif token.type == "link_close" and active_href is not None:
            link_kind = _classify_target(active_href, "markdown")
            target_title = None
            target_heading = None
            if link_kind == "internal":
                target_title = active_href.split("#", 1)[0] or None
                if "#" in active_href:
                    target_heading = active_href.split("#", 1)[1] or None
            elif link_kind == "same-document":
                target_heading = active_href[1:] or None
            links.append(
                LinkOccurrence(
                    source_path=source_path,
                    ordinal=starting_ordinal + len(links),
                    source_section_ordinal=section_ordinal,
                    syntax="markdown",
                    link_kind=link_kind,
                    raw_target=active_href,
                    target_title=target_title,
                    target_heading=target_heading,
                    target_block_id=None,
                    display_text="".join(active_text) or None,
                    is_embed=False,
                )
            )
            active_href = None
            active_text = []
        elif active_href is not None and token.type in {"text", "code_inline"}:
            active_text.append(token.content)
        elif token.type == "wikilink":
            title, heading, block_id, display = _split_wiki_target(token.content)
            target_for_classification = title
            if title is None and (heading or block_id):
                target_for_classification = None
            links.append(
                LinkOccurrence(
                    source_path=source_path,
                    ordinal=starting_ordinal + len(links),
                    source_section_ordinal=section_ordinal,
                    syntax="wikilink",
                    link_kind=_classify_target(target_for_classification, "wikilink"),
                    raw_target=token.content,
                    target_title=title,
                    target_heading=heading,
                    target_block_id=block_id,
                    display_text=display,
                    is_embed=bool((token.meta or {}).get("is_embed")),
                )
            )
    return links


def _sections(body: str, tokens: list[Token], source_path: str) -> list[SectionRecord]:
    lines = body.splitlines(keepends=True)
    headings: list[tuple[int, int, str]] = []
    for index, token in enumerate(tokens):
        if token.type != "heading_open" or token.map is None:
            continue
        inline = tokens[index + 1]
        level = int(token.tag[1:])
        headings.append((token.map[0], level, inline.content))

    records: list[SectionRecord] = []
    if not headings or any(line.strip() for line in lines[: headings[0][0]]):
        end = headings[0][0] if headings else len(lines)
        preamble = "".join(lines[:end])
        if preamble:
            records.append(
                SectionRecord(
                    source_path,
                    ordinal=0,
                    parent_ordinal=None,
                    heading_level=0,
                    heading=None,
                    body=preamble,
                    content_hash=_sha256_text(preamble),
                )
            )

    stack: list[tuple[int, int]] = []
    ordinal_offset = len(records)
    for position, (line_number, level, heading) in enumerate(headings):
        next_line = headings[position + 1][0] if position + 1 < len(headings) else len(lines)
        body_start = line_number + 1
        section_body = "".join(lines[body_start:next_line])
        while stack and stack[-1][0] >= level:
            stack.pop()
        ordinal = ordinal_offset + position
        parent = stack[-1][1] if stack else None
        records.append(
            SectionRecord(
                source_path,
                ordinal=ordinal,
                parent_ordinal=parent,
                heading_level=level,
                heading=heading,
                body=section_body,
                content_hash=_sha256_text(section_body),
            )
        )
        stack.append((level, ordinal))
    return records


def _section_starts(
    sections: list[SectionRecord], tokens: list[Token]
) -> list[tuple[int, int]]:
    starts = (
        [(0, sections[0].ordinal)]
        if sections and sections[0].heading is None
        else []
    )
    heading_sections = iter(section for section in sections if section.heading is not None)
    for token in tokens:
        if token.type == "heading_open" and token.map is not None:
            section = next(heading_sections)
            starts.append((token.map[0], section.ordinal))
    return starts


def _section_for_line(starts: list[tuple[int, int]], line: int) -> int | None:
    applicable = [ordinal for start, ordinal in starts if start <= line]
    return applicable[-1] if applicable else None


def _link_occurrences(
    tokens: list[Token], sections: list[SectionRecord], source_path: str
) -> list[LinkOccurrence]:
    links: list[LinkOccurrence] = []
    section_starts = _section_starts(sections, tokens)
    for token in tokens:
        if token.type != "inline" or not token.children:
            continue
        line = token.map[0] if token.map is not None else 0
        section_ordinal = _section_for_line(section_starts, line)
        links.extend(
            _inline_links(
                source_path,
                section_ordinal,
                token.children,
                starting_ordinal=len(links),
            )
        )
    return links


def _category_assignments(
    value: Any, source_path: str
) -> tuple[list[CategoryAssignment], list[ValidationIssue]]:
    categories, warnings = _string_list(value, "categories", source_path)
    assignments: list[CategoryAssignment] = []
    for ordinal, raw in enumerate(categories):
        if raw.startswith("[[") and raw.endswith("]]"):
            title, _, _, _ = _split_wiki_target(raw[2:-2])
        else:
            warnings.append(
                ValidationIssue(
                    "warning",
                    "legacy-bare-category",
                    source_path,
                    "category is a legacy bare name rather than an Obsidian wiki link",
                )
            )
            title = raw.strip() or None
        if title is None:
            warnings.append(
                ValidationIssue(
                    "warning",
                    "category-missing-title",
                    source_path,
                    "category wiki link has no target title and was skipped",
                )
            )
            continue
        assignments.append(CategoryAssignment(source_path, ordinal, raw, title))
    return assignments, warnings


def parse_source(vault_root: Path, source: SourceFile) -> ParsedSourceDocument:
    path = vault_root / source.source_path
    raw_bytes = path.read_bytes()
    try:
        raw_markdown = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{source.source_path}: source is not valid UTF-8") from error
    try:
        document = parse_markdown(raw_markdown)
    except FrontmatterError as error:
        raise ValueError(f"{source.source_path}: {error}") from error

    parser = create_markdown_parser()
    tokens = parser.parse(document.body)
    sections = _sections(document.body, tokens, source.source_path)
    links = _link_occurrences(tokens, sections, source.source_path)
    tags, tag_warnings = _string_list(
        document.frontmatter.get("tags"), "tags", source.source_path
    )
    categories, category_warnings = _category_assignments(
        document.frontmatter.get("categories"), source.source_path
    )

    return ParsedSourceDocument(
        source_path=source.source_path,
        source_kind=source.kind,
        document_id=document.frontmatter.get("id"),
        title=Path(source.source_path).stem,
        document_type=document.frontmatter.get("type"),
        status=document.frontmatter.get("status"),
        authority=document.frontmatter.get("authority"),
        created_at=str(document.frontmatter.get("date"))
        if document.frontmatter.get("date") is not None
        else None,
        updated_at=str(document.frontmatter.get("updated"))
        if document.frontmatter.get("updated") is not None
        else None,
        last_verified_at=str(document.frontmatter.get("last_verified"))
        if document.frontmatter.get("last_verified") is not None
        else None,
        content_hash=hashlib.sha256(raw_bytes).hexdigest(),
        raw_markdown=raw_markdown,
        raw_frontmatter=_plain_json(document.frontmatter),
        tags=tags,
        categories=categories,
        sections=sections,
        links=links,
        warnings=tag_warnings + category_warnings,
    )


def parse_sources(vault_root: Path, sources: Iterable[SourceFile]) -> list[ParsedSourceDocument]:
    return [parse_source(vault_root, source) for source in sources]
