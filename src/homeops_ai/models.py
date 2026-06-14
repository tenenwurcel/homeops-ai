from dataclasses import asdict, dataclass, field
from typing import Any, Literal


SourceKind = Literal["knowledge", "category"]
Severity = Literal["warning", "error"]
LinkSyntax = Literal["wikilink", "markdown"]
LinkKind = Literal["internal", "external", "attachment", "same-document"]


@dataclass(frozen=True)
class SourceFile:
    source_path: str
    kind: SourceKind


@dataclass(frozen=True)
class ValidationIssue:
    severity: Severity
    code: str
    source_path: str
    message: str


@dataclass
class FileMigration:
    source_path: str
    source_kind: SourceKind
    before_sha256: str
    after_sha256: str
    proposed_id: str
    changes: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[ValidationIssue] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return self.before_sha256 != self.after_sha256

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["changed"] = self.changed
        return data


@dataclass
class MigrationReport:
    schema_version: int
    migration_id: str
    created_at: str
    vault_root: str
    include_uppercase_markdown: bool
    files: list[FileMigration]
    issues: list[ValidationIssue] = field(default_factory=list)

    @property
    def errors(self) -> list[ValidationIssue]:
        return [issue for issue in self.issues if issue.severity == "error"]

    @property
    def warnings(self) -> list[ValidationIssue]:
        return [issue for issue in self.issues if issue.severity == "warning"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "migration_id": self.migration_id,
            "created_at": self.created_at,
            "vault_root": self.vault_root,
            "include_uppercase_markdown": self.include_uppercase_markdown,
            "summary": {
                "eligible_files": len(self.files),
                "changed_files": sum(item.changed for item in self.files),
                "unchanged_files": sum(not item.changed for item in self.files),
                "warnings": len(self.warnings)
                + sum(len(item.warnings) for item in self.files),
                "errors": len(self.errors),
            },
            "issues": [asdict(issue) for issue in self.issues],
            "files": [item.to_dict() for item in self.files],
        }


@dataclass(frozen=True)
class SectionRecord:
    source_path: str
    ordinal: int
    parent_ordinal: int | None
    heading_level: int
    heading: str | None
    body: str
    content_hash: str


@dataclass(frozen=True)
class CategoryAssignment:
    source_path: str
    ordinal: int
    raw_target: str
    target_title: str


@dataclass(frozen=True)
class LinkOccurrence:
    source_path: str
    ordinal: int
    source_section_ordinal: int | None
    syntax: LinkSyntax
    link_kind: LinkKind
    raw_target: str
    target_title: str | None
    target_heading: str | None
    target_block_id: str | None
    display_text: str | None
    is_embed: bool


@dataclass
class ParsedSourceDocument:
    source_path: str
    source_kind: SourceKind
    document_id: str | None
    title: str
    document_type: str | None
    status: str | None
    authority: str | None
    created_at: str | None
    updated_at: str | None
    last_verified_at: str | None
    content_hash: str
    raw_markdown: str
    raw_frontmatter: dict[str, Any]
    tags: list[str]
    categories: list[CategoryAssignment]
    sections: list[SectionRecord]
    links: list[LinkOccurrence]
    warnings: list[ValidationIssue] = field(default_factory=list)
