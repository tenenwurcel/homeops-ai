import os
import shutil
import uuid
from pathlib import Path
from typing import Any

from homeops_ai.models import SourceFile


def normalize_source_path(vault_root: Path, path: Path) -> str:
    root = vault_root.resolve()
    resolved = path.resolve()
    if not resolved.is_relative_to(root):
        raise ValueError(f"path escapes vault root: {path}")
    return resolved.relative_to(root).as_posix()


def _is_markdown(path: Path, include_uppercase: bool) -> bool:
    if include_uppercase:
        return path.suffix.lower() == ".md"
    return path.suffix == ".md"


def discover_sources(
    vault_root: Path, *, include_uppercase_markdown: bool = False
) -> list[SourceFile]:
    """Discover approved Markdown sources without traversing excluded directories."""
    root = vault_root.resolve()
    if not root.is_dir():
        raise ValueError(f"vault root is not a directory: {root}")

    sources: list[SourceFile] = []
    for path in root.iterdir():
        if path.is_file() and _is_markdown(path, include_uppercase_markdown):
            sources.append(
                SourceFile(normalize_source_path(root, path), kind="knowledge")
            )

    categories = root / "Categories"
    if categories.is_dir():
        for path in categories.iterdir():
            if path.is_file() and _is_markdown(path, include_uppercase_markdown):
                sources.append(
                    SourceFile(normalize_source_path(root, path), kind="category")
                )

    return sorted(sources, key=lambda item: item.source_path.casefold())


def inventory_paths(
    vault_root: Path, *, include_uppercase_markdown: bool = True
) -> dict[str, list[dict[str, Any]]]:
    """Record included sources and excluded files without reading excluded content."""
    root = vault_root.resolve()
    sources = discover_sources(
        root, include_uppercase_markdown=include_uppercase_markdown
    )
    included_paths = {source.source_path for source in sources}
    included = [
        {"source_path": source.source_path, "kind": source.kind} for source in sources
    ]
    excluded: list[dict[str, str]] = []

    for path in sorted(
        (item for item in root.rglob("*") if item.is_file()),
        key=lambda item: item.relative_to(root).as_posix().casefold(),
    ):
        source_path = normalize_source_path(root, path)
        if source_path in included_paths:
            continue
        parts = path.relative_to(root).parts
        if parts[0] == "Templates":
            reason = "template"
        elif any(part.startswith(".") for part in parts):
            reason = "hidden-or-trash"
        elif path.suffix.lower() == ".md":
            reason = "markdown-outside-contract"
        else:
            reason = "non-markdown-artifact"
        excluded.append({"source_path": source_path, "reason": reason})

    return {"included": included, "excluded": excluded}


def export_snapshot(vault_root: Path, destination: Path) -> dict[str, Any]:
    """Export exact approved source bytes plus path-only excluded artifacts."""
    root = vault_root.resolve()
    output = destination.resolve()
    if output == root or output.is_relative_to(root):
        raise ValueError("snapshot destination must be outside the source vault")
    if output.exists():
        raise ValueError(f"snapshot destination already exists: {output}")

    inventory = inventory_paths(root, include_uppercase_markdown=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.parent / f".{output.name}.{uuid.uuid4()}.tmp"
    temporary.mkdir()

    try:
        for item in inventory["included"]:
            source = root / item["source_path"]
            target = temporary / item["source_path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())

        for item in inventory["excluded"]:
            target = temporary / item["source_path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.touch()

        os.replace(temporary, output)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise

    return {
        "source_vault": str(root),
        "snapshot": str(output),
        "included_sources": len(inventory["included"]),
        "excluded_path_placeholders": len(inventory["excluded"]),
    }
