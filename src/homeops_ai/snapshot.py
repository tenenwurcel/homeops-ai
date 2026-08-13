"""Strict immutable snapshot manifests and deterministic transport archives."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Iterable

from homeops_ai.deployment import (
    DeploymentError,
    canonical_json_bytes,
    sha256_json,
    strict_json_loads,
)


SNAPSHOT_SCHEMA_VERSION = 1
SNAPSHOT_CONTRACT_VERSION = "homeops-snapshot-v1"
RECEIVER_SCHEMA_VERSION = 1
RECEIVER_PROTOCOL = "homeops.receiver/v1"
DEFAULT_MAX_FILES = 10_000
DEFAULT_MAX_BYTES = 128 * 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UUID4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_PUBLISHER_ID = re.compile(r"^[a-z][a-z0-9-]{0,62}$")


class SnapshotError(RuntimeError):
    """A snapshot violates the immutable snapshot contract."""


def validate_publisher_id(value: Any) -> str:
    """Validate the publisher identity shared by both protocol implementations."""

    if not isinstance(value, str) or not _PUBLISHER_ID.fullmatch(value):
        raise SnapshotError("publisher_id must match [a-z][a-z0-9-]{0,62}")
    return value


def safe_relative_path(value: Any) -> str:
    """Validate a canonical relative POSIX path without resolving through disk."""

    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise SnapshotError("snapshot path must be a non-empty POSIX string")
    # receiver-v1 deliberately uses the portable printable-ASCII subset of
    # USTAR names. Python's tarfile can emit UTF-8 bytes in a nominal USTAR
    # header, but Go reports that extension as FormatUnknown. Fail while
    # constructing the local snapshot, before opening an SSH transport.
    if any(ord(character) < 0x20 or ord(character) > 0x7E for character in value):
        raise SnapshotError("snapshot path must contain printable ASCII only")
    path = PurePosixPath(value)
    if path.is_absolute() or value != path.as_posix():
        raise SnapshotError(f"snapshot path is not canonical: {value!r}")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise SnapshotError(f"snapshot path contains unsafe components: {value!r}")
    return value


def resolve_beneath(root: Path, relative: str, *, must_exist: bool = True) -> Path:
    """Resolve a declared path and reject every symlink in the path walk."""

    relative = safe_relative_path(relative)
    base = root.resolve(strict=True)
    current = base
    for part in PurePosixPath(relative).parts:
        current = current / part
        if current.is_symlink():
            raise SnapshotError(f"snapshot path traverses a symlink: {relative}")
    try:
        resolved = current.resolve(strict=must_exist)
    except FileNotFoundError as error:
        raise SnapshotError(f"declared snapshot file is missing: {relative}") from error
    if not resolved.is_relative_to(base):
        raise SnapshotError(f"snapshot path escapes root: {relative}")
    return resolved


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def snapshot_identity(manifest: dict[str, Any]) -> dict[str, Any]:
    """Return content-only manifest fields covered by ``snapshot_id``."""

    return {
        "schema_version": manifest["schema_version"],
        "snapshot_contract_version": manifest["snapshot_contract_version"],
        "source_fingerprint": manifest["source_fingerprint"],
        "artifact_fingerprint": manifest["artifact_fingerprint"],
        "logical_fingerprint": manifest["logical_fingerprint"],
        "included_source_count": manifest["included_source_count"],
        "excluded_artifact_count": manifest["excluded_artifact_count"],
        "file_count": manifest["file_count"],
        "total_uncompressed_bytes": manifest["total_uncompressed_bytes"],
        "inventory": manifest["inventory"],
    }


_MANIFEST_FIELDS = {
    "schema_version",
    "snapshot_contract_version",
    "snapshot_id",
    "created_at",
    "source_fingerprint",
    "artifact_fingerprint",
    "logical_fingerprint",
    "included_source_count",
    "excluded_artifact_count",
    "file_count",
    "total_uncompressed_bytes",
    "inventory",
    "exporter",
}
_INVENTORY_FIELDS = {"path", "kind", "source_kind", "exclusion_reason", "size", "sha256"}
_EXPORTER_FIELDS = {"package_version", "source_revision"}


def validate_snapshot_manifest(
    manifest: Any,
    *,
    max_files: int = DEFAULT_MAX_FILES,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> dict[str, Any]:
    if not isinstance(manifest, dict) or set(manifest) != _MANIFEST_FIELDS:
        raise SnapshotError("snapshot manifest has missing or unknown fields")
    if manifest["schema_version"] != SNAPSHOT_SCHEMA_VERSION:
        raise SnapshotError("unsupported snapshot schema version")
    if manifest["snapshot_contract_version"] != SNAPSHOT_CONTRACT_VERSION:
        raise SnapshotError("unsupported snapshot contract version")
    for field in ("snapshot_id", "source_fingerprint", "artifact_fingerprint", "logical_fingerprint"):
        if not isinstance(manifest[field], str) or not _SHA256.fullmatch(manifest[field]):
            raise SnapshotError(f"snapshot {field} must be a lowercase SHA-256")
    if not isinstance(manifest["created_at"], str) or not manifest["created_at"]:
        raise SnapshotError("snapshot created_at must be a non-empty string")
    exporter = manifest["exporter"]
    if not isinstance(exporter, dict) or set(exporter) != _EXPORTER_FIELDS:
        raise SnapshotError("snapshot exporter has missing or unknown fields")
    if not all(isinstance(exporter[field], str) and exporter[field] for field in _EXPORTER_FIELDS):
        raise SnapshotError("snapshot exporter fields must be non-empty strings")
    inventory = manifest["inventory"]
    if not isinstance(inventory, list):
        raise SnapshotError("snapshot inventory must be a list")
    if len(inventory) > max_files:
        raise SnapshotError("snapshot exceeds the file-count limit")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    included = 0
    excluded = 0
    total_bytes = 0
    for item in inventory:
        if not isinstance(item, dict) or set(item) != _INVENTORY_FIELDS:
            raise SnapshotError("snapshot inventory item has missing or unknown fields")
        path = safe_relative_path(item["path"])
        if path in seen:
            raise SnapshotError(f"snapshot inventory contains duplicate path: {path}")
        seen.add(path)
        if item["kind"] not in {"source", "excluded"}:
            raise SnapshotError(f"snapshot inventory has invalid kind for {path}")
        if not isinstance(item["size"], int) or isinstance(item["size"], bool) or item["size"] < 0:
            raise SnapshotError(f"snapshot inventory has invalid size for {path}")
        if not isinstance(item["sha256"], str) or not _SHA256.fullmatch(item["sha256"]):
            raise SnapshotError(f"snapshot inventory has invalid SHA-256 for {path}")
        if item["kind"] == "source":
            if item["source_kind"] not in {"knowledge", "category"} or item["exclusion_reason"] is not None:
                raise SnapshotError(f"snapshot source metadata is invalid for {path}")
            included += 1
        else:
            if item["source_kind"] is not None or not isinstance(item["exclusion_reason"], str):
                raise SnapshotError(f"snapshot exclusion metadata is invalid for {path}")
            if item["size"] != 0 or item["sha256"] != hashlib.sha256(b"").hexdigest():
                raise SnapshotError(f"snapshot excluded path is not an empty placeholder: {path}")
            excluded += 1
        total_bytes += item["size"]
        normalized.append(dict(item))
    if [item["path"] for item in normalized] != sorted(seen, key=lambda value: (value.casefold(), value)):
        raise SnapshotError("snapshot inventory is not canonically sorted")
    if total_bytes > max_bytes:
        raise SnapshotError("snapshot exceeds the uncompressed-byte limit")
    expected_counts = {
        "included_source_count": included,
        "excluded_artifact_count": excluded,
        "file_count": len(normalized),
        "total_uncompressed_bytes": total_bytes,
    }
    for field, actual in expected_counts.items():
        if manifest[field] != actual:
            raise SnapshotError(f"snapshot {field} disagrees with inventory")
    if manifest["snapshot_id"] != sha256_json(snapshot_identity(manifest)):
        raise SnapshotError("snapshot_id does not match snapshot identity")
    return json.loads(json.dumps(manifest))


def create_snapshot_manifest(
    vault_root: Path,
    inspection: dict[str, Any],
    *,
    created_at: str,
    package_version: str,
    source_revision: str,
) -> dict[str, Any]:
    """Hash a completed snapshot vault and create its canonical manifest."""

    root = vault_root.resolve(strict=True)
    raw_inventory = inspection["inventory"]
    inventory: list[dict[str, Any]] = []
    empty_hash = hashlib.sha256(b"").hexdigest()
    for item in raw_inventory["included"]:
        path = safe_relative_path(item["source_path"])
        source = resolve_beneath(root, path)
        if not source.is_file():
            raise SnapshotError(f"included snapshot path is not a regular file: {path}")
        inventory.append(
            {
                "path": path,
                "kind": "source",
                "source_kind": item["kind"],
                "exclusion_reason": None,
                "size": source.stat().st_size,
                "sha256": file_sha256(source),
            }
        )
    for item in raw_inventory["excluded"]:
        path = safe_relative_path(item["source_path"])
        placeholder = resolve_beneath(root, path)
        if not placeholder.is_file() or placeholder.stat().st_size:
            raise SnapshotError(f"excluded snapshot path is not an empty regular file: {path}")
        inventory.append(
            {
                "path": path,
                "kind": "excluded",
                "source_kind": None,
                "exclusion_reason": item["reason"],
                "size": 0,
                "sha256": empty_hash,
            }
        )
    inventory.sort(key=lambda item: (item["path"].casefold(), item["path"]))
    manifest: dict[str, Any] = {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "snapshot_contract_version": SNAPSHOT_CONTRACT_VERSION,
        "snapshot_id": "0" * 64,
        "created_at": created_at,
        "source_fingerprint": inspection["source_fingerprint"],
        "artifact_fingerprint": inspection["artifact_fingerprint"],
        "logical_fingerprint": inspection["logical_fingerprint"],
        "included_source_count": sum(item["kind"] == "source" for item in inventory),
        "excluded_artifact_count": sum(item["kind"] == "excluded" for item in inventory),
        "file_count": len(inventory),
        "total_uncompressed_bytes": sum(item["size"] for item in inventory),
        "inventory": inventory,
        "exporter": {
            "package_version": package_version,
            "source_revision": source_revision,
        },
    }
    manifest["snapshot_id"] = sha256_json(snapshot_identity(manifest))
    return validate_snapshot_manifest(manifest)


def verify_snapshot(
    vault_root: Path,
    manifest: dict[str, Any],
    *,
    inspect: bool = True,
) -> dict[str, Any]:
    """Independently verify declared bytes, inventory, and HomeOps fingerprints."""

    checked = validate_snapshot_manifest(manifest)
    root = vault_root.resolve(strict=True)
    actual_paths: list[str] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise SnapshotError(f"snapshot contains a symlink: {relative}")
        if path.is_file():
            actual_paths.append(safe_relative_path(relative))
        elif not path.is_dir():
            raise SnapshotError(f"snapshot contains a non-regular object: {relative}")
    declared = [item["path"] for item in checked["inventory"]]
    if sorted(actual_paths, key=lambda value: (value.casefold(), value)) != declared:
        raise SnapshotError("snapshot files do not exactly match declared inventory")
    for item in checked["inventory"]:
        path = resolve_beneath(root, item["path"])
        if not path.is_file() or path.stat().st_size != item["size"] or file_sha256(path) != item["sha256"]:
            raise SnapshotError(f"snapshot file does not match manifest: {item['path']}")
    if inspect:
        # Delayed import avoids a build <-> snapshot import cycle.
        from homeops_ai.build import inspect_vault

        inspected = inspect_vault(root)
        if inspected["validation"]["errors"]:
            raise SnapshotError("snapshot vault validation failed")
        for field in ("source_fingerprint", "artifact_fingerprint", "logical_fingerprint"):
            if inspected[field] != checked[field]:
                raise SnapshotError(f"snapshot {field} does not match independent inspection")
    return checked


def write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    checked = validate_snapshot_manifest(manifest)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(canonical_json_bytes(checked) + b"\n")
    os.chmod(path, 0o600)


def read_manifest(path: Path) -> dict[str, Any]:
    try:
        return validate_snapshot_manifest(
            strict_json_loads(path.read_text(encoding="utf-8"))
        )
    except DeploymentError as error:
        raise SnapshotError("snapshot manifest is invalid JSON") from error


def canonical_receiver_json(value: dict[str, Any], fields: tuple[str, ...]) -> bytes:
    if tuple(value) != fields:
        raise SnapshotError("receiver message fields are missing, reordered, or unknown")
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"


def validate_request_message(request: dict[str, Any]) -> dict[str, Any]:
    fields = (
        "schema_version",
        "protocol",
        "request_id",
        "publisher_id",
        "capability_token",
        "release_policy_id",
        "snapshot_id",
        "expected_current_deployment_id",
        "snapshot_manifest_sha256",
    )
    canonical_receiver_json(request, fields)
    if request["schema_version"] != RECEIVER_SCHEMA_VERSION or request["protocol"] != RECEIVER_PROTOCOL:
        raise SnapshotError("unsupported receiver request protocol")
    if not isinstance(request["request_id"], str) or not _UUID4.fullmatch(request["request_id"]):
        raise SnapshotError("request_id must be a lowercase UUIDv4")
    validate_publisher_id(request["publisher_id"])
    for field in (
        "capability_token",
        "release_policy_id",
        "snapshot_id",
        "snapshot_manifest_sha256",
    ):
        if not isinstance(request[field], str) or not _SHA256.fullmatch(request[field]):
            raise SnapshotError(f"{field} must be a lowercase SHA-256")
    expected = request["expected_current_deployment_id"]
    if not isinstance(expected, str) or (expected and not _SHA256.fullmatch(expected)):
        raise SnapshotError("expected_current_deployment_id must be empty or a lowercase SHA-256")
    return dict(request)


def _tar_info(name: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = 0o600
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.type = tarfile.REGTYPE
    # Fail here, before any SSH write, when USTAR cannot encode a path.
    try:
        info.tobuf(format=tarfile.USTAR_FORMAT, encoding="utf-8", errors="strict")
    except (ValueError, UnicodeError) as error:
        raise SnapshotError(f"path cannot be represented by USTAR: {name}") from error
    return info


def write_submission_archive(
    output: BinaryIO,
    request: dict[str, Any],
    manifest: dict[str, Any],
    vault_root: Path,
) -> None:
    """Write the exact receiver-v1 uncompressed deterministic USTAR payload."""

    checked_request = validate_request_message(request)
    checked_manifest = verify_snapshot(vault_root, manifest)
    request_bytes = canonical_receiver_json(
        checked_request,
        (
            "schema_version", "protocol", "request_id", "publisher_id",
            "capability_token", "release_policy_id", "snapshot_id",
            "expected_current_deployment_id",
            "snapshot_manifest_sha256",
        ),
    )
    manifest_bytes = canonical_json_bytes(checked_manifest) + b"\n"
    if hashlib.sha256(manifest_bytes).hexdigest() != request["snapshot_manifest_sha256"]:
        raise SnapshotError("request snapshot_manifest_sha256 does not match manifest bytes")
    if request["snapshot_id"] != checked_manifest["snapshot_id"]:
        raise SnapshotError("request snapshot_id does not match manifest")
    entries: list[tuple[str, bytes | Path]] = [
        ("request.json", request_bytes),
        ("snapshot.json", manifest_bytes),
    ]
    vault_entries = [
        (f"vault/{item['path']}", resolve_beneath(vault_root.resolve(), item["path"]))
        for item in checked_manifest["inventory"]
    ]
    # Transport canonicalization is locale-free bytewise ASCII ordering and
    # matches Go's string comparison. The manifest intentionally keeps its
    # separate user-facing case-folded inventory order.
    vault_entries.sort(key=lambda item: item[0])
    entries.extend(vault_entries)
    with tarfile.open(fileobj=output, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
        for name, content in entries:
            if isinstance(content, bytes):
                archive.addfile(_tar_info(name, len(content)), io.BytesIO(content))
            else:
                archive.addfile(_tar_info(name, content.stat().st_size), content.open("rb"))


def submission_archive_bytes(
    request: dict[str, Any], manifest: dict[str, Any], vault_root: Path
) -> bytes:
    output = io.BytesIO()
    write_submission_archive(output, request, manifest, vault_root)
    return output.getvalue()


def archive_member_names(payload: bytes) -> Iterable[str]:
    """Small inspection helper used by tests and offline diagnostics."""

    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        return tuple(member.name for member in archive.getmembers())
