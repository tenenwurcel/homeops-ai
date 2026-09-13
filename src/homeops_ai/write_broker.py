import argparse
import fcntl
import grp
import hashlib
import json
import os
import re
import signal
import socket
import socketserver
import stat
import tempfile
import threading
import unicodedata
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import FrameType
from typing import Any

from ruamel.yaml.comments import CommentedMap

from homeops_ai.build import inspect_vault
from homeops_ai.frontmatter import MarkdownDocument, render_markdown
from homeops_ai.source_contract import export_snapshot


PROTOCOL = "homeops.write/v1"
MAX_REQUEST_BYTES = 128 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
MAX_TITLE_CHARS = 160
MAX_BODY_BYTES = 64 * 1024
MAX_CATEGORIES = 8
MAX_CATEGORY_CHARS = 120
MAX_TAGS = 16
MAX_TAG_CHARS = 64
MAX_SUBJECT_CHARS = 512
MAX_CLIENT_ID_CHARS = 512
MAX_VALIDATION_ERRORS = 16
TAG_PATTERN = re.compile(r"\A[a-zA-Z0-9][a-zA-Z0-9_./-]*\Z")
INVALID_FILENAME_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


class WriteBrokerError(RuntimeError):
    pass


class WriteBrokerConfigurationError(ValueError):
    pass


class WriteBrokerProtocolError(ValueError):
    pass


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_uuid4(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 36:
        raise WriteBrokerProtocolError(f"{field} must be a canonical UUIDv4")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        raise WriteBrokerProtocolError(f"{field} must be a canonical UUIDv4") from error
    if parsed.version != 4 or str(parsed) != value:
        raise WriteBrokerProtocolError(f"{field} must be a canonical UUIDv4")
    return value


def _validate_identity(value: Any, field: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or any(ord(character) < 0x20 for character in value)
    ):
        raise WriteBrokerProtocolError(f"{field} is invalid")
    return value


def _fingerprint(kind: str, value: str) -> str:
    return _sha256(f"{PROTOCOL}\0{kind}\0{value}".encode("utf-8"))


def _same_vault_identity(first: dict[str, Any], second: dict[str, Any]) -> bool:
    return all(
        first.get(field) == second.get(field)
        for field in (
            "source_fingerprint",
            "artifact_fingerprint",
            "logical_fingerprint",
        )
    )


def _validate_real_directory(path: Path, name: str) -> Path:
    if not path.is_absolute():
        raise WriteBrokerConfigurationError(f"{name} must be absolute")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise WriteBrokerConfigurationError(f"cannot inspect {name}") from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise WriteBrokerConfigurationError(f"{name} must be a real directory")
    return path.resolve()


def _ensure_private_directory(path: Path) -> Path:
    if not path.is_absolute():
        raise WriteBrokerConfigurationError("state directory must be absolute")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    resolved = _validate_real_directory(path, "state directory")
    metadata = path.stat(follow_symlinks=False)
    if metadata.st_mode & 0o077:
        raise WriteBrokerConfigurationError(
            "write-broker state directories may be accessible only by their owner"
        )
    return resolved


def _validate_private_directory(path: Path) -> Path:
    resolved = _validate_real_directory(path, "state directory")
    if path.stat(follow_symlinks=False).st_mode & 0o077:
        raise WriteBrokerConfigurationError(
            "write-broker state directories may be accessible only by their owner"
        )
    return resolved


def _read_bounded_regular(path: Path, maximum: int) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise WriteBrokerError("broker state is unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= maximum:
            raise WriteBrokerError("broker state is invalid")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise WriteBrokerError("broker state is invalid")
        return data
    finally:
        os.close(descriptor)


def _load_json(path: Path, maximum: int = MAX_REQUEST_BYTES) -> dict[str, Any]:
    try:
        value = json.loads(_read_bounded_regular(path, maximum))
    except (json.JSONDecodeError, UnicodeError) as error:
        raise WriteBrokerError("broker state is invalid") from error
    if not isinstance(value, dict):
        raise WriteBrokerError("broker state is invalid")
    return value


def _sync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_exclusive(path: Path, data: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    published = False
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
        os.fsync(descriptor)
        published = True
    finally:
        os.close(descriptor)
        if not published:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
    _sync_directory(path.parent)


def _category_name(value: Any) -> str:
    if not isinstance(value, str):
        raise WriteBrokerProtocolError("categories must contain strings")
    cleaned = unicodedata.normalize("NFKC", value).strip()
    if cleaned.startswith("[[") and cleaned.endswith("]]"):
        cleaned = cleaned[2:-2].strip()
    if (
        not 1 <= len(cleaned) <= MAX_CATEGORY_CHARS
        or any(character in cleaned for character in ("[", "]", "#", "|", "/", "\\"))
        or any(ord(character) < 0x20 for character in cleaned)
    ):
        raise WriteBrokerProtocolError("category name is invalid")
    return cleaned


def _normalize_note(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != {"title", "body", "categories", "tags"}:
        raise WriteBrokerProtocolError("note has an invalid shape")
    title = raw["title"]
    if not isinstance(title, str):
        raise WriteBrokerProtocolError("title must be a string")
    title = unicodedata.normalize("NFKC", title).strip()
    if (
        not 1 <= len(title) <= MAX_TITLE_CHARS
        or "\n" in title
        or "\r" in title
        or any(ord(character) < 0x20 for character in title)
    ):
        raise WriteBrokerProtocolError("title is invalid")

    body = raw["body"]
    if not isinstance(body, str):
        raise WriteBrokerProtocolError("body must be a string")
    body = body.replace("\r\n", "\n").replace("\r", "\n").strip()
    if (
        not body
        or any(ord(character) < 0x20 and character not in "\n\t" for character in body)
        or len(body.encode("utf-8")) > MAX_BODY_BYTES
    ):
        raise WriteBrokerProtocolError(
            "body is empty, contains control characters, or exceeds the size limit"
        )

    raw_categories = raw["categories"]
    if not isinstance(raw_categories, list) or not 1 <= len(raw_categories) <= MAX_CATEGORIES:
        raise WriteBrokerProtocolError(
            f"categories must contain between 1 and {MAX_CATEGORIES} entries"
        )
    categories: list[str] = []
    seen_categories: set[str] = set()
    for value in raw_categories:
        category = _category_name(value)
        key = category.casefold()
        if key not in seen_categories:
            categories.append(category)
            seen_categories.add(key)

    raw_tags = raw["tags"]
    if not isinstance(raw_tags, list) or len(raw_tags) > MAX_TAGS:
        raise WriteBrokerProtocolError(f"tags must contain at most {MAX_TAGS} entries")
    tags: list[str] = []
    seen_tags: set[str] = set()
    for value in raw_tags:
        if not isinstance(value, str):
            raise WriteBrokerProtocolError("tags must contain strings")
        tag = unicodedata.normalize("NFKC", value).strip().removeprefix("#")
        if not 1 <= len(tag) <= MAX_TAG_CHARS or TAG_PATTERN.fullmatch(tag) is None:
            raise WriteBrokerProtocolError("tag is invalid")
        key = tag.casefold()
        if key not in seen_tags and key != "mcp-capture":
            tags.append(tag)
            seen_tags.add(key)
    if len(tags) >= MAX_TAGS:
        raise WriteBrokerProtocolError(
            f"tags must contain at most {MAX_TAGS - 1} non-mcp entries"
        )
    tags.append("mcp-capture")
    return {
        "title": title,
        "body": body,
        "categories": categories,
        "tags": tags,
    }


def _safe_filename_title(title: str) -> str:
    cleaned = INVALID_FILENAME_CHARS.sub("-", title)
    cleaned = re.sub(r"\s+", " ", cleaned).strip(" .-")
    if not cleaned:
        cleaned = "Untitled"
    encoded = cleaned.encode("utf-8")
    while len(encoded) > 120:
        cleaned = cleaned[:-1].rstrip(" .-")
        encoded = cleaned.encode("utf-8")
    return cleaned or "Untitled"


def _render_capture(intent: dict[str, Any]) -> bytes:
    note = intent["note"]
    created = datetime.fromisoformat(intent["created_at"])
    frontmatter = CommentedMap()
    frontmatter["id"] = intent["document_id"]
    frontmatter["categories"] = [f"[[{category}]]" for category in note["categories"]]
    frontmatter["tags"] = note["tags"]
    frontmatter["date"] = created.strftime("%Y-%m-%d,%H:%M")
    frontmatter["type"] = "reference"
    frontmatter["status"] = "current"
    frontmatter["updated"] = created.strftime("%Y-%m-%d")
    frontmatter["authority"] = "supporting"
    frontmatter["mcp_request_id"] = intent["request_id"]
    body = f"\n# {note['title']}\n\n{note['body']}\n"
    return render_markdown(MarkdownDocument(frontmatter, body, True)).encode("utf-8")


@dataclass(frozen=True)
class WriteBrokerClient:
    socket_path: Path
    timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        if not self.socket_path.is_absolute():
            raise WriteBrokerConfigurationError("broker socket must be absolute")
        if not 0 < self.timeout_seconds <= 60:
            raise WriteBrokerConfigurationError(
                "broker timeout must be greater than zero and at most 60 seconds"
            )

    def request(self, payload: dict[str, Any]) -> dict[str, Any]:
        frame = _canonical_json(payload)
        if len(frame) > MAX_REQUEST_BYTES:
            raise WriteBrokerError("write request exceeds the broker limit")
        try:
            metadata = self.socket_path.lstat()
        except OSError as error:
            raise WriteBrokerError("write broker is unavailable") from error
        if not stat.S_ISSOCK(metadata.st_mode):
            raise WriteBrokerError("write broker is unavailable")
        response = bytearray()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout_seconds)
                connection.connect(str(self.socket_path))
                connection.sendall(frame)
                connection.shutdown(socket.SHUT_WR)
                while len(response) <= MAX_RESPONSE_BYTES:
                    chunk = connection.recv(
                        min(65536, MAX_RESPONSE_BYTES + 1 - len(response))
                    )
                    if not chunk:
                        break
                    response.extend(chunk)
        except (OSError, TimeoutError) as error:
            raise WriteBrokerError("write broker is unavailable") from error
        if not response or len(response) > MAX_RESPONSE_BYTES:
            raise WriteBrokerError("write broker returned an invalid response")
        try:
            parsed = json.loads(response)
        except (json.JSONDecodeError, UnicodeError) as error:
            raise WriteBrokerError("write broker returned an invalid response") from error
        if (
            not isinstance(parsed, dict)
            or parsed.get("schema_version") != 1
            or parsed.get("protocol") != PROTOCOL
            or not isinstance(parsed.get("outcome"), str)
        ):
            raise WriteBrokerError("write broker returned an invalid response")
        return parsed

    def capture_note(
        self,
        *,
        request_id: str,
        subject: str,
        client_id: str,
        title: str,
        body: str,
        categories: list[str],
        tags: list[str],
    ) -> dict[str, Any]:
        return self.request(
            {
                "schema_version": 1,
                "protocol": PROTOCOL,
                "operation": "capture_note",
                "request_id": request_id,
                "actor": {"subject": subject, "client_id": client_id},
                "note": {
                    "title": title,
                    "body": body,
                    "categories": categories,
                    "tags": tags,
                },
            }
        )

    def write_status(
        self, *, request_id: str, subject: str, client_id: str
    ) -> dict[str, Any]:
        return self.request(
            {
                "schema_version": 1,
                "protocol": PROTOCOL,
                "operation": "write_status",
                "request_id": request_id,
                "actor": {"subject": subject, "client_id": client_id},
            }
        )


class VaultWriteBroker:
    def __init__(
        self,
        vault_root: Path,
        state_dir: Path,
        *,
        allowed_subjects: tuple[str, ...],
    ):
        self.vault_root = _validate_real_directory(vault_root, "vault root")
        self.state_dir = _validate_private_directory(state_dir)
        if (
            self.state_dir == self.vault_root
            or self.state_dir.is_relative_to(self.vault_root)
            or self.vault_root.is_relative_to(self.state_dir)
        ):
            raise WriteBrokerConfigurationError(
                "write-broker state must be outside the synced vault"
            )
        if not allowed_subjects or len(allowed_subjects) > 16:
            raise WriteBrokerConfigurationError(
                "between 1 and 16 write subjects must be configured"
            )
        try:
            self.allowed_subjects = frozenset(
                _validate_identity(subject, "write subject", MAX_SUBJECT_CHARS)
                for subject in allowed_subjects
            )
        except WriteBrokerProtocolError as error:
            raise WriteBrokerConfigurationError(str(error)) from error
        if len(self.allowed_subjects) != len(allowed_subjects):
            raise WriteBrokerConfigurationError("write subjects must be unique")
        self.requests_dir = _ensure_private_directory(self.state_dir / "requests")
        self.results_dir = _ensure_private_directory(self.state_dir / "results")
        self.staging_dir = _ensure_private_directory(self.state_dir / "staging")
        self._lock_path = self.state_dir / "broker.lock"
        self._lock_descriptor = os.open(
            self._lock_path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.fchmod(self._lock_descriptor, 0o600)
        self._thread_lock = threading.Lock()

    def close(self) -> None:
        if self._lock_descriptor >= 0:
            os.close(self._lock_descriptor)
            self._lock_descriptor = -1

    def _locked(self):
        return _BrokerLock(self)

    def _response(self, outcome: str, **fields: Any) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "protocol": PROTOCOL,
            "outcome": outcome,
            **fields,
        }

    def handle(self, request: Any) -> dict[str, Any]:
        if not isinstance(request, dict):
            raise WriteBrokerProtocolError("request must be an object")
        if request.get("schema_version") != 1 or request.get("protocol") != PROTOCOL:
            raise WriteBrokerProtocolError("unsupported write-broker protocol")
        operation = request.get("operation")
        request_id = _validate_uuid4(request.get("request_id"), "request_id")
        actor = request.get("actor")
        if not isinstance(actor, dict) or set(actor) != {"subject", "client_id"}:
            raise WriteBrokerProtocolError("actor has an invalid shape")
        subject = _validate_identity(actor["subject"], "subject", MAX_SUBJECT_CHARS)
        client_id = _validate_identity(
            actor["client_id"], "client_id", MAX_CLIENT_ID_CHARS
        )
        if subject not in self.allowed_subjects:
            return self._response("NOT_FOUND", request_id=request_id)
        actor_fingerprint = _fingerprint("subject", subject)
        client_fingerprint = _fingerprint("client", client_id)
        if operation == "capture_note":
            if set(request) != {
                "schema_version",
                "protocol",
                "operation",
                "request_id",
                "actor",
                "note",
            }:
                raise WriteBrokerProtocolError("capture request has an invalid shape")
            try:
                note = _normalize_note(request.get("note"))
            except WriteBrokerProtocolError as error:
                return self._response(
                    "REJECTED",
                    request_id=request_id,
                    retryable=False,
                    message=str(error),
                )
            return self._capture(
                request_id,
                actor_fingerprint,
                client_fingerprint,
                note,
            )
        if operation == "write_status":
            if set(request) != {
                "schema_version",
                "protocol",
                "operation",
                "request_id",
                "actor",
            }:
                raise WriteBrokerProtocolError("status request has an invalid shape")
            return self._status(request_id, actor_fingerprint)
        raise WriteBrokerProtocolError("unknown write-broker operation")

    def _capture(
        self,
        request_id: str,
        actor_fingerprint: str,
        client_fingerprint: str,
        note: dict[str, Any],
    ) -> dict[str, Any]:
        request_hash = _sha256(_canonical_json(note))
        request_path = self.requests_dir / f"{request_id}.json"
        with self._locked():
            if request_path.exists():
                intent = _load_json(request_path)
                if (
                    intent.get("request_hash") != request_hash
                    or intent.get("actor_fingerprint") != actor_fingerprint
                ):
                    return self._response(
                        "REQUEST_ID_CONFLICT",
                        request_id=request_id,
                        retryable=False,
                    )
                return self._process_intent(intent, idempotent=True)

            now = datetime.now().astimezone()
            safe_title = _safe_filename_title(note["title"])
            intent = {
                "schema_version": 1,
                "protocol": PROTOCOL,
                "request_id": request_id,
                "request_hash": request_hash,
                "actor_fingerprint": actor_fingerprint,
                "client_fingerprint": client_fingerprint,
                "created_at": now.isoformat(timespec="seconds"),
                "document_id": str(uuid.uuid4()),
                "target": f"Capture - {safe_title} - {request_id[:8]}.md",
                "note": note,
            }
            content = _render_capture(intent)
            intent["content_sha256"] = _sha256(content)
            _write_exclusive(request_path, _canonical_json(intent))
            return self._process_intent(intent, idempotent=False)

    def _status(self, request_id: str, actor_fingerprint: str) -> dict[str, Any]:
        request_path = self.requests_dir / f"{request_id}.json"
        with self._locked():
            if not request_path.exists():
                return self._response("NOT_FOUND", request_id=request_id)
            intent = _load_json(request_path)
            if intent.get("actor_fingerprint") != actor_fingerprint:
                return self._response("NOT_FOUND", request_id=request_id)
            existing_result = self._result(request_id)
            if existing_result is not None:
                return {**existing_result, "idempotent": True}

            content = _render_capture(intent)
            if _sha256(content) != intent.get("content_sha256"):
                raise WriteBrokerError("broker intent content is invalid")
            target_name = intent.get("target")
            if (
                not isinstance(target_name, str)
                or Path(target_name).name != target_name
                or not target_name.endswith(".md")
            ):
                raise WriteBrokerError("broker intent target is invalid")
            destination = self.vault_root / target_name
            try:
                destination.lstat()
                destination_exists = True
            except FileNotFoundError:
                destination_exists = False
            if destination_exists:
                try:
                    existing = _read_bounded_regular(destination, MAX_REQUEST_BYTES)
                except WriteBrokerError:
                    existing = b""
                if existing != content:
                    return self._response(
                        "REJECTED",
                        request_id=request_id,
                        retryable=False,
                        message="capture target exists with different content",
                    )
                return self._pending(intent, "capture-present-awaiting-retry")
            return self._pending(intent, "awaiting-capture-retry")

    def _result(self, request_id: str) -> dict[str, Any] | None:
        path = self.results_dir / f"{request_id}.json"
        if not path.exists():
            return None
        result = _load_json(path, MAX_RESPONSE_BYTES)
        if (
            result.get("schema_version") != 1
            or result.get("protocol") != PROTOCOL
            or result.get("request_id") != request_id
        ):
            raise WriteBrokerError("broker result state is invalid")
        return result

    def _publish_result(self, result: dict[str, Any]) -> dict[str, Any]:
        path = self.results_dir / f"{result['request_id']}.json"
        try:
            _write_exclusive(path, _canonical_json(result))
        except FileExistsError:
            existing = self._result(result["request_id"])
            if existing != result:
                raise WriteBrokerError("broker result state conflicts")
            return existing
        return result

    def _validation_errors(self, inspected: dict[str, Any]) -> list[dict[str, str]]:
        errors = inspected.get("validation", {}).get("errors", [])
        return [
            {
                "code": str(item.get("code", "validation-error"))[:128],
                "source_path": str(item.get("source_path", ""))[:512],
                "message": str(item.get("message", "validation failed"))[:1024],
            }
            for item in errors[:MAX_VALIDATION_ERRORS]
            if isinstance(item, dict)
        ]

    def _pending(self, intent: dict[str, Any], state: str) -> dict[str, Any]:
        return self._response(
            "ACCEPTED",
            request_id=intent["request_id"],
            retryable=True,
            state=state,
            document_id=intent["document_id"],
            source_path=intent["target"],
        )

    def _process_intent(
        self, intent: dict[str, Any], *, idempotent: bool
    ) -> dict[str, Any]:
        request_id = intent.get("request_id")
        _validate_uuid4(request_id, "stored request_id")
        existing_result = self._result(request_id)
        if existing_result is not None:
            return {**existing_result, "idempotent": True}

        content = _render_capture(intent)
        if _sha256(content) != intent.get("content_sha256"):
            raise WriteBrokerError("broker intent content is invalid")
        target_name = intent.get("target")
        if (
            not isinstance(target_name, str)
            or Path(target_name).name != target_name
            or not target_name.endswith(".md")
        ):
            raise WriteBrokerError("broker intent target is invalid")
        destination = self.vault_root / target_name

        try:
            destination.lstat()
            destination_exists = True
        except FileNotFoundError:
            destination_exists = False
        except OSError:
            return self._pending(intent, "waiting-for-readable-vault")
        if destination_exists:
            try:
                existing = _read_bounded_regular(destination, MAX_REQUEST_BYTES)
            except WriteBrokerError:
                existing = b""
            if existing != content:
                return self._publish_result(
                    self._response(
                        "REJECTED",
                        request_id=request_id,
                        retryable=False,
                        message="capture target already exists with different content",
                    )
                )
            try:
                inspected = inspect_vault(self.vault_root)
            except (OSError, ValueError):
                return self._pending(intent, "waiting-for-readable-vault")
            if self._validation_errors(inspected):
                return self._pending(intent, "waiting-for-valid-vault")
            return self._publish_applied(
                intent,
                inspected,
                recovered=True,
                idempotent=True,
            )

        try:
            baseline = inspect_vault(self.vault_root)
        except (OSError, ValueError):
            return self._pending(intent, "waiting-for-readable-vault")
        if self._validation_errors(baseline):
            return self._pending(intent, "waiting-for-valid-vault")

        with tempfile.TemporaryDirectory(
            prefix=f"{request_id}.", dir=self.staging_dir
        ) as temporary:
            candidate = Path(temporary) / "vault"
            try:
                export_snapshot(self.vault_root, candidate)
                (candidate / target_name).write_bytes(content)
                candidate_inspection = inspect_vault(candidate)
            except (OSError, ValueError):
                return self._pending(intent, "waiting-for-stable-vault")

        candidate_errors = self._validation_errors(candidate_inspection)
        if candidate_errors:
            return self._publish_result(
                self._response(
                    "REJECTED",
                    request_id=request_id,
                    retryable=False,
                    message="capture would violate the vault validation contract",
                    validation_errors=candidate_errors,
                )
            )

        try:
            before_publish = inspect_vault(self.vault_root)
        except (OSError, ValueError):
            return self._pending(intent, "waiting-for-stable-vault")
        if not _same_vault_identity(before_publish, baseline) or self._validation_errors(
            before_publish
        ):
            return self._pending(intent, "waiting-for-stable-vault")

        try:
            self._publish_note(target_name, content)
        except FileExistsError:
            return self._pending(intent, "waiting-for-stable-vault")
        except OSError:
            return self._pending(intent, "waiting-for-writable-vault")

        try:
            published = inspect_vault(self.vault_root)
        except (OSError, ValueError):
            concurrent_source_change = True
        else:
            concurrent_source_change = bool(
                self._validation_errors(published)
            ) or not _same_vault_identity(published, candidate_inspection)
        return self._publish_applied(
            intent,
            candidate_inspection,
            recovered=False,
            idempotent=idempotent,
            concurrent_source_change=concurrent_source_change,
        )

    def _publish_note(self, target_name: str, content: bytes) -> None:
        root_descriptor = os.open(
            self.vault_root,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        temporary_name = f".{uuid.uuid4()}.homeops-partial"
        descriptor = -1
        try:
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=root_descriptor,
            )
            os.fchmod(descriptor, 0o660)
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(content)
                stream.flush()
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.link(
                temporary_name,
                target_name,
                src_dir_fd=root_descriptor,
                dst_dir_fd=root_descriptor,
                follow_symlinks=False,
            )
            os.fsync(root_descriptor)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                try:
                    os.unlink(temporary_name, dir_fd=root_descriptor)
                    os.fsync(root_descriptor)
                except FileNotFoundError:
                    pass
            finally:
                os.close(root_descriptor)

    def _publish_applied(
        self,
        intent: dict[str, Any],
        inspected: dict[str, Any],
        *,
        recovered: bool,
        idempotent: bool,
        concurrent_source_change: bool = False,
    ) -> dict[str, Any]:
        result = self._response(
            "APPLIED",
            request_id=intent["request_id"],
            retryable=False,
            document_id=intent["document_id"],
            source_path=intent["target"],
            content_sha256=intent["content_sha256"],
            source_fingerprint=inspected["source_fingerprint"],
            applied_at=datetime.now().astimezone().isoformat(timespec="seconds"),
            recovered=recovered,
            concurrent_source_change=concurrent_source_change,
        )
        stored = self._publish_result(result)
        return {**stored, "idempotent": idempotent}


class _BrokerLock:
    def __init__(self, broker: VaultWriteBroker):
        self.broker = broker

    def __enter__(self):
        self.broker._thread_lock.acquire()
        try:
            fcntl.flock(self.broker._lock_descriptor, fcntl.LOCK_EX)
        except BaseException:
            self.broker._thread_lock.release()
            raise
        return self

    def __exit__(self, *_: Any) -> None:
        try:
            fcntl.flock(self.broker._lock_descriptor, fcntl.LOCK_UN)
        finally:
            self.broker._thread_lock.release()


class _BrokerRequestHandler(socketserver.StreamRequestHandler):
    def setup(self) -> None:
        self.request.settimeout(10)
        super().setup()

    def handle(self) -> None:
        try:
            frame = self.rfile.readline(MAX_REQUEST_BYTES + 1)
            if (
                not frame
                or len(frame) > MAX_REQUEST_BYTES
                or not frame.endswith(b"\n")
                or self.rfile.read(1)
            ):
                response = self.server.broker._response(  # type: ignore[attr-defined]
                    "PROTOCOL_REJECTED", retryable=False
                )
            else:
                request = json.loads(frame)
                response = self.server.broker.handle(request)  # type: ignore[attr-defined]
        except (json.JSONDecodeError, UnicodeError, WriteBrokerProtocolError, OSError):
            response = self.server.broker._response(  # type: ignore[attr-defined]
                "PROTOCOL_REJECTED", retryable=False
            )
        except Exception:
            response = self.server.broker._response(  # type: ignore[attr-defined]
                "INTERNAL_ERROR", retryable=True
            )
        encoded = _canonical_json(response)
        if len(encoded) <= MAX_RESPONSE_BYTES:
            try:
                self.wfile.write(encoded)
            except OSError:
                pass


class UnixWriteBrokerServer(socketserver.UnixStreamServer):
    allow_reuse_address = False

    def __init__(
        self,
        socket_path: Path,
        broker: VaultWriteBroker,
        *,
        socket_group: str | None = None,
        socket_gid: int | None = None,
    ):
        if not socket_path.is_absolute():
            raise WriteBrokerConfigurationError("broker socket must be absolute")
        parent = _validate_real_directory(socket_path.parent, "broker socket parent")
        if parent.stat(follow_symlinks=False).st_mode & 0o022:
            raise WriteBrokerConfigurationError(
                "broker socket parent must not be writable by group or others"
            )
        if socket_group is not None and socket_gid is not None:
            raise WriteBrokerConfigurationError(
                "configure only one broker socket group selector"
            )
        if socket_gid is not None and not 0 <= socket_gid <= 2**31 - 1:
            raise WriteBrokerConfigurationError("broker socket gid is invalid")
        group_id = os.getegid()
        if socket_group is not None:
            try:
                group_id = grp.getgrnam(socket_group).gr_gid
            except KeyError as error:
                raise WriteBrokerConfigurationError(
                    "broker socket group does not exist"
                ) from error
        elif socket_gid is not None:
            group_id = socket_gid

        try:
            existing = socket_path.lstat()
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if not stat.S_ISSOCK(existing.st_mode):
                raise WriteBrokerConfigurationError(
                    "refusing to replace a non-socket broker path"
                )
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                    probe.settimeout(0.2)
                    probe.connect(str(socket_path))
            except FileNotFoundError:
                pass
            except ConnectionRefusedError:
                try:
                    current = socket_path.lstat()
                except FileNotFoundError:
                    pass
                else:
                    if (
                        not stat.S_ISSOCK(current.st_mode)
                        or (current.st_dev, current.st_ino)
                        != (existing.st_dev, existing.st_ino)
                    ):
                        raise WriteBrokerConfigurationError(
                            "broker socket changed during stale-socket recovery"
                        )
                    socket_path.unlink()
            except OSError as error:
                raise WriteBrokerConfigurationError(
                    "cannot prove the existing broker socket is stale"
                ) from error
            else:
                raise WriteBrokerConfigurationError(
                    "broker socket is already served by another process"
                )
        self.socket_path = socket_path
        self.broker = broker
        self._socket_identity: tuple[int, int] | None = None
        super().__init__(str(socket_path), _BrokerRequestHandler, bind_and_activate=False)
        try:
            self.server_bind()
            metadata = socket_path.lstat()
            if not stat.S_ISSOCK(metadata.st_mode):
                raise WriteBrokerConfigurationError(
                    "broker bind did not create a Unix socket"
                )
            self._socket_identity = (metadata.st_dev, metadata.st_ino)
            self.server_activate()
            os.chown(socket_path, -1, group_id)
            socket_path.chmod(0o660)
        except BaseException:
            self.server_close()
            raise

    def server_close(self) -> None:
        super().server_close()
        identity = getattr(self, "_socket_identity", None)
        if identity is None:
            return
        try:
            metadata = self.socket_path.lstat()
        except FileNotFoundError:
            self._socket_identity = None
            return
        if stat.S_ISSOCK(metadata.st_mode) and (
            metadata.st_dev,
            metadata.st_ino,
        ) == identity:
            self.socket_path.unlink()
        self._socket_identity = None


def add_write_broker_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--vault", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--unix-socket", type=Path, required=True)
    socket_group = parser.add_mutually_exclusive_group()
    socket_group.add_argument("--socket-group")
    socket_group.add_argument("--socket-gid", type=int)
    parser.add_argument("--allowed-subject", action="append", default=[])


def run_write_broker_from_args(args: argparse.Namespace) -> None:
    broker = VaultWriteBroker(
        args.vault,
        args.state_dir,
        allowed_subjects=tuple(args.allowed_subject),
    )
    try:
        server = UnixWriteBrokerServer(
            args.unix_socket,
            broker,
            socket_group=args.socket_group,
            socket_gid=args.socket_gid,
        )
    except BaseException:
        broker.close()
        raise

    def request_shutdown(_: int, __: FrameType | None) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    previous_handlers = {
        handled_signal: signal.signal(handled_signal, request_shutdown)
        for handled_signal in (signal.SIGINT, signal.SIGTERM)
    }
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        for handled_signal, previous in previous_handlers.items():
            signal.signal(handled_signal, previous)
        server.server_close()
        broker.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the private HomeOps vault write broker"
    )
    add_write_broker_arguments(parser)
    args = parser.parse_args()
    try:
        run_write_broker_from_args(args)
    except WriteBrokerConfigurationError as error:
        parser.error(str(error))
