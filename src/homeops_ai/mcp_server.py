import argparse
import asyncio
import json
import os
import signal
import socket
import stat
import threading
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import FrameType
from typing import Any
from urllib.parse import urlsplit

import jwt
import uvicorn
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.routes import (
    build_resource_metadata_url,
    create_protected_resource_routes,
)
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from starlette.requests import Request
from starlette.responses import JSONResponse

from homeops_ai.build import active_state
from homeops_ai.context_compiler import ContextCompilerError, compile_context
from homeops_ai.query import (
    QueryError,
    execute_query,
    pinned_build_manifest,
    query_names,
)
from homeops_ai.write_broker import (
    WriteBrokerClient,
    WriteBrokerConfigurationError,
    WriteBrokerError,
)


DEFAULT_DATA_DIR = Path("data")
MAX_MCP_ROWS = 1000
MAX_JWKS_BYTES = 1024 * 1024
MAX_JWKS_KEYS = 32
MAX_BEARER_TOKEN_BYTES = 16 * 1024
MAX_HTTP_REQUEST_BYTES = 1024 * 1024
JWT_ALGORITHM = "RS256"
MIN_RSA_KEY_BITS = 2048
MAX_RSA_KEY_BITS = 8192
READ_ONLY_SERVER_INSTRUCTIONS = (
    "Read-only access to a published HomeOps knowledge snapshot. Results are not "
    "live device discovery; inspect build_status provenance and freshness before "
    "treating them as current. Device control, shell execution, arbitrary queries, "
    "and infrastructure mutation are unavailable."
)
WRITABLE_SERVER_INSTRUCTIONS = (
    "Read access uses only a published, verified HomeOps knowledge snapshot. "
    "The create-only capture_note tool sends a bounded note to a separate local "
    "vault broker; it never edits or deletes an existing note and never writes "
    "directly to the derived Cozo database. Use a new UUIDv4 request_id, do not "
    "submit secrets, and inspect write_status until publication becomes active. "
    "Status is read-only; an accepted request that asks for a retry must be "
    "resubmitted through capture_note with the same ID and content. "
    "An active publication confirms the local verified build only; it does not "
    "attest that Obsidian Sync has reached another device. "
    "Results are not live device discovery, and device control, shell execution, "
    "arbitrary queries, and infrastructure mutation remain unavailable."
)
READ_ONLY_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
CREATE_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)


class MCPToolError(RuntimeError):
    pass


class MCPServerConfigurationError(ValueError):
    pass


class _UnixSocketUvicornServer(uvicorn.Server):
    """Let the launcher own signals so its socket-cleanup finally block runs."""

    @contextmanager
    def capture_signals(self) -> Generator[None, None, None]:
        yield


class _HomeOpsFastMCP(FastMCP):
    """Keep connection and tool authorization scopes independent."""

    def __init__(
        self,
        *args: Any,
        advertised_scopes: tuple[str, ...] = (),
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._advertised_scopes = advertised_scopes

    def streamable_http_app(self) -> Any:
        app = super().streamable_http_app()
        auth = self.settings.auth
        if not self._advertised_scopes or auth is None or auth.resource_server_url is None:
            return app

        metadata_path = urlsplit(
            str(build_resource_metadata_url(auth.resource_server_url))
        ).path
        replacement = create_protected_resource_routes(
            resource_url=auth.resource_server_url,
            authorization_servers=[auth.issuer_url],
            scopes_supported=list(self._advertised_scopes),
        )
        app.router.routes = [
            replacement[0]
            if getattr(route, "path", None) == metadata_path
            else route
            for route in app.router.routes
        ]
        return app


def _validate_https_url(
    value: str, name: str, *, expected_path: str | None = None
) -> None:
    if not value or len(value) > 2048 or not value.isascii():
        raise MCPServerConfigurationError(f"{name} must be a bounded HTTPS URL")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        parsed.port
    except ValueError as error:
        raise MCPServerConfigurationError(f"{name} is not a valid URL") from error
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.netloc != parsed.netloc.lower()
    ):
        raise MCPServerConfigurationError(
            f"{name} must be an HTTPS URL without credentials, query, or fragment"
        )
    if expected_path is not None and parsed.path != expected_path:
        raise MCPServerConfigurationError(
            f"{name} must use the exact path {expected_path}"
        )


@dataclass(frozen=True)
class HTTPAuthConfig:
    issuer_url: str
    resource_url: str
    audience: str
    jwks_file: Path
    required_scope: str = "homeops:read"
    allowed_origins: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_https_url(self.issuer_url, "issuer_url")
        _validate_https_url(self.resource_url, "resource_url", expected_path="/mcp")
        if not self.audience or len(self.audience) > 2048:
            raise MCPServerConfigurationError("audience must be non-empty and bounded")
        if self.audience != self.resource_url:
            raise MCPServerConfigurationError(
                "audience must exactly match resource_url"
            )
        if not 1 <= len(self.required_scope) <= 256 or any(
            ord(character) < 0x21 or ord(character) > 0x7E or character in {'"', "\\"}
            for character in self.required_scope
        ):
            raise MCPServerConfigurationError(
                "required_scope must be one non-empty OAuth scope"
            )
        if not self.jwks_file.is_absolute():
            raise MCPServerConfigurationError("jwks_file must be an absolute path")
        if len(self.allowed_origins) > 16 or len(set(self.allowed_origins)) != len(
            self.allowed_origins
        ):
            raise MCPServerConfigurationError(
                "allowed_origins must contain at most 16 unique origins"
            )
        for origin in self.allowed_origins:
            _validate_https_url(origin, "allowed_origin")
            if urlsplit(origin).path:
                raise MCPServerConfigurationError(
                    "allowed_origin must contain only scheme and authority"
                )


@dataclass(frozen=True)
class MCPWriteConfig:
    broker_socket: Path
    allowed_subjects: tuple[str, ...]
    required_scope: str = "homeops:write"
    timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        if not self.broker_socket.is_absolute():
            raise MCPServerConfigurationError("write broker socket must be absolute")
        if (
            not 1 <= len(self.required_scope) <= 256
            or any(
                ord(character) < 0x21
                or ord(character) > 0x7E
                or character in {'"', "\\"}
                for character in self.required_scope
            )
        ):
            raise MCPServerConfigurationError(
                "write scope must be one non-empty OAuth scope"
            )
        if (
            not self.allowed_subjects
            or len(self.allowed_subjects) > 16
            or len(set(self.allowed_subjects)) != len(self.allowed_subjects)
        ):
            raise MCPServerConfigurationError(
                "write subjects must contain between 1 and 16 unique subjects"
            )
        if any(
            not isinstance(subject, str)
            or not 1 <= len(subject) <= 512
            or any(ord(character) < 0x20 for character in subject)
            for subject in self.allowed_subjects
        ):
            raise MCPServerConfigurationError("write subject is invalid")
        try:
            WriteBrokerClient(
                self.broker_socket, timeout_seconds=self.timeout_seconds
            )
        except WriteBrokerConfigurationError as error:
            raise MCPServerConfigurationError(str(error)) from error


class OfflineJWKSTokenVerifier(TokenVerifier):
    """Verify OAuth access tokens against an integrity-controlled local JWKS."""

    def __init__(self, config: HTTPAuthConfig):
        self._config = config
        self._keys = self._load_keys(config.jwks_file)

    @staticmethod
    def _load_keys(path: Path) -> dict[str, Any]:
        try:
            file_descriptor = os.open(
                path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
        except OSError as error:
            raise MCPServerConfigurationError(
                f"cannot open JWKS file: {path}"
            ) from error

        try:
            metadata = os.fstat(file_descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise MCPServerConfigurationError("JWKS path must be a regular file")
            if metadata.st_mode & 0o022:
                raise MCPServerConfigurationError(
                    "JWKS file must not be writable by group or others"
                )
            if not 0 < metadata.st_size <= MAX_JWKS_BYTES:
                raise MCPServerConfigurationError(
                    f"JWKS file must be between 1 and {MAX_JWKS_BYTES} bytes"
                )
            with os.fdopen(file_descriptor, "rb", closefd=False) as stream:
                document = json.loads(stream.read(MAX_JWKS_BYTES + 1))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise MCPServerConfigurationError("JWKS file is not valid JSON") from error
        finally:
            os.close(file_descriptor)

        if not isinstance(document, dict):
            raise MCPServerConfigurationError("JWKS document must be an object")
        raw_keys = document.get("keys")
        if not isinstance(raw_keys, list) or not 1 <= len(raw_keys) <= MAX_JWKS_KEYS:
            raise MCPServerConfigurationError(
                f"JWKS must contain between 1 and {MAX_JWKS_KEYS} keys"
            )

        keys: dict[str, Any] = {}
        for raw_key in raw_keys:
            if not isinstance(raw_key, dict):
                raise MCPServerConfigurationError("each JWKS key must be an object")
            key_id = raw_key.get("kid")
            if not isinstance(key_id, str) or not key_id or len(key_id) > 128:
                raise MCPServerConfigurationError(
                    "each JWKS key must have a bounded non-empty kid"
                )
            if key_id in keys:
                raise MCPServerConfigurationError("JWKS key ids must be unique")
            if raw_key.get("kty") != "RSA":
                raise MCPServerConfigurationError("JWKS may contain only RSA keys")
            if any(
                parameter in raw_key
                for parameter in ("d", "p", "q", "dp", "dq", "qi", "oth")
            ):
                raise MCPServerConfigurationError(
                    "JWKS must not contain private key material"
                )
            if raw_key.get("alg") not in (None, JWT_ALGORITHM):
                raise MCPServerConfigurationError(f"JWKS keys must use {JWT_ALGORITHM}")
            if raw_key.get("use") not in (None, "sig"):
                raise MCPServerConfigurationError("JWKS keys must be signing keys")
            key_operations = raw_key.get("key_ops")
            if key_operations is not None and (
                not isinstance(key_operations, list) or "verify" not in key_operations
            ):
                raise MCPServerConfigurationError(
                    "JWKS key_ops must permit verification"
                )
            try:
                parsed_key = jwt.PyJWK.from_dict(
                    raw_key,
                    algorithm=JWT_ALGORITHM,
                )
            except (jwt.PyJWTError, ValueError, TypeError) as error:
                raise MCPServerConfigurationError(
                    "JWKS contains an invalid key"
                ) from error
            key_size = getattr(parsed_key.key, "key_size", 0)
            if not MIN_RSA_KEY_BITS <= key_size <= MAX_RSA_KEY_BITS:
                raise MCPServerConfigurationError(
                    "JWKS RSA keys must be between "
                    f"{MIN_RSA_KEY_BITS} and {MAX_RSA_KEY_BITS} bits"
                )
            keys[key_id] = parsed_key
        return keys

    async def verify_token(self, token: str) -> AccessToken | None:
        if not isinstance(token, str) or not 0 < len(token) <= MAX_BEARER_TOKEN_BYTES:
            return None
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != JWT_ALGORITHM:
                return None
            key_id = header.get("kid")
            if not isinstance(key_id, str) or key_id not in self._keys:
                return None
            claims = jwt.decode(
                token,
                self._keys[key_id],
                algorithms=[JWT_ALGORITHM],
                issuer=self._config.issuer_url,
                leeway=30,
                options={
                    "require": ["iss", "sub", "aud", "exp", "iat"],
                    "verify_aud": False,
                },
            )
        except (jwt.PyJWTError, ValueError, TypeError):
            return None

        audience = claims.get("aud")
        if audience != self._config.audience and audience != [self._config.audience]:
            return None
        subject = claims.get("sub")
        expires_at = claims.get("exp")
        issued_at = claims.get("iat")
        if (
            not isinstance(subject, str)
            or not subject
            or isinstance(expires_at, bool)
            or not isinstance(expires_at, int)
            or isinstance(issued_at, bool)
            or not isinstance(issued_at, int)
        ):
            return None
        token_resource = claims.get("resource")
        if token_resource is not None and token_resource != self._config.resource_url:
            return None
        raw_scope = claims.get("scope", "")
        if not isinstance(raw_scope, str) or len(raw_scope) > 4096:
            return None
        scope_tokens = raw_scope.split(" ") if raw_scope else []
        if any(
            not scope_token
            or any(
                ord(character) < 0x21
                or ord(character) > 0x7E
                or character in {'"', "\\"}
                for character in scope_token
            )
            for scope_token in scope_tokens
        ):
            return None
        scopes = list(dict.fromkeys(scope_tokens))
        if len(scopes) > 64:
            return None
        client_id = claims.get("client_id", claims.get("azp", self._config.audience))
        if not isinstance(client_id, str) or not client_id:
            return None
        return AccessToken(
            token=token,
            client_id=client_id,
            scopes=scopes,
            expires_at=expires_at,
            resource=self._config.resource_url,
            subject=subject,
            claims={
                "iss": self._config.issuer_url,
                "aud": self._config.audience,
            },
        )


def _clean_params(params: dict[str, Any] | None) -> dict[str, str]:
    if params is None:
        return {}
    if not isinstance(params, dict):
        raise MCPToolError("params must be an object")
    cleaned = {}
    for key, value in params.items():
        if not isinstance(key, str):
            raise MCPToolError("params keys must be strings")
        if value is None:
            continue
        cleaned[key] = str(value)
    return cleaned


def _bounded_rows(result: dict[str, Any], max_rows: int) -> dict[str, Any]:
    if not 1 <= max_rows <= MAX_MCP_ROWS:
        raise MCPToolError(f"max_rows must be between 1 and {MAX_MCP_ROWS}")
    rows = result.get("rows")
    if not isinstance(rows, list):
        return result
    returned = rows[:max_rows]
    return {
        **result,
        "rows": returned,
        "mcp": {
            "returned_rows": len(returned),
            "truncated": len(rows) > len(returned),
            "max_rows": max_rows,
            "available_queries": query_names(),
        },
    }


def get_build_status(data_dir: Path, run_id: str | None = None) -> dict[str, Any]:
    with pinned_build_manifest(data_dir, run_id=run_id) as manifest:
        validation_path = (
            data_dir.resolve() / "builds" / manifest["run_id"] / "validation.json"
        )
        validation = None
        if validation_path.is_file():
            import json

            validation = json.loads(validation_path.read_text(encoding="utf-8"))
        return {
            "schema_version": 2,
            "run_id": manifest["run_id"],
            "deployment": manifest["_deployment_provenance"],
            "active": active_state(data_dir.resolve()),
            "result": manifest["result"],
            "profile": manifest["profile"],
            "started_at": manifest["started_at"],
            "completed_at": manifest["completed_at"],
            "verified_at": manifest.get("verified_at"),
            "source_fingerprint": manifest["source_fingerprint"],
            "logical_fingerprint": manifest["logical_fingerprint"],
            "artifact_fingerprint": manifest["artifact_fingerprint"],
            "counts": manifest["counts"],
            "validation": validation,
            "available_queries": query_names(),
            "trust_policy": {
                "read_only": True,
                "generated_answer": False,
                "live_discovery_performed": False,
            },
        }


def run_stable_query(
    data_dir: Path,
    name: str,
    params: dict[str, Any] | None = None,
    run_id: str | None = None,
    max_rows: int = 100,
) -> dict[str, Any]:
    try:
        result = execute_query(data_dir, name, _clean_params(params), run_id=run_id)
    except QueryError as error:
        raise MCPToolError(str(error)) from error
    return _bounded_rows(result, max_rows)


def compile_context_bundle(
    data_dir: Path,
    question: str,
    risk_level: str = "normal",
    max_documents: int = 5,
    max_sections: int = 8,
    max_chars: int = 6000,
    run_id: str | None = None,
) -> dict[str, Any]:
    try:
        return compile_context(
            data_dir,
            question,
            risk_level=risk_level,
            max_documents=max_documents,
            max_sections=max_sections,
            max_chars=max_chars,
            run_id=run_id,
        )
    except (ContextCompilerError, QueryError) as error:
        raise MCPToolError(str(error)) from error


def _write_principal(config: MCPWriteConfig) -> tuple[str, str]:
    verified_identity = get_access_token()
    if (
        verified_identity is None
        or config.required_scope not in verified_identity.scopes
        or verified_identity.subject not in config.allowed_subjects
    ):
        raise MCPToolError("write access is not authorized")
    return verified_identity.subject, verified_identity.client_id


def _publication_status(
    data_dir: Path, response: dict[str, Any]
) -> dict[str, Any]:
    if response.get("outcome") != "APPLIED":
        return response
    document_id = response.get("document_id")
    source_path = response.get("source_path")
    publication: dict[str, Any] = {"state": "pending"}
    try:
        result = execute_query(
            data_dir,
            "document-by-id",
            {"document_id": str(document_id)},
        )
        rows = result.get("rows", [])
        if (
            len(rows) == 1
            and rows[0].get("document_id") == document_id
            and rows[0].get("source_path") == source_path
        ):
            publication = {
                "state": "active",
                "run_id": result["run_id"],
                "deployment": result["deployment"],
            }
        else:
            publication = {
                "state": "pending",
                "active_run_id": result["run_id"],
            }
    except QueryError:
        publication = {"state": "unavailable"}
    return {
        **response,
        "publication": publication,
        "obsidian_sync": {"state": "not-observed"},
    }


def create_server(
    data_dir: Path = DEFAULT_DATA_DIR,
    *,
    http_auth: HTTPAuthConfig | None = None,
    write_config: MCPWriteConfig | None = None,
    host: str = "127.0.0.1",
    port: int = 8000,
) -> FastMCP:
    resolved_data_dir = data_dir.resolve()
    if write_config is not None and http_auth is None:
        raise MCPServerConfigurationError(
            "write tools require authenticated Streamable HTTP"
        )
    if (
        write_config is not None
        and http_auth is not None
        and write_config.required_scope == http_auth.required_scope
    ):
        raise MCPServerConfigurationError(
            "read and write OAuth scopes must be distinct"
        )
    token_verifier = None
    auth_settings = None
    transport_security = None
    if http_auth is not None:
        token_verifier = OfflineJWKSTokenVerifier(http_auth)
        resource = urlsplit(http_auth.resource_url)
        resource_origin = f"{resource.scheme}://{resource.netloc}"
        allowed_origins = list(
            dict.fromkeys((resource_origin, *http_auth.allowed_origins))
        )
        auth_settings = AuthSettings(
            issuer_url=http_auth.issuer_url,
            resource_server_url=http_auth.resource_url,
            required_scopes=[http_auth.required_scope],
        )
        transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[resource.netloc, "127.0.0.1:*", "localhost:*"],
            allowed_origins=allowed_origins,
        )

    advertised_scopes = (
        (http_auth.required_scope,)
        if http_auth is not None
        else ()
    )
    if write_config is not None:
        advertised_scopes += (write_config.required_scope,)

    mcp = _HomeOpsFastMCP(
        "HomeOps AI",
        advertised_scopes=advertised_scopes,
        instructions=(
            WRITABLE_SERVER_INSTRUCTIONS
            if write_config is not None
            else READ_ONLY_SERVER_INSTRUCTIONS
        ),
        host=host,
        port=port,
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=http_auth is not None,
        max_request_body_size=MAX_HTTP_REQUEST_BYTES,
        token_verifier=token_verifier,
        auth=auth_settings,
        transport_security=transport_security,
    )

    @mcp.tool(
        title="HomeOps build status",
        annotations=READ_ONLY_ANNOTATIONS,
    )
    def build_status(run_id: str | None = None) -> dict[str, Any]:
        """Return metadata for the active verified HomeOps build."""
        return get_build_status(resolved_data_dir, run_id=run_id)

    @mcp.tool(
        title="Run a stable HomeOps query",
        annotations=READ_ONLY_ANNOTATIONS,
    )
    def query(
        name: str,
        params: dict[str, Any] | None = None,
        run_id: str | None = None,
        max_rows: int = 100,
    ) -> dict[str, Any]:
        """Run one stable read-only HomeOps query against a verified build."""
        return run_stable_query(
            resolved_data_dir,
            name,
            params=params,
            run_id=run_id,
            max_rows=max_rows,
        )

    @mcp.tool(
        title="Compile a HomeOps context bundle",
        annotations=READ_ONLY_ANNOTATIONS,
    )
    def context_bundle(
        question: str,
        risk_level: str = "normal",
        max_documents: int = 5,
        max_sections: int = 8,
        max_chars: int = 6000,
        run_id: str | None = None,
    ) -> dict[str, Any]:
        """Compile a deterministic evidence bundle without generating an answer."""
        return compile_context_bundle(
            resolved_data_dir,
            question,
            risk_level=risk_level,
            max_documents=max_documents,
            max_sections=max_sections,
            max_chars=max_chars,
            run_id=run_id,
        )

    if write_config is not None:
        broker = WriteBrokerClient(
            write_config.broker_socket,
            timeout_seconds=write_config.timeout_seconds,
        )

        @mcp.tool(
            title="Capture a new HomeOps note",
            annotations=CREATE_ANNOTATIONS,
        )
        def capture_note(
            request_id: str,
            title: str,
            body: str,
            categories: list[str],
            tags: list[str] | None = None,
        ) -> dict[str, Any]:
            """Create one supporting root note through the validated vault broker.

            request_id must be a new canonical UUIDv4. Reusing it with the exact
            same note is safe; reusing it with different content is rejected.
            Categories must name existing vault categories. Never submit secrets.
            This tool cannot edit, rename, or delete any existing note.
            """
            subject, client_id = _write_principal(write_config)
            try:
                response = broker.capture_note(
                    request_id=request_id,
                    subject=subject,
                    client_id=client_id,
                    title=title,
                    body=body,
                    categories=categories,
                    tags=tags or [],
                )
            except WriteBrokerError as error:
                raise MCPToolError(str(error)) from error
            return _publication_status(resolved_data_dir, response)

        @mcp.tool(
            title="Check a HomeOps note write",
            annotations=READ_ONLY_ANNOTATIONS,
        )
        def write_status(request_id: str) -> dict[str, Any]:
            """Observe broker and verified-build status without retrying a write."""
            subject, client_id = _write_principal(write_config)
            try:
                response = broker.write_status(
                    request_id=request_id,
                    subject=subject,
                    client_id=client_id,
                )
            except WriteBrokerError as error:
                raise MCPToolError(str(error)) from error
            return _publication_status(resolved_data_dir, response)

    @mcp.custom_route("/healthz", methods=["GET"])
    async def healthz(_: Request) -> JSONResponse:
        return JSONResponse(
            {
                "status": "ok",
                "service": "homeops-ai-mcp",
            }
        )

    return mcp


def add_mcp_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument(
        "--transport",
        choices=("stdio", "streamable-http"),
        default="stdio",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--unix-socket", type=Path)
    parser.add_argument("--issuer-url")
    parser.add_argument("--resource-url")
    parser.add_argument("--audience")
    parser.add_argument("--jwks-file", type=Path)
    parser.add_argument("--required-scope", default="homeops:read")
    parser.add_argument("--allowed-origin", action="append", default=[])
    parser.add_argument("--write-broker-socket", type=Path)
    parser.add_argument("--write-scope", default="homeops:write")
    parser.add_argument("--write-subject", action="append", default=[])
    parser.add_argument("--write-timeout-seconds", type=float, default=10.0)
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="validate HTTP auth configuration and JWKS, then exit",
    )


def _http_auth_from_args(args: argparse.Namespace) -> HTTPAuthConfig:
    required = {
        "issuer_url": args.issuer_url,
        "resource_url": args.resource_url,
        "audience": args.audience,
        "jwks_file": args.jwks_file,
    }
    missing = [name.replace("_", "-") for name, value in required.items() if not value]
    if missing:
        raise MCPServerConfigurationError(
            "streamable-http requires " + ", ".join(f"--{name}" for name in missing)
        )
    if not 1 <= args.port <= 65535:
        raise MCPServerConfigurationError("port must be between 1 and 65535")
    return HTTPAuthConfig(
        issuer_url=args.issuer_url,
        resource_url=args.resource_url,
        audience=args.audience,
        jwks_file=args.jwks_file,
        required_scope=args.required_scope,
        allowed_origins=tuple(args.allowed_origin),
    )


def _write_config_from_args(args: argparse.Namespace) -> MCPWriteConfig | None:
    if args.write_broker_socket is None:
        if args.write_subject:
            raise MCPServerConfigurationError(
                "--write-subject requires --write-broker-socket"
            )
        return None
    if not args.write_subject:
        raise MCPServerConfigurationError(
            "--write-broker-socket requires at least one --write-subject"
        )
    if args.unix_socket is None:
        raise MCPServerConfigurationError(
            "write tools require the MCP service to use --unix-socket"
        )
    if args.write_broker_socket.resolve(strict=False) == args.unix_socket.resolve(
        strict=False
    ):
        raise MCPServerConfigurationError(
            "MCP and write-broker Unix sockets must be distinct"
        )
    return MCPWriteConfig(
        broker_socket=args.write_broker_socket,
        allowed_subjects=tuple(args.write_subject),
        required_scope=args.write_scope,
        timeout_seconds=args.write_timeout_seconds,
    )


def _prepare_unix_socket(path: Path) -> socket.socket:
    if not path.is_absolute():
        raise MCPServerConfigurationError("unix_socket must be an absolute path")
    try:
        parent_metadata = path.parent.stat(follow_symlinks=False)
    except OSError as error:
        raise MCPServerConfigurationError(
            f"cannot inspect Unix socket parent: {path.parent}"
        ) from error
    if not stat.S_ISDIR(parent_metadata.st_mode):
        raise MCPServerConfigurationError("Unix socket parent must be a directory")
    if parent_metadata.st_mode & 0o022:
        raise MCPServerConfigurationError(
            "Unix socket parent must not be writable by group or others"
        )
    try:
        existing = path.lstat()
    except FileNotFoundError:
        existing = None
    except OSError as error:
        raise MCPServerConfigurationError(
            f"cannot inspect Unix socket path: {path}"
        ) from error
    if existing is not None:
        if not stat.S_ISSOCK(existing.st_mode):
            raise MCPServerConfigurationError(
                "refusing to replace a non-socket Unix socket path"
            )
        path.unlink()

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(path))
        path.chmod(0o600)
        listener.listen(128)
        listener.setblocking(False)
    except BaseException:
        listener.close()
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISSOCK(metadata.st_mode):
                path.unlink()
        raise
    return listener


def _run_streamable_http_unix(server: FastMCP, path: Path) -> None:
    if threading.current_thread() is not threading.main_thread():
        raise MCPServerConfigurationError(
            "Unix-socket HTTP transport must run in the main thread"
        )
    listener = _prepare_unix_socket(path)
    application = server.streamable_http_app()
    configuration = uvicorn.Config(
        application,
        log_level=server.settings.log_level.lower(),
        access_log=True,
        proxy_headers=False,
        server_header=False,
        limit_concurrency=64,
        backlog=128,
        timeout_keep_alive=10,
        timeout_graceful_shutdown=10,
    )
    uvicorn_server = _UnixSocketUvicornServer(configuration)

    def request_shutdown(_: int, __: FrameType | None) -> None:
        if uvicorn_server.should_exit:
            uvicorn_server.force_exit = True
        uvicorn_server.should_exit = True

    shutdown_signals = (signal.SIGINT, signal.SIGTERM)
    previous_handlers = {
        shutdown_signal: signal.getsignal(shutdown_signal)
        for shutdown_signal in shutdown_signals
    }
    for shutdown_signal in shutdown_signals:
        signal.signal(shutdown_signal, request_shutdown)
    try:
        asyncio.run(uvicorn_server.serve(sockets=[listener]))
    finally:
        for shutdown_signal, previous_handler in previous_handlers.items():
            signal.signal(shutdown_signal, previous_handler)
        listener.close()
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISSOCK(metadata.st_mode):
                path.unlink()


def run_server_from_args(args: argparse.Namespace) -> None:
    if args.transport == "stdio":
        if args.check_config:
            raise MCPServerConfigurationError(
                "--check-config requires --transport streamable-http"
            )
        if args.write_broker_socket is not None or args.write_subject:
            raise MCPServerConfigurationError(
                "write tools require --transport streamable-http"
            )
        create_server(args.data_dir).run(transport="stdio")
        return

    http_auth = _http_auth_from_args(args)
    write_config = _write_config_from_args(args)
    server = create_server(
        args.data_dir,
        http_auth=http_auth,
        write_config=write_config,
        host=args.host,
        port=args.port,
    )
    if args.check_config:
        print("HomeOps MCP HTTP configuration is valid")
        return
    if args.unix_socket is not None:
        _run_streamable_http_unix(server, args.unix_socket)
        return
    server.run(transport="streamable-http")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the HomeOps MCP server")
    add_mcp_arguments(parser)
    args = parser.parse_args()

    try:
        run_server_from_args(args)
    except MCPServerConfigurationError as error:
        parser.error(str(error))
