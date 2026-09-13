import json
import stat
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import anyio
import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client

from homeops_ai.build import active_state, inspect_vault, rebuild
from homeops_ai.mcp_server import (
    HTTPAuthConfig,
    MAX_MCP_ROWS,
    MCPWriteConfig,
    MCPServerConfigurationError,
    MCPToolError,
    OfflineJWKSTokenVerifier,
    _prepare_unix_socket,
    _write_config_from_args,
    compile_context_bundle,
    create_server,
    get_build_status,
    run_stable_query,
)
from homeops_ai.snapshot import create_snapshot_manifest, write_manifest
from homeops_ai.source_contract import export_snapshot
from homeops_ai.write_broker import UnixWriteBrokerServer, VaultWriteBroker


ISSUER_URL = "https://auth.example.test/application/o/homeops-mcp/"
RESOURCE_URL = "https://mcp.example.test/mcp"
AUDIENCE = RESOURCE_URL
KEY_ID = "homeops-test-key"


def _auth_material(tmp_path: Path) -> tuple[HTTPAuthConfig, object]:
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(
        jwt.algorithms.RSAAlgorithm.to_jwk(signing_key.public_key())
    )
    public_jwk.update(
        {
            "kid": KEY_ID,
            "alg": "RS256",
            "use": "sig",
            "key_ops": ["verify"],
        }
    )
    jwks_file = tmp_path / "jwks.json"
    jwks_file.write_text(json.dumps({"keys": [public_jwk]}), encoding="utf-8")
    jwks_file.chmod(0o644)
    return (
        HTTPAuthConfig(
            issuer_url=ISSUER_URL,
            resource_url=RESOURCE_URL,
            audience=AUDIENCE,
            jwks_file=jwks_file,
        ),
        signing_key,
    )


def _access_token(
    signing_key: object,
    *,
    issuer: str = ISSUER_URL,
    audience: object = AUDIENCE,
    scope: object = "openid homeops:read",
    subject: object = "test-user",
    key_id: str = KEY_ID,
    issued_at: int | None = None,
    expires_at: int | None = None,
    extra_claims: dict[str, object] | None = None,
) -> str:
    now = int(time.time())
    claims = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "iat": issued_at if issued_at is not None else now - 1,
        "exp": expires_at if expires_at is not None else now + 300,
        "scope": scope,
        "azp": "chatgpt-test-client",
    }
    claims.update(extra_claims or {})
    return jwt.encode(
        claims,
        signing_key,
        algorithm="RS256",
        headers={"kid": key_id},
    )


def _write_vault(vault: Path) -> None:
    (vault / "Categories").mkdir()
    (vault / "Categories" / "AI.md").write_text(
        """---
id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
type: category
status: current
---
"""
    )
    (vault / "AI Context.md").write_text(
        """---
id: "11111111-1111-4111-8111-111111111111"
categories: ["[[AI]]"]
type: context-index
status: current
authority: canonical
---
Current priorities link to [[Heavy VM]] and [[AI Plan]].
"""
    )
    (vault / "Heavy VM.md").write_text(
        """---
id: "22222222-2222-4222-8222-222222222222"
categories: ["[[AI]]"]
type: current-state
status: current
authority: canonical
---
## Services

The Heavy VM currently runs HomeOps. See [[Missing]].
"""
    )
    (vault / "AI Plan.md").write_text(
        """---
id: "33333333-3333-4333-8333-333333333333"
categories: ["[[AI]]"]
type: plan
status: in-progress
authority: supporting
---
The active AI plan links to [[Heavy VM]].
"""
    )
    (vault / "Legacy.md").write_text(
        """---
id: "44444444-4444-4444-8444-444444444444"
categories: ["[[AI]]"]
type: plan
status: historical
authority: supporting
---
Legacy guidance links to [[AI Context]].
"""
    )
    (vault / "Missing Lifecycle.md").write_text(
        """---
id: "55555555-5555-4555-8555-555555555555"
---
Incomplete legacy metadata.
"""
    )


def _build_data(tmp_path: Path) -> Path:
    vault = tmp_path / "vault"
    data = tmp_path / "data"
    vault.mkdir()
    _write_vault(vault)
    rebuild(vault, data)
    return data


def _promote_versioned_build(
    tmp_path: Path,
    vault: Path,
    data: Path,
    *,
    sequence: int,
    expected_deployment_id: str | None,
) -> tuple[str, str]:
    revision = "a" * 40
    digest = "sha256:" + "b" * 64
    staging = tmp_path / f"snapshot-staging-{sequence}"
    export_snapshot(vault, staging / "vault")
    inspected = inspect_vault(staging / "vault")
    manifest = create_snapshot_manifest(
        staging / "vault",
        inspected,
        created_at=f"2026-08-13T12:0{sequence}:00+00:00",
        package_version="0.4.1",
        source_revision=revision,
    )
    snapshot = tmp_path / "vault-snapshots" / manifest["snapshot_id"]
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    staging.rename(snapshot)
    write_manifest(snapshot / "snapshot.json", manifest)
    build = rebuild(
        snapshot / "vault",
        data,
        snapshot_manifest=manifest,
        snapshot_received_at=f"2026-08-13T12:0{sequence}:30+00:00",
        homeops_version="0.4.1",
        source_revision=revision,
        image_digest=digest,
        expected_current_deployment_id=expected_deployment_id,
    )
    return build["run_id"], build["deployment_id"]


def test_build_status_reports_verified_read_only_contract(tmp_path: Path) -> None:
    data = _build_data(tmp_path)

    status = get_build_status(data)

    assert status["result"] == "verified"
    assert status["active"]["current"] == status["run_id"]
    assert status["counts"]["source_document"] == 6
    assert status["validation"]["valid"] is True
    assert status["trust_policy"] == {
        "read_only": True,
        "generated_answer": False,
        "live_discovery_performed": False,
    }
    assert "context" in status["available_queries"]


def test_explicit_previous_and_retained_runs_report_mcp_provenance(
    tmp_path: Path,
) -> None:
    vault = tmp_path / "vault"
    data = tmp_path / "data"
    vault.mkdir()
    _write_vault(vault)

    first_run, first_deployment = _promote_versioned_build(
        tmp_path,
        vault,
        data,
        sequence=1,
        expected_deployment_id=None,
    )
    context = vault / "AI Context.md"
    context.write_text(
        context.read_text(encoding="utf-8") + "\nSecond deployment.\n",
        encoding="utf-8",
    )
    second_run, second_deployment = _promote_versioned_build(
        tmp_path,
        vault,
        data,
        sequence=2,
        expected_deployment_id=first_deployment,
    )
    context.write_text(
        context.read_text(encoding="utf-8") + "\nThird deployment.\n",
        encoding="utf-8",
    )
    third_run, third_deployment = _promote_versioned_build(
        tmp_path,
        vault,
        data,
        sequence=3,
        expected_deployment_id=second_deployment,
    )

    previous = get_build_status(data, run_id=second_run)
    assert previous["deployment"]["role"] == "previous"
    assert previous["deployment"]["active"] is False
    assert previous["deployment"]["retained"] is True
    assert previous["deployment"]["deployment_id"] == second_deployment

    retained = get_build_status(data, run_id=first_run)
    assert retained["deployment"]["role"] == "retained"
    assert retained["deployment"]["active"] is False
    assert retained["deployment"]["retained"] is True
    assert retained["deployment"]["deployment_id"] == first_deployment

    query = run_stable_query(data, "canonical-current", run_id=first_run)
    assert query["run_id"] == first_run
    assert query["deployment"]["role"] == "retained"
    bundle = compile_context_bundle(data, "What currently runs?", run_id=second_run)
    assert bundle["build"]["run_id"] == second_run
    assert bundle["build"]["deployment"]["role"] == "previous"

    selected_before = active_state(data)
    assert selected_before["current"] == third_run
    assert selected_before["current_deployment"]["deployment_id"] == third_deployment

    async def run_explicit_mcp_calls() -> None:
        server = StdioServerParameters(
            command=str(Path(sys.executable).with_name("homeops-ai")),
            args=["mcp", "--data-dir", str(data)],
        )
        async with stdio_client(server) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                previous_result = await session.call_tool(
                    "build_status", {"run_id": second_run}
                )
                assert previous_result.isError is False
                assert previous_result.structuredContent["deployment"]["role"] == (
                    "previous"
                )
                retained_result = await session.call_tool(
                    "build_status", {"run_id": first_run}
                )
                assert retained_result.isError is False
                assert retained_result.structuredContent["deployment"]["role"] == (
                    "retained"
                )

    anyio.run(run_explicit_mcp_calls)
    assert active_state(data) == selected_before


def test_query_tool_uses_stable_queries_and_bounds_rows(tmp_path: Path) -> None:
    data = _build_data(tmp_path)

    result = run_stable_query(data, "link-inventory", max_rows=2)

    assert result["query"] == "link-inventory"
    assert len(result["rows"]) == 2
    assert result["mcp"]["returned_rows"] == 2
    assert result["mcp"]["truncated"] is True


def test_query_tool_rejects_invalid_params_and_row_limits(tmp_path: Path) -> None:
    data = _build_data(tmp_path)

    with pytest.raises(MCPToolError, match="params must be an object"):
        run_stable_query(data, "canonical-current", params=["not", "an", "object"])
    with pytest.raises(MCPToolError, match=f"between 1 and {MAX_MCP_ROWS}"):
        run_stable_query(data, "canonical-current", max_rows=0)


def test_context_bundle_tool_preserves_risk_policy(tmp_path: Path) -> None:
    data = _build_data(tmp_path)

    bundle = compile_context_bundle(
        data,
        "Change the Heavy VM",
        risk_level="risky",
        max_documents=2,
        max_sections=2,
        max_chars=1000,
    )

    assert bundle["bundle_kind"] == "homeops-context-bundle"
    assert bundle["live_verification"]["required"]
    assert bundle["trust_policy"]["generated_answer"] is False
    assert bundle["selection"]["document_count"] <= 2


def test_stdio_mcp_server_exposes_read_only_tools(tmp_path: Path) -> None:
    data = _build_data(tmp_path)

    async def run_smoke() -> None:
        server = StdioServerParameters(
            command=str(Path(sys.executable).with_name("homeops-ai")),
            args=["mcp", "--data-dir", str(data)],
        )
        async with stdio_client(server) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                tools = await session.list_tools()
                assert {tool.name for tool in tools.tools} == {
                    "build_status",
                    "context_bundle",
                    "query",
                }
                for tool in tools.tools:
                    assert tool.annotations is not None
                    assert tool.annotations.readOnlyHint is True
                    assert tool.annotations.destructiveHint is False
                    assert tool.annotations.idempotentHint is True
                    assert tool.annotations.openWorldHint is False

                result = await session.call_tool("build_status", {})
                assert result.isError is False
                assert result.structuredContent["result"] == "verified"
                assert (
                    result.structuredContent["active"]["current"]
                    == active_state(data)["current"]
                )

    anyio.run(run_smoke)


def test_http_auth_configuration_is_strict(tmp_path: Path) -> None:
    config, _ = _auth_material(tmp_path)
    assert config.required_scope == "homeops:read"

    with pytest.raises(MCPServerConfigurationError, match="HTTPS URL"):
        HTTPAuthConfig(
            issuer_url="http://auth.example.test/issuer",
            resource_url=RESOURCE_URL,
            audience=AUDIENCE,
            jwks_file=config.jwks_file,
        )
    with pytest.raises(MCPServerConfigurationError, match="exact path /mcp"):
        HTTPAuthConfig(
            issuer_url=ISSUER_URL,
            resource_url="https://mcp.example.test/not-mcp",
            audience=AUDIENCE,
            jwks_file=config.jwks_file,
        )
    with pytest.raises(MCPServerConfigurationError, match="exactly match"):
        HTTPAuthConfig(
            issuer_url=ISSUER_URL,
            resource_url=RESOURCE_URL,
            audience="urn:unbound-audience",
            jwks_file=config.jwks_file,
        )
    with pytest.raises(MCPServerConfigurationError, match="one non-empty"):
        HTTPAuthConfig(
            issuer_url=ISSUER_URL,
            resource_url=RESOURCE_URL,
            audience=AUDIENCE,
            jwks_file=config.jwks_file,
            required_scope="homeops:read another",
        )


def test_jwks_must_be_regular_bounded_and_not_group_writable(
    tmp_path: Path,
) -> None:
    config, _ = _auth_material(tmp_path)
    config.jwks_file.chmod(0o666)
    with pytest.raises(MCPServerConfigurationError, match="writable"):
        OfflineJWKSTokenVerifier(config)

    config.jwks_file.chmod(0o644)
    duplicate = json.loads(config.jwks_file.read_text(encoding="utf-8"))
    duplicate["keys"].append(duplicate["keys"][0])
    config.jwks_file.write_text(json.dumps(duplicate), encoding="utf-8")
    with pytest.raises(MCPServerConfigurationError, match="unique"):
        OfflineJWKSTokenVerifier(config)


def test_jwks_rejects_private_key_material(tmp_path: Path) -> None:
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(signing_key))
    private_jwk.update({"kid": KEY_ID, "alg": "RS256", "use": "sig"})
    jwks_file = tmp_path / "private-jwks.json"
    jwks_file.write_text(json.dumps({"keys": [private_jwk]}), encoding="utf-8")
    jwks_file.chmod(0o600)
    config = HTTPAuthConfig(
        issuer_url=ISSUER_URL,
        resource_url=RESOURCE_URL,
        audience=AUDIENCE,
        jwks_file=jwks_file,
    )

    with pytest.raises(MCPServerConfigurationError, match="private key"):
        OfflineJWKSTokenVerifier(config)


def test_jwks_rejects_weak_rsa_keys(tmp_path: Path) -> None:
    weak_signing_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    weak_public_jwk = json.loads(
        jwt.algorithms.RSAAlgorithm.to_jwk(weak_signing_key.public_key())
    )
    weak_public_jwk.update({"kid": KEY_ID, "alg": "RS256", "use": "sig"})
    jwks_file = tmp_path / "weak-jwks.json"
    jwks_file.write_text(json.dumps({"keys": [weak_public_jwk]}), encoding="utf-8")
    jwks_file.chmod(0o600)
    config = HTTPAuthConfig(
        issuer_url=ISSUER_URL,
        resource_url=RESOURCE_URL,
        audience=AUDIENCE,
        jwks_file=jwks_file,
    )

    with pytest.raises(MCPServerConfigurationError, match="2048 and 8192 bits"):
        OfflineJWKSTokenVerifier(config)


@pytest.mark.parametrize(
    ("token_changes", "header_key_id"),
    [
        ({"issuer": "https://wrong.example.test/"}, KEY_ID),
        ({"audience": "https://wrong.example.test/mcp"}, KEY_ID),
        ({"audience": [AUDIENCE, "https://extra.example.test/mcp"]}, KEY_ID),
        ({"subject": ""}, KEY_ID),
        ({"expires_at": 1}, KEY_ID),
        ({"issued_at": int(time.time()) + 3600}, KEY_ID),
        ({"extra_claims": {"resource": "https://wrong.example.test/mcp"}}, KEY_ID),
        ({"scope": "openid\thomeops:read"}, KEY_ID),
        ({}, "unknown-key"),
    ],
)
def test_offline_verifier_rejects_invalid_token_constraints(
    tmp_path: Path,
    token_changes: dict[str, object],
    header_key_id: str,
) -> None:
    config, signing_key = _auth_material(tmp_path)
    verifier = OfflineJWKSTokenVerifier(config)
    token = _access_token(signing_key, key_id=header_key_id, **token_changes)

    assert anyio.run(verifier.verify_token, token) is None


def test_offline_verifier_accepts_exact_token_and_preserves_scopes(
    tmp_path: Path,
) -> None:
    config, signing_key = _auth_material(tmp_path)
    verifier = OfflineJWKSTokenVerifier(config)

    access = anyio.run(verifier.verify_token, _access_token(signing_key))

    assert access is not None
    assert access.subject == "test-user"
    assert access.client_id == "chatgpt-test-client"
    assert access.resource == RESOURCE_URL
    assert access.scopes == ["openid", "homeops:read"]
    assert anyio.run(verifier.verify_token, "not-a-jwt") is None


def test_streamable_http_requires_oauth_and_serves_resource_metadata(
    tmp_path: Path,
) -> None:
    data = _build_data(tmp_path)
    config, signing_key = _auth_material(tmp_path)
    app = create_server(data, http_auth=config).streamable_http_app()

    async def run_http_smoke() -> None:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="https://mcp.example.test",
        ) as client:
            health = await client.get("/healthz")
            assert health.status_code == 200
            assert health.json() == {
                "status": "ok",
                "service": "homeops-ai-mcp",
            }

            metadata = await client.get("/.well-known/oauth-protected-resource/mcp")
            assert metadata.status_code == 200
            assert metadata.json() == {
                "resource": RESOURCE_URL,
                "authorization_servers": [ISSUER_URL],
                "scopes_supported": ["homeops:read"],
                "bearer_methods_supported": ["header"],
            }

            unauthenticated = await client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            )
            assert unauthenticated.status_code == 401
            challenge = unauthenticated.headers["www-authenticate"]
            assert 'error="invalid_token"' in challenge
            assert (
                'resource_metadata="https://mcp.example.test/'
                '.well-known/oauth-protected-resource/mcp"' in challenge
            )

            malformed = await client.post(
                "/mcp",
                headers={"Authorization": "Bearer not-a-jwt"},
                json={"jsonrpc": "2.0", "id": 2, "method": "initialize"},
            )
            assert malformed.status_code == 401

            insufficient_scope = await client.post(
                "/mcp",
                headers={
                    "Authorization": "Bearer "
                    + _access_token(signing_key, scope="openid")
                },
                json={"jsonrpc": "2.0", "id": 3, "method": "initialize"},
            )
            assert insufficient_scope.status_code == 403
            assert insufficient_scope.json()["error"] == "insufficient_scope"

    anyio.run(run_http_smoke)


def test_authenticated_streamable_http_lists_and_calls_read_only_tools(
    tmp_path: Path,
) -> None:
    data = _build_data(tmp_path)
    config, signing_key = _auth_material(tmp_path)
    server = create_server(data, http_auth=config)
    app = server.streamable_http_app()

    async def run_authenticated_smoke() -> None:
        transport = httpx.ASGITransport(app=app)
        headers = {"Authorization": "Bearer " + _access_token(signing_key)}
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=transport,
                base_url="https://mcp.example.test",
                headers=headers,
            ) as http_client:
                async with streamable_http_client(
                    RESOURCE_URL,
                    http_client=http_client,
                ) as (read_stream, write_stream, _):
                    async with ClientSession(read_stream, write_stream) as session:
                        initialized = await session.initialize()
                        assert initialized.serverInfo.name == "HomeOps AI"
                        assert "published HomeOps" in initialized.instructions
                        tools = await session.list_tools()
                        assert {tool.name for tool in tools.tools} == {
                            "build_status",
                            "context_bundle",
                            "query",
                        }
                        for tool in tools.tools:
                            assert tool.annotations is not None
                            assert tool.annotations.readOnlyHint is True
                            assert tool.annotations.destructiveHint is False
                            assert tool.annotations.openWorldHint is False

                        result = await session.call_tool("build_status", {})
                        assert result.isError is False
                        assert result.structuredContent["result"] == "verified"

    anyio.run(run_authenticated_smoke)


def test_authenticated_writable_http_requires_write_scope_and_subject(
    tmp_path: Path,
) -> None:
    data = _build_data(tmp_path)
    vault = tmp_path / "vault"
    config, signing_key = _auth_material(tmp_path)
    state = tmp_path / "write-state"
    state.mkdir(mode=0o700)
    runtime = tmp_path / "write-runtime"
    runtime.mkdir(mode=0o700)
    socket_path = runtime / "broker.sock"
    broker = VaultWriteBroker(vault, state, allowed_subjects=("test-user",))
    broker_server = UnixWriteBrokerServer(socket_path, broker)
    broker_thread = threading.Thread(
        target=broker_server.serve_forever,
        daemon=True,
    )
    broker_thread.start()
    try:
        write_config = MCPWriteConfig(
            broker_socket=socket_path,
            allowed_subjects=("test-user",),
        )
        app = create_server(
            data,
            http_auth=config,
            write_config=write_config,
        ).streamable_http_app()

        async def run_writable_smoke() -> None:
            transport = httpx.ASGITransport(app=app)
            async with app.router.lifespan_context(app):
                async with httpx.AsyncClient(
                    transport=transport,
                    base_url="https://mcp.example.test",
                ) as raw_client:
                    metadata = await raw_client.get(
                        "/.well-known/oauth-protected-resource/mcp"
                    )
                    assert metadata.status_code == 200
                    assert metadata.json()["scopes_supported"] == [
                        "homeops:read",
                        "homeops:write",
                    ]
                read_only_headers = {
                    "Authorization": "Bearer " + _access_token(signing_key)
                }
                async with httpx.AsyncClient(
                    transport=transport,
                    base_url="https://mcp.example.test",
                    headers=read_only_headers,
                ) as read_only_client:
                    async with streamable_http_client(
                        RESOURCE_URL,
                        http_client=read_only_client,
                    ) as (read_stream, write_stream, _):
                        async with ClientSession(read_stream, write_stream) as session:
                            await session.initialize()
                            tools = await session.list_tools()
                            assert {tool.name for tool in tools.tools} == {
                                "build_status",
                                "capture_note",
                                "context_bundle",
                                "query",
                                "write_status",
                            }
                            denied = await session.call_tool(
                                "capture_note",
                                {
                                    "request_id": str(uuid.uuid4()),
                                    "title": "Denied without write scope",
                                    "body": "This must not be written.",
                                    "categories": ["AI"],
                                    "tags": [],
                                },
                            )
                            assert denied.isError is True

                headers = {
                    "Authorization": "Bearer "
                    + _access_token(
                        signing_key,
                        scope="openid homeops:read homeops:write",
                    )
                }
                async with httpx.AsyncClient(
                    transport=transport,
                    base_url="https://mcp.example.test",
                    headers=headers,
                ) as http_client:
                    async with streamable_http_client(
                        RESOURCE_URL,
                        http_client=http_client,
                    ) as (read_stream, write_stream, _):
                        async with ClientSession(read_stream, write_stream) as session:
                            initialized = await session.initialize()
                            assert "create-only capture_note" in initialized.instructions
                            tools = await session.list_tools()
                            by_name = {tool.name: tool for tool in tools.tools}
                            assert set(by_name) == {
                                "build_status",
                                "capture_note",
                                "context_bundle",
                                "query",
                                "write_status",
                            }
                            assert by_name["capture_note"].annotations is not None
                            assert (
                                by_name["capture_note"].annotations.readOnlyHint
                                is False
                            )
                            assert (
                                by_name["capture_note"].annotations.destructiveHint
                                is False
                            )
                            assert by_name["write_status"].annotations is not None
                            assert (
                                by_name["write_status"].annotations.readOnlyHint is True
                            )

                            request_id = str(uuid.uuid4())
                            captured = await session.call_tool(
                                "capture_note",
                                {
                                    "request_id": request_id,
                                    "title": "Cross-device capture",
                                    "body": "Captured through the authenticated MCP.",
                                    "categories": ["AI"],
                                    "tags": ["remote"],
                                },
                            )
                            assert captured.isError is False
                            assert captured.structuredContent["outcome"] == "APPLIED"
                            assert captured.structuredContent["publication"] == {
                                "state": "pending",
                                "active_run_id": active_state(data)["current"],
                            }
                            assert captured.structuredContent["obsidian_sync"] == {
                                "state": "not-observed"
                            }

                            rebuild(vault, data)
                            status = await session.call_tool(
                                "write_status", {"request_id": request_id}
                            )
                            assert status.isError is False
                            assert status.structuredContent["outcome"] == "APPLIED"
                            assert (
                                status.structuredContent["publication"]["state"]
                                == "active"
                            )
                            assert status.structuredContent["obsidian_sync"] == {
                                "state": "not-observed"
                            }

                denied_headers = {
                    "Authorization": "Bearer "
                    + _access_token(
                        signing_key,
                        subject="another-user",
                        scope="openid homeops:read homeops:write",
                    )
                }
                async with httpx.AsyncClient(
                    transport=transport,
                    base_url="https://mcp.example.test",
                    headers=denied_headers,
                ) as denied_client:
                    async with streamable_http_client(
                        RESOURCE_URL,
                        http_client=denied_client,
                    ) as (read_stream, write_stream, _):
                        async with ClientSession(read_stream, write_stream) as session:
                            await session.initialize()
                            denied = await session.call_tool(
                                "capture_note",
                                {
                                    "request_id": str(uuid.uuid4()),
                                    "title": "Denied",
                                    "body": "This must not be written.",
                                    "categories": ["AI"],
                                    "tags": [],
                                },
                            )
                            assert denied.isError is True

        anyio.run(run_writable_smoke)
    finally:
        broker_server.shutdown()
        broker_server.server_close()
        broker_thread.join(timeout=5)
        broker.close()


def test_write_configuration_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(MCPServerConfigurationError, match="authenticated"):
        create_server(
            tmp_path,
            write_config=MCPWriteConfig(
                broker_socket=tmp_path / "broker.sock",
                allowed_subjects=("test-user",),
            ),
        )

    base_arguments = {
        "write_broker_socket": tmp_path / "broker.sock",
        "write_subject": ["test-user"],
        "write_scope": "homeops:write",
        "write_timeout_seconds": 10.0,
    }
    with pytest.raises(MCPServerConfigurationError, match="use --unix-socket"):
        _write_config_from_args(
            SimpleNamespace(**base_arguments, unix_socket=None)
        )
    with pytest.raises(MCPServerConfigurationError, match="must be distinct"):
        _write_config_from_args(
            SimpleNamespace(
                **base_arguments,
                unix_socket=tmp_path / "broker.sock",
            )
        )

    config, _ = _auth_material(tmp_path)
    with pytest.raises(MCPServerConfigurationError, match="distinct"):
        create_server(
            tmp_path,
            http_auth=config,
            write_config=MCPWriteConfig(
                broker_socket=tmp_path / "broker.sock",
                allowed_subjects=("test-user",),
                required_scope="homeops:read",
            ),
        )


def test_unix_socket_is_private_and_non_socket_is_never_replaced(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    socket_path = runtime / "mcp.sock"

    listener = _prepare_unix_socket(socket_path)
    try:
        assert stat.S_ISSOCK(socket_path.lstat().st_mode)
        assert stat.S_IMODE(socket_path.lstat().st_mode) == 0o600
    finally:
        listener.close()
        socket_path.unlink()

    socket_path.write_text("preserve me", encoding="utf-8")
    with pytest.raises(MCPServerConfigurationError, match="refusing to replace"):
        _prepare_unix_socket(socket_path)
    assert socket_path.read_text(encoding="utf-8") == "preserve me"


def test_streamable_http_cli_serves_authenticated_mcp_on_unix_socket(
    tmp_path: Path,
) -> None:
    data = _build_data(tmp_path)
    config, signing_key = _auth_material(tmp_path)
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    socket_path = runtime / "mcp.sock"
    command = [
        sys.executable,
        "-c",
        "from homeops_ai.cli import main; main()",
        "mcp",
        "--transport",
        "streamable-http",
        "--data-dir",
        str(data),
        "--unix-socket",
        str(socket_path),
        "--issuer-url",
        config.issuer_url,
        "--resource-url",
        config.resource_url,
        "--audience",
        config.audience,
        "--jwks-file",
        str(config.jwks_file),
    ]
    check = subprocess.run(
        [*command, "--check-config"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert check.returncode == 0, check.stderr
    assert check.stdout == "HomeOps MCP HTTP configuration is valid\n"
    assert not socket_path.exists()

    process = subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    stderr = ""
    try:
        deadline = time.monotonic() + 10
        while not socket_path.exists() and process.poll() is None:
            if time.monotonic() >= deadline:
                pytest.fail("timed out waiting for the MCP Unix socket")
            time.sleep(0.02)
        if process.poll() is not None:
            stderr = process.stderr.read() if process.stderr else ""
            pytest.fail(f"MCP HTTP process exited before serving: {stderr}")
        assert stat.S_IMODE(socket_path.lstat().st_mode) == 0o600

        async def run_unix_smoke() -> None:
            transport = httpx.AsyncHTTPTransport(
                uds=str(socket_path),
                trust_env=False,
            )
            headers = {
                "Host": "mcp.example.test",
                "Authorization": "Bearer " + _access_token(signing_key),
            }
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://localhost",
                headers=headers,
            ) as http_client:
                health = await http_client.get("/healthz")
                assert health.status_code == 200
                async with streamable_http_client(
                    "http://localhost/mcp",
                    http_client=http_client,
                ) as (read_stream, write_stream, _):
                    async with ClientSession(read_stream, write_stream) as session:
                        await session.initialize()
                        result = await session.call_tool("build_status", {})
                        assert result.isError is False
                        assert result.structuredContent["result"] == "verified"

        anyio.run(run_unix_smoke)
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            _, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            _, stderr = process.communicate(timeout=5)
            pytest.fail(f"MCP HTTP process did not terminate cleanly: {stderr}")

    assert process.returncode == 0, stderr
    assert not socket_path.exists()
