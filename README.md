# HomeOps AI

An evidence-backed knowledge platform for the homelab, network, smart home, and
projects documented in the Obsidian vault.

The initial milestone validates CozoDB as an embedded, derived-data store. The
vault and verified live discovery remain authoritative.

## Development

The project pins Python 3.12 and CozoDB/PyCozo 0.7.6 because CozoDB is pre-1.0
and does not promise API, syntax, or storage compatibility.

```bash
uv sync
uv run pytest
go test ./...
go test -race ./...
go vet ./...
uv run homeops-ai smoke
uv run homeops-ai smoke --database data/homeops.db
```

The persistent smoke database is intentionally ignored by Git.

## Vault Migration Preview

HomeOps never changes vault notes during ingestion. UUID and lifecycle metadata
migrations are separate, reviewed operations:

```bash
uv run homeops-ai vault inventory --vault /path/to/vault
uv run homeops-ai vault migrate \
  --vault /path/to/vault \
  --dry-run \
  --output data/reports/vault-migration.json
```

After reviewing the JSON report, the exact reviewed plan can be applied:

```bash
uv run homeops-ai vault migrate \
  --vault /path/to/vault \
  --apply \
  --report data/reports/vault-migration.json
```

Apply creates exact-byte snapshots under `data/migrations/<migration-id>/`
before modifying any source file. Restore refuses to overwrite files changed
after migration:

```bash
uv run homeops-ai vault restore \
  --vault /path/to/vault \
  --migration-id <migration-id>
```

## Immutable Knowledge Builds

Validate the vault before rebuilding. Unresolved internal links are preserved and
reported as warnings; ambiguous links and unresolved category assignments fail
validation.

```bash
uv run homeops-ai vault validate --vault /path/to/vault
uv run homeops-ai db rebuild --vault /path/to/vault
uv run homeops-ai db verify
uv run homeops-ai db builds
uv run homeops-ai db rollback
uv run homeops-ai db cleanup --failed
```

Each rebuild creates an immutable candidate under `data/builds/<run-id>/`.
HomeOps closes the database, verifies it through a constrained separate process,
then atomically updates `data/active.json`. An unchanged source and artifact
fingerprint does not create another build unless `--force` is used.

## Deterministic Queries And Evaluation

Stable read-only queries run against the active verified build:

```bash
uv run homeops-ai query canonical-current
uv run homeops-ai query links-to --param 'title=Heavy VM'
uv run homeops-ai query context --param 'question=What currently runs here?'
```

The versioned evaluation suite separates graph correctness, deterministic
context usefulness, and expected capability gaps. Generated reports remain
derived local state under `data/`:

```bash
uv run homeops-ai evaluate \
  --cases evaluation/deterministic-homeops-v1.yaml \
  --output data/evaluation/deterministic-homeops-v1.json
```

Compile exact evidence sections into a deterministic, budgeted context bundle.
Risk is explicit; risky bundles always require fresh live discovery before
mutation:

```bash
uv run homeops-ai context compile \
  --question 'Prepare context for changing the Heavy VM' \
  --risk risky \
  --output data/context/heavy-vm-change.json
```

Evaluate the versioned context-compiler contract:

```bash
uv run homeops-ai evaluate \
  --cases evaluation/context-compiler-v1.yaml \
  --output data/evaluation/context-compiler-v1.json
```

## MCP Server

HomeOps can expose the verified build through a stdio MCP server. This remains
the default transport, does not listen on a network socket, and calls only the
existing stable read-only query and context-compiler APIs.

```bash
uv run homeops-ai-mcp --data-dir data
```

The same server is also available through the main CLI, which is useful for the
container image because its entrypoint is `homeops-ai`:

```bash
uv run homeops-ai mcp --data-dir data
```

For a conventional remote MCP deployment, the same server can use authenticated
Streamable HTTP. HTTP mode cannot start without an HTTPS issuer, canonical MCP
resource/audience, and a local asymmetric public JWKS. The production launcher
uses a private Unix socket so the HomeOps container still needs no network:

```bash
uv run homeops-ai mcp \
  --transport streamable-http \
  --data-dir data \
  --unix-socket /run/homeops-mcp/mcp.sock \
  --issuer-url https://auth.example.test/application/o/homeops-mcp/ \
  --resource-url https://mcp.example.test/mcp \
  --audience https://mcp.example.test/mcp \
  --jwks-file /var/lib/homeops-ai/oauth-jwks.json
```

The access token must be an RS256 JWT whose only audience is the canonical
resource URL and whose `scope` includes `homeops:read`. The JWKS is loaded once
at startup and must contain only public RSA verification keys; deploy a
validated replacement and restart the service for key rotation. The MCP route
is `/mcp`, RFC 9728 metadata is published at
`/.well-known/oauth-protected-resource/mcp`, and `/healthz` contains only a
non-sensitive liveness result.

Writable MCP is an explicit HTTP-only mode. The MCP process still receives no
vault mount and needs no network: it sends one bounded request over a private
Unix socket to a separate broker. The broker is create-only, validates the
complete candidate vault, durably records the request, and atomically publishes
a new root Markdown note. It has no edit, rename, delete, shell, or direct Cozo
operation.

Run the broker under the dedicated vault-writer identity. Its state directory
must be private and outside the synced vault:

```bash
uv run homeops-ai write-broker \
  --vault /var/lib/homeops/vault \
  --state-dir /var/lib/homeops-write-broker \
  --unix-socket /run/homeops-write-broker/broker.sock \
  --socket-group homeops-mcp \
  --allowed-subject '<exact OAuth subject>'
```

Then opt the authenticated MCP process into those tools:

```bash
uv run homeops-ai mcp \
  --transport streamable-http \
  --data-dir data \
  --unix-socket /run/homeops-mcp/mcp.sock \
  --issuer-url https://auth.example.test/application/o/homeops-mcp/ \
  --resource-url https://mcp.example.test/mcp \
  --audience https://mcp.example.test/mcp \
  --jwks-file /var/lib/homeops-ai/oauth-jwks.json \
  --write-broker-socket /run/homeops-write-broker/broker.sock \
  --write-subject '<exact OAuth subject>'
```

Writable mode advertises and requires both `homeops:read` and `homeops:write`.
The write tools also enforce the exact configured token subject. Keep write
approval enabled in the MCP client and never submit secrets. A `capture_note`
call requires a canonical UUIDv4 `request_id`; retrying the same ID with the
same content is idempotent, while different content is rejected. Captures are
supporting `reference` notes tagged `mcp-capture`, not canonical instructions.
`write_status` never retries or publishes a pending write. If a capture remains
`ACCEPTED` with `awaiting-capture-retry`, invoke `capture_note` again with the
same request ID and identical content through the normal write-approval path.
`publication.state = active` proves only that the note reached the local
verified HomeOps build. The MCP deliberately does not inspect Headless Sync
credentials or claim delivery to another Obsidian device.

The MCP surface is intentionally small:

- `build_status`: active verified build metadata, counts, validation, and
  available stable queries.
- `query`: one stable read-only query by name, with string parameters and a
  bounded row count.
- `context_bundle`: deterministic evidence bundle compilation. Risk is explicit;
  risky bundles still require fresh live read-only discovery before mutation.
- `capture_note` (opt-in): create one validated supporting note; it is annotated
  as a non-destructive write so capable clients can require confirmation.
- `write_status` (opt-in): read-only reporting of durable broker state and
  whether the captured document has reached the active verified build.

## Automatic Transactional Pipeline

The workstation-side NixOS timer runs once after startup and then every 30
minutes. Each run takes a local lock, validates and snapshots the vault, and
asks the host for its redacted current deployment identity. Matching content,
source revision, package version, immutable runtime image digest, and build
contracts finish as `UNCHANGED` without transferring or rebuilding anything.

Changed snapshots travel through a dedicated, multiplexed SSH connection. The
key is restricted to four exact forced-command receiver verbs; client-supplied
shell commands, arguments, PTYs, forwarding, and direct spool access are not
available. The Go receiver validates a bounded deterministic USTAR stream,
removes the raw request capability, and atomically publishes an immutable
request for the unprivileged processor.

The host processor independently verifies the snapshot and receipt, builds a
new immutable Cozo candidate, and runs `evaluation/promotion-safe-v1.yaml`.
Only a passing candidate is reported as ready. The workstation verifies that
its source has not moved and sends a compare-and-swap commit; the host then
atomically selects the deployment and publishes the exact redacted identity
used by later preflight checks. Failed validation, transfer, build, evaluation,
or CAS leaves the active database untouched, and the workstation records the
bounded result for diagnostics.

The runtime container includes the Python coordinator/processor and OpenSSH
client. The privileged forced-command receiver is deliberately separate: Nix
builds `./cmd/homeops-receiver` from the same tagged source with
`buildGoModule`, installs an immutable wrapper with fixed paths and identities,
and grants the publisher no filesystem access to pipeline spools. The MCP
service resolves only the atomically selected, verified Cozo deployment.

Deployment retention starts with a fail-closed inventory only. The planner
retains the current and previous pairs, three additional verified deployments,
builds pinned by a live reader, unresolved pipeline attempts, and failure
evidence. It emits only exact allowlisted bundle paths and accounts for snapshots
shared by multiple deployments:

```bash
uv run homeops-ai pipeline retention-plan \
  --root /var/lib/homeops-ai \
  --keep-additional-verified 3
```

This command is always a dry run. HomeOps intentionally provides no
deployment-retention apply/delete command or scheduled retention cleanup. Any
future cleanup remains separately gated by operational soak, review of the exact
plan, and rollback verification. The legacy `db cleanup --failed` command is a
separate, manually invoked surface and does not apply a retention plan.

Tagged releases and manually dispatched runs first run the complete Python and
Go suites (including the race detector and vet), build the Python and receiver
artifacts, build and exercise the runtime container, and scan it. Only then does
`.github/workflows/container.yml` publish to GHCR. The NixOS configuration must
reference the resulting immutable `ghcr.io/<owner>/homeops-ai@sha256:...`
digest, never a mutable tag or a manually installed local image ID.
