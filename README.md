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

## Read-Only MCP Server

HomeOps can expose the verified build through a stdio MCP server. The server
does not listen on a network socket and all tools call the existing stable
read-only query and context-compiler APIs.

```bash
uv run homeops-ai-mcp --data-dir data
```

The same server is also available through the main CLI, which is useful for the
container image because its entrypoint is `homeops-ai`:

```bash
uv run homeops-ai mcp --data-dir data
```

The MCP surface is intentionally small:

- `build_status`: active verified build metadata, counts, validation, and
  available stable queries.
- `query`: one stable read-only query by name, with string parameters and a
  bounded row count.
- `context_bundle`: deterministic evidence bundle compilation. Risk is explicit;
  risky bundles still require fresh live read-only discovery before mutation.

## NixOS Host Deployment

Export a deployment snapshot before synchronizing the vault to a NixOS host:

```bash
uv run homeops-ai vault snapshot \
  --vault /path/to/vault \
  --output /tmp/homeops-vault-snapshot
```

The snapshot contains exact bytes for approved root and `Categories/` Markdown
sources. Other vault files are represented only by empty path placeholders so
link-resolution inventory remains deterministic without copying hidden, trash,
template, or artifact contents. The deployed container binds the promoted
snapshot read-only and stores reproducible Cozo builds under
`/var/lib/homeops-ai/data`.

After the NixOS service is installed, synchronize and promote a
validated snapshot with:

```bash
HOMEOPS_TARGET=ssh-user@nixos-host \
  deploy/nixos-host/sync-snapshot.sh /path/to/vault
```

The NixOS path unit starts a constrained rebuild when the script updates the
snapshot symlink and touches `/var/lib/homeops-ai/rebuild-request`. A daily
timer also verifies restart and unchanged-input behavior.

Tagged releases and manually dispatched runs publish the reviewed `Containerfile`
to GHCR through `.github/workflows/container.yml`. The NixOS configuration
must reference the resulting immutable `ghcr.io/<owner>/homeops-ai@sha256:...`
digest, never a mutable tag or a manually installed local image ID.
