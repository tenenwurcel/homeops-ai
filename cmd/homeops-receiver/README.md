# HomeOps forced-command receiver

`homeops-receiver` is the narrow server-side boundary for the automated
publisher. It accepts exactly these `SSH_ORIGINAL_COMMAND` strings:

```text
homeops-receiver-v1 submit
homeops-receiver-v1 status
homeops-receiver-v1 commit
homeops-receiver-v1 current
```

There are no client-controlled command arguments and no shell parsing. A PTY
or any other command is rejected. `submit` reads a deterministic, uncompressed
USTAR stream from stdin. `status` and `commit` read one canonical compact JSON
object followed by one newline. Every reply is one compact JSON line on stdout.

The archive contains, in this exact order:

```text
request.json
snapshot.json
vault/<strictly sorted regular-file paths>
```

Every entry is a USTAR regular file with mode `0600`, numeric UID/GID zero,
empty owner names, epoch mtime, no extended metadata, and a canonical safe
relative path made only of printable ASCII. Symlinks, hard links, directories,
devices, FIFOs, duplicate or unsorted paths, undeclared roots, non-ASCII or
control characters, and resource-bound violations fail closed.
Python `tarfile`'s canonical all-zero padding to its 10 KiB record boundary is
accepted; other trailing bytes are not.

The transport order for `vault/...` is raw bytewise ASCII order, independent of
the manifest's user-facing case-folded inventory order. This gives Go and
Python an exact locale-free comparator. The processor verifies the proof path
set and manifest membership by mapping, not by relying on either order.

## Protocol v1

The wire `request.json` is canonical JSON with this field order:

```text
schema_version, protocol, request_id, publisher_id, capability_token,
release_policy_id,
snapshot_id, expected_current_deployment_id, snapshot_manifest_sha256
```

`protocol` is `homeops.receiver/v1`; `request_id` is a lowercase UUIDv4;
`capability_token` is 32 random bytes encoded as 64 lowercase hexadecimal
characters. The receiver never persists or returns the token. It stores only
its SHA-256 digest and publishes a sanitized queued request with the same field
order minus `capability_token`.

Status input has `schema_version, protocol, request_id, publisher_id,
capability_token`. It returns `PENDING` until the trusted processor publishes a
matching result, then returns `RESULT` containing that result. Both responses
include `commit_accepted`, which reports whether the exact durable commit marker
already exists and closes the lost-response recovery window. A wrong token and
an absent request are deliberately indistinguishable (`NOT_FOUND`).

Commit input has `schema_version, protocol, request_id, publisher_id,
capability_token, candidate_deployment_id, expected_current_deployment_id`.
Commit is accepted only after a matching `CANDIDATE_READY` result. The durable
commit authorization contains no capability and binds the candidate, expected
current deployment, and submission archive SHA-256. Identical retries are
idempotent; conflicting retries fail closed.

Current takes empty stdin and returns the trusted redacted CAS projection from
`/var/lib/homeops-ai/pipeline-state/current.json`. Absence is an error: initial
bootstrap must explicitly publish the all-empty schema-v2 projection. A
selected deployment requires every field below to be nonempty:

```text
schema_version, current_deployment_id, snapshot_id, run_id,
source_fingerprint, artifact_fingerprint, logical_fingerprint,
homeops_version, source_revision, image_digest, snapshot_contract_version,
build_contract_version, promoted_at
```

Its response envelope has exactly `schema_version, protocol, outcome, current`.

## Trusted invocation and permissions

Production must use one immutable Nix-store wrapper allowed by an exact sudoers
rule. Do not grant sudo access to the raw receiver binary or let the SSH client
choose flags, paths, publisher identity, group, or bounds. The binary itself
requires effective root and a consumer group; the wrapper supplies fixed flags:

```text
homeops-receiver \
  --incoming-dir=/var/lib/homeops-ai/incoming \
  --results-dir=/var/lib/homeops-ai/results \
  --commits-dir=/var/lib/homeops-ai/commits \
  --publisher-id=workstation \
  --consumer-user=homeops-builder \
  --consumer-group=homeops-pipeline \
  --current-state-file=/var/lib/homeops-ai/pipeline-state/current.json
```

The publisher account must not belong to `homeops-pipeline` and must have no
direct access to these namespaces. The receiver privately stages an upload,
removes the raw capability from queued metadata, seals directories as
`root:homeops-pipeline 0750` and files as `root:homeops-pipeline 0640`, then
atomically publishes the request. Results are processor-owned and not writable
by the receiver's SSH account. The immutable wrapper must retain
`SSH_ORIGINAL_COMMAND` and `SSH_TTY`; the receiver compares them exactly.

Run the focused tests with a writable Go cache:

```bash
GOCACHE=/tmp/homeops-go-cache GOPATH=/tmp/homeops-go-path go test ./...
```

The suite includes unit tests, fuzz targets, adversarial archive cases, replay
and capability checks, and a Python `tarfile` streaming interoperability test.
