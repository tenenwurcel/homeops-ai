#!/usr/bin/env bash
set -euo pipefail

vault="${1:?usage: HOMEOPS_TARGET=user@host $0 /path/to/vault}"
target="${HOMEOPS_TARGET:?set HOMEOPS_TARGET to user@host}"
project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
homeops="${HOMEOPS_BIN:-${project_root}/.venv/bin/homeops-ai}"
snapshot_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
work_dir="$(mktemp -d)"
snapshot_dir="/var/lib/homeops-ai/vault-snapshots/${snapshot_id}"
ssh_command=(ssh -F /dev/null -o IdentitiesOnly=yes -o IdentityAgent=SSH_AUTH_SOCK)

cleanup() {
  rm -rf "${work_dir}"
}
trap cleanup EXIT

"${homeops}" vault validate --vault "${vault}" >/dev/null
"${homeops}" vault snapshot \
  --vault "${vault}" \
  --output "${work_dir}/vault"

"${ssh_command[@]}" "${target}" "mkdir -p '${snapshot_dir}'"
rsync -a --delete -e "ssh -F /dev/null -o IdentitiesOnly=yes -o IdentityAgent=SSH_AUTH_SOCK" \
  "${work_dir}/vault/" \
  "${target}:${snapshot_dir}/"
"${ssh_command[@]}" "${target}" \
  "ln -sfn '${snapshot_dir}' /var/lib/homeops-ai/vault-current && touch /var/lib/homeops-ai/rebuild-request"

printf 'Promoted deployment vault snapshot: %s\n' "${snapshot_id}"
