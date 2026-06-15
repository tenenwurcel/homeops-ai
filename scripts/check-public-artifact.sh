#!/usr/bin/env bash
set -euo pipefail

files=(
  .containerignore
  .github
  Containerfile
  README.md
  pyproject.toml
  uv.lock
  src
  tests
  deploy
  evaluation
  scripts
)

patterns=(
  '-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----'
  '(^|[^[:alnum:]_])(password|passwd|api[_-]?key|access[_-]?token|private[_-]?key)[[:space:]]*[:=][[:space:]]*[^$[:space:]]+'
  '[[:alnum:]._%+-]+@[[:alnum:].-]+\.[[:alpha:]]{2,}'
  '(^|[^[:digit:]])10\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}([^[:digit:]]|$)'
  '(^|[^[:digit:]])192\.168\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}([^[:digit:]]|$)'
  '(^|[^[:digit:]])172\.(1[6-9]|2[0-9]|3[01])\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}([^[:digit:]]|$)'
  '/home/[^/[:space:]]+'
)

failed=0
for pattern in "${patterns[@]}"; do
  if grep -RInE \
    --exclude=check-public-artifact.sh \
    --exclude-dir=__pycache__ \
    -- "${pattern}" "${files[@]}"; then
    failed=1
  fi
done

if ((failed)); then
  printf 'Public artifact privacy check failed.\n' >&2
  exit 1
fi
