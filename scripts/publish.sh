#!/usr/bin/env bash
# Verify by default. Cargo stages workspace dependencies and orders uploads.
set -euo pipefail
cd "$(dirname "$0")/.."

dry_run=(--dry-run)
if [[ "${1:-}" == "--publish" ]]; then
  dry_run=()
  shift
fi

exec cargo publish --workspace --registry crates-io --locked --features alibi/axum,alibi/poem,alibi/seaorm,alibi/redis-cache "${dry_run[@]}" "$@"
