#!/usr/bin/env bash
# Compat tier: the official better-auth client against the pinned TypeScript
# reference server and the Rust fixture server, compared trace for trace.
# Too slow for CI; run it once before merging.
# The static compat checks (route inventory, OpenAPI contract, release pin)
# run with the rest of the `compat` target in `cargo nextest run`.
set -euo pipefail
cd "$(dirname "$0")/.."
export BETTER_AUTH_REQUIRE_REFERENCE_SERVER=1

for project in reference-server client-tests; do
  if [[ ! -d "tests/compat/$project/node_modules" ]]; then
    echo "tests/compat/$project dependencies are missing; run 'bun install --cwd tests/compat/$project --frozen-lockfile'." >&2
    exit 1
  fi
done

bun run --cwd tests/compat/client-tests format:check
bun run --cwd tests/compat/client-tests lint
bun run --cwd tests/compat/client-tests typecheck
bun tests/compat/client-tests/support/check-coverage.ts --inventory-only

# Build both fixture backends up front so a compiler failure is not reported as a scenario failure.
mkdir -p coverage
cargo build --locked --manifest-path tests/compat/rust-server/Cargo.toml
cp tests/compat/rust-server/target/debug/compat-rust-server coverage/compat-rust-server-sqlx
cargo build --locked --manifest-path tests/compat/rust-server/Cargo.toml --features seaorm
cp tests/compat/rust-server/target/debug/compat-rust-server coverage/compat-rust-server-seaorm
bun tests/compat/reference-server/generate-openapi.mjs --profile all-in --format routes --output coverage/upstream-routes.json
# The route inventory writes coverage/runtime-routes.json for the evidence gate.
cargo nextest run --locked --test compat -E 'test(/^route_inventory::/)'

# Comparator negative controls first: a comparator that cannot detect drift
# must not be allowed to report parity.
bun test --cwd tests/compat/client-tests harness

# One total fixture budget for both complete adapters. Each adapter owns its
# immutable executable and evidence namespace; neither can satisfy the other's gate.
if [[ -n "${BETTER_AUTH_COMPAT_JOBS:-}" ]]; then
  jobs="$BETTER_AUTH_COMPAT_JOBS"
else
  jobs="$(bash scripts/compat-jobs.sh)"
fi
if [[ ! "$jobs" =~ ^[0-9]+$ ]] || (( jobs < 1 || jobs > 32 )); then
  echo "BETTER_AUTH_COMPAT_JOBS must be between 1 and 32" >&2
  exit 1
fi

printf "Compatibility fixture budget: %s pairs total\n" "$jobs"

run_backend() {
  local backend="$1" workers="$2"
  BETTER_AUTH_COMPAT_BACKEND="$backend" BETTER_AUTH_COMPAT_JOBS="$workers" \
    COMPAT_ARTIFACT_NAMESPACE="$backend" \
    BETTER_AUTH_COMPAT_EXECUTABLE="$PWD/coverage/compat-rust-server-$backend" \
    cargo nextest run --locked --test compat --run-ignored only --no-capture \
      -E 'test(=sdk::tests::full_client_compat) | test(=sdk::tests::browser_client_compat)'
}
if (( jobs == 1 )); then
  run_backend sqlx 1
  run_backend seaorm 1
else
  run_backend sqlx "$((jobs / 2))" &
  sqlx_pid=$!
  run_backend seaorm "$((jobs - jobs / 2))" &
  seaorm_pid=$!
  status=0
  wait "$sqlx_pid" || status=1
  wait "$seaorm_pid" || status=1
  exit "$status"
fi
