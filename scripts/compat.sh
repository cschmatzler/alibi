#!/usr/bin/env bash
# Compat tier: the official better-auth client against the pinned TypeScript
# reference server and the Rust fixture server, compared trace for trace.
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

# Build both fixture backends up front so a compiler failure is not reported as a scenario failure.
cargo build --locked --manifest-path tests/compat/rust-server/Cargo.toml
cargo build --locked --manifest-path tests/compat/rust-server/Cargo.toml --features seaorm2

mkdir -p coverage
bun tests/compat/reference-server/generate-openapi.mjs --profile all-in --format routes --output coverage/upstream-routes.json
# The route inventory writes coverage/runtime-routes.json for the evidence gate.
cargo nextest run --locked --test compat -E 'test(/^route_inventory::/)'

# Comparator negative controls first: a comparator that cannot detect drift
# must not be allowed to report parity.
bun test --cwd tests/compat/client-tests harness

# Every scenario directory, every process environment, then Chromium, once
# per store backend: the fixture server serves the same scenarios from
# `SqlxStore` and from `SeaOrmStore`.
for backend in sqlx seaorm; do
  BETTER_AUTH_COMPAT_BACKEND="$backend" cargo nextest run --locked --test compat --run-ignored only --no-capture \
    -E 'test(=sdk::tests::full_client_compat) | test(=sdk::tests::browser_client_compat)'
done
