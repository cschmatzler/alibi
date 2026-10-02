#!/usr/bin/env bash
set -euo pipefail

export BETTER_AUTH_REQUIRE_REFERENCE_SERVER=1
mkdir -p coverage
bun tests/compat/reference-server/generate-openapi.mjs --profile all-in --format routes --output coverage/upstream-routes.json

skip_build=false

for arg in "$@"; do
  case "$arg" in
    --skip-build) skip_build=true ;;
    *) echo "Unknown argument: $arg" >&2; exit 1 ;;
  esac
done

if ! command -v bun >/dev/null 2>&1; then
  echo "bun is required for alignment checks. Install Bun first." >&2
  exit 1
fi

if [[ ! -d tests/compat/reference-server/node_modules ]]; then
  echo "tests/compat/reference-server dependencies are missing. Run 'cd tests/compat/reference-server && bun install'." >&2
  exit 1
fi

if [[ ! -d tests/compat/client-tests/node_modules ]]; then
  echo "tests/compat/client-tests dependencies are missing. Run 'cd tests/compat/client-tests && bun install'." >&2
  exit 1
fi

if [[ "$skip_build" != "true" ]]; then
  cargo build --workspace
  cargo build --manifest-path tests/compat/rust-server/Cargo.toml
fi

cargo nextest run --features axum --test axum_integration_tests
cargo nextest run --test openapi_contract_tests --no-capture
cargo nextest run --test route_inventory_tests --no-capture
cargo nextest run --test client_compat_tests --run-ignored only --no-capture full_client_compat
cargo nextest run --test client_compat_tests --run-ignored only --no-capture browser_client_compat
