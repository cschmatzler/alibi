#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export BETTER_AUTH_REQUIRE_REFERENCE_SERVER=1
unset BETTER_AUTH_UPDATE_CAPABILITIES
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
bun install --cwd compat-tests/reference-server --frozen-lockfile
bun install --cwd compat-tests/client-tests --frozen-lockfile
cargo fmt --all -- --check
cargo fmt --manifest-path compat-tests/rust-server/Cargo.toml -- --check
cargo clippy --workspace --locked -- -D warnings
cargo clippy --workspace --locked --features axum,seaorm2,redis-cache -- -D warnings
cargo check -p better-auth --locked --no-default-features --features rustls,axum,seaorm2,redis-cache
mkdir -p coverage
bun compat-tests/reference-server/generate-openapi.mjs --profile all-in --format routes --output coverage/upstream-routes.json
cargo test --workspace --locked
cargo test --locked --manifest-path compat-tests/rust-server/Cargo.toml
cargo test --workspace --locked --features axum,seaorm2,redis-cache
cargo test --locked --manifest-path compat-tests/rust-server/Cargo.toml
bun run --cwd compat-tests/client-tests typecheck
bun test --cwd compat-tests/client-tests harness
./scripts/alignment-check.sh
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --locked --no-deps
./scripts/coverage.sh
