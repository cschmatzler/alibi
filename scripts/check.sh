#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export BETTER_AUTH_REQUIRE_REFERENCE_SERVER=1
unset BETTER_AUTH_UPDATE_CAPABILITIES
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
bun install --cwd tests/compat/reference-server --frozen-lockfile
bun install --cwd tests/compat/client-tests --frozen-lockfile
cargo fmt --all -- --check
cargo fmt --manifest-path tests/compat/rust-server/Cargo.toml -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --locked --features axum,seaorm2,redis-cache -- -D warnings
cargo check -p better-auth --locked --no-default-features --features rustls,axum,seaorm2,redis-cache
mkdir -p coverage
bun tests/compat/reference-server/generate-openapi.mjs --profile all-in --format routes --output coverage/upstream-routes.json
cargo nextest run --workspace --locked
cargo nextest run --locked --manifest-path tests/compat/rust-server/Cargo.toml
cargo nextest run --workspace --locked --features axum,seaorm2,redis-cache
cargo test --workspace --doc --locked --features axum,seaorm2,redis-cache
bun run --cwd tests/compat/client-tests format:check
bun run --cwd tests/compat/client-tests typecheck
bun test --cwd tests/compat/client-tests harness
./scripts/alignment-check.sh
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --locked --no-deps
./scripts/coverage.sh
