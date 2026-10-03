#!/usr/bin/env bash
# The complete gate, run by CI and `bun run test`. Stages run in order of cost.
set -euo pipefail
cd "$(dirname "$0")/.."
export BETTER_AUTH_REQUIRE_REFERENCE_SERVER=1
unset BETTER_AUTH_UPDATE_CAPABILITIES
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
stage() { printf '\n==> %s\n' "$*"; }

stage "Install the pinned upstream projects"
bun install --cwd tests/compat/reference-server --frozen-lockfile
bun install --cwd tests/compat/client-tests --frozen-lockfile

stage "Format, lint and type-check"
cargo fmt --all -- --check
cargo fmt --manifest-path tests/compat/rust-server/Cargo.toml -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --locked --features axum,seaorm2,redis-cache -- -D warnings
cargo check -p better-auth --locked --no-default-features --features rustls,axum,seaorm2,redis-cache
cargo check -p better-auth --locked --no-default-features --features rustls,axum,sqlx
cargo clippy --manifest-path tests/compat/rust-server/Cargo.toml --all-targets --locked -- -D warnings
cargo clippy --manifest-path tests/compat/rust-server/Cargo.toml --all-targets --locked --features seaorm2 -- -D warnings
bun run --cwd tests/compat/client-tests format:check
bun run --cwd tests/compat/client-tests lint
bun run --cwd tests/compat/client-tests typecheck

stage "Unit, integration, static compat and repository tests"
cargo nextest run --workspace --locked
cargo nextest run --workspace --locked --features axum,seaorm2,redis-cache
cargo nextest run --locked --manifest-path tests/compat/rust-server/Cargo.toml
cargo test --workspace --doc --locked --features axum,seaorm2,redis-cache

stage "Differential compatibility against upstream"
./scripts/compat.sh

stage "Documentation"
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --locked --no-deps

stage "Coverage floor"
./scripts/coverage.sh
