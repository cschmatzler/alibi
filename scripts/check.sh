#!/usr/bin/env bash
# The native gate, run by CI: formatting, lints, feature builds, every native
# test tier and documentation. The differential suite against the TypeScript
# reference server is `./scripts/compat.sh`; run it once before merging.
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
stage() { printf '\n==> %s\n' "$*"; }

stage "Format and lint"
cargo fmt --all -- --check
cargo fmt --manifest-path tests/compat/rust-server/Cargo.toml -- --check
cargo clippy --workspace --all-targets --locked --features axum,seaorm,redis-cache -- -D warnings
cargo clippy --manifest-path tests/compat/rust-server/Cargo.toml --all-targets --locked -- -D warnings
cargo clippy --manifest-path tests/compat/rust-server/Cargo.toml --all-targets --locked --features seaorm -- -D warnings

stage "Feature builds"
for features in rustls,axum,sqlx-sqlite rustls,axum,sqlx-postgres rustls,seaorm,poem native-tls,sqlx; do
  cargo check --locked -p alibi --lib --no-default-features --features "$features"
done

stage "Native tests"
cargo nextest run --workspace --locked --features axum,seaorm,redis-cache
cargo test --workspace --doc --locked --features axum,seaorm,redis-cache

stage "Documentation"
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --locked --no-deps
