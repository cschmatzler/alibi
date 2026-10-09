#!/usr/bin/env bash
# Check a downstream build without workspace dev-dependency feature unification.
set -euo pipefail
cd "$(dirname "$0")/.."
repo_root="$PWD"
consumer_dir=$(mktemp -d)
trap 'rm -rf "$consumer_dir"' EXIT
mkdir "$consumer_dir/src"
cat > "$consumer_dir/Cargo.toml" <<EOF
[package]
name = "alibi-rustls-consumer"
version = "0.0.0"
edition = "2024"

[dependencies]
alibi = { path = "$repo_root", default-features = false, features = ["axum", "sqlx-postgres", "rustls"] }
EOF
cat > "$consumer_dir/src/main.rs" <<'EOF'
use alibi::plugins::EmailPasswordPlugin;

fn main() {
    let _plugin = EmailPasswordPlugin::new();
}
EOF
# Reuse the repository's dependency versions; Cargo adds the consumer package.
cp Cargo.lock "$consumer_dir/Cargo.lock"
cargo tree --manifest-path "$consumer_dir/Cargo.toml" --edges normal \
    --prefix none --format '{p}' > "$consumer_dir/dependencies.txt"
if grep -E '^(openssl(-sys)?|webauthn-rs(-core)?) v' "$consumer_dir/dependencies.txt"; then
    echo 'rustls consumers without passkeys must not depend on OpenSSL or WebAuthn' >&2
    exit 1
fi
cargo build --manifest-path "$consumer_dir/Cargo.toml" --locked \
    --target-dir "${CARGO_TARGET_DIR:-$repo_root/target}"
