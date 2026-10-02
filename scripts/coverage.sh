#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export BETTER_AUTH_REQUIRE_REFERENCE_SERVER=1
mkdir -p coverage
# Keep this checkout's coverage objects separate from shared build caches.
export CARGO_LLVM_COV_TARGET_DIR="$PWD/coverage/target"
export BETTER_AUTH_COMPAT_COVERAGE_TARGET_DIR="$CARGO_LLVM_COV_TARGET_DIR"
cargo llvm-cov clean --workspace
# Preserve the native matrix and add its existing public HTTP/SDK and server-call owners.
# Both runs contribute real native execution to one unchanged production floor.
cargo llvm-cov nextest --workspace --locked --features axum,seaorm2,redis-cache --no-report
cargo llvm-cov nextest --workspace --locked --features axum,seaorm2,redis-cache \
  --no-report --test client_compat_tests --run-ignored only --test-threads 1 \
  -E 'test(=tests::oauth_client_compat) | test(=tests::account_management_client_compat) | test(=tests::jwt_client_compat) | test(=tests::sessions_client_compat) | test(=tests::user_management_client_compat) | test(=tests::captcha_client_compat) | test(=tests::server_endpoints_client_compat)'
export LLVM_COV_FLAGS="${LLVM_COV_FLAGS:+$LLVM_COV_FLAGS }-object=coverage/target/debug/compat-rust-server"
cargo llvm-cov report --locked --package '*' \
  --ignore-filename-regex '(tests/|scripts/|target/)' \
  --lcov --output-path coverage/lcov.info
# cargo-llvm-cov 0.9's built-in floor check omits LLVM_COV_FLAGS (and therefore
# the fixture object). Enforce the same floor on the complete LLVM report.
awk -F: '
  /^SF:/ {
    if (active || $0 == "SF:") invalid = 1
    active = 1; lines = -1; hits = -1
  }
  /^LF:/ {
    if (!active || NF != 2 || $2 !~ /^[0-9]+$/ || lines >= 0) invalid = 1
    else lines = $2 + 0
  }
  /^LH:/ {
    if (!active || NF != 2 || $2 !~ /^[0-9]+$/ || hits >= 0) invalid = 1
    else hits = $2 + 0
  }
  /^end_of_record$/ {
    if (!active || lines < 0 || hits < 0 || hits > lines) invalid = 1
    else { total += lines; covered += hits }
    active = 0
  }
  END {
    if (invalid || active || total == 0) { print "Coverage report is missing or invalid"; exit 1 }
    printf "Native line coverage: %d/%d (%.6f%%); required 75%%\n", covered, total, covered * 100 / total
    exit (covered * 100 < total * 75)
  }
' coverage/lcov.info
