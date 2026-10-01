#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export BETTER_AUTH_REQUIRE_REFERENCE_SERVER=1
mkdir -p coverage
cargo llvm-cov nextest --workspace --locked --features axum,seaorm2,redis-cache \
  --ignore-filename-regex '(tests/|scripts/|target/)' \
  --lcov --output-path coverage/lcov.info --fail-under-lines 75
