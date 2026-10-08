#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p coverage
# Keep this checkout's coverage objects separate from shared build caches.
export CARGO_LLVM_COV_TARGET_DIR="$PWD/coverage/target"
cargo llvm-cov clean --workspace
cargo llvm-cov nextest --workspace --locked --features axum,seaorm,redis-cache --no-report
cargo llvm-cov report --locked --package '*' \
  --ignore-filename-regex '(tests/|scripts/|target/)' \
  --lcov --output-path coverage/lcov.raw.info
# Exclude marked test modules while preserving their production execution.
# Report lines only: LLVM's LCOV output has no function-end ranges.
lcov --add-tracefile coverage/lcov.raw.info --filter region \
  --rc c_file_extensions=rs --rc function_coverage=0 \
  --rc derive_function_end_line=0 --output-file coverage/lcov.info
# Enforce the floor on the filtered report rather than cargo-llvm-cov's raw total.
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
    printf "Native line coverage: %d/%d (%.6f%%); required 85%%\n", covered, total, covered * 100 / total
    exit (covered * 100 < total * 85)
  }
' coverage/lcov.info
