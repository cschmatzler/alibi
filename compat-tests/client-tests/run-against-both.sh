#!/usr/bin/env bash
set -euo pipefail
capability="all"
for arg in "$@"; do
  case "$arg" in
    account-management|admin|api-key|core|device-authorization|email-verification|generic-oauth|oauth|organization|passkey|password-management|sessions|two-factor|user-management|one-time-token|all|browser) capability="$arg" ;;
    --skip-build) ;;
    *) echo "Unknown compatibility capability: $arg" >&2; exit 1 ;;
  esac
done
case "$capability" in
  all) test_name="full_client_compat" ;;
  *) test_name="${capability//-/_}_client_compat" ;;
esac
cargo test --test client_compat_tests "$test_name" -- --ignored --nocapture
