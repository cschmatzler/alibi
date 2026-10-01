#!/usr/bin/env bash
# Run one scenario family (or everything) through the Rust orchestrator, which
# builds the Rust fixture server, starts both servers on allocated ports, runs
# the official-client scenarios against each and compares the traces.
set -euo pipefail
cd "$(dirname "$0")/../../.."
capability="all"
for arg in "$@"; do
  case "$arg" in
    all|browser) capability="$arg" ;;
    account-management|admin|api-key|core|device-authorization|email-verification|generic-oauth|oauth|organization|passkey|password-management|sessions|siwe|two-factor|user-management|one-time-token|jwt|phone-number|multiple-sessions) capability="$arg" ;;
    organization-teams|organization-dynamic-roles|organization-hooks|json-numbers|two-factor-trust|username-availability|two-factor-totp|two-factor-lockout|two-factor-skip-order|two-factor-pending-cancel|two-factor-passwordless|two-factor-otp-config) capability="$arg" ;;
    --skip-build) ;;
    *)
      echo "Unknown compatibility capability: $arg" >&2
      echo "Known families:" >&2
      grep -oE 'async fn [a-z0-9_]+_client_compat' tests/client_compat_tests/tests.rs | sed -E 's/async fn (.*)_client_compat/  \1/; s/_/-/g; s/^  full$/  all/' >&2
      exit 1 ;;
  esac
done
case "$capability" in
  all) test_name="full_client_compat" ;;
  *) test_name="${capability//-/_}_client_compat" ;;
esac
export BETTER_AUTH_REQUIRE_REFERENCE_SERVER=1
cargo test --locked --test client_compat_tests "$test_name" -- --ignored --nocapture
