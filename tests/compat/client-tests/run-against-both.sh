#!/usr/bin/env bash
# Run scenarios through the Rust orchestrator, which builds the Rust fixture
# server, starts both servers on allocated ports, runs the official-client
# scenarios against each and compares the traces.
#
#   ./run-against-both.sh                          all scenarios
#   ./run-against-both.sh core/session             one scenario directory
#   ./run-against-both.sh core|plugins             one scenario group
#   ./run-against-both.sh browser|environment      browser or process-environment suites
#   ./run-against-both.sh tests/plugins/jwt/keyring.test.ts  any client-test files or directories
#
# Fixtures use SqlxStore; BETTER_AUTH_COMPAT_BACKEND=seaorm serves them from SeaOrmStore.
set -euo pipefail
cd "$(dirname "$0")/../../.."
scenario_root="tests/compat/client-tests/tests"
paths=()
test_name="full_client_compat"
for arg in "$@"; do
  case "$arg" in
    --skip-build) ;;
    all) test_name="full_client_compat" ;;
    browser|environment) test_name="${arg}_client_compat" ;;
    tests/*|*.ts) paths+=("$arg") ;;
    *)
      if [[ -e "$scenario_root/$arg" ]]; then
        paths+=("tests/$arg")
      elif [[ -d "$scenario_root/plugins/$arg" ]]; then
        paths+=("tests/plugins/$arg")
      else
        echo "Unknown compatibility scenario: $arg" >&2
        exit 1
      fi ;;
  esac
done
export BETTER_AUTH_REQUIRE_REFERENCE_SERVER=1
if ((${#paths[@]})); then
  export BETTER_AUTH_COMPAT_PATHS="${paths[*]}"
  test_name="selected_client_compat"
fi
cargo nextest run --locked --test compat --run-ignored only --no-capture -E "test(=sdk::tests::$test_name)"
