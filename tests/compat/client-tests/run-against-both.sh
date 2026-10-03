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
paths=()
target="all"
for arg in "$@"; do
  case "$arg" in
    --skip-build) ;;
    tests/*|*.ts) paths+=("$arg") ;;
    *)
      if [[ "$arg" == all || "$arg" == browser || "$arg" == environment || -d "tests/compat/client-tests/tests/$arg" ]]; then
        target="$arg"
      else
        echo "Unknown scenario directory: $arg" >&2
        echo "Known directories: generated core plugins $(cd tests/compat/client-tests/tests && ls -d core/* plugins/* | tr '\n' ' ')" >&2
        exit 1
      fi ;;
  esac
done
export BETTER_AUTH_REQUIRE_REFERENCE_SERVER=1
if ((${#paths[@]})); then
  export BETTER_AUTH_COMPAT_PATHS="${paths[*]}"
  test_name="selected_client_compat"
elif [[ "$target" == all ]]; then
  test_name="full_client_compat"
else
  test_name="${target//-/_}"
  test_name="${test_name//\//_}_client_compat"
fi
cargo nextest run --locked --test compat --run-ignored only --no-capture -E "test(=sdk::tests::$test_name)"
