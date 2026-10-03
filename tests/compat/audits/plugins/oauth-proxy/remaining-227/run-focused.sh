#!/usr/bin/env bash
# Selected process proof: production environment inputs are isolated to these
# owned fixture processes, never injected into unrelated SDK runs.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../../../../.." && pwd)
artifacts=${1:-$(mktemp -d /tmp/oauth-proxy-227-proof.XXXXXX)}
mkdir -p "$artifacts"
artifacts=$(cd "$artifacts" && pwd)
cd "$root"
features=()
if [[ ${BETTER_AUTH_COMPAT_BACKEND:-sqlx} == seaorm ]]; then features=(--features seaorm); fi
CARGO_BUILD_JOBS=2 cargo build --locked --manifest-path tests/compat/rust-server/Cargo.toml "${features[@]}" > "$artifacts/build.log" 2>&1
binary=${CARGO_TARGET_DIR:-$root/tests/compat/rust-server/target}/debug/compat-rust-server
read -r source_port native_port < <(python3 - <<'PY'
import socket
sockets = [socket.socket() for _ in range(2)]
for sock in sockets: sock.bind(('127.0.0.1', 0))
print(*(sock.getsockname()[1] for sock in sockets))
PY
)
# Clear every Source vendor candidate and existing app/base environment input.
unset VERCEL_URL NETLIFY_URL RENDER_URL AWS_LAMBDA_FUNCTION_NAME GOOGLE_CLOUD_FUNCTION_NAME AZURE_FUNCTION_NAME BETTER_AUTH_URL BETTER_AUTH_BASE_URL NEXT_PUBLIC_BETTER_AUTH_URL PUBLIC_BETTER_AUTH_URL
export NODE_ENV=production BUN_ENV=production TEST=false NO_PROXY=localhost,127.0.0.1 no_proxy=localhost,127.0.0.1
(cd tests/compat/reference-server && BETTER_AUTH_URL="http://127.0.0.1:$source_port" NETLIFY_URL="http://localhost:$source_port" PORT="$source_port" bun run server.ts) > "$artifacts/source.log" 2>&1 &
source_pid=$!
BETTER_AUTH_URL="http://127.0.0.1:$native_port" NETLIFY_URL="http://localhost:$native_port" PORT="$native_port" "$binary" > "$artifacts/native.log" 2>&1 &
native_pid=$!
trap 'kill -TERM "$source_pid" "$native_pid" 2>/dev/null || true; wait "$source_pid" "$native_pid" 2>/dev/null || true' EXIT
python3 - "$source_port" "$native_port" <<'PY'
import sys,time,urllib.request
for port in sys.argv[1:]:
    for attempt in range(60):
        try:
            print(urllib.request.urlopen(f'http://localhost:{port}/__health', timeout=1).read().decode())
            break
        except Exception: time.sleep(.5)
    else: raise RuntimeError('fixture health failed ' + port)
PY
cd tests/compat/client-tests
AUTH_BASE_URL_TS="http://localhost:$source_port" AUTH_BASE_URL_RUST="http://localhost:$native_port" COMPAT_OBSERVATIONS_DIR="$artifacts/raw" COMPAT_COVERAGE=1 bun test tests/plugins/oauth-proxy/proxy.test.ts process-proofs/oauth-proxy-environment.test.ts -t 'OAuth proxy remaining' > "$artifacts/checks.log" 2>&1
cat "$artifacts/checks.log"
