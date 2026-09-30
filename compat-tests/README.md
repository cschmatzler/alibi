# Compatibility testing

The published TypeScript `better-auth@1.7.6` runtime is the behavioral reference.
The client, reference server, passkey plugin and API-key plugin are pinned to
that version with committed Bun lockfiles.

## Full gate

```bash
devenv test
# Equivalent inside the development shell, and in CI:
./scripts/check.sh
```

This runs formatting, strict Clippy, all workspace unit/integration/doc tests,
feature builds, TypeScript type checking, harness negative controls, raw wire
checks, the complete SDK scenario directory, Chromium tests, docs, and LLVM
line coverage. Default and `axum,seaorm2,redis-cache` configurations are tested;
`rustls,axum,seaorm2,redis-cache` is also compiled without default features.
The excluded Rust compatibility server is built, formatted, and tested. Its
SQLite regression verifies that connection maintenance retains migrated tables
and persisted user identity throughout the fixture lifetime.
Missing reference dependencies or an unavailable server fail this gate.

Rust is pinned in `rust-toolchain.toml`. `devenv.lock` pins Bun and native
packages. CI uses the same Rust and Bun versions and the same gate script.
Chromium is supplied by devenv; CI installs Playwright's browser and system
libraries. Outside devenv, run `bunx playwright install --with-deps chromium`
in `client-tests/` before browser checks.

## What the tests establish

- Rust tests cover storage, plugin logic, integration routes and feature builds.
- SDK scenarios run sequentially against fresh TS and Rust fixture state.
  Their values, response shapes, status codes, redirects and cookie attributes
  are compared. The full runner discovers `tests/`, so new directories join
  the gate automatically.
- The comparator retains all fields and array elements. Generated identifiers
  and opaque tokens use a bijection: repeated references and token rotation
  must agree. Provider/configuration IDs remain literal. Dates must be valid
  and lifetimes must agree within a 1.5-second execution tolerance. Only the
  configured local server origins and known URL entropy are normalized.
- `tough-cookie` handles expiry, deletion, domains and paths. Cookie security
  attributes are compared; the raw exception list is empty. Chromium separately
  checks real browser session persistence, HttpOnly behavior and logout.
- Password scenarios import actual hashes produced by each runtime into both
  fixture stores, then exercise official-client sign-in, Unicode normalization,
  incorrect passwords, credential replacement, and persisted account ownership.
  Test-only password controls stay outside the public authentication router.
- A software ES256 authenticator produces valid registration and authentication
  signatures. The passkey scenario checks persisted credentials, ownership
  rejection, counter updates, replay rejection, rename and deletion.
- Harness negative controls deliberately corrupt identity relationships,
  lifetimes, redirects, array structure and cookies. A live HTTP/SDK canary
  confirms wrong session ownership and removed cookie protection are detected.

The browser fixture uses local HTTP. Production HTTPS/Secure-cookie deployment
behavior is not claimed by that test. Structural route evidence is also not a
claim that every behavior of an endpoint has been tested.

## Capability inventory and coverage

`capabilities.json` records the union of Rust routes and the pinned upstream
`all-in` plugin profile together with core/aligned profiles (plugin overrides
cannot hide core methods). HTTP method is part of identity; parameter names are
normalized to `{}`. Device authorization is included in the Rust fixture.
Server-only functions and plugins outside that profile are not HTTP inventory
entries. The file explicitly marks routes absent from Rust and missing evidence.

Evidence is recorded only after a dual-server scenario passes. Each route can
require named scenarios for successful responses, rejection, authorization and
state transitions. A state entry requires an explicit scenario declaration and
assertions of the resulting state. CI fails if a declared route or existing
required evidence disappears. A successful HTTP response alone proves neither
all edge cases nor complete parity.

To update the inventory deliberately after adding routes or tests:

```bash
mkdir -p coverage
bun compat-tests/reference-server/generate-openapi.mjs --profile all-in --format routes --output coverage/upstream-routes.json
BETTER_AUTH_UPDATE_CAPABILITIES=1 cargo test --test compat_coverage_tests
BETTER_AUTH_UPDATE_CAPABILITIES=1 cargo test --test client_compat_tests full_client_compat -- --ignored --nocapture
```

Review the resulting `capabilities.json` diff, especially removed requirements.
The full gate clears the update flag and always enforces the committed inventory.
Reports are written to `client-tests/artifacts/` and `coverage/lcov.info` and
uploaded by CI. LLVM coverage measures workspace source executed by Rust tests,
with a 75% line floor. External Bun/browser traffic is tracked by capability
evidence, not counted in that source coverage percentage.

## Focused checks

Run these in `devenv shell` after installing both projects with
`bun install --frozen-lockfile`:

```bash
bun run --cwd compat-tests/client-tests typecheck
bun test --cwd compat-tests/client-tests harness
cargo test --test client_compat_tests passkey_client_compat -- --ignored --nocapture
cargo test --test client_compat_tests browser_client_compat -- --ignored --nocapture
./scripts/alignment-check.sh
```

The Rust orchestrator starts and checks both servers on allocated ports and
stops them on completion. Direct Bun scenario runs require running reference
and Rust servers; configure `AUTH_BASE_URL_TS` and `AUTH_BASE_URL_RUST`.

## Managed JWT capability

`tests/jwt` uses the official `jwtClient` and pinned JOSE 6.2.12 to check public
JWKS, all five asymmetric signing algorithms, complete authenticated user claims,
get-session response headers, configured claims/path/header settings, encrypted
and plain private-key persistence, signing-key rotation and public grace periods.
Trusted signing and verification run through fixture-only server controls.

Run `./compat-tests/client-tests/run-against-both.sh jwt` for this family.
Automatic JWT-backed core session cookie caching remains a separate integration
boundary; the managed-keyring plugin exposes no inactive cache option.
