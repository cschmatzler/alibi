# Compatibility testing

The published TypeScript `better-auth@1.7.6` runtime is the behavioral reference.
The client, reference server, passkey plugin and API-key plugin are pinned to
that version with committed Bun lockfiles. `capabilities.json` carries the single
committed `upstreamVersion`; `tests/upstream_pin_tests.rs` fails when any
manifest, lockfile, document, harness schema or fixture server restates a
different release, and both fixture servers report the release they reproduce
on `/__health`, which every scenario run verifies before comparing anything.

## Layout

All tests live under the repository `tests/` directory:

| Path | Contents |
| --- | --- |
| `tests/*.rs` | Cargo integration tests for the `better-auth` crate, including `account_oauth_tests` |
| `tests/support/compat/` | Shared Rust helpers: OpenAPI schema loading, shape validation, in-process fixtures |
| `tests/fixtures/` | Pinned vectors consumed by Rust unit tests and both fixture servers: SIWE EIP-191 signature, encrypted upstream JWK, encrypted account-cookie vectors, One Tap keys |
| `tests/compat/reference-server/` | The pinned TypeScript runtime with test-only control routes and configuration profiles |
| `tests/compat/rust-server/` | The excluded Rust fixture package exposing the same control routes and profiles |
| `tests/compat/client-tests/` | Official-client scenarios, the trace comparator, harness negative controls and Chromium checks |
| `tests/compat/audits/` | Per-capability implementation audits |

Unit tests that need crate-private items stay next to their modules under
`crates/*/src` as Rust convention requires; fixture files they consume are
referenced from `tests/fixtures/` with `include_str!`.

## Full gate

```bash
devenv test
# Equivalent inside the development shell, and in CI:
full-check
```

This runs formatting, strict Clippy, all workspace unit/integration/doc tests,
feature builds, TypeScript type checking, harness negative controls, the
complete SDK scenario directory, Chromium tests, docs, and LLVM line coverage.
Every dual-server comparison runs through the official client against both
fixture servers on allocated ports started and stopped by the Rust orchestrator;
there is no in-process shape-only comparison layer with tolerated differences. Default and `axum,seaorm2,redis-cache` configurations are tested;
`rustls,axum,seaorm2,redis-cache` is also compiled without default features.
The excluded Rust compatibility server is built, formatted, and tested. Its
SQLite regression verifies that connection maintenance retains migrated tables
and persisted user identity throughout the fixture lifetime.
Missing reference dependencies or an unavailable server fail this gate.

The shared Rust style supplies nextest, Clippy, rustfmt, and Mr. Boxington.
The style input is private and requires GitHub SSH access. `devenv test` runs
its strict Rust gate followed by the compatibility gate. `devenv.lock` pins all
tools, including Bun and Chromium. Update the style with `devenv update rust-style`.
Outside devenv, run `bunx playwright install --with-deps chromium` in
`client-tests/` before browser checks.


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
- Account-cookie scenarios authenticate actual compact encrypted cookies with the
  published decoder and retain their complete protected headers and payloads.
  The explicit evidence container tracks random JWT IDs, token rotation and
  repeated claims without normalizing application JWT-shaped data. See the
  [comparison regression audit](audits/encrypted-cookie-comparison.md).
- Compact session-cache evidence authenticates complete cookies with the
  published decoder, retains raw ordered chunk cookies and attributes, and
  compares the full user/session projection, version and effective lifetime.
  Cached endpoint reads and physical session storage are separate contracts.
  See the [cache audit](audits/session-cookie-cache-compact.md).
- OAuth proxy evidence uses two real local auth instances and a deterministic
  provider that verifies the actual PKCE exchange. It decrypts and retains the
  complete original package, state and profile, including all relationships and
  callback URL components. See the [proxy audit](audits/oauth-proxy.md).
- Harness negative controls deliberately corrupt identity relationships,
  lifetimes, redirects, array structure and cookies. A live HTTP/SDK canary
  confirms wrong session ownership and removed cookie protection are detected.
- The scenario gate classifies every comparator difference as client-visible
  (`observation…`) or raw transport (`traces…`) drift and fails on anything
  outside those roots, so a comparator helper cannot report a finding under a
  path the gate would discard. `harness/classification.test.ts` reproduces the
  former API-key-row regression through the real classifier. The allowlist
  guard tests the comparator's actual trace paths, including cookie scopes,
  status codes and redirect locations.
- `support/profiles.ts` is the runtime registry of configuration profiles. The
  `core/profiles` scenario requests `/ok` under every registered profile on both
  servers, so a profile served by one runtime only, or a typo in a profile name,
  fails before any scenario depends on it.
- Every 4xx/5xx response body in the raw trace is recorded completely and
  compared by value through the identity bijection, not as a type shape. Error
  codes, messages and field names therefore cannot drift silently even when a
  scenario does not return that response. Successful bodies remain shape-compared
  in the trace and value-compared wherever the scenario returns them.

Concurrent request scenarios may use separate instances of the same tracing
fetch and record both complete observations through `ctx.recordTransport` in
success/rejection order. This describes unordered outcomes without comparing
network completion order. Every request, response shape, status, selected header
and cookie attribute remains in the canonical trace comparison; returned values
and stored state share its identity graph.

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

Evidence is recorded only after a dual-server scenario passes. A category accepts a scenario name or a nonempty array of names; every named scenario is required. Regeneration preserves existing requirements and refuses missing scenarios, removed routes, and duplicate route declarations. New configuration evidence is added explicitly without replacing earlier flows. Each route can
require named scenarios for successful responses, rejection, authorization and
state transitions. A state entry requires an explicit scenario declaration and
assertions of the resulting state. CI fails if a declared route or existing
required evidence disappears. A successful HTTP response alone proves neither
all edge cases nor complete parity.

To update the inventory deliberately after adding routes or tests:

```bash
mkdir -p coverage
bun tests/compat/reference-server/generate-openapi.mjs --profile all-in --format routes --output coverage/upstream-routes.json
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
bun run --cwd tests/compat/client-tests typecheck
bun test --cwd tests/compat/client-tests harness
cargo test --test client_compat_tests passkey_client_compat -- --ignored --nocapture
cargo test --test client_compat_tests browser_client_compat -- --ignored --nocapture
cargo test --test client_compat_tests organization_teams_client_compat -- --ignored --nocapture
cargo test --test client_compat_tests organization_dynamic_roles_client_compat -- --ignored --nocapture
./scripts/alignment-check.sh
```

The Rust orchestrator starts and checks both servers on allocated ports and
stops them on completion. Direct Bun scenario runs require running reference
and Rust servers; configure `AUTH_BASE_URL_TS` and `AUTH_BASE_URL_RUST`.

## One-time tokens

`devenv shell -- cargo test --test client_compat_tests one_time_token_client_compat -- --ignored --nocapture` runs the official client against the pinned TypeScript and Rust fixtures. Four explicit profiles exercise plain and hashed storage, no-cookie consumption, server-only issuance and response headers. The scenarios assert stored session ownership, expiry, revocation, replay and newest-generation invalidation.

This database-backed integration uses persisted sessions and verification records. Secondary-storage-only sessions remain a separate integration boundary.

## Managed JWT capability

`tests/jwt` uses the official `jwtClient` and pinned JOSE 6.2.12 to check public
JWKS, all five asymmetric signing algorithms, complete authenticated user claims,
get-session response headers, configured claims/path/header settings, encrypted
and plain private-key persistence, signing-key rotation and public grace periods.
Trusted signing and verification run through fixture-only server controls.

Run `./tests/compat/client-tests/run-against-both.sh jwt` for this family.
Automatic JWT-backed core session cookie caching remains a separate integration
boundary; the managed-keyring plugin exposes no inactive cache option.

The JWT family also exercises normally refreshed token middleware, suppressed
and deferred reads, original completed-handler snapshots, API-key session
ownership and exact exposed-header ordering. Payload callbacks receive the
complete nested session response, including deferred `needsRefresh`; direct
get-session hooks observe the original stored snapshot. See the
[interaction audit](audits/jwt-session-interactions.md) for configuration evidence
and the pinned expiry-cleanup behavior.

Organization-team checks use dedicated teams, no-default-team, request-dependent
limit, and removable-final-team configurations under `/__test/profiles/`. Private
fixture controls inspect persisted organization state and invoke typed server-only
team APIs; public flows use the official client and its cookie jar. See the
[organization-team implementation audit](audits/organization-teams.md) for the
supported branches, lifecycle evidence, and remaining integration boundaries.

Dynamic-role checks add disabled, quota, missing-access-control, delegated-role,
and asynchronous-policy profiles. They inspect stored permission JSON, tenant
scopes, member assignments, API-key authority, and controlled overlapping
permission-cache reloads. See the [dynamic-role implementation audit](audits/organization-dynamic-roles.md)
for the configuration contracts, source quirks, review evidence, and remaining
schema and integration boundaries.

SIWE checks use the official `siweClient`, independent signed EIP-191 messages,
and a local ERC-1271 JSON-RPC provider. They compare wallet/account/session
ownership, nonce expiry and single use, email reservation, callback context,
ENS behavior, bans, and overlapping verification. Run
`devenv shell -- cargo test --test client_compat_tests siwe_client_compat -- --ignored --nocapture`.
The [SIWE implementation audit](audits/siwe.md) records the pinned runtime's
global nonce contract and remaining storage/schema/provider boundaries.
OpenAPI/reference whole-document proof and remaining configuration branches are tracked in [the OpenAPI audit](audits/open-api.md).

Native user-list filters accept `UserFilterValue::Scalar(String)` or
`UserFilterValue::Multiple(Vec<String>)`; existing scalar native callers can use
`filter_value: Some("value".into())`. SeaORM binds array filters to actual model
columns. `AuthEntity` derives bindings for declared application fields, including
physical column renames. Manual `SeaOrmUserModel` implementations can override
`list_users_column` to add typed plugin/application columns. See the
[admin array-filter audit](audits/admin-array-filters.md) for actual SQL, SDK,
custom-model and authorization evidence and the remaining adapter boundaries.

## Why upstream's own test suite is not run against the Rust server

The pinned `better-auth@1.7.6` repository ships 98 non-adapter test files in
`packages/better-auth` (2,382 cases) plus 551 cases in `@better-auth/core`.
They are not an HTTP conformance suite: every file constructs its own
`betterAuth(options)` through `getTestInstance`, 53 of 98 files call server-side
`auth.api.*` functions in-process, 36 reach into `auth.$context`, 20 drive fake
timers, 19 read or write the adapter directly, and 13 spy on internals. The
official client in those tests is wired to `auth.handler` through
`customFetchImpl`, never to a socket. Pointing that suite at the Rust server
would need a bridge that maps each file's `options` onto a running fixture
configuration, translates `auth.api.*` and adapter calls into control routes and
replaces timer manipulation with clock controls. That is what the explicit
`/__test/profiles/*` configurations and `/__test/*` controls here do by hand,
scenario by scenario, with both runtimes compared instead of one asserted.
Upstream test files remain the primary source when writing a scenario; the
`// Upstream reference:` markers in Rust tests and the per-capability audits
record which ones each flow reproduces.

## Supported scope and remaining behavior

The current wrap checkpoint and review/evidence owners are recorded in the
[implementation ledger](IMPLEMENTATION-LEDGER.md). The
[GitHub triage index](https://github.com/cschmatzler/better-auth-rs/issues/234)
links the remaining 96 scoped issues; [the backlog](PARITY-BACKLOG.md) summarizes
missing plugins, modes, providers and unproved configuration/integration branches.
All selected-profile HTTP routes being registered is not a full-parity claim.
The nine package/integration exclusions requested by the user remain explicit.

The stateful compact-cache implementation exposes `CookieCacheConfig` with a
floating-point maximum age and async version callback. Created callbacks receive
actual model references; stored/cached reads receive their filtered public
projections. Selected ordinary endpoint guards use cached projections, while
`AuthContext::require_session` retains physical authorization. JWT/JWE cache
and stateless modes are not implemented. `OAuthProxyConfig` configures explicit
current/production URLs, an optional dedicated secret and a floating-point maximum
payload age; `OAuthProxyPlugin` implements database-state GET completion and
retains the legacy completion route. Cookie-state mode is rejected explicitly.

OAuth account encryption uses the pinned SHA-256/XChaCha20-Poly1305 wire format.
Previously persisted native AES ciphertext has no live fallback and is not
silently migrated. The installed-data conversion boundary is tracked in
[issue #190](https://github.com/cschmatzler/better-auth-rs/issues/190).
