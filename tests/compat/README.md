# Compatibility testing

The published TypeScript `better-auth@1.7.7` runtime is the behavioral reference.
The client, reference server, passkey plugin and API-key plugin are pinned to
that version with committed Bun lockfiles. `capabilities.json` carries the single
committed `upstreamVersion`; `tests/compat/upstream_pin.rs` fails when any
manifest, lockfile, document, harness schema or fixture server restates a
different release, and both fixture servers report the release they reproduce
on `/__health`, which every scenario run verifies before comparing anything.

## Layout

Parity with upstream is established by one mechanism: the differential SDK
suite, which runs the official client against both servers and compares
everything they return and store. Unit and integration tests check the Rust
implementation on its own terms and do not claim parity; see
[../README.md](../README.md) for the tiers.

| Path | Contents |
| --- | --- |
| `main.rs` | Cargo target `compat`: the Rust side of this tier |
| `sdk.rs` | Starts both fixture servers and runs the SDK suite; one runner per scenario directory |
| `route_inventory.rs` | Fails when the Rust router's routes differ from `capabilities.json` |
| `upstream_pin.rs` | Fails when any manifest, lockfile or fixture names a different upstream release |
| `openapi_contract/` | In-process response-shape checks against upstream's generated OpenAPI contract; fast drift detection, not parity |
| `client-tests/tests/core/<area>/` | SDK scenarios for upstream's core API routes (session, user, account, password, social, ...) |
| `client-tests/tests/plugins/<plugin>/` | SDK scenarios per upstream plugin, named as upstream names it |
| `client-tests/tests/generated/` | Model-based lifecycle sequences |
| `client-tests/{environment,browser}/` | Process-environment pairs and Chromium checks |
| `client-tests/support/` | The scenario runtime, trace recorder and comparator |
| `client-tests/harness/` | Negative controls proving the comparator and gates detect drift |
| `reference-server/` | The pinned TypeScript runtime; `fixtures/` holds one configuration module per capability |
| `rust-server/` | The Rust fixture package; `src/fixtures/` mirrors the reference server's fixtures |
| `audits/{core,plugins}/` | Implementation audits under the same keys as the scenarios; `harness/` audits the comparator itself |
| `capabilities.json` | Every upstream route with the scenarios that prove each evidence category, or why there are none |

Keep tests focused on observable behavior and independent contracts. Comparator
negative controls belong in the harness because they catch false passing results;
one-off diagnostics of dependency internals and checks of comment wording do not.

## Running the suite

```bash
devenv shell -- ./scripts/compat.sh
# or, from the repository root:
bun run test:compat
```

CI does not run this suite; it is too slow and resource-hungry for every push.
Native tests (`./scripts/check.sh`) protect behavior between runs, and the
differential suite runs once before merging. It installs nothing: run
`bun install --frozen-lockfile` in `reference-server/` and `client-tests/` first.
It formats, lints and type-checks the Bun harness, runs the harness negative
controls, the complete SDK scenario directory against both store adapters,
process-environment cases and Chromium tests, then checks each adapter's evidence.
Every dual-server comparison runs through the official client against both
fixture servers on allocated ports started and stopped by the Rust orchestrator;
there is no in-process shape-only comparison layer with tolerated differences. Default and `axum,seaorm,redis-cache` configurations are tested;
`rustls,axum,seaorm,redis-cache` is also compiled without default features.
The excluded Rust compatibility server is built, formatted, and tested. Its
SQLite regression verifies that connection maintenance retains migrated tables
and persisted user identity throughout the fixture lifetime.
Missing reference dependencies or an unavailable server fail this gate.
Normal fixture processes explicitly use production mode. The `environment/`
suite starts fresh pairs for `NODE_ENV=dev`, `development`, `test`, and production
with `TEST=0`, checking the dependency's process-initialization behavior. Run it
alone with `tests/compat/client-tests/run-against-both.sh environment` inside the
development shell.

Each SDK scenario runs against TypeScript and then Rust and defaults to a
30-second test deadline, including real password hashing and multi-step tables.
Workers take the next scenario file from a shared queue, prioritizing measured
slow files in `scenario-costs.json`; every discovered file still runs. Each pair
owns separate fixture databases and process-global state, and executes its files
and scenarios serially. The default budget reserves two CPUs and 4 GiB of
available memory, estimates 1.5 GiB per pair, and caps concurrency at 16 pairs.
Linux cgroup memory limits also constrain that budget; hosts without memory
measurements default to at most four pairs.

`./scripts/compat.sh` shares that total budget between concurrent SQLx and SeaORM
runs, using separately compiled fixture executables and evidence namespaces.
Standalone SDK owners use the budget for their selected adapter. Set
`BETTER_AUTH_COMPAT_JOBS=1` for serial execution or choose 1–32 pairs explicitly.
Full-suite evidence is cleared once per adapter and checked only after all its
workers finish. A passing adapter cannot supply another adapter's receipts.
The Rust fixture uses optimized production code and one Tokio event loop, and
resolves its complete Axum router once before accepting connections. Scenarios
can override that deadline; assertions about protocol timeouts and lifetimes
remain independent. A cold run builds both fixture executables first.

The shared Rust style supplies nextest, Clippy, rustfmt, and Mr. Boxington.
The style input is private and requires GitHub SSH access. `scripts/check.sh`
combines the Rust and compatibility gates. `devenv.lock` pins all
tools, including Bun and Chromium. Update the style with `devenv update rust-style`.
Outside devenv, run `bunx playwright install --with-deps chromium` in
`client-tests/` before browser checks.


## What the tests establish

- Rust tests cover storage, plugin logic, integration routes and feature builds.
- SDK scenarios run sequentially within isolated TS/Rust worker pairs against
  fresh fixture state.
  Their values, response shapes, status codes, redirects and cookie attributes
  are compared. The full runner discovers `tests/`, so new directories join
  the gate automatically.
- The comparator retains all fields and array elements. Generated identifiers
  and opaque tokens use a bijection: repeated references and token rotation
  must agree. Provider/configuration IDs remain literal. Dates must be valid
  and lifetimes must agree within a 1.5-second execution tolerance. Only the
  configured local server origins and known URL entropy are normalized.
- `tough-cookie` handles expiry, deletion, domains and paths. Cookie security
  attributes are compared without exceptions. Chromium separately
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
  [comparison regression audit](audits/harness/encrypted-cookie-comparison.md).
- Compact session-cache evidence authenticates complete cookies with the
  published decoder, retains raw ordered chunk cookies and attributes, and
  compares the full user/session projection, version and effective lifetime.
  Cached endpoint reads and physical session storage are separate contracts.
  See the [cache audit](audits/core/session/cookie-cache-compact.md).
- OAuth proxy evidence uses two real local auth instances and a deterministic
  provider that verifies the actual PKCE exchange. It decrypts and retains the
  complete original package, state and profile, including all relationships and
  callback URL components. See the [proxy audit](audits/plugins/oauth-proxy/README.md).
- Harness negative controls deliberately corrupt identity relationships,
  lifetimes, redirects, array structure and cookies. A live HTTP/SDK canary
  confirms wrong session ownership and removed cookie protection are detected.
- The scenario gate classifies every comparator difference as client-visible
  (`observation…`) or raw transport (`traces…`) drift and fails on anything
  outside those roots, so a comparator helper cannot report a finding under a
  path the gate would discard. `harness/classification.test.ts` reproduces the
  former API-key-row regression through the real classifier. Every difference
  fails the scenario; there is no exception filter. Negative controls use the
  comparator's actual trace paths, including cookie scopes, status codes and
  redirect locations.
- Agreement only counts when the reference served the scenario.
  `support/oracle.ts` fails a passing comparison when the TypeScript run made
  no request, hit an unrouted auth path (better-call's empty 404: a mistyped
  path 404s identically on both servers), or got a fixture control's generic
  `{"message":"Internal server error"}` (any thrown error collapses to it, so
  agreement says nothing about which error). Scenarios that do this on purpose
  declare it next to the call:
  `{ oracle: { unroutedRequests | collapsedFixtureErrors: "<reason>" } }`.
  The evidence gate fails on a declaration its scenario no longer needs.
  Upstream's own 5xx responses are not exempted: they are behavior Rust must
  reproduce, and the comparator already checks their bodies.
- Every scenario starts from empty storage. After `/__test/reset-state` the
  runner reads `/__test/residue` (row counts of every non-empty table in the
  fixture's primary SQLite database) on both servers and refuses to run on
  leftovers. This caught `twoFactor` rows surviving the TypeScript reset and
  hook receipts surviving the Rust one. Secondary in-memory stores and
  per-fixture receipts are still each fixture's own `reset()`.
- Read controls distinguish "absent" (a JSON 404 from the fixture) from "not
  served" (an empty 404): a control route missing on one server throws instead
  of reading as `null` on both.
- `harness/registration.test.ts` requires every file under `tests/` to register
  through `compatScenario`; files that compare the runtimes directly are listed
  there with the reason, and `.skip`/`.only`/`.todo` are rejected.
- `support/profiles.ts` is the runtime registry of configuration profiles. The
  `core/profiles` scenario requests `/ok` under every registered profile on both
  servers, so a profile served by one runtime only, or a typo in a profile name,
  fails before any scenario depends on it.
- Every public authentication response body, including successful responses that a scenario discards,
  is retained and compared by value through the identity bijection. All response
  headers are compared except the explicit transport fields `date`, `server`,
  `connection`, `keep-alive`, `content-length` and `transfer-encoding`.
  `set-cookie` is compared as structured cookie evidence. CORS, cache policy,
  content-type parameters and application headers remain observable. Private
  fixture controls retain transport shapes and use their scenario's typed state
  observations; internal ciphertext and callback receipts are not public wire contracts.
- Runtime clock normalization retains field and entity provenance. Later session
  observations can use their actual sign-in issuance window; user updates require
  the actual previously issued session cookie. Session expiry remains tied to its
  creation/update clock or an explicit scoped expiry control. Clock comparisons
  retain the existing 1.5-second tolerance; this is not subsecond timing proof.

Concurrent request scenarios may use separate instances of the same tracing
fetch and record both complete observations through `ctx.recordTransport` in
success/rejection order. This describes unordered outcomes without comparing
network completion order. Every request, complete response, status, policy header
and cookie attribute remains in the canonical trace comparison; returned values
and stored state share its identity graph.

The browser fixture uses local HTTP. Production HTTPS/Secure-cookie deployment
behavior is not claimed by that test. Structural route evidence is also not a
claim that every behavior of an endpoint has been tested.

## Assurance of the combined suite

The assurance runner evaluates what the suite can establish, including missing
tests and missing assertions. It is an explicit command; CI routing is unchanged.
Install both Bun projects with their frozen lockfiles and run inside `devenv shell`:

```bash
cd tests/compat/client-tests
bun run assurance:inventory
bun run assurance run --budget 12
```

`run` builds and owns the Rust fixture, instruments the pinned upstream fixture,
runs the selected SDK scenarios, and runs an upstream-versus-mutated-upstream
campaign with clean executions before and after it. The strict command exits
nonzero while any in-scope obligation lacks evidence. `--report-only` permits
coverage gaps for exploration; broken execution still fails. The default budget
is a bounded sample, and every unrun mutation stays unresolved. Use repeated
`--tests tests/path.test.ts` or `--mutation ID` for focused work. For example:

```bash
bun run assurance run --report-only --budget 5 \
  --tests tests/core/password/password.test.ts \
  --tests tests/core/user/user.test.ts
bun run assurance:mutate --tests tests/core/password/password.test.ts \
  --mutation 'npm:better-auth/dist/api/routes/password.mjs#omit-effect:6479:6541' \
  --report-only
```

Each command owns a fresh directory under `artifacts/assurance/`, containing:

- `harness-controls.json` and `.log`: the harness negative controls run before
  fixture execution. Missing, failing or stale controls prevent a complete report;
  the fingerprint includes the controls themselves.
- `inventory.json`: an independent denominator from the SHA-256-pinned source
  archive in `../upstream-source.json`, authenticated published npm archives,
  public exports/options, repository source files, upstream test templates,
  static branch arms/functions and source mutation candidates. Installed package
  bytes must match the committed Bun lockfile's npm integrity. Unloaded modules
  remain in the branch denominator. Parameterized tests are counted as templates,
  not guessed expanded cases. Optional chains, loops and catches not measured by
  Istanbul are explicit unmeasured obligations.
- `parity/suite.json` and `events.jsonl`: registered and completed scenarios,
  per-scenario oracle coverage, run identity and harness fingerprint. Parity runs
  also record the tested Rust executable and build-input fingerprints; reporting
  refuses changed inputs. Only passing
  dual-fixture scenarios contribute coverage. Startup and reset execution are
cleared before each scenario. Missing acknowledgements and incomplete runs fail.
- `campaign/mutations.json`: reached and detected source/response mutations,
  survivors, unreachable changes, unchanged targets, inconclusive executions and
  unrun candidates. Source mutations negate conditions, alter comparison boundaries
  or omit persistent/delivery effects. Response mutations remove or change fields,
  status, headers and cookie protection. A detection requires a behavioral failure
  in the same scenario that reached the changed behavior. Startup failures, generic
  exceptions, timeouts, stale evidence and unrelated failures never count as kills.
- `report.json`: uncovered branches/functions, unmapped upstream obligations,
  unproven contracts, unresolved mutations and explicit scope exclusions. There
  is no percentage that can compensate for a missing obligation.

`../assurance-contracts.json` binds exact upstream anchors to named test owners and
required mutations. Start with the reset-delivery, single-use and account-deletion
contracts; other obligations intentionally remain unmapped until reviewed. A
matching route or test name alone does not create a semantic binding. New upstream
exports, options and source files enter the denominator even if our tests never
mention them. The nine documented integration exclusions remain visible with reasons.
Equivalent mutations require explicit, reviewed reasons; survivors are never
automatically classified as equivalent.

The generated lifecycle family explores two users, four actors, saved-cookie
replay, expiry, password changes/resets, revocation and deletion across default,
disabled-refresh and deferred-refresh profiles. Every action checks physical
user/account/session state and probes every issued cookie. It complements the
handwritten plugin/configuration scenarios; it does not generate all possible
plugins, configurations, storage backends or schedules.

```bash
bun run assurance:generate --seed 42 --steps 50 --profile session-deferred
bun run assurance replay --replay artifacts/assurance/RUN/replay.json --report-only
bun run assurance shrink --replay artifacts/assurance/RUN/parity/replay-0.json --budget 100
bun run assurance:report --directory artifacts/assurance/RUN
```

Failed generated cases save their symbolic actions as replay files without
ephemeral credentials. Reduction accepts only the same behavioral failure with
valid execution evidence, and records budget exhaustion. State comparison is
provided by explicit persisted-state observations and the generated model;
mutation survival exposes side effects that existing assertions fail to observe.
No universal database snapshot or exhaustive configuration/concurrency exploration
is claimed. `--reference-only` uses two upstream fixtures to validate the harness
and is labeled as such; it cannot establish Rust compatibility. Even a completed
report would establish evidence only within its declared inventory, mutation
operators and scope, not a mathematical proof over every possible input.

## Capability inventory and coverage

`capabilities.json` records the union of Rust routes and the pinned upstream
`all-in` plugin profile together with core/aligned profiles (plugin overrides
cannot hide core methods). HTTP method is part of identity; parameter names are
normalized to `{}`. Device authorization is included in the Rust fixture.
Server-only functions and plugins outside that profile are not HTTP inventory
entries. The file explicitly marks routes absent from Rust and missing evidence.

Each route has four evidence categories: success, rejection, authorization
(a 401/403 or ownership denial) and state (a scenario that declares the
transition and asserts the stored result). Every category holds one of:

- scenario names, all of which must pass against both servers and produce that
  evidence;
- `{ "notApplicable": "<reason>" }`, when the route cannot exhibit it, such as
  authorization on a public route;
- `{ "knownGap": "<reason>" }`, when evidence is missing. The gate prints every
  known gap, and regeneration replaces a gap once a scenario produces the evidence.

An empty category fails the gate, so absence is always either explained or
listed. Regeneration preserves existing requirements and refuses missing
scenarios, removed routes and duplicate declarations.

What this proves: every upstream HTTP route exists in Rust and has passing
differential evidence for each applicable category. What it does not prove:
configuration options, server-only APIs, hooks and plugin combinations are not
in this denominator. They are covered only where a scenario exercises them,
and by the assurance runner below, which is not part of the gate. The open
work is tracked in [PARITY-BACKLOG.md](PARITY-BACKLOG.md).

To update the inventory deliberately after adding routes or tests:

```bash
mkdir -p coverage
bun tests/compat/reference-server/generate-openapi.mjs --profile all-in --format routes --output coverage/upstream-routes.json
BETTER_AUTH_UPDATE_CAPABILITIES=1 cargo nextest run --test compat route_inventory::
BETTER_AUTH_UPDATE_CAPABILITIES=1 cargo nextest run --test compat sdk::tests::full_client_compat --run-ignored only --no-capture
```

Review the resulting `capabilities.json` diff, especially removed requirements.
`compat.sh` clears the update flag and always enforces the committed inventory.
Reports are written to `client-tests/artifacts/`. TypeScript source and browser
behavior are tracked through capability evidence and their own assertions.

## Focused checks

Run these in `devenv shell` after installing both projects with
`bun install --frozen-lockfile`:

```bash
bun run --cwd tests/compat/client-tests format:check
bun run --cwd tests/compat/client-tests lint
bun run --cwd tests/compat/client-tests typecheck
bun test --cwd tests/compat/client-tests harness
tests/compat/client-tests/run-against-both.sh plugins/passkey
tests/compat/client-tests/run-against-both.sh browser
tests/compat/client-tests/run-against-both.sh tests/plugins/organization/teams.test.ts
./scripts/compat.sh
```

Every scenario directory (`core/<area>`, `plugins/<plugin>`, `generated`) has a `<group>_<area>_client_compat`
runner in `tests/compat/sdk.rs`, and a guard test keeps that list in
sync. File-level runs go through `selected_client_compat`, which reads the
space-separated paths in `BETTER_AUTH_COMPAT_PATHS`.

The Rust orchestrator starts and checks both servers on allocated ports and
stops them on completion. Direct Bun scenario runs require running reference
and Rust servers; configure `AUTH_BASE_URL_TS` and `AUTH_BASE_URL_RUST`.

## One-time tokens

`devenv shell -- cargo nextest run --test compat sdk::tests::plugins_one_time_token_client_compat --run-ignored only --no-capture` runs the official client against the pinned TypeScript and Rust fixtures. Four explicit profiles exercise plain and hashed storage, no-cookie consumption, server-only issuance and response headers. The scenarios assert stored session ownership, expiry, revocation, replay and newest-generation invalidation.

This database-backed integration uses persisted sessions and verification records. Secondary-storage-only sessions remain a separate integration boundary.

## Managed JWT capability

`tests/plugins/jwt` uses the official `jwtClient` and pinned JOSE 6.2.12 to check public
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
[interaction audit](audits/plugins/jwt/session-interactions.md) for configuration evidence
and the pinned expiry-cleanup behavior.

Organization-team checks use dedicated teams, no-default-team, request-dependent
limit, and removable-final-team configurations under `/__test/profiles/`. Private
fixture controls inspect persisted organization state and invoke typed server-only
team APIs; public flows use the official client and its cookie jar. See the
[organization-team implementation audit](audits/plugins/organization/teams.md) for the
supported branches, lifecycle evidence, and remaining integration boundaries.

Dynamic-role checks add disabled, quota, missing-access-control, delegated-role,
and asynchronous-policy profiles. They inspect stored permission JSON, tenant
scopes, member assignments, API-key authority, and controlled overlapping
permission-cache reloads. See the [dynamic-role implementation audit](audits/plugins/organization/dynamic-roles.md)
for the configuration contracts, source quirks, review evidence, and remaining
schema and integration boundaries.

SIWE checks use the official `siweClient`, independent signed EIP-191 messages,
and a local ERC-1271 JSON-RPC provider. They compare wallet/account/session
ownership, nonce expiry and single use, email reservation, callback context,
ENS behavior, bans, and overlapping verification. Run
`devenv shell -- cargo nextest run --test compat sdk::tests::plugins_siwe_client_compat --run-ignored only --no-capture`.
The [SIWE implementation audit](audits/plugins/siwe/README.md) records the pinned runtime's
global nonce contract and remaining storage/schema/provider boundaries.
OpenAPI/reference whole-document proof and remaining configuration branches are tracked in [the OpenAPI audit](audits/plugins/open-api/README.md).

Native user-list filters accept `UserFilterValue::Scalar(String)` or
`UserFilterValue::Multiple(Vec<String>)`; existing scalar native callers can use
`filter_value: Some("value".into())`. SeaORM binds array filters to actual model
columns. `AuthEntity` derives bindings for declared application fields, including
physical column renames. Manual `SeaOrmUserModel` implementations can override
`list_users_column` to add typed plugin/application columns. See the
[admin array-filter audit](audits/plugins/admin/array-filters.md) for actual SQL, SDK,
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
