# Tests

Four tiers, each with one job. Native tests check the Rust
implementation on its own terms; only the compat tier makes claims about parity
with upstream `better-auth`.

| Tier | Where | What it establishes | Run |
| --- | --- | --- | --- |
| Unit | inline `#[cfg(test)] mod tests` at the end of each module in `crates/*` and `src/` | Private logic of one module | `cargo nextest run --lib` |
| Integration | `tests/integration/` (Cargo target `integration`) | The public builder, router, stores and framework integrations working together | `cargo nextest run --test integration` |
| End-to-end | `tests/e2e/` (Cargo target `e2e`, feature `axum`) | Real HTTP, cookie handling, authentication and reset delivery with SQLite | `cargo nextest run --test e2e` |
| Compat | `tests/compat/` (Cargo target `compat` plus the Bun harness) | Behavior matches the pinned upstream release | `./scripts/compat.sh` |

`tests/repo/` (target `repo`) holds repository invariants: banned legacy
symbols and README/crate consistency. `./scripts/check.sh` runs every tier and is
the CI gate.

## Fast native feedback

```bash
# In the devenv/direnv shell:
cargo nextest run
cargo nextest run --lib
cargo nextest run --test integration
cargo nextest run --test e2e
cargo nextest run -E 'test(storage::plugin_flows)'
cargo nextest run --no-run
```

Cargo's `default-members` selects the workspace. The root development dependency
enables Axum, Poem and SeaORM alongside SQLx for repository tests, without changing
the features downstream applications enable. No wrapper or special nextest profile
is needed. Outside the development shell, prefix the command with `devenv shell --`.

No Bun, upstream install, Redis, PostgreSQL, browser install, or external network
service is needed. Tests use isolated SQLite databases and ephemeral localhost
HTTP servers. The first run compiles the workspace; subsequent runs reuse Cargo
artifacts. The default nextest profile runs cases concurrently, collects all
failures and does not retry. The JUnit report is
`target/nextest/default/junit.xml`. The **Native tests** CI workflow runs the same
command. The existing full project gate and compat scripts remain unchanged.

### What is skipped

A bare run keeps Rust's explicit `#[ignore]` decisions. They are not hidden by a
nextest default filter. With the workspace and development features enabled:

| Ignored cases | Why |
| --- | --- |
| 42 compat SDK runners | Require the upstream/Rust fixture servers and Bun; run through the unchanged compat harness |
| 260 PostgreSQL matrix cases | Require `BETTER_AUTH_TEST_POSTGRES_URL`; SQLite variants run by default for both stores |
| 3 admin clock proofs | Require a controlled `CLOCK_REALTIME` fixed at the documented proof timestamp |

The earlier root-package-only command reported 116 skips: 42 compat, 72
PostgreSQL and 2 clock cases. The broader workspace discovers additional tests,
including their explicit ignores. The 62 fast, in-process compat contract checks
also run by default; they launch no upstream services. Excluding their entire
binary with a default filter would also silently exclude explicitly selected SDK
runners in the existing compat script.

The native CI workflow explicitly runs PostgreSQL, Redis, and the exact-clock proofs. The clock profile preserves a separate JUnit report so it cannot overwrite the full default-suite report. PostgreSQL and Redis use separate service-backed profiles (see below). A filtered
nextest invocation also labels nonmatching tests as skipped; those are different
from `#[ignore]` cases.

### Audited surface and verification

The reviewed inventory is [the native surface ledger](../reports/native-surface/matrix.json):
144 HTTP routes, 18 server-only operations, 37 OAuth/provider implementations,
23 callback/policy groups, and the core, storage, framework and generated-schema
contracts. Each entry names its native assertion owner; registered integration
cases record their actual backend variants. This is a review artifact, not a test
that passes by comparing copied lists.

The latest [verification receipt](../reports/native-surface/verification.json)
records the commands, results and source fingerprint. A bare `cargo nextest run`
runs **1,074 passing tests**, including 62 existing in-process compat checks that
need no upstream server. Its **305 ignored cases** are exactly 260 PostgreSQL
cases, 42 upstream SDK runners, and 3 fixed-clock proofs. The PostgreSQL cases,
3 clock proofs, and 2 feature-gated Redis cases also passed in their respective
service runs. Six doctests and four lean feature builds passed. No claim is made
that the GitHub workflow has already run remotely.

[Production line execution](../reports/native-surface/current.json) is **84.04%**
(49,503 / 58,902 instrumented lines), measured from the combined default and
PostgreSQL runs. It is a diagnostic alongside reviewed assertions, not proof of
every input, branch, or configuration combination. The ledger explicitly records
dormant declarations, unsupported model defaults, documentation-only examples,
and external provider limitations. Redis and fixed-clock checks are validated
separately and are not included in this percentage.

To reproduce combined coverage in the development shell, with disposable
PostgreSQL configured in `BETTER_AUTH_TEST_POSTGRES_URL`:

```bash
export CARGO_LLVM_COV_TARGET_DIR="$PWD/coverage/native-audit/target"
cargo llvm-cov clean --workspace
cargo llvm-cov nextest --locked --no-report --profile postgres --run-ignored only -E 'test(postgres)'
cargo llvm-cov nextest --locked --no-clean --summary-only
cargo llvm-cov report --locked --package '*' --ignore-filename-regex '(tests/|scripts/|target/)' --lcov --output-path coverage/native-audit/raw.info
lcov --add-tracefile coverage/native-audit/raw.info --filter region --rc c_file_extensions=rs --rc function_coverage=0 --rc derive_function_end_line=0 --output-file coverage/native-audit/lcov.info
```

Start with a clean instrumented workspace to exclude obsolete test binaries, and
retain profiles explicitly for the second run. The recorded JSON retains only
workspace production paths (`src/` and `crates/`). The earlier baseline is a
historical discovery snapshot; it is not a controlled before/after comparison.

### Coverage ownership (test-audit authoring gate)

Reuse existing native tests instead of translating the compat scenarios again.
The hundreds of core/plugin unit cases and the integration storage contracts
already own input validation, transaction boundaries, atomic operations, session
expiry/revocation, key rotation and plugin behavior. Compat remains the upstream
oracle. Native cases protect the implementation between compatibility runs.

The new cases have distinct owners and failure modes:

| Owner | Contract and credible regression | Why this layer |
| --- | --- | --- |
| `crates/core/src/config/client_ip.rs` | Reject spoofed forwarding chains, fail malformed hops closed, match proxy addresses before IPv6 grouping, honor tracking opt-out | Pure shared policy; existing config tests only checked defaults |
| `integration/core/client_ip.rs` | Initialized custom IP policy and user-agent reach the session actually persisted by signup | Detects missing dispatch configuration propagation, which parser tests cannot reach |
| `storage/plugin_flows/passwordless.rs` | Delivered magic links, email/phone OTPs and one-time tokens produce usable sessions and reject replay on both adapters | Public dispatch, delivery callbacks and database consumption work together; plugin unit tables remain their existing owners |
| `storage/plugin_flows/providers.rs` | HIBP and all four CAPTCHA protocols gate writes; One Tap verifies real signed identity; OAuth Popup binds completion to the issued opener | Local HTTP captures provider requests; real signature verification and persistence run on both stores |
| `storage/plugin_flows/session_plugins.rs` | Consent controls tracking, delivered device proofs restrict multi-session access, and custom projection cannot replace bearer authority | Tests plugin initialization and interaction through public routes on both stores |
| `storage/plugin_flows/crypto.rs` | An issued SIWE nonce and a registered passkey authenticate using real signatures and persisted credentials | Independent wallet vector and simulated authenticator exercise both stores without seeded credentials |
| `crates/api/src/plugins/passkey/source/tests.rs` | All six certificate formats bind original signed bytes and configured trust; previously issued RSA credentials survive the registry migration | Independently signed vectors and a credential serialized by the removed fork protect cryptographic and storage-format extensions; handler tests own persistence and challenge consumption |
| `e2e` cookie journey | Delivered cookies authenticate separate clients; rejected cross-origin signout preserves authority; successful signout expires the cookie and invalidates replay | Existing in-process adapter tests synthesize signed cookie headers; this owns real HTTP/client cookie interoperability |
| `e2e` reset journey | A delivered reset URL redirects to a usable token, resets credentials once, and revokes existing sessions | Exercises the application callback, redirect, client and handler composition without seeding a token |

The native gate also retains the existing OAuth account-encryption, anonymous
OAuth-context and magic-link lifecycle tests. Their direct storage fixtures and
lookups now use the `auth-state:` and `magic-link:` namespaces introduced by the
1.7.7 security update (`f45534b0`). Before this correction, eleven cases failed at
setup/lookup; some absence assertions queried keys the handlers no longer wrote.
The corrected checks inspect the records the real paths actually persist.

No production exports, flags, wrappers or injection hooks were added. E2E uses
the existing public builder, store migration API, framework adapter and delivery
callback. The mailbox only captures a real notification; it does not generate
tokens or implement authentication. Each journey gets a fresh database, server
and cookie jars. HTTP and mailbox waits are bounded, and server tasks are cleaned
up on both success and assertion failure. These tests use a real HTTP client,
not a browser engine or the TypeScript SDK; those remain compat responsibilities.

## Layout

```text
tests/
├── integration/            Cargo target `integration`
│   ├── main.rs
│   ├── core/               upstream core API areas (session/, schema/, http_flow, ...)
│   ├── plugins/            one module per plugin (organization/, anonymous/, jwt, ...)
│   ├── storage/            store contract tests, run against SqlxStore and SeaOrmStore
│   └── axum_integration/   the Axum adapter (feature `axum`)
├── e2e/                    Cargo target `e2e`: localhost HTTP journeys
├── compat/                 everything compared against upstream
│   ├── main.rs             Cargo target `compat`
│   ├── sdk.rs              starts both fixture servers and runs the SDK suite
│   ├── route_inventory.rs  Rust routes == capabilities.json
│   ├── upstream_pin.rs     every manifest names the same upstream release
│   ├── openapi_contract/   in-process shapes against upstream's OpenAPI document
│   ├── client-tests/       Bun differential suite (scenarios, comparator, harness controls)
│   ├── reference-server/   the pinned TypeScript runtime and its fixtures
│   ├── rust-server/        the Rust fixture server mirroring reference-server
│   └── audits/             per-capability implementation audits
├── repo/                   Cargo target `repo`
├── support/                helpers shared by `integration` and `compat`
└── fixtures/               pinned vectors (SIWE, JWT, OAuth, One Tap) and CLI output
```

Integration modules mirror the scenario tree in
`tests/compat/client-tests/tests/{core,plugins}`, so the native and the
differential evidence for one area sit under the same name.

## Store backends

Both bundled stores must behave identically. Each test in
`tests/integration/storage/` is generic over a `Backend` and runs once for
`SqlxStore` and once for `SeaOrmStore`, on file-backed SQLite. Tests that avoid
SQLite-only SQL also have ignored PostgreSQL variants, run with
`BETTER_AUTH_TEST_POSTGRES_URL=postgres://... cargo nextest run --test integration -E 'test(/^storage::/)' --run-ignored only`.
Each test gets a fresh schema in that database. To include the SQLx crate's own
PostgreSQL wire-type test too:

```bash
BETTER_AUTH_TEST_POSTGRES_URL=postgres://... cargo nextest run --profile postgres --run-ignored only -E 'test(postgres)'
```

Optional Redis session/rate-limit tests are selected explicitly:

```bash
BETTER_AUTH_TEST_REDIS_URL=redis://... TEST_RATE_LIMIT_REDIS_URL=redis://... \
  cargo nextest run --features redis-cache --profile redis --run-ignored only -E 'test(redis)'
```

Use isolated disposable services. Fixed-clock proofs retain their existing setup
in `compat/audits/plugins/admin/`. They distinguish an admin ban expiring exactly
now from one expiring a millisecond before or after, and check mutation-hook
ordering. A moving wall clock cannot reliably exercise equality; the proof clock
controls `CLOCK_REALTIME` without adding a production clock-injection API.

The Rust fixture server serves the compat suite from `SqlxStore`. Set
`BETTER_AUTH_COMPAT_BACKEND=seaorm` (fixture feature `seaorm`) to serve it from
`SeaOrmStore`; `./scripts/compat.sh` runs both.

## Where a new test goes

- It needs private items of one module: a unit test in that module.
- It checks a store guarantee (atomicity, concurrency, hook phases, physical
  rows): a generic test in `tests/integration/storage/`, so both backends run it.
- It drives the public Rust API, a store or the Axum adapter and has no upstream
  counterpart (typed configuration errors, custom entity schemas, hook ordering,
  SQL-level guarantees): `tests/integration/<core|plugins>/<area>.rs`.
- It needs real HTTP transport, delivered cookies or a composed user journey:
  `tests/e2e/`; reuse its server and cookie-client fixture and avoid replaying
  endpoint validation tables already owned by unit/integration tests.
- It makes a claim about upstream behavior: an SDK scenario in
  `tests/compat/client-tests/tests/<core|plugins>/<area>/`. Never assert an
  upstream behavior only in Rust; the reference server is the oracle.
- It changes how traces are compared: a negative control in
  `tests/compat/client-tests/harness/` that fails without the change.
- Pinned binary/vector data: `tests/fixtures/<area>/`, loaded with `include_str!`.

## Conventions

- One Cargo target per tier keeps link time flat; add modules, not new
  `tests/*.rs` crates.
- Keep inline unit modules inside `LCOV_EXCL_START` / `LCOV_EXCL_STOP` so the
  coverage floor measures production lines only.
- Gate feature-dependent modules on their `mod` declaration
  (`#[cfg(feature = "axum")] mod oauth_proxy;`).
- `.config/nextest.toml` serializes the SDK runners, which each own a server pair.
- A nextest filter that selects nothing fails; quote exact names as
  `-E 'test(=sdk::tests::plugins_jwt_client_compat)'`.

See [compat/README.md](compat/README.md) for how the differential suite works
and what it does and does not prove.
