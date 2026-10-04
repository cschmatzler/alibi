# Native HTTP exposure fixes (issues 449 and 451)

Base: `93a9d1bded75314477425980df4fac4eb7f5c7a5` from actual origin/main,
including dependency migration `817eeb59` and recorder PR 454. Fresh
`git clone --no-hardlinks` at `/tmp/better-auth-sixissues-http-exposure`.
The attached `aa0d13885de5a4272ffe49a6a136155fcdf46962` checkout is untouched.
No upstream version change or issue 453 work is included. Root separately owns
the 1.7.7 port and pin bump in `/tmp/better-auth-sixissues-upstream`; its
additive overlap in `captcha.rs` changes only the `error_response` final
Content-Type header and must preserve this OPTIONS guard. These new CAPTCHA
assertions do not pin the prior response Content-Type.

## Production ownership

CAPTCHA's physical HTTP hook precedes native CORS. Skip only OPTIONS in that
plugin, preserving the existing transport/global/plugin ordering and response,
raw and cache issuance lifecycle. Native CORS continues to control allowed
origins. Protected POSTs still fail with `MISSING_RESPONSE` without a token.

The OpenAPI plugin now registers and handles `/__test/openapi.json`. Core
registration/dispatch and Axum's unconditional literal mounting no longer own
it. Its native annotation moves with it; ordinary documents hide the alias,
while `include_native_extensions` documents it when actually installed.
The alias retains its prior schema without native extensions, and Rust
in-process schema APIs remain usable without the plugin. No config fields or
test-only production seams were added.

## Source and dependency provenance

The scoped reference-server `bun install --frozen-lockfile` succeeded using a
private Bun cache and fresh project node_modules. Installed Better Auth 1.7.6
`dist/plugins/captcha/index.mjs` uses the **Source onRequest stage**, matches
paths, and reads `x-captcha-response` without a method guard. Skipping OPTIONS
is a deliberate supported fix for Rust's native CorsConfig integration, which
Source does not supply. The native OpenAPI embedding alias likewise has no
upstream parity claim. The 1.7.6 oracle stays unchanged.

Full logs, failed intermediate run, regression patch and installed source
snapshots are preserved at
`/tmp/better-auth-final-verification-20261004/http-exposure/`.
Cargo home/target and Bun cache are private there. Final proof also explicitly
sets a private MBX_CACHE_DIR; initial runs used the devenv compiler-cache
default. No prior campaign artifacts were removed or reused as test evidence.

## Test authoring gate

- Extend the existing real HTTP composition owner over SqlxStore and SeaOrmStore:
  allowed-origin browser preflight succeeds without a token and returns the
  configured method/header permissions; wrong-origin OPTIONS gets no grant;
  a valid real-account sign-in POST without a token remains denied specifically
  by CAPTCHA. A regression removing the method guard fails on the preflight.
  Existing response/raw/cache/lifecycle checks remain in this same owner.
- Extend the application OpenAPI owner: without the plugin direct HTTP returns
  empty 404 and native documents omit the unregistered alias; with it, the
  alias serves the configured schema, and independent custom schema/route
  assertions still verify real content. Unconditional core dispatch fails the
  new default assertion.
- Axum has a distinct mounting/fallback risk: a real nested router over the
  actual SeaOrm store denies default exposure and serves core routes and User
  schema when opted in. Unconditional core exposure fails the absent case.
- Delete two duplicate native-endpoint smoke probes from the compatibility tier
  that assumed unconditional exposure. The stronger integration owners now
  cover default, opt-in, real document content and transport independently.

No mocks, source-grep pseudo-proof, new ignores, relaxed assertions or broad
campaign. Existing PostgreSQL ignored variants are not evidence for this run.

## Commands and observed results

Commands run through devenv with `CARGO_BUILD_JOBS=2`,
`CARGO_PROFILE_DEV_DEBUG=0`, `CARGO_PROFILE_TEST_DEBUG=0`, `--locked`, and private
`CARGO_HOME` / `CARGO_TARGET_DIR`.

Pre-fix `cargo test --features axum,seaorm --test integration <filter> -- --nocapture`:

- `physical_http_composition`: both SQLite stores fail with 400
  `MISSING_RESPONSE` instead of allowed preflight 204.
- `application_schema_and_plugin_annotations`: fails with default 200 versus 404.
- `openapi_embedding_requires_plugin_in_axum`: fails with default 200 versus 404.

Preserved runtime transcripts are alongside this report. First post-fix owner
run: 3 passed, 1 failed because the OpenAPI plugin's empty metadata override
hid the moved alias even in native documents. Explicit plugin-owned metadata
repaired it without changing the existing assertion.

Final owner/sibling command:

```sh
cargo nextest run --locked --features axum,seaorm --test integration \
  -E 'test(storage::http_composition::) | test(plugins::open_api::) | test(axum_integration::router::) | test(core::rust_surface_auth::)'
```

Result: **45 passed**, 398 outside the selection. Includes the existing
response/raw/cache composition assertions and both SQLite stores.

Scoped lint command:

```sh
cargo clippy --locked -p better-auth -p better-auth-api -p better-auth-core \
  --all-targets --features axum,seaorm -- -D warnings
```

Passed again on the final sources. `cargo fmt --all -- --check` and
`git diff --check` passed. Core OpenAPI/CORS siblings: **9 passed**, 154
outside the selection. See `final-checks.log`.

Production Rust LOC: +29/-25 (net +4). Tests: +161/-29 (net +132),
including removal of the duplicate compatibility smoke probes. No tooling
changes. Documentation and provenance reports are separate. The repository has no
`run-vitest.mjs`, `check-changed.mjs` or PR workflow scripts from the generic
test-audit skill; its actual check script uses Cargo/devenv and Bun. This work
uses scoped native owners rather than invoking the full campaign gate.

## Review and acceptance

One coherent PR with `Closes #449` / `Closes #451`. Root must personally review
the exact final head before merge. No merge or explicit issue closure is
performed by the implementation worker. No full repository, differential,
docs-build, PostgreSQL or all-features green claim is made.

Provenance SHA-256:

```text
7e43660d7952f58831cac5267ab70f5e65a498ea4e4da027c9085971c7df0056  Cargo.lock
7c566346f54bd056586f4bcceb4b36de09c0ccee759954defd5fe5d802d7d1fe  bun.lock
c97812a1fd72e85de5484bfdd1dbc75398731e3d311805b6314eb1246bc60c26  bun.lock
fcfa8aea785b77930c1a0f496594cb2986c4276ddaacb0bd67df53bed473686f  captcha-1.7.6.mjs
1af4a15615e37a2bb0a55d4786e64b0a0e45340b81b3eb6e7c1a8346f51a1bee  open-api-1.7.6.mjs
```
