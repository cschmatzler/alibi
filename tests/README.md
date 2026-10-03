# Tests

Three tiers, each with one job. Unit and integration tests check the Rust
implementation on its own terms; only the compat tier makes claims about parity
with upstream `better-auth`.

| Tier | Where | What it establishes | Run |
| --- | --- | --- | --- |
| Unit | inline `#[cfg(test)] mod tests` at the end of each module in `crates/*` and `src/` | Private logic of one module | `cargo nextest run --workspace` |
| Integration | `tests/integration/` (Cargo target `integration`) | The public builder, router, stores and framework integrations working together | `cargo nextest run --test integration` |
| Compat | `tests/compat/` (Cargo target `compat` plus the Bun harness) | Behavior matches the pinned upstream release | `./scripts/compat.sh` |

`tests/repo/` (target `repo`) holds repository invariants: banned legacy
symbols and README/crate consistency. `./scripts/check.sh` runs every tier and is
the CI gate.

## Layout

```text
tests/
├── integration/            Cargo target `integration`
│   ├── main.rs
│   ├── core/               upstream core API areas (session/, schema/, http_flow, ...)
│   ├── plugins/            one module per plugin (organization/, anonymous/, jwt, ...)
│   ├── storage/            store contract tests, run against SqlxStore and SeaOrmStore
│   └── axum_integration/   the Axum adapter (feature `axum`)
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
Each test gets a fresh schema in that database.

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
