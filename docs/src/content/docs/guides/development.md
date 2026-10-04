---
title: "Contributing"
description: "Set up the development environment, run the checks, understand the test tiers, and work on these docs."
---

## Environment

The repository uses [devenv](https://devenv.sh/getting-started/) (Nix) and [direnv](https://direnv.net/docs/hook.html). With direnv's shell hook enabled, the checked-in `.envrc` activates the environment automatically:

```bash
direnv allow
devenv shell -- ./scripts/check.sh      # the complete gate
```

Or enter the shell manually with `devenv shell`. Rust tooling and lint rules come from the private `cschmatzler/rust` flake: local development needs GitHub SSH access, and CI fetches the locked revision with the `RUST_STYLE_TOKEN` secret. `devenv.lock` pins every tool, including Bun and Chromium.

## Repository map

```text
crates/core            runtime: config, sessions, middleware, stores, plugin traits
crates/api             all plugin implementations
crates/sqlx            SQLx store, AuthEntity derive, rate-limit storage
crates/seaorm          SeaORM store and entities
crates/cli             `better-auth-rs generate`
crates/schema-registry plugin schemas shared by the CLI and macros
src/                   the `better-auth` facade crate and Axum/Poem integrations
tests/                 unit/integration/compat tiers (see below)
docs/                  this Astro Starlight site
alchemy/               docs deployment (Railway) with Alchemy
```

See [Workspace crates](/reference/crates/) for what each crate publishes.

## Tests

| Tier | Where | Establishes | Run |
| --- | --- | --- | --- |
| Unit | inline `#[cfg(test)]` modules | Private logic of a module | `cargo nextest run --workspace` |
| Integration | `tests/integration/` | Public builder, router, stores and adapters together; both stores run every storage test | `cargo nextest run --test integration` |
| Compat | `tests/compat/` | Behavior matches the pinned `better-auth@1.7.6` | `./scripts/compat.sh` |

`./scripts/check.sh` runs formatting, strict Clippy, every tier, feature builds, TypeScript checks, doctests, rustdoc and the coverage floor. Read the tier guides before adding a test: [Tests](https://github.com/cschmatzler/better-auth-rs/blob/main/tests/README.md) explains where a new test belongs, and [Compatibility testing](https://github.com/cschmatzler/better-auth-rs/blob/main/tests/compat/README.md) describes the differential harness and the compatibility contract.

## Work on the docs

The documentation is an Astro Starlight site in `docs/`. From the repository root:

```bash
bun install
bun run docs:dev       # live preview
bun run docs:check     # Astro diagnostics
bun run docs:build     # static build and search index
```

- Content lives in `docs/src/content/docs`; **navigation** (the sidebar order and groups) is configured explicitly in `docs/astro.config.mjs`. A new page does not appear until you add it there.
- Every page follows the same shape: what it is, **schema** needs, a **complete Rust example**, **endpoints** with request/response examples, a **configuration** table, security notes, and a link to the official frontend docs.
- Examples must be complete — include `use` lines and plugin registration — and must compile against this repository's API. Verify behavior claims against a running instance rather than from memory; response bodies in the docs are real captures.
- Mark an intentionally partial snippet with `nocheck` in its fence (` ```rust nocheck `) so tooling can skip it.
- Link to the official Better Auth docs for frontend usage; target the pinned compatibility version (1.7.6).
- Prefer tables for options and endpoints, and state defaults.

## Style

Match the surrounding code: comments only where they explain why, no generated-looking filler, `unwrap`/`expect`/`panic` are denied by the workspace lints in library code. Public behavior changes need a test in the right tier and, when they affect upstream-compatible HTTP behavior, a differential scenario.
