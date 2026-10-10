---
title: "Workspace crates"
description: "The crates that make up Alibi and what each one is for."
---

Depend on **one** library crate, `alibi`. It re-exports the complete public API of the workspace crates: `alibi-core` at the same paths, and the plugin and store crates as `alibi::plugins`, `alibi::sqlx` and `alibi::seaorm`. The table below describes implementation ownership, not additional application dependencies.

| Crate | Description | Depend on it directly when… |
| --- | --- | --- |
| [`alibi`](https://github.com/cschmatzler/better-auth-rs/tree/main) | Composition and public facade: `Alibi`, `AuthBuilder`, request dispatch, plugins, stores and framework integrations | Always |
| [`alibi-core`](https://github.com/cschmatzler/better-auth-rs/tree/main/crates/core) | Shared contracts and services: configuration, sessions, middleware, store decoration, plugin/endpoint contracts and errors | Never — every item is available at the same path under `alibi` (for example `alibi::config`, `alibi::store`, `alibi::utils`) |
| [`alibi-plugins`](https://github.com/cschmatzler/better-auth-rs/tree/main/crates/plugins) | Built-in plugin implementations and their OpenAPI metadata | Never — use `alibi::plugins` |
| [`alibi-sqlx`](https://github.com/cschmatzler/better-auth-rs/tree/main/crates/sqlx) | SQLx store, `AuthEntity` and `SqlxModel` derives, rate-limit storage, bundled migrations | Never — use `alibi::sqlx` |
| [`alibi-seaorm`](https://github.com/cschmatzler/better-auth-rs/tree/main/crates/seaorm) | SeaORM store, entities, `AuthEntity` derive, rate-limit storage | Never — use `alibi::seaorm` |
| [`alibi-cli`](https://github.com/cschmatzler/better-auth-rs/tree/main/crates/cli) | The `alibi` binary (`generate`) | Install it as a tool; see the [CLI reference](/reference/cli/) |
| `alibi-macros` | `#[derive(AuthSchema)]`, `PluginConfig` | Never — use `alibi::AuthSchema` and `alibi::PluginConfig` |
| `alibi-sqlx-macros`, `alibi-seaorm-macros` | Derive implementations behind the SQLx and SeaORM stores | Never — use `alibi::sqlx` or `alibi::seaorm` |
| `alibi-schema-registry`, `alibi-entity-codegen` | Plugin schema definitions and shared derive code used by the CLI and macros | Never |

Install the CLI as a separate tool using the same release version as your application; see the [CLI reference](/reference/cli/).

The workspace release is `0.5.0`. The library and supporting crates are published on crates.io.
