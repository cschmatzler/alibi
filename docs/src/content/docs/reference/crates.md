---
title: "Workspace crates"
description: "The crates that make up Alibi and what each one is for."
---

Depend on **one** library crate, `alibi`. Its public modules re-export the APIs you need from the workspace crates. The table below describes implementation ownership, not additional application dependencies.

| Crate | Description | Depend on it directly when… |
| --- | --- | --- |
| [`alibi`](https://github.com/cschmatzler/better-auth-rs/tree/main) | Composition and public facade: `BetterAuth`, `AuthBuilder`, request dispatch, plugins, stores and framework integrations | Always |
| [`alibi-core`](https://github.com/cschmatzler/better-auth-rs/tree/main/crates/core) | Shared contracts and services: configuration, sessions, middleware, store decoration, plugin/endpoint contracts and errors | Never — use `better_auth::config`, `better_auth::session`, `better_auth::user_validation`, and `better_auth::utils` |
| [`alibi-api`](https://github.com/cschmatzler/better-auth-rs/tree/main/crates/api) | Built-in plugin implementations and their OpenAPI metadata | Never — use `better_auth::plugins` |
| [`alibi-sqlx`](https://github.com/cschmatzler/better-auth-rs/tree/main/crates/sqlx) | SQLx store, `AuthEntity` and `SqlxModel` derives, rate-limit storage, bundled migrations | Never — use `better_auth::sqlx` |
| [`alibi-seaorm`](https://github.com/cschmatzler/better-auth-rs/tree/main/crates/seaorm) | SeaORM store, entities, `AuthEntity` derive, rate-limit storage | Never — use `better_auth::seaorm` |
| [`alibi-cli`](https://github.com/cschmatzler/better-auth-rs/tree/main/crates/cli) | The `better-auth-rs` binary (`generate`) | Install it as a tool; see the [CLI reference](/reference/cli/) |
| `alibi-macros` | `#[derive(AuthSchema)]`, `PluginConfig` | Never — use `better_auth::AuthSchema` and `better_auth::PluginConfig` |
| `alibi-sqlx-macros`, `alibi-seaorm-macros` | Derive implementations behind the SQLx and SeaORM stores | Never — use `better_auth::sqlx` or `better_auth::seaorm` |
| `alibi-schema-registry`, `alibi-entity-codegen` | Plugin schema definitions and shared derive code used by the CLI and macros | Never |

Install the CLI as a separate tool using the same release version as your application; see the [CLI reference](/reference/cli/).

The workspace release is `0.1.0`. The library and supporting crates are published on crates.io.
