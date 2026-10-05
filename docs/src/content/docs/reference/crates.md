---
title: "Workspace crates"
description: "The crates that make up Better Auth RS and what each one is for."
---

Depend on **one** library crate, `better-auth`. Its public modules re-export the APIs you need from the workspace crates. The table below describes implementation ownership, not additional application dependencies.

| Crate | Description | Depend on it directly when… |
| --- | --- | --- |
| [`better-auth`](https://github.com/cschmatzler/better-auth-rs/tree/main) | Composition and public facade: `BetterAuth`, `AuthBuilder`, request dispatch, plugins, stores and framework integrations | Always |
| [`better-auth-core`](https://github.com/cschmatzler/better-auth-rs/tree/main/crates/core) | Shared contracts and services: configuration, sessions, middleware, store decoration, plugin/endpoint contracts and errors | Never — use `better_auth::config`, `better_auth::session`, `better_auth::user_validation`, and `better_auth::utils` |
| [`better-auth-api`](https://github.com/cschmatzler/better-auth-rs/tree/main/crates/api) | Built-in plugin implementations and their OpenAPI metadata | Never — use `better_auth::plugins` |
| [`better-auth-sqlx`](https://github.com/cschmatzler/better-auth-rs/tree/main/crates/sqlx) | SQLx store, `AuthEntity` and `SqlxModel` derives, rate-limit storage, bundled migrations | Never — use `better_auth::sqlx` |
| [`better-auth-seaorm`](https://github.com/cschmatzler/better-auth-rs/tree/main/crates/seaorm) | SeaORM store, entities, `AuthEntity` derive, rate-limit storage | Never — use `better_auth::seaorm` |
| [`better-auth-cli`](https://github.com/cschmatzler/better-auth-rs/tree/main/crates/cli) | The `better-auth-rs` binary (`generate`) | Install it as a tool; see the [CLI reference](/reference/cli/) |
| `better-auth-macros` | `#[derive(AuthSchema)]`, `PluginConfig` | Never — use `better_auth::AuthSchema` and `better_auth::PluginConfig` |
| `better-auth-sqlx-macros`, `better-auth-seaorm-macros` | Derive implementations behind the SQLx and SeaORM stores | Never — use `better_auth::sqlx` or `better_auth::seaorm` |
| `better-auth-schema-registry`, `better-auth-entity-codegen` | Plugin schema definitions and shared derive code used by the CLI and macros | Never |

Install the CLI as a separate tool using the same Git revision as your application; see the [CLI reference](/reference/cli/).

The workspace version is `1.0.0-alpha.3`; the library is used from Git and has no crates.io release yet.
