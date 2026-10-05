---
title: "Workspace crates"
description: "The crates that make up Better Auth RS and what each one is for."
---

You normally depend on **one** crate, `better-auth`, which re-exports the others. Reach for the smaller crates only for the advanced APIs listed below.

| Crate | Description | Depend on it directly when… |
| --- | --- | --- |
| [`better-auth`](https://github.com/cschmatzler/better-auth-rs/tree/main) | Composition and public facade: `BetterAuth`, `AuthBuilder`, request dispatch, plugins, stores and framework integrations | Always |
| [`better-auth-core`](https://github.com/cschmatzler/better-auth-rs/tree/main/crates/core) | Shared contracts and services: configuration, sessions, middleware, store decoration, plugin/endpoint contracts and errors | You use a core API that the facade does not re-export (for example `user_validation`, `session::cookie_cache::CookieCacheVersion`, JSON helpers in plugin callbacks) |
| [`better-auth-api`](https://github.com/cschmatzler/better-auth-rs/tree/main/crates/api) | Built-in plugin implementations and their OpenAPI metadata | Never — use `better_auth::plugins` |
| [`better-auth-sqlx`](https://github.com/cschmatzler/better-auth-rs/tree/main/crates/sqlx) | SQLx store, `AuthEntity` and `SqlxModel` derives, rate-limit storage, bundled migrations | Never — use `better_auth::sqlx` |
| [`better-auth-seaorm`](https://github.com/cschmatzler/better-auth-rs/tree/main/crates/seaorm) | SeaORM store, entities, `AuthEntity` derive, rate-limit storage | Never — use `better_auth::seaorm` |
| [`better-auth-cli`](https://github.com/cschmatzler/better-auth-rs/tree/main/crates/cli) | The `better-auth-rs` binary (`generate`) | Install it as a tool; see the [CLI reference](/reference/cli/) |
| `better-auth-sqlx-macros`, `better-auth-seaorm-macros` | Backend-specific `AuthEntity` derives | Re-exported by the matching adapter |
| `better-auth-macros` | `#[derive(AuthSchema)]`, `PluginConfig` | Re-exported by core |
| `better-auth-sqlx-macros`, `better-auth-seaorm-macros` | Derive implementations behind the SQLx and SeaORM stores | Never — re-exported by the store crates |
| `better-auth-schema-registry`, `better-auth-entity-codegen` | Plugin schema definitions and shared derive code used by the CLI and macros | Never |

When you add `better-auth-core` (or the CLI), use the **same Git revision** as `better-auth` so every crate resolves to one copy:

```toml
better-auth = { git = "https://github.com/cschmatzler/better-auth-rs", rev = "<commit>", features = ["axum"] }
better-auth-core = { git = "https://github.com/cschmatzler/better-auth-rs", rev = "<commit>" }
```

The workspace version is `1.0.0-alpha.3`; the library is used from Git and has no crates.io release yet.
