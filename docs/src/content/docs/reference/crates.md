---
title: "Workspace crates"
description: "The crates that make up Better Auth RS and what each one is for."
---

You normally depend on **one** crate, `better-auth`, which re-exports the others. Reach for the smaller crates only for the advanced APIs listed below.

| Crate | Description | Depend on it directly when… |
| --- | --- | --- |
| [`better-auth`](https://github.com/cschmatzler/better-auth-rs/tree/main) | The facade: `BetterAuth`, `AuthBuilder`, `AuthConfig`, plugins, store re-exports, Axum and Poem integrations | Always |
| [`better-auth-core`](https://github.com/cschmatzler/better-auth-rs/tree/main/crates/core) | Runtime: configuration, sessions, middleware, store traits, endpoint dispatch, plugin traits, errors | You use a core API that the facade does not re-export (for example `user_validation`, `cache::CookieCacheVersion`, JSON helpers in plugin callbacks) |
| [`better-auth-api`](https://github.com/cschmatzler/better-auth-rs/tree/main/crates/api) | The plugin implementations | Never — use `better_auth::plugins` |
| [`better-auth-sqlx`](https://github.com/cschmatzler/better-auth-rs/tree/main/crates/sqlx) | SQLx store, `AuthEntity` and `SqlxModel` derives, rate-limit storage, bundled migrations | Never — use `better_auth::sqlx` |
| [`better-auth-seaorm`](https://github.com/cschmatzler/better-auth-rs/tree/main/crates/seaorm) | SeaORM store, entities, `AuthEntity` derive, rate-limit storage | Never — use `better_auth::seaorm` |
| [`better-auth-cli`](https://github.com/cschmatzler/better-auth-rs/tree/main/crates/cli) | The `better-auth-rs` binary (`generate`) | Install it as a tool; see the [CLI reference](/reference/cli/) |
| `better-auth-macros` | `#[derive(AuthSchema)]`, `PluginConfig` | Re-exported by core |
| `better-auth-schema-registry`, `better-auth-entity-codegen` | Plugin schema definitions and shared derive code used by the CLI and macros | Never |
| `better-auth-webauthn-rs`, `better-auth-webauthn-rs-core` | Vendored WebAuthn verification for [passkeys](/plugins/passkey/) | Never |

When you add `better-auth-core` (or the CLI), use the **same Git revision** as `better-auth` so every crate resolves to one copy:

```toml
better-auth = { git = "https://github.com/cschmatzler/better-auth-rs", rev = "<commit>", features = ["axum"] }
better-auth-core = { git = "https://github.com/cschmatzler/better-auth-rs", rev = "<commit>" }
```

The workspace version is `1.0.0-alpha.3`; the library is used from Git and has no crates.io release yet.
