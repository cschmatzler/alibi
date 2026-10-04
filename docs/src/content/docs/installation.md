---
title: "Installation"
description: "Add Better Auth RS, generate a schema, mount the auth routes and make the first request."
---

This page builds a working Axum server with email and password authentication on SQLite. Every later page assumes this setup and shows only what changes.

**Requirements:** Rust 1.85 or newer (edition 2024), and a Tokio runtime. The default build uses OpenSSL (`native-tls`); see [Cargo features](/reference/features/) for Rustls.

## 1. Add the dependencies

Better Auth RS is distributed from its Git repository:

```toml title="Cargo.toml"
[dependencies]
better-auth = { git = "https://github.com/cschmatzler/better-auth-rs", features = ["axum"] }
axum = "0.8"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
chrono = { version = "0.4", features = ["serde"] }
sqlx = { version = "0.9", default-features = false, features = ["sqlite", "chrono", "json", "derive"] }
```

`serde`, `serde_json`, `chrono` and `sqlx` are needed because the generated models derive from them. Pin the Git dependency to a reviewed commit for reproducible builds:

```toml title="Cargo.toml"
better-auth = { git = "https://github.com/cschmatzler/better-auth-rs", rev = "<commit>", features = ["axum"] }
```

Install the CLI from the same revision (`cargo install --git … --rev <commit>`).

## 2. Set environment variables

```bash
export BETTER_AUTH_SECRET="$(openssl rand -base64 32)"
export BETTER_AUTH_URL="http://localhost:3000"
export DATABASE_URL="sqlite://auth.db?mode=rwc"
```

| Variable | Purpose |
| --- | --- |
| `BETTER_AUTH_SECRET` | Signs cookies and tokens and derives encryption keys. At least 32 characters; keep it out of source control. |
| `BETTER_AUTH_URL` | The public origin of the server. Used for cookie security, OAuth callbacks and links in emails. |
| `DATABASE_URL` | SQLite or PostgreSQL URL. |

The library never reads these itself and does not load `.env` files; the code below reads them explicitly. To rotate or version secrets, see [Secrets and key rotation](/reference/secrets/).

## 3. Generate the schema

```bash
cargo install --git https://github.com/cschmatzler/better-auth-rs --locked better-auth-cli
better-auth-rs generate -o src/auth_schema.rs
```

The generated file is yours to keep and edit. It contains:

- `user`, `session`, `account` and `verification` models (`mod user { pub struct Model … }` and so on) deriving `sqlx::FromRow` and `AuthEntity`;
- `AppAuthSchema`, a unit struct implementing `AuthSchema` that names those four models;
- `run_app_migrations`, which creates the tables for a new database.

Plugins that need columns or tables (two-factor, organization, admin, API keys, …) are added with `--plugins`; see [Database](/concepts/database/) and the CLI [reference](/reference/cli/).

## 4. Build the instance and mount it

```rust title="src/main.rs"
mod auth_schema;

use auth_schema::{AppAuthSchema, run_app_migrations};
use axum::Router;
use better_auth::integrations::axum::AxumIntegration;
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::sqlx::{SqlxPool, SqlxStore};
use better_auth::{AuthConfig, BetterAuth};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = AuthConfig::new(std::env::var("BETTER_AUTH_SECRET")?)
        .base_url(std::env::var("BETTER_AUTH_URL")?);
    let pool = SqlxPool::connect(&std::env::var("DATABASE_URL")?).await?;
    run_app_migrations(&pool).await?;
    let store = SqlxStore::<AppAuthSchema>::new(config.clone(), pool);

    let auth = Arc::new(
        BetterAuth::<AppAuthSchema>::new(config)
            .store(store)
            .plugin(EmailPasswordPlugin::new().enable_signup(true))
            .build()
            .await?,
    );

    let app = Router::new()
        .nest("/api/auth", auth.clone().axum_router())
        .with_state(auth);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

What each step does:

1. `AuthConfig` is created once and given to **both** the store and the builder, so they agree on session and field policy.
2. `SqlxPool::connect` selects SQLite or PostgreSQL from the URL scheme.
3. `run_app_migrations` creates the generated tables. It is meant for new local databases; use your own versioned migrations as the schema evolves (see [Database](/concepts/database/)).
4. `.plugin(...)` registers features. Credential sign-in is disabled until `EmailPasswordPlugin` is registered, and signup is off until `enable_signup(true)`.
5. `.build().await` validates the configuration, initializes every plugin and returns a `BetterAuth<AppAuthSchema>`.
6. `axum_router()` returns the auth routes. Nest it at `AuthConfig::base_path` — `/api/auth` unless you change it.

## 5. Try it

```bash
cargo run
# in another terminal:
curl http://localhost:3000/api/auth/ok
```

```json
{"ok":true}
```

Continue with [Basic usage](/basic-usage/) to sign up, sign in and read the session.

## Production checklist

- Use a long random `BETTER_AUTH_SECRET` and an `https://` `BETTER_AUTH_URL`. HTTPS turns on `Secure` cookies and the `__Secure-` cookie prefix.
- List every browser origin that calls the API in `AuthConfig::trusted_origin`; see [Security](/concepts/security/).
- Behind a reverse proxy, configure `advanced.ip_address` so rate limits and session metadata see real client IPs; see [Rate limiting](/concepts/rate-limit/).
- Replace `run_app_migrations` with your own migrations.
- Run more than one instance? Use [shared rate-limit storage](/concepts/rate-limit/#share-quotas) and, if you use caches or secondary storage, a shared backend ([Secondary storage](/concepts/secondary-storage/)).

Related upstream topic: [Installation](https://www.better-auth.com/docs/installation).
