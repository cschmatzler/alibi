---
title: "Installation"
description: "Add Better Auth RS, generate a schema, and mount authentication routes."
---

## Add the Git dependency

Better Auth RS is distributed directly from its Git repository. Add these dependencies to an application using Rust edition 2024:

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

Pin the Git dependency to a reviewed commit with `rev = "<commit>"` when you need a reproducible revision. Install the CLI from the same revision with `--rev <commit>`.

SQLx is the default backend. See [Cargo features](/reference/features/) to select PostgreSQL, SeaORM, or a different TLS stack.

## Set environment variables

Generate a high-entropy secret with `openssl rand -base64 32`. Set the variables in your shell or load them with your application's environment loader:

```bash
export BETTER_AUTH_SECRET="$(openssl rand -base64 32)"
export BETTER_AUTH_URL="http://localhost:3000"
export DATABASE_URL="sqlite://auth.db?mode=rwc"
```

The example below reads them explicitly. Better Auth RS does not load a `.env` file for you.

## Generate the database schema

```bash
cargo install --git https://github.com/cschmatzler/better-auth-rs --locked better-auth-cli
better-auth-rs generate -o src/auth_schema.rs
```

The generated file defines user, session, account, and verification models, an `AppAuthSchema`, and `run_app_migrations`. You own this file and the application's migrations. For an existing database, see [database concepts](/concepts/database/) and [existing databases](/guides/existing-databases/).

## Create the auth instance and mount the handler

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

`/api/auth` is the default base path. Keep your router mount and `AuthConfig::base_path` aligned when changing it. `run_app_migrations` is useful for a new local database; use versioned application migrations as your schema evolves.

## Next steps

Continue to [basic usage](/basic-usage/) or [Axum integration](/integrations/axum/).

Related upstream topic: [Installation](https://www.better-auth.com/docs/installation).
