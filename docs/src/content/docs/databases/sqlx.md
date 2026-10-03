---
title: "SQLx"
description: "Use SQLite or PostgreSQL with SQLx and AuthEntity."
---

SQLx is the default store backend and supports SQLite and PostgreSQL.

## Connect and build

Generate the schema as shown in [installation](/installation/), then connect the pool and supply the store:

```rust
use crate::auth_schema::{AppAuthSchema, run_app_migrations};
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::sqlx::{SqlxPool, SqlxStore};
use better_auth::{AuthConfig, BetterAuth};

async fn build_auth(
    secret: &str,
    database_url: &str,
) -> Result<BetterAuth<AppAuthSchema>, Box<dyn std::error::Error>> {
    let config = AuthConfig::new(secret).base_url("http://localhost:3000");
    let pool = SqlxPool::connect(database_url).await?;
    run_app_migrations(&pool).await?;
    let store = SqlxStore::<AppAuthSchema>::new(config.clone(), pool);

    Ok(BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new())
        .build()
        .await?)
}
```

`SqlxPool` selects the engine from the URL. Use `sqlx-sqlite` or `sqlx-postgres` with default features disabled to select one engine; retain a TLS feature for outbound requests.

## Existing models

Derive `sqlx::FromRow` and `better_auth::sqlx::AuthEntity` on your models. `#[auth(table = "...")]` selects a table; `#[sqlx(rename = "...")]` maps a column.

Use `DateTime<Utc>` for PostgreSQL `TIMESTAMPTZ` and `NaiveDateTime` for existing UTC `TIMESTAMP` columns. See [existing databases](/guides/existing-databases/) before changing a schema's timestamp representation.
