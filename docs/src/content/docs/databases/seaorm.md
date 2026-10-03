---
title: "SeaORM"
description: "Use application-owned SeaORM entities for authentication."
---

SeaORM uses the same `AuthStore` contract as SQLx.

## Generate entities

```toml
better-auth = { git = "https://github.com/cschmatzler/better-auth-rs", default-features = false, features = ["axum", "seaorm", "rustls"] }
```

```bash
better-auth-rs generate --backend seaorm -o src/auth_schema.rs
```

Add `serde`, `serde_json`, and `chrono` as in [installation](/installation/). The example installs generated tables for a new database. Use versioned application migrations as your schema evolves.

## Connect and build

```rust
use crate::auth_schema::{AppAuthSchema, run_app_migrations};
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::seaorm::{Database, SeaOrmStore};
use better_auth::{AuthConfig, BetterAuth};

async fn build_auth(
    secret: &str,
    database_url: &str,
) -> Result<BetterAuth<AppAuthSchema>, Box<dyn std::error::Error>> {
    let config = AuthConfig::new(secret).base_url("http://localhost:3000");
    let database = Database::connect(database_url).await?;
    run_app_migrations(&database).await?;
    let store = SeaOrmStore::<AppAuthSchema>::new(config.clone(), database);

    Ok(BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new())
        .build()
        .await?)
}
```

For existing entities, derive `DeriveEntityModel` and `better_auth::seaorm::AuthEntity`, then select them in `AuthSchema`. Use `SchemaMigrator` only when installing the bundled schema. See [existing databases](/guides/existing-databases/) for UTC timestamp conventions.
