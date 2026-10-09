---
title: "SeaORM"
description: "Use SeaORM entities for users, sessions, accounts and plugin data."
---

`SeaOrmStore` implements the same `AuthStore` contract as the SQLx store, with full feature parity: every plugin that works on SQLx works on SeaORM. Choose it when your application already uses SeaORM entities, migrations and connections.

## Dependencies

Enable the `seaorm` feature. SeaORM is re-exported as `alibi::seaorm::sea_orm`, so you do not need a separate `sea-orm` dependency for the generated code:

```toml title="Cargo.toml"
alibi = { version = "0.2.0", default-features = false, features = ["axum", "seaorm", "rustls"] }
axum = "0.8"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

If your application also depends on `sea-orm` directly, use the same `2.x` version to share types. TLS comes from `rustls` or `native-tls` ([Cargo features](/reference/features/)).

## Generate entities

```bash
alibi generate --backend seaorm -o src/auth_schema.rs
alibi generate --backend seaorm --plugins organization,two-factor -o src/auth_schema.rs
```

The file defines the four entities, an `AppAuthSchema`, and `run_app_migrations(&DatabaseConnection)`:

```rust title="src/auth_schema.rs (excerpt)" nocheck
mod user {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "user")]
    #[sea_orm(table_name = "users")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: Option<String>,
        pub email: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
```

## Connect and build

```rust seaorm
use crate::auth_schema::{AppAuthSchema, run_app_migrations};
use alibi::plugins::EmailPasswordPlugin;
use alibi::seaorm::{Database, SeaOrmStore};
use alibi::{AuthConfig, BetterAuth};

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
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .build()
        .await?)
}
```

`Database::connect` takes a SQLite (`sqlite:`) or PostgreSQL (`postgres:`) URL. To tune the pool, build `ConnectOptions` and call `Database::connect(options)` — SeaORM's `DatabaseConnection` is a cheap handle that you can share between your application and authentication.

## Use your own entities

Derive `DeriveEntityModel` and `alibi::seaorm::AuthEntity` on your model, then select it in the schema:

```rust nocheck
#[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, alibi::seaorm::AuthEntity)]
#[auth(role = "user", id_generator = "crate::ids::new_user_id")]
#[sea_orm(table_name = "app_users")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub email_verified: bool,
    pub image: Option<String>,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
    pub locale: Option<String>,
}
```

The container attributes match SQLx: `role`, `id_generator` and `secondary_storage`; the table name comes from `sea_orm(table_name)`. Required fields per role are checked at compile time.

For PostgreSQL fixed-width `CHAR(n)` ids, use `#[sea_orm(column_type = "Char(Some(30))", save_as = "bpchar")]`; omit `save_as` on SQLite. See [Existing databases](/databases/existing-databases/).

## Hooks

The hook trait is shared with SQLx; use `SeaOrmBackend`:

```rust seaorm
use crate::auth_schema::AppAuthSchema;
use async_trait::async_trait;
use alibi::prelude::CreateUser;
use alibi::seaorm::{SeaOrmBackend, SeaOrmStore};
use alibi::store::{DatabaseHookContext, DatabaseHooks, HookControl};
use alibi::AuthResult;

struct DefaultName;

#[async_trait]
impl DatabaseHooks<AppAuthSchema, SeaOrmBackend> for DefaultName {
    async fn before_create_user(
        &self,
        user: &mut CreateUser,
        _: &DatabaseHookContext<'_, SeaOrmBackend>,
    ) -> AuthResult<HookControl> {
        user.name.get_or_insert_with(|| "New user".into());
        Ok(HookControl::Continue)
    }
}

fn hooked(store: SeaOrmStore<AppAuthSchema>) -> SeaOrmStore<AppAuthSchema> {
    store.hook(DefaultName)
}
```

See [Hooks](/concepts/hooks/).

## Migrations

`run_app_migrations` creates the generated entities with `Schema::create_table_from_entity` — convenient for new databases and tests. In production, keep migrations in your `sea-orm-migration` crate. The store can also install the library's bundled schema (all plugin tables with keys and indexes) through `SchemaMigrator::migrate`; see [Database](/concepts/database/#migrations). Rate-limit storage in the database has its own entity and migrator: `alibi::seaorm::SeaOrmRateLimitStorage` ([Rate limiting](/concepts/rate-limit/#share-quotas)).

## Frontend

See the official [database guide](https://www.better-auth.com/docs/concepts/database).
