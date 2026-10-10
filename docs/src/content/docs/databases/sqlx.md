---
title: "SQLx"
description: "Use SQLite or PostgreSQL through SQLx: connection, pools, models, hooks and migrations."
---

SQLx is the default store backend. `SqlxStore` supports SQLite and PostgreSQL and works with the generated models or your own `AuthEntity` models.

## Dependencies

SQLx is enabled by the default `sqlx` feature. To pick one engine, disable default features and select `sqlx-sqlite` or `sqlx-postgres`; keep a TLS feature (`native-tls` or `rustls`) for outbound HTTP:

```toml title="Cargo.toml"
alibi = { version = "0.4.0", default-features = false, features = ["axum", "sqlx-postgres", "rustls"] }
sqlx = { version = "0.9", default-features = false, features = ["postgres", "chrono", "json", "derive"] }
```

The generated models derive from `sqlx::FromRow`, so your application depends on `sqlx` with the `chrono`, `json` and `derive` features and the engine you use. See [Cargo features](/reference/features/).

## Connect and build

`SqlxPool::connect` selects the engine from the URL scheme (`sqlite:` or `postgres:` / `postgresql:`):

```rust
use crate::auth_schema::{AppAuthSchema, run_app_migrations};
use alibi::plugins::EmailPasswordPlugin;
use alibi::sqlx::{SqlxPool, SqlxStore};
use alibi::{AuthConfig, Alibi};

async fn build_auth(
    secret: &str,
    database_url: &str,
) -> Result<Alibi<AppAuthSchema>, Box<dyn std::error::Error>> {
    let config = AuthConfig::new(secret).base_url("http://localhost:3000");
    let pool = SqlxPool::connect(database_url).await?;
    run_app_migrations(&pool).await?;
    let store = SqlxStore::<AppAuthSchema>::new(config.clone(), pool);

    Ok(Alibi::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .build()
        .await?)
}
```

Always pass the same `AuthConfig` to the store and the builder: the store applies [field policies](/concepts/field-policies/) and session settings from it.

## Share your application's pool

Better Auth runs on the pool you give it, so you can tune connection limits and share one pool between your application and authentication. Wrap an existing `sqlx` pool with `SqlxPool::from` and read it back with `as_postgres()` / `as_sqlite()`:

```rust
use alibi::sqlx::SqlxPool;
use sqlx::postgres::PgPoolOptions;

async fn shared_pool(url: &str) -> Result<(SqlxPool, sqlx::PgPool), sqlx::Error> {
    let pg = PgPoolOptions::new()
        .max_connections(20)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(url)
        .await?;
    let auth_pool = SqlxPool::from(pg.clone()); // pools are reference-counted handles
    Ok((auth_pool, pg))
}
```

Auth writes that must be atomic (sign-up, session issuance, organization changes) run in transactions on this pool.

For organization plugin tables, bind three application models with `OrganizationModels`; see [application-owned organization tables](/plugins/organization/#application-owned-sqlx-tables).

## Use your own models

Derive `sqlx::FromRow` and `alibi::sqlx::AuthEntity` on structs that contain the required fields for their role (user, session, account, verification). Extra columns are allowed:

```rust nocheck
#[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::AuthEntity)]
#[auth(role = "session", table = "app_sessions")]
pub struct Session {
    pub id: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub token: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub user_id: String,
    pub active: bool,
}
```

| Attribute | Where | Meaning |
| --- | --- | --- |
| `#[auth(role = "…")]` | struct | `user`, `session`, `account` or `verification` |
| `#[auth(table = "…")]` | struct | Table name (default `users`, `sessions`, `accounts`, `verifications`) |
| `#[auth(id_generator = "path::to::fn")]` | struct | Application ID factory returning a `String` |
| `#[auth(secondary_storage)]` | struct | Allow [secondary-storage](/concepts/secondary-storage/) snapshots |
| `#[sqlx(rename = "…")]` | field | Column name |
| `#[auth(column_type = "bpchar")]` | field | PostgreSQL wire type for fixed-width `CHAR(n)` columns |

Select the models in an `AuthSchema` (the generated file does this for you):

```rust nocheck
pub struct AppAuthSchema;
impl alibi::AuthSchema for AppAuthSchema {
    type User = user::Model;
    type Session = session::Model;
    type Account = account::Model;
    type Verification = verification::Model;
}
```

Timestamps: use `DateTime<Utc>` for SQLite and PostgreSQL `TIMESTAMPTZ`; use `NaiveDateTime` for an existing PostgreSQL `TIMESTAMP` column that already stores UTC. See [Existing databases](/databases/existing-databases/).

## Hooks

Wrap the store to observe or veto writes. In the hook, `ctx.db` is the pool and `ctx.tx` the active transaction:

```rust
use crate::auth_schema::AppAuthSchema;
use async_trait::async_trait;
use alibi::sqlx::{SqlxBackend, SqlxStore};
use alibi::store::{DatabaseHookContext, DatabaseHooks, HookControl};
use alibi::prelude::{AuthUser, CreateUser};
use alibi::AuthResult;

struct RejectReserved;

#[async_trait]
impl DatabaseHooks<AppAuthSchema, SqlxBackend> for RejectReserved {
    async fn before_create_user(
        &self,
        user: &mut CreateUser,
        _: &DatabaseHookContext<'_, SqlxBackend>,
    ) -> AuthResult<HookControl> {
        let reserved = user.email.as_deref().is_some_and(|email| email.starts_with("admin@"));
        Ok(if reserved { HookControl::Cancel } else { HookControl::Continue })
    }
}

fn hooked(store: SqlxStore<AppAuthSchema>) -> SqlxStore<AppAuthSchema> {
    store.hook(RejectReserved)
}
```

More in [Hooks](/concepts/hooks/).

## Migrations

`run_app_migrations(&pool)` creates the generated tables once. For real deployments use versioned migrations and consider the library's [bundled schema](/concepts/database/#migrations) (`SchemaMigrator::migrate`) or its reference DDL as a source. Plugin tables (two-factor, passkey, API keys, JWKS, organizations, …) are included in the generated schema when you pass `--plugins`.

SQLite note: SQLite has no native `TIMESTAMPTZ`; timestamps are stored as UTC text and compared accordingly.

## Frontend

See the official [database guide](https://www.better-auth.com/docs/concepts/database).
