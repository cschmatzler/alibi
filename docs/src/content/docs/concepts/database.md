---
title: "Database"
description: "Application-owned auth models, the generated schema, plugin tables and migrations."
---

Alibi does not impose a database layer. You own four model structs — user, session, account and verification — and tell the library about them through an `AuthSchema`. The store (SQLx or SeaORM) maps those models to tables; plugins that need extra tables bring their own.

| Role | Table (default) | Holds |
| --- | --- | --- |
| User | `users` | Identity and profile |
| Session | `sessions` | Session token, expiry, owner, client metadata |
| Account | `accounts` | Password hash or OAuth credentials for one provider |
| Verification | `verifications` | Time-limited proofs: reset tokens, OTP codes, magic links, OAuth state |

A user has many accounts (one per sign-in method) and many sessions.

## Generate a schema

```bash
alibi generate -o src/auth_schema.rs                       # SQLx, core models
alibi generate --backend seaorm -o src/auth_schema.rs      # SeaORM entities
alibi generate --plugins username,admin,two-factor -o src/auth_schema.rs
```

The output contains the four models, an `AppAuthSchema`, and — for SQLx — `run_app_migrations`:

```rust title="src/auth_schema.rs (excerpt)" nocheck
pub mod user {
    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::AuthEntity)]
    #[auth(role = "user", table = "users")]
    pub struct Model {
        pub id: String,
        pub name: Option<String>,
        pub email: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        pub created_at: chrono::DateTime<chrono::Utc>,
        pub updated_at: chrono::DateTime<chrono::Utc>,
    }
}
// … session, account, verification …

pub struct AppAuthSchema;
impl AuthSchema for AppAuthSchema {
    type User = user::Model;
    type Session = session::Model;
    type Account = account::Model;
    type Verification = verification::Model;
}
```

Include it with `mod auth_schema;` and use `AppAuthSchema` as the type parameter of `BetterAuth`, `SqlxStore` and every extractor. Regenerate whenever you add a plugin that needs columns, review the diff, and write the matching migration. See the [CLI reference](/reference/cli/) for all flags.

## Plugin schema

Pass the plugins whose storage you need with `--plugins` (comma separated, or `all`):

| `--plugins` value | Adds | Used by |
| --- | --- | --- |
| `username` | `users.username`, `users.display_username` | [Username](/plugins/username/) |
| `two-factor` | `users.two_factor_enabled`, table `two_factor` | [Two-factor](/plugins/two-factor/) |
| `admin` | `users.role`, `banned`, `ban_reason`, `ban_expires`, `metadata`; `sessions.impersonated_by` | [Admin](/plugins/admin/) |
| `anonymous` | `users.is_anonymous` | [Anonymous](/plugins/anonymous/) |
| `phone-number` | `users.phone_number`, `users.phone_number_verified` | [Phone number](/plugins/phone-number/) |
| `last-login-method` | `users.last_login_method` | [Last login method](/plugins/last-login-method/) |
| `device-authorization` | table `device_code` | [Device authorization](/plugins/device-authorization/) |
| `api-key` | table `api_keys` | [API key](/plugins/api-key/) |
| `passkey` | table `passkeys` | [Passkey](/plugins/passkey/) |
| `jwt` | table `jwks` | [JWT](/plugins/jwt/) |
| `siwe` | table `wallet_address` | [Sign in with Ethereum](/plugins/siwe/) |
| `organization` | tables `organization`, `member`, `invitation`; `sessions.active_organization_id` | [Organization](/plugins/organization/) |
| `organization-teams` | tables `team`, `team_member`; `sessions.active_team_id` | Organization [teams](/plugins/organization/#teams) |
| `organization-dynamic-roles` | table `organization_role` | Organization [dynamic roles](/plugins/organization/#dynamic-roles) |

Plugins not listed (bearer, CAPTCHA, magic link, email OTP, one-time token, OAuth popup/proxy, One Tap, multi-session, OpenAPI, custom session, compromised-password check) store their state in the `verifications` table or in cookies and need no schema changes.

## Migrations

There are three ways to create the tables; pick one per environment.

**Bootstrap (`run_app_migrations`).** The generated function runs `CREATE TABLE IF NOT EXISTS` for the selected models. It is convenient for a new local database and tests, but it creates bare tables — no foreign keys and no indexes.

**Bundled schema (`SchemaMigrator`).** The SQLx and SeaORM stores can install the library's complete schema — every plugin's columns and tables with foreign keys and indexes — and record it in a `better_auth_migrations` ledger. Use it with models that map the whole schema (`generate --plugins all`):

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::AuthConfig;
use alibi::sqlx::{SqlxPool, SqlxStore};
use alibi::store::SchemaMigrator;

async fn migrate(config: AuthConfig, pool: SqlxPool) -> alibi::AuthResult<()> {
    let store = SqlxStore::<AppAuthSchema>::new(config, pool);
    store.migrate().await // idempotent; fails if the ledger lists an unknown version
}
```

**Your own migrations.** For production, keep migrations in the tool you already use and treat the generated schema as a starting point. At minimum, add:

```sql
CREATE UNIQUE INDEX idx_users_email ON users (email);
CREATE UNIQUE INDEX idx_sessions_token ON sessions (token);
CREATE INDEX idx_sessions_user_id ON sessions (user_id);
CREATE INDEX idx_accounts_user_id ON accounts (user_id);
CREATE INDEX idx_accounts_provider_account ON accounts (provider_id, account_id);
CREATE INDEX idx_verifications_identifier ON verifications (identifier);
```

The library's reference DDL lives in [`crates/sqlx/migrations`](https://github.com/cschmatzler/better-auth-rs/tree/main/crates/sqlx/migrations).

:::tip
Rate-limit storage in the database has its own table and ledger, separate from the auth schema. See [Rate limiting](/concepts/rate-limit/#share-quotas).
:::

## Handwritten models

Models are ordinary structs deriving `AuthEntity` (`alibi::sqlx::AuthEntity` or `alibi::seaorm::AuthEntity`). Required fields depend on the role; extra columns of your own are allowed and surface through [additional fields](/concepts/field-policies/).

```rust nocheck
#[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::AuthEntity)]
#[auth(role = "user", table = "app_users")]
pub struct User {
    pub id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub email_verified: bool,
    pub image: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub locale: Option<String>, // your own column
}
```

Container attributes on the model:

| Attribute | Meaning |
| --- | --- |
| `role = "user" \| "session" \| "account" \| "verification"` | Which auth role this model plays (required) |
| `table = "…"` | Table name (SQLx; SeaORM uses `sea_orm(table_name)`) |
| `id_generator = "path::to::fn"` | Application function returning a unique `String` ID; the default is a 36-character UUID |
| `secondary_storage` | Allow the model to be cached in [secondary storage](/concepts/secondary-storage/) |

Per-field `#[sqlx(rename = "…")]` maps a column name, and `#[auth(column_type = "bpchar")]` selects a PostgreSQL wire type. Timestamp and fixed-width column conventions for existing databases are covered in [Existing databases](/databases/existing-databases/).

## Where to go next

- Store setup: [SQLx](/databases/sqlx/) or [SeaORM](/databases/seaorm/).
- Reacting to writes: [Hooks](/concepts/hooks/).
- Keeping everything in memory: [No database](/databases/no-database/).
