---
title: "Existing databases"
description: "Adopt Alibi on a database you already have: table names, timestamp types, fixed-width ids and custom id generators."
---

You do not have to let the library own your schema. If you already have `users`, `sessions` and friends, keep your migrations and describe the existing tables with your own models. This page covers the mappings that most often need attention. The core idea is in [Database](/concepts/database/): models are plain structs deriving `AuthEntity`, and `AuthSchema` names them.

## Rename tables and columns

```rust nocheck
#[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, better_auth::sqlx::AuthEntity)]
#[auth(role = "user", table = "app_users")]
pub struct UserModel {
    pub id: String,
    pub name: Option<String>,
    #[sqlx(rename = "email_address")]
    pub email: Option<String>,
    pub email_verified: bool,
    pub image: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}
```

`table = "…"` selects the table and `#[sqlx(rename = "…")]` maps a field to a differently named column. For SeaORM use `#[sea_orm(table_name = "…")]` and `#[sea_orm(column_name = "…")]`. Fields your application needs but Better Auth does not — a tenant id, a plan — can stay on the model; expose them through [additional fields](/concepts/field-policies/).

## Timestamp columns

Match the Rust timestamp type to each existing column:

| PostgreSQL column | Rust type |
| --- | --- |
| `TIMESTAMPTZ` | `chrono::DateTime<chrono::Utc>` |
| `TIMESTAMP WITHOUT TIME ZONE` | `chrono::NaiveDateTime` |
| Nullable timestamp | `Option` around the matching type |
| SQLite `TEXT`/`DATETIME` | `chrono::DateTime<chrono::Utc>` |

For example, a verification table with naive timestamps:

```rust nocheck
#[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, better_auth::sqlx::AuthEntity)]
#[auth(role = "verification", table = "verifications")]
pub struct VerificationModel {
    pub id: String,
    pub identifier: String,
    pub value: String,
    pub expires_at: chrono::NaiveDateTime,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}
```

The same mapping applies to user, session and account timestamps; select the model in your `AuthSchema` as usual.

**Naive timestamps must already represent UTC.** They are read as UTC wall-clock time and bound without an offset; the library does not convert local-time data and cannot repair values that were shifted by a previous writer. Run a one-off migration first if your `TIMESTAMP` columns hold local time.

Bundled models (the generated ones) use aware timestamps; use handwritten models for naive columns. SeaORM supports the same convention for the four core entities; plugin tables use their bundled models. If you implement the storage traits by hand, pair `SqlValue::NaiveTimestamp` with `ColumnKind::NaiveTimestamp` so predicates and writes agree.

## PostgreSQL fixed-width ids

Keep existing `CHAR(n)` columns and `String` fields. SQLx models opt each fixed-width field into PostgreSQL's `bpchar` wire type:

```rust nocheck
#[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, better_auth::sqlx::AuthEntity)]
#[auth(role = "session", table = "sessions")]
pub struct SessionModel {
    #[auth(column_type = "bpchar")]
    pub id: String,
    #[auth(column_type = "bpchar")]
    pub user_id: String,
    pub token: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub active: bool,
}
```

Apply this to every `CHAR(n)` primary id, foreign key and optional fixed-width field. Parameters and nulls are bound as `bpchar`, so indexes on those columns remain usable. Ordinary `TEXT`/`VARCHAR` fields keep text bindings, and SQLite binds the exact string as text. For handwritten implementations pair `ColumnKind::BpChar` with `SqlValue::BpChar`.

For SeaORM on PostgreSQL, write the column as `#[sea_orm(column_type = "Char(Some(30))", save_as = "bpchar")]` next to the usual primary-key attributes; omit `save_as` on SQLite.

PostgreSQL pads stored `CHAR(n)` values, ignores trailing spaces in equality and rejects overlength non-space input; the adapter never trims, pads or truncates returned strings (see PostgreSQL's [character type semantics](https://www.postgresql.org/docs/18/datatype-character.html)).

## Generate ids that fit your columns

The default id is a 36-character UUID and is never shortened. When existing columns are narrower, or you use a different id scheme, give the model an id generator:

```rust nocheck
#[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, better_auth::sqlx::AuthEntity)]
#[auth(role = "user", table = "users", id_generator = "crate::ids::user_id")]
pub struct UserModel { /* … */ }
```

```rust nocheck
pub mod ids {
    /// A 26-character, time-sortable id that fits `CHAR(26)` (uses the `ulid` crate).
    pub fn user_id() -> String {
        ulid::Ulid::new().to_string()
    }
}
```

The function must return a unique `String` and runs only when no explicit id is supplied. Both `AuthEntity` derives accept `id_generator`.

## Checklist when adopting an existing schema

1. Declare one model per role with the right `table` and column names.
2. Make every timestamp type match its column; verify UTC.
3. Add the unique indexes on `users.email` and `sessions.token` if they are missing ([Database](/concepts/database/#migrations)).
4. Generate plugin tables with `better-auth-rs generate --plugins …` and review the DDL against yours.
5. Keep application migrations in charge of the schema; do not call `run_app_migrations` against production data.
