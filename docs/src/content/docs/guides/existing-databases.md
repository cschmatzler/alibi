---
title: "Existing databases"
description: "Use your existing PostgreSQL timestamp columns and application migrations."
---

Keep your application's migrations and match the Rust timestamp type to each existing column:

| PostgreSQL column | Rust type |
| --- | --- |
| `TIMESTAMPTZ` | `chrono::DateTime<chrono::Utc>` |
| `TIMESTAMP WITHOUT TIME ZONE` | `chrono::NaiveDateTime` |
| Nullable timestamp | `Option` around the matching type |

For example, an existing verification table with naive timestamps can use:

```rust
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

Select this model in your application's `AuthSchema`; see [database concepts](/concepts/database/). The same mapping applies to user, session, and account timestamps.

Naive timestamps must already represent UTC wall-clock time. Generated accessors interpret them as UTC, and writes bind them without an offset. This does not convert local-time data or repair previously shifted values.

Bundled models use aware timestamps. Use custom rows for existing PostgreSQL `TIMESTAMP` columns. For handwritten SQLx implementations, pair `SqlValue::NaiveTimestamp` with `ColumnKind::NaiveTimestamp` so predicates and writes agree. SeaORM supports the same naive UTC convention; plugin tables use their bundled models.

## PostgreSQL fixed-width IDs

Keep existing `CHAR(n)` columns and `String` fields. SQLx models opt into PostgreSQL's `bpchar` wire type on each fixed-width field:

```rust
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

Apply this to all `CHAR(n)` primary IDs, foreign keys, and optional fixed-width fields. Parameters and nulls use `bpchar`, leaving indexed columns unchanged. Handwritten implementations pair `ColumnKind::BpChar` with `SqlValue::BpChar`. Ordinary `TEXT`/`VARCHAR` fields retain text bindings; SQLite binds the exact string as text.

Both entity derives also accept `id_generator = "path::to::function"` on the model. Supply an application function returning a unique `String` that fits your existing columns. It runs only when no explicit ID is supplied; the default UUID is 36 characters and is never shortened automatically.

For SeaORM PostgreSQL fields, use `column_type = "Char(Some(30))", save_as = "bpchar"` alongside the usual primary-key attributes. The cast applies to parameters, preserving indexes. Omit `save_as` on SQLite/MySQL models.

PostgreSQL pads stored `CHAR(n)` values, ignores trailing spaces in equality, and rejects overlength non-space input. The adapter does not trim, pad, or truncate returned strings. See [PostgreSQL character semantics](https://www.postgresql.org/docs/18/datatype-character.html). Keep application migrations in charge of existing schemas.
