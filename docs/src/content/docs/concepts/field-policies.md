---
title: "Additional fields"
description: "Add your own columns to users, sessions and accounts, and control input, storage and output."
---

You can add columns to the user, session and account models and have them flow through the API: accepted at sign-up and in `/update-user`, stored by the adapter, and returned in session and user responses. Each field has a **policy** that decides who may write it and who sees it.

Adding a field takes two steps — a column and a policy.

## 1. Add the column

Add a field to your model and a column to the table (and a migration):

```rust nocheck
#[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::AuthEntity)]
#[auth(role = "user", table = "users")]
pub struct User {
    pub id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub email_verified: bool,
    pub image: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub locale: Option<String>, // new
    pub plan: Option<String>,   // new
}
```

```sql
ALTER TABLE users ADD COLUMN locale TEXT;
ALTER TABLE users ADD COLUMN plan TEXT;
```

## 2. Declare the policy

Policies live on `AuthConfig` and must be set before the store is created:

```rust
use alibi::AuthConfig;
use alibi::field_policy::FieldConfig;
use serde_json::json;

fn auth_config(secret: &str) -> AuthConfig {
    let mut config = AuthConfig::new(secret);
    // Writable by the user; defaults to "en".
    config.user.additional_fields.insert(
        "locale".into(),
        FieldConfig::new(json!({ "type": "string" })).default_value(json!("en")),
    );
    // Visible to the user but only writable by the server.
    config.user.additional_fields.insert(
        "plan".into(),
        FieldConfig::new(json!({ "type": "string" }))
            .read_only()
            .default_value(json!("free")),
    );
    config
}
```

Session and account fields use `config.session.additional_fields` and `config.account.additional_fields`.

The behavior, against a real instance:

```bash
# sign-up: locale accepted, default applied for plan, unknown keys ignored
curl … /sign-up/email -d '{"name":"B","email":"b@example.com","password":"…","locale":"de"}'
# {"token":"…","user":{"id":"…","name":"B","email":"b@example.com",…,"locale":"de","plan":"free"}}

# update-user: read-only field is rejected
curl -b cookies.txt … /update-user -d '{"plan":"pro"}'
# 400 {"code":"FIELD_NOT_ALLOWED","message":"plan is not allowed to be set"}

curl -b cookies.txt … /update-user -d '{"locale":"fr"}'
# {"status":true}
```

## Policy reference

`FieldConfig::new(schema)` takes a JSON schema fragment describing the type (used for validation metadata and the [OpenAPI](/plugins/open-api/) output) and chains the options below:

| Method | Effect |
| --- | --- |
| `.default_value(value)` / `.default_callback(fn)` | Value used when the client omits the field on creation |
| `.read_only()` | Reject client writes (`FIELD_NOT_ALLOWED` on updates; ignored at sign-up). The server can still write it — through [hooks](/concepts/hooks/), plugins or your own queries |
| `.hidden()` | Never include the field in public responses |
| `.validate(fn)` | Synchronous validator and normalizer for client input: `Fn(&JsValue) -> Result<JsValue, String>` |
| `.transform(fn)` | Transform input before storage: `Fn(Option<&JsValue>) -> AuthResult<Option<JsValue>>` |
| `.transform_adapter_input(async fn)` | Awaited just before the database write (encryption, lookups) |
| `.transform_output(async fn)` | Awaited when reading from the database (decryption, formatting) |
| `.on_update(fn)` | Value computed on every update (for example a "last seen" stamp) |
| `.field_name("column")` | Map the logical name to a differently named physical column |

Asynchronous endpoint validation (`validate_async`) is rejected during request parsing, matching the pinned runtime; use an adapter transform or a hook for I/O.

```rust
use alibi::AuthConfig;
use alibi::field_policy::FieldConfig;
use serde_json::json;

fn auth_config(secret: &str) -> AuthConfig {
    let mut config = AuthConfig::new(secret);
    config.user.additional_fields.insert(
        "timezone".into(),
        FieldConfig::new(json!({ "type": "string" }))
            .field_name("tz") // physical column is `tz`
            .default_value(json!("UTC"))
            .validate(|value| match value.as_str() {
                Some(zone) if zone.contains('/') || zone == "UTC" => Ok(value.clone()),
                _ => Err("timezone must be an IANA name such as Europe/Berlin".into()),
            }),
    );
    config
}
```

## What is exposed where

| Surface | Includes hidden fields? | Notes |
| --- | --- | --- |
| Public responses (`/get-session`, `/sign-in/*`, `/sign-up/*`) | No | Governed by `.hidden()` |
| Cached sessions ([cookie cache](/concepts/cookies/)) | No | Caches keep the public policy |
| Account responses (`/list-accounts`) | No | Tokens and password hashes are always removed |
| `AdapterRecord` snapshots in hooks and callbacks | **Yes** | Trusted server-side data; never forward it to a client |
| Your own handlers (`CurrentSession`) | Yes | You receive the full model |

Because the extractors return your own model, you can read additional fields directly (`session.user.plan`); public output remains filtered.

## Plugin fields

Plugins register their own fields through the same mechanism — for example `username`, `role` and `banned` (admin), `twoFactorEnabled`, `phoneNumber`. Generate the columns with `--plugins` ([Database](/concepts/database/#plugin-schema)); you do not declare their policies yourself.
