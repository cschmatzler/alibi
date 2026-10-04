---
title: "Username"
description: "Sign in with a username, with configurable validation, normalization and display names."
---

Username support is part of `EmailPasswordPlugin`: it adds `username` and `displayUsername` to the user, a sign-in route and an availability check. Users still have an email address; the username is an additional identifier.

## Schema

```bash
better-auth-rs generate --plugins username -o src/auth_schema.rs
```

This adds `users.username` and `users.display_username` (both nullable). Apply the migration, then enable the feature:

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new().enable_signup(true).enable_username(true))
        .build()
        .await
}
```

## Endpoints

| Method | Path | Body | Result |
| --- | --- | --- | --- |
| `POST` | `/sign-up/email` | the usual fields plus `username`, `displayUsername` | Creates the user with a username |
| `POST` | `/sign-in/username` | `username`, `password`, optional `rememberMe`, `callbackURL` | Same response as `/sign-in/email` |
| `POST` | `/is-username-available` | `{"username":"ada"}` | `{"available":true}` |
| `POST` | `/update-user` | `username`, `displayUsername` | Change the username (unless `immutable_username`) |

```bash
curl -i -c cookies.txt http://localhost:3000/api/auth/sign-up/email \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"name":"Ada","email":"ada@example.com","password":"a-long-example-password","username":"Ada_L","displayUsername":"Ada L."}'

curl -i -c cookies.txt http://localhost:3000/api/auth/sign-in/username \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"username":"ada_l","password":"a-long-example-password"}'
```

The stored `username` is the **normalized** form (`ada_l`); `displayUsername` keeps the text the user typed (`Ada L.`). Lookups always normalize their input, so `ADA_L`, `Ada_L` and `ada_l` all find the same user. Errors include `USERNAME_IS_ALREADY_TAKEN`, `USERNAME_TOO_SHORT`, `USERNAME_TOO_LONG`, `INVALID_USERNAME` and `INVALID_USERNAME_OR_PASSWORD`.

## Default policy

| Rule | Default |
| --- | --- |
| Length | 3–30 UTF-16 code units |
| Characters | ASCII letters, digits, `_` and `.` |
| Normalization | Lowercase |
| Display name | Stored as typed, if `include_display_username` |
| Changeable | Yes |

## Customize the policy

Configure `UsernameConfig` with `username_config`:

```rust
use async_trait::async_trait;
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::plugins::email_password::{
    UsernameConfig, UsernameNormalization, UsernameValidationOrder, UsernameValidator,
};
use better_auth::AuthResult;
use std::sync::Arc;

struct NoReservedNames;

#[async_trait]
impl UsernameValidator for NoReservedNames {
    async fn validate(&self, value: &str) -> AuthResult<bool> {
        let syntactically_ok = value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        let reserved = ["admin", "root", "support"];
        Ok(syntactically_ok && !reserved.contains(&value.to_lowercase().as_str()))
    }
}

fn email_password() -> EmailPasswordPlugin {
    EmailPasswordPlugin::new()
        .enable_signup(true)
        .enable_username(true)
        .username_config(UsernameConfig {
            min_length: 4,
            max_length: 20,
            normalization: UsernameNormalization::Lowercase,
            validator: Some(Arc::new(NoReservedNames)),
            validation_order: Some(UsernameValidationOrder::PostNormalization),
            immutable_username: true,
            ..Default::default()
        })
}
```

| `UsernameConfig` field | Default | Meaning |
| --- | --- | --- |
| `min_length`, `max_length` | 3, 30 | Length bounds; `0` selects the default |
| `normalization` | `Lowercase` | `Lowercase`, `Preserve`, or `Custom(Arc<dyn UsernameNormalizer>)` |
| `validator` | none | Replace the character rule with your own `UsernameValidator` |
| `validation_order` | pre-normalization | Validate the raw input or the normalized value |
| `include_display_username` | `true` | Store a display name |
| `display_normalizer`, `display_validator`, `display_validation_order` | none | Same hooks for the display name |
| `immutable_username` | `false` | Reject changes after creation |
| `input` | `true` | Admit usernames from endpoint callers (set `false` to assign them only on the server) |

Validation order matters when normalization changes the string: with the default (pre-normalization) a validator sees `Ada_L`, with `PostNormalization` it sees `ada_l`.

## With other plugins

- [Admin](/plugins/admin/): `create-user` and `update-user` validate and normalize usernames with the same rules.
- [Email OTP](/plugins/email-otp/) and [phone number](/plugins/phone-number/) sign-ups accept `username` too, running the same transform stages.
- Usernames are unique case-insensitively through normalization; add a unique index on `users.username` ([Database](/concepts/database/#migrations)).

## Frontend

See the official [username guide](https://www.better-auth.com/docs/plugins/username).
