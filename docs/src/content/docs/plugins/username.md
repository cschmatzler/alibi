---
title: "Username"
description: "Username sign-in and validation policies."
---

Username sign-in is part of `EmailPasswordPlugin`.

## Setup

```bash
better-auth-rs generate --plugins username -o src/auth_schema.rs
```

Apply the schema changes, then enable username support:

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
        .plugin(EmailPasswordPlugin::new().enable_username(true))
        .build()
        .await
}
```

## Options

Sign-in uses `/sign-in/username`; email signup also accepts a username. The default policy lowercases ASCII usernames and allows 3–30 characters.

Use `username_config` to change length bounds, normalization, validators, or input policies. Validation order depends on the selected pre/post-normalization policy; see the [username implementation](https://github.com/cschmatzler/better-auth-rs/blob/main/crates/api/src/plugins/email_password/mod.rs) for the complete options.

## Frontend

See the official [username guide](https://www.better-auth.com/docs/plugins/username).
