---
title: "Users & accounts"
description: "Identity, linked credentials, profile updates, and account lifecycle."
---

A user is an identity; an account is a linked password or provider credential. One user can have several accounts and sessions.

## Configure lifecycle operations

The builder includes user and account management. Replace the default user module to enable email changes:

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::UserManagementPlugin;
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(UserManagementPlugin::new().change_email_enabled(true))
        .build()
        .await
}
```

Configure verification delivery before offering email changes. Account deletion is separately enabled with `delete_user_enabled(true)` and may require delivery callbacks and application hooks.

## Linking and application data

`AuthConfig::account` controls provider-linking policies. Matching profile data does not establish account ownership.

Add application fields to your models and declare their [API policies](/concepts/field-policies/). Public account responses remove credentials; physical models and trusted hooks may still contain them.

## Frontend

See the official [users and accounts guide](https://www.better-auth.com/docs/concepts/users-accounts).
