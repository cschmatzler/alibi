---
title: "Email & password"
description: "Configure password signup, sign-in, and related account flows."
---

`EmailPasswordPlugin` enables password signup and sign-in. Session, password-reset, and account-management modules are already included by the builder.

## Setup

Use the generated schema and store from [installation](/installation/):

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
        .plugin(
            EmailPasswordPlugin::new()
                .enable_signup(true)
                .password_min_length(12),
        )
        .build()
        .await
}
```

Signup uses `/sign-up/email`; sign-in uses `/sign-in/email`. See [basic usage](/basic-usage/) for requests.

## Options

Use `auto_sign_in(false)` to require sign-in after signup, or [require email verification](/authentication/email-verification/) before issuing sessions. [Username sign-in](/plugins/username/) is configured on the same plugin.

The default hasher is `ScryptHasher`. Supply a `PasswordHasher` through `password_hasher` when using an existing credential format. Password-reset delivery is configured through `PasswordManagementPlugin`.

## Frontend

See the official [email/password guide](https://www.better-auth.com/docs/authentication/email-password).
