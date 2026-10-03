---
title: "Have I Been Pwned"
description: "Check password choices against the compromised-password range API."
---

`HaveIBeenPwnedPlugin` checks password choices against the compromised-password range API.

## Setup

Use the schema, configuration, and store from [installation](/installation/).

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::{EmailPasswordPlugin, HaveIBeenPwnedPlugin};
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(HaveIBeenPwnedPlugin::new())
        .build()
        .await
}
```

## Endpoints and options

`HaveIBeenPwnedConfig` configures rejection policy and an application-owned `PwnedPasswordClient` when a custom HTTP client is needed.

The plugin checks password admission. It does not change the stored password hash format or replace the normal password verifier.

## Frontend

See the official [Have I Been Pwned guide](https://www.better-auth.com/docs/plugins/have-i-been-pwned).
