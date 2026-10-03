---
title: "Last login method"
description: "Remember which authentication method a visitor last used."
---

`LastLoginMethodPlugin` records which authentication method a visitor last used.

## Setup

Use the schema, configuration, and store from [installation](/installation/).

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::LastLoginMethodPlugin;
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(LastLoginMethodPlugin::new())
        .build()
        .await
}
```

## Endpoints and options

Configure the method cookie and optional persistence with `LastLoginMethodConfig`. For persisted user fields, generate the schema with `better-auth-rs generate --plugins last-login-method -o src/auth_schema.rs` and apply your migrations.

Use the result to guide the sign-in UI. It is a presentation hint, not evidence that a request is authenticated or allowed to access a resource.

## Frontend

See the official [Last login method guide](https://www.better-auth.com/docs/plugins/last-login-method).
