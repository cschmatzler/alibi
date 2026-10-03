---
title: "One-time token"
description: "Exchange an existing session through a short-lived, single-use credential."
---

`OneTimeTokenPlugin` exchanges an existing session through a short-lived, single-use credential.

## Setup

Use the schema, configuration, and store from [installation](/installation/).

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::one_time_token::OneTimeTokenPlugin;
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(OneTimeTokenPlugin::new())
        .build()
        .await
}
```

## Endpoints and options

Import `OneTimeTokenPlugin` from `better_auth::plugins::one_time_token`. Generate a credential through `/one-time-token/generate` from an authenticated session, then consume it through `/one-time-token/verify`.

Configure expiry, generation, and storage using `OneTimeTokenConfig`. Pass the token over a trusted channel and avoid logging it. Consumption is a credential handoff, not a substitute for application authorization.

## Frontend

See the official [One-time token guide](https://www.better-auth.com/docs/plugins/one-time-token).
