---
title: "Bearer"
description: "Authenticate requests with session tokens in the Authorization header."
---

`BearerPlugin` authenticates requests with session tokens in the Authorization header.

## Setup

Use the schema, configuration, and store from [installation](/installation/).

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::BearerPlugin;
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(BearerPlugin::new())
        .build()
        .await
}
```

## Endpoints and options

Register the plugin to accept `Authorization: Bearer <session-token>` on authenticated requests. Configure signed-token policy with `BearerConfig` when needed.

A bearer session token is distinct from the [JWT plugin](/plugins/jwt/)'s signed JWT and from an [API key](/plugins/api-key/). Use the credential type required by the API you are calling.

## Frontend

See the official [Bearer guide](https://www.better-auth.com/docs/plugins/bearer).
