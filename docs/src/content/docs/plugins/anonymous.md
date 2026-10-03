---
title: "Anonymous"
description: "Create a temporary user identity before full account registration."
---

`AnonymousPlugin` creates a temporary user identity before full account registration.

## Setup

Generate the plugin schema and apply it with your application migrations:

```bash
better-auth-rs generate --plugins anonymous -o src/auth_schema.rs
```

Use the schema, configuration, and store from [installation](/installation/).

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::AnonymousPlugin;
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(AnonymousPlugin::new())
        .build()
        .await
}
```

## Endpoints and options

Start with `POST /sign-in/anonymous`. Configure linking through `AnonymousConfig` and the `LinkAnonymousAccount` callback to transfer application-owned data when the visitor adopts a permanent identity. `POST /delete-anonymous-user` supports removal of the anonymous account.

The user's anonymous state is part of the identity lifecycle; decide what temporary users can access in application authorization.

## Frontend

See the official [Anonymous guide](https://www.better-auth.com/docs/plugins/anonymous).
