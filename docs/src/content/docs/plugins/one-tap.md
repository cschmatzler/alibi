---
title: "One Tap"
description: "Verify Google One Tap credentials on the Rust server."
---

`OneTapPlugin` verifies Google credentials and issues a session.

## Setup

Register the matching Google provider so One Tap can use its client ID:

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::oauth::OAuthProvider;
use better_auth::plugins::{OAuthPlugin, OneTapPlugin};
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
    client_id: &str,
    client_secret: &str,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(
            OAuthPlugin::new()
                .add_provider("google", OAuthProvider::google(client_id, client_secret)),
        )
        .plugin(OneTapPlugin::new())
        .build()
        .await
}
```

Credentials are submitted to `/one-tap/callback`. Set `OneTapConfig::client_id` explicitly when not deriving it from the OAuth provider. `GoogleJwksSource` allows an application-owned key source.

## Frontend

See the official [One Tap guide](https://www.better-auth.com/docs/plugins/one-tap).
