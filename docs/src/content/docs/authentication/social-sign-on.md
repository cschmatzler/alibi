---
title: "Social sign-on"
description: "Register OAuth providers in Rust."
---

`OAuthPlugin` adds social sign-in. Provider credentials stay on the server.

## Setup

Pass your provider credentials to this function alongside the configured store:

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::OAuthPlugin;
use better_auth::plugins::oauth::OAuthProvider;
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
        .build()
        .await
}
```

## Provider configuration

Register your public callback URL with Google, for example `https://auth.example.com/api/auth/callback/google`. The provider name, base URL, and auth mount must match the server configuration.

Sign-in starts at `/sign-in/social` with a `provider` and `callbackURL`. Add more providers with additional `add_provider` calls. `AuthConfig::account` controls linking policies; review them before allowing automatic account linking.

## Frontend

See the official [social sign-on guide](https://www.better-auth.com/docs/authentication/social-sign-on).
