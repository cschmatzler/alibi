---
title: "Passkey"
description: "WebAuthn registration and authentication using passkeys."
---

`PasskeyPlugin` handles WebAuthn registration and authentication using passkeys.

## Setup

```bash
better-auth-rs generate --plugins passkey -o src/auth_schema.rs
```

Apply the generated schema with your migrations. The example uses the configuration and store from [installation](/installation/).

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::PasskeyPlugin;
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(
            PasskeyPlugin::new()
                .rp_id("localhost")
                .rp_name("My application")
                .origin("http://localhost:3000"),
        )
        .build()
        .await
}
```

## Endpoints and options

The relying-party ID and origin must match the browser origin used for WebAuthn. Use HTTPS outside local development.

The Rust backend generates ceremony options and verifies credentials at `/passkey/verify-registration` and `/passkey/verify-authentication`. Configure the registration and authentication callbacks when adapting ceremonies to an existing identity model.

## Frontend

See the official [Passkey guide](https://www.better-auth.com/docs/plugins/passkey).
