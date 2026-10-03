---
title: "JWT"
description: "Issue signed JSON Web Tokens and expose a JWKS key set."
---

`JwtPlugin` issues signed JSON Web Tokens and exposes a JWKS key set.

## Setup

Generate the plugin schema and apply it with your application migrations:

```bash
better-auth-rs generate --plugins jwt -o src/auth_schema.rs
```

Use the schema, configuration, and store from [installation](/installation/).

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::jwt::JwtPlugin;
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(JwtPlugin::new())
        .build()
        .await
}
```

## Endpoints and options

Authenticated callers request a JWT at `/token`. Services verify it with the JWKS endpoint and check issuer, audience, and expiry. Configure signing and claims with `JwtPluginConfig`.

JWTs do not replace database sessions. The [cookie-cache guide](/concepts/cookies/) explains the separate option to sign cached sessions with the local keyring.

## Frontend

See the official [JWT guide](https://www.better-auth.com/docs/plugins/jwt).
