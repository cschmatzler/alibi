---
title: "API key"
description: "Issue, manage, and verify scoped API credentials."
---

`ApiKeyPlugin` issues, manages, and verifies scoped API credentials.

## Setup

```bash
better-auth-rs generate --plugins api-key -o src/auth_schema.rs
```

Apply the generated schema with your migrations. The example uses the configuration and store from [installation](/installation/).

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::ApiKeyPlugin;
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(ApiKeyPlugin::builder().build())
        .build()
        .await
}
```

## Endpoints and options

Create, update, or delete keys at `/api-key/create`, `/api-key/update`, and `/api-key/delete`. Use `ApiKeyConfig` or the builder for permissions, expiration, quotas, and rate limits. Deliver the plaintext key only to its owner.

## Storage

Keys use SQL by default. `ApiKeyStorageMode::SecondaryStorage` selects a cache; `custom_storage` overrides it. API-key storage is independent of session storage.

Permanent keys require a cache with `set_without_expiry`. Secondary-only quota admission is not atomic across concurrent requests. Enable `fallback_to_database` for durable rows and guarded database admission. Cache failures can leave earlier writes in place; `defer_updates` sends secondary usage writes to the application's background-task handler.

See the [API-key storage implementation](https://github.com/cschmatzler/better-auth-rs/tree/main/crates/api/src/plugins/api_key) for custom backends.

## Frontend

See the official [API key guide](https://www.better-auth.com/docs/plugins/api-key).
