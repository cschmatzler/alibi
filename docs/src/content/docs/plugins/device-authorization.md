---
title: "Device authorization"
description: "Authorize a CLI or constrained device through a browser on another device."
---

`DeviceAuthorizationPlugin` lets a user authorize a CLI or constrained device from another device.

## Setup

```bash
better-auth-rs generate --plugins device-authorization -o src/auth_schema.rs
```

Apply the generated schema with your migrations. The example uses the configuration and store from [installation](/installation/).

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::DeviceAuthorizationPlugin;
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(DeviceAuthorizationPlugin::new().verification_uri("http://localhost:3000/device"))
        .build()
        .await
}
```

## Endpoints and options

The device starts at `POST /device/code`, shows the verification URL and user code, then polls `POST /device/token` using the issued interval. An authenticated user approves or denies the request through `/device/approve` or `/device/deny`.

Validate client identifiers with the plugin's `validate_client` callback. The configured verification URI identifies the application's approval page. Respect pending, expiry, and slowdown responses when implementing the device client.

## Frontend

See the official [Device authorization guide](https://www.better-auth.com/docs/plugins/device-authorization).
