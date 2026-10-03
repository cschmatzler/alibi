---
title: "Device authorization"
description: "Authorize a CLI or constrained device through a browser on another device."
---

`DeviceAuthorizationPlugin` lets a user authorize a CLI or constrained device from another device.

With `AuthBuilder::without_database`, device codes live in the built-in store for that auth instance. Restarting or creating a new instance loses pending and approved codes. Use a durable application store when grants must survive a restart.

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

Approval and denial validate the pending grant and its claimed owner before updating it. As in Better Auth 1.7.6, overlapping decisions that both read a pending grant can both succeed; the last completed store write determines its state. A later decision that reads an already processed grant is rejected. Redemption still consumes the grant only once.

Validate client identifiers with the plugin's `validate_client` callback. The configured verification URI identifies the application's approval page. Respect pending, expiry, and slowdown responses when implementing the device client.

## Frontend

See the official [Device authorization guide](https://www.better-auth.com/docs/plugins/device-authorization).
