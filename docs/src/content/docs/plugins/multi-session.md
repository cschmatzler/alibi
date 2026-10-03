---
title: "Multi-session"
description: "Keep multiple signed-in identities on one browser or device."
---

`MultiSessionPlugin` keeps multiple signed-in identities on one browser or device.

## Setup

Use the schema, configuration, and store from [installation](/installation/).

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::MultiSessionPlugin;
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(MultiSessionPlugin::new())
        .build()
        .await
}
```

## Endpoints and options

The plugin keeps a device's session collection and exposes `/multi-session/list-device-sessions`, `/multi-session/set-active`, and `/multi-session/revoke`.

This is account switching on one device. To list a user's sessions across devices, use [session management](/concepts/session-management/). Configure bounds and behavior with `MultiSessionConfig`.

## Frontend

See the official [Multi-session guide](https://www.better-auth.com/docs/plugins/multi-session).
