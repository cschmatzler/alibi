---
title: "Plugins"
description: "Compose authentication features with Rust plugins."
---

Add features with `.plugin(...)` and finish initialization with `.build().await`. Explicit core plugins replace their default configuration; extra plugins add new capabilities.

## Register a plugin

Generate and migrate the fields required by the plugin, then build the auth instance:

```bash
better-auth-rs generate --plugins admin -o src/auth_schema.rs
```

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::{AdminPlugin, EmailPasswordPlugin};
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new())
        .plugin(AdminPlugin::new())
        .build()
        .await
}
```

The builder includes default session, user, account, password, verification, and OAuth modules. Credential login remains disabled until you configure `EmailPasswordPlugin`.

Browse [native plugins](/plugins/) for setup and schema requirements. `auth.registered_routes()` and the [OpenAPI specification](/plugins/open-api/) show the initialized endpoint surface.

## Frontend

See the official [client plugin documentation](https://www.better-auth.com/docs/concepts/client#plugins).
