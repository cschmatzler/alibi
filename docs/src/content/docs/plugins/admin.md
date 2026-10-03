---
title: "Admin"
description: "Administrative user management, bans, impersonation, and role-based permissions."
---

`AdminPlugin` provides administrative user management, bans, impersonation, and role-based permissions.

## Setup

```bash
better-auth-rs generate --plugins admin -o src/auth_schema.rs
```

Apply the generated schema with your migrations. The example uses the configuration and store from [installation](/installation/).

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::AdminPlugin;
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(AdminPlugin::new())
        .build()
        .await
}
```

## Endpoints and options

Configure `AdminConfig` and `RolePermissions` for your application. Protect administrative operations with the plugin's permission policies; hiding an admin page is not an authorization check.

Use the configured OpenAPI specification for the active user-management and session endpoints. Ban fields and role data belong to your application schema.

## Frontend

See the official [Admin guide](https://www.better-auth.com/docs/plugins/admin).
