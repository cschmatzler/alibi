---
title: "Custom session"
description: "Project session output into application response data."
---

`CustomSessionPlugin` changes the JSON returned by GET `/get-session`. Register it before `SessionManagementPlugin` so it owns that route.

## Setup

Add `async-trait = "0.1"`. This example adds an application label to the public session response:

```rust
use crate::auth_schema::AppAuthSchema;
use async_trait::async_trait;
use better_auth::plugin::AuthContext;
use better_auth::plugins::{CustomSessionPlugin, SessionManagementPlugin, SessionTransform};
use better_auth::prelude::AuthRequest;
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};
use serde_json::Value;

struct AppSession;

#[async_trait]
impl SessionTransform<AppAuthSchema> for AppSession {
    async fn transform(
        &self,
        mut session: Value,
        _: &AuthRequest,
        _: &AuthContext<AppAuthSchema>,
    ) -> AuthResult<Value> {
        session["application"] = Value::String("my-app".into());
        Ok(session)
    }
}

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(CustomSessionPlugin::new(AppSession))
        .plugin(SessionManagementPlugin::new())
        .build()
        .await
}
```

## Options

`mutate_device_sessions(true)` applies the transform to multi-session entries too. The transform changes response data, not the authenticated principal. The replacement accepts GET only, even when deferred refresh is enabled.

## Frontend

See the official [custom session guide](https://www.better-auth.com/docs/plugins/custom-session).
