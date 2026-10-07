---
title: "Custom session"
description: "Reshape the /get-session response with your own application data."
---

`GET /get-session` returns the session and user. Frontends often also need data that lives elsewhere — a subscription tier, a workspace list, feature flags. `CustomSessionPlugin` runs your async transform on every `/get-session` response so the client gets everything in a single request.

The transform changes **response data only**. It does not change the authenticated principal, cookies, or what other plugins see.

## Setup

Register it **before** `SessionManagementPlugin` so it owns the `GET /get-session` route (the first plugin to register a route wins — see [Plugin concepts](/concepts/plugins/#order-matters-in-two-places)). Add `async-trait = "0.1"`:

```rust
use crate::auth_schema::AppAuthSchema;
use async_trait::async_trait;
use alibi::plugin::AuthContext;
use alibi::plugins::{CustomSessionPlugin, SessionManagementPlugin, SessionTransform};
use alibi::prelude::AuthRequest;
use alibi::sqlx::SqlxStore;
use alibi::{AuthConfig, AuthResult, BetterAuth};
use serde_json::Value;

struct AppSession;

#[async_trait]
impl SessionTransform<AppAuthSchema> for AppSession {
    async fn transform(
        &self,
        mut session: Value,
        _request: &AuthRequest,
        _context: &AuthContext<AppAuthSchema>,
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

`GET /get-session` now returns the original body with your addition:

```json
{"session":{…},"user":{…},"application":"my-app"}
```

## What the transform receives

`session` is the **public** projection — exactly the JSON `/get-session` would have returned, including configured [additional fields](/concepts/field-policies/) and `needsRefresh` during deferred refresh.

`context` gives access to the store and configuration, so you can look up data for `session["user"]["id"]`:

```rust
use crate::auth_schema::AppAuthSchema;
use async_trait::async_trait;
use alibi::plugin::AuthContext;
use alibi::plugins::SessionTransform;
use alibi::prelude::AuthRequest;
use alibi::AuthResult;
use serde_json::{Value, json};

struct WithPlan;

#[async_trait]
impl SessionTransform<AppAuthSchema> for WithPlan {
    async fn transform(
        &self,
        mut session: Value,
        request: &AuthRequest,
        context: &AuthContext<AppAuthSchema>,
    ) -> AuthResult<Value> {
        let user_id = session["user"]["id"].as_str().unwrap_or_default().to_owned();
        // Query your own tables with the same database the auth store uses,
        // or call another service here. Keep it fast: this runs on every read.
        let plan = lookup_plan(&user_id).await;
        session["plan"] = json!(plan);
        let _ = (request, context);
        Ok(session)
    }
}

async fn lookup_plan(_user_id: &str) -> &'static str {
    "pro"
}
```

Return an `AuthError` from the transform for an intentional API error; an ordinary failure produces an empty `500`.

## Options

| Method | Default | Effect |
| --- | --- | --- |
| `CustomSessionPlugin::new(transform)` | — | Install the transform |
| `.mutate_device_sessions(true)` | `false` | Also apply the transform to each entry of [`/multi-session/list-device-sessions`](/plugins/multi-session/) |

The replacement serves `GET /get-session` only — also when [deferred refresh](/concepts/session-management/#deferred-refresh) is enabled, in which case the transformed response is the `GET` body.

## Notes

- The transform runs on every session read, including cookie-cache hits. Do not put per-request cost in it; cache aggressively.
- Do not add secrets: the result is returned to the client.
- Because the client sees the extra data, update your TypeScript client types with the official `customSessionClient` plugin.

## Frontend

See the official [custom session guide](https://www.better-auth.com/docs/plugins/custom-session).
