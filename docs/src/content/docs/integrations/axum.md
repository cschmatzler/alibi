---
title: "Axum"
description: "Mount authentication routes and protect application handlers."
---

Enable the `axum` feature and mount the auth router at its configured base path. This example also protects `/profile` with a session extractor:

```rust
use crate::auth_schema::AppAuthSchema;
use axum::{Router, routing::get};
use better_auth::BetterAuth;
use better_auth::integrations::axum::{AxumIntegration, CurrentSession};
use better_auth::prelude::AuthUser;
use std::sync::Arc;

async fn profile(session: CurrentSession<AppAuthSchema>) -> String {
    format!("Hello, {}", session.user.id())
}

fn router(auth: Arc<BetterAuth<AppAuthSchema>>) -> Router {
    Router::new()
        .nest("/api/auth", auth.clone().axum_router())
        .route("/profile", get(profile))
        .with_state(auth)
}
```

`CurrentSession` returns HTTP 401 when no valid session exists. Use `OptionalSession` for routes that also serve anonymous visitors.

## Application state

If your application has its own state, implement `FromRef` so the auth instance and session extractors can read it:

```rust
use crate::auth_schema::AppAuthSchema;
use axum::{Router, extract::FromRef};
use better_auth::BetterAuth;
use better_auth::integrations::axum::AxumIntegration;
use std::sync::Arc;

#[derive(Clone)]
struct AppState {
    auth: Arc<BetterAuth<AppAuthSchema>>,
}

impl FromRef<AppState> for Arc<BetterAuth<AppAuthSchema>> {
    fn from_ref(state: &AppState) -> Self {
        state.auth.clone()
    }
}

fn router(state: AppState) -> Router {
    Router::new()
        .nest(
            "/api/auth",
            state.auth.clone().axum_router_with_state::<AppState>(),
        )
        .with_state(state)
}
```

## Request lifetime

Axum supervises accepted, fully buffered auth requests, so dispatch can continue after a client disconnects. Keep the runtime alive while requests drain; process shutdown can still cancel them.

See [installation](/installation/) for a runnable server.
