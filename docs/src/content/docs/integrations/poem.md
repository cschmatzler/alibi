---
title: "Poem"
description: "Mount authentication endpoints and extract sessions in Poem."
---

Enable Better Auth's `poem` feature and add `poem = "3.1"` to your application. Build the auth instance with your SQLx or SeaORM store before mounting it at the configured base path:

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::BetterAuth;
use better_auth::integrations::poem::{PoemIntegration, CurrentSession};
use better_auth::prelude::AuthUser;
use poem::{Endpoint, EndpointExt, Route, get, handler};
use std::sync::Arc;

#[handler]
async fn profile(session: CurrentSession<AppAuthSchema>) -> String {
    format!("Hello, {}", session.user.id())
}

fn app(auth: Arc<BetterAuth<AppAuthSchema>>) -> impl Endpoint {
    Route::new()
        .nest("/api/auth", auth.clone().poem_endpoint())
        .at("/profile", get(profile))
        .data(auth)
}
```

`CurrentSession` validates the session and loads its user. Missing or invalid sessions return HTTP 401; `OptionalSession` yields `None` for any extraction failure, including missing auth data and storage errors, matching the Axum integration. Use `CurrentSession` when failures must be reported to the caller. Install the same `Arc<BetterAuth<AppAuthSchema>>` with `.data(auth)` on routes using these extractors.

The endpoint preserves the original URL when nested, query parameters, request bytes, and repeated response headers including every `Set-Cookie`. Auth dispatch owns method matching, request protection, and plugin hooks. Request bodies are buffered within the configured body limit before dispatch.

Fully buffered requests continue after a client disconnect. Dropping the endpoint drains accepted work while its Tokio runtime remains alive. Keep the runtime alive during shutdown; stopping the runtime or process can cancel pending work. Dispatch carries auth request context and tracing, but does not copy arbitrary application task-local values.
