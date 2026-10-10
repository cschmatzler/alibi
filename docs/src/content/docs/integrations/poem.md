---
title: "Poem"
description: "Mount the auth endpoint in a Poem application and extract sessions."
---

The Poem adapter nests the auth API as a single `Endpoint` and provides `CurrentSession` and `OptionalSession` extractors. Enable the `poem` feature and add `poem` to your application:

```toml title="Cargo.toml"
alibi = { version = "0.5.0", features = ["poem"] }
poem = "3.1"
```

## Mount the endpoint and protect a route

Build the auth instance with your SQLx or SeaORM store as usual, then nest `poem_endpoint()` at the configured base path and install the instance as shared data for the extractors:

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::Alibi;
use alibi::integrations::{CurrentSession, poem::PoemIntegration};
use alibi::prelude::AuthUser;
use poem::{Endpoint, EndpointExt, Route, get, handler};
use std::sync::Arc;

#[handler]
async fn profile(session: CurrentSession<AppAuthSchema>) -> String {
    format!("Hello, {}", session.user.id())
}

fn app(auth: Arc<Alibi<AppAuthSchema>>) -> impl Endpoint {
    Route::new()
        .nest("/api/auth", auth.clone().poem_endpoint())
        .at("/profile", get(profile))
        .data(auth)
}
```

Serve it with Poem's server:

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::Alibi;
use alibi::integrations::poem::PoemIntegration;
use poem::{EndpointExt, Route, Server, listener::TcpListener};
use std::sync::Arc;

async fn serve(auth: Arc<Alibi<AppAuthSchema>>) -> std::io::Result<()> {
    let app = Route::new()
        .nest("/api/auth", auth.clone().poem_endpoint())
        .data(auth);
    Server::new(TcpListener::bind("127.0.0.1:3000")).run(app).await
}
```

## Extractors

| Extractor | When there is no valid session |
| --- | --- |
| `CurrentSession<S>` | Rejects with `401` |
| `OptionalSession<S>` | Yields `None` for **any** extraction failure — a missing session, missing auth data or a storage error — matching the Axum adapter. Use `CurrentSession` when failures must be reported |

Both expose `user` and `session` in your own model types. The extractors need the same `Arc<Alibi<S>>` installed with `.data(auth)` on the routes that use them; as in Axum they validate the session cookie.

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::integrations::OptionalSession;
use poem::handler;

#[handler]
async fn home(session: OptionalSession<AppAuthSchema>) -> String {
    match session.0 {
        Some(_) => "signed in".to_owned(),
        None => "anonymous".to_owned(),
    }
}
```

## Behavior to know

- The endpoint preserves the original URL (even when nested), query parameters, request bytes and repeated response headers, including every `Set-Cookie`.
- Auth dispatch owns method matching, request protection and plugin hooks; Poem only forwards.
- Request bodies are buffered within the configured `BodyLimitConfig` before dispatch.
- A fully buffered request continues after the client disconnects. Dropping the endpoint drains accepted work while its Tokio runtime remains alive — keep the runtime running during shutdown, because stopping the runtime or process can cancel pending work.
- Dispatch carries auth request context and tracing, not arbitrary application task-local values.
- As with Axum, the client IP comes from proxy headers; configure `advanced.ip_address` ([Session management](/concepts/session-management/#session-metadata)).

For CORS, use Poem's `Cors` middleware around the nested endpoint (or the builder's [`CorsConfig`](/concepts/security/#cors), not both), and add the app origin to `trusted_origins`.
