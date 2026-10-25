---
title: "Axum"
description: "Mount the auth routes in an Axum application and protect handlers with the session layer or extractors."
---

The Axum adapter mounts every auth route as a nested router, resolves sessions for your own routes with `SessionLayer`, and provides the `CurrentSession` and `OptionalSession` extractors. It needs Axum 0.8 and the `axum` feature:

```toml title="Cargo.toml"
alibi = { version = "0.11.0", features = ["axum"] }
axum = "0.8"
```

## Mount the router and protect a route

```rust
use crate::auth_schema::AppAuthSchema;
use axum::{Router, routing::get};
use alibi::Alibi;
use alibi::integrations::{CurrentSession, axum::AxumIntegration};
use alibi::prelude::AuthUser;
use std::sync::Arc;

async fn profile(session: CurrentSession<AppAuthSchema>) -> String {
    format!("Hello, {}", session.user.id())
}

fn router(auth: Arc<Alibi<AppAuthSchema>>) -> Router {
    Router::new()
        .nest("/api/auth", auth.clone().axum_router())
        .route("/profile", get(profile))
        .with_state(auth)
}
```

- `axum_router()` is implemented for `Arc<Alibi<S>>`. It returns a `Router<Arc<Alibi<S>>>`, so the application state is the auth instance.
- Nest it at `AuthConfig::base_path` (`/api/auth` by default). Auth dispatch itself owns method matching, disabled paths and trailing-slash policy, so the nested router answers `405`/`404` exactly like the reference server rather than Axum's own defaults.
- The extractors need `Arc<Alibi<S>>` in the router state.

## Resolve sessions with `SessionLayer`

`SessionLayer` runs get-session for each request, as Better Auth's `getSessionFromCtx` does for its own endpoints: it reads and validates the cookie cache, renews an aging session (`update_age`/`expires_in`), clears the cookies of an ended one, and appends the resulting `Set-Cookie` headers to your handler's response. Handlers read the session with `ResolvedSession`:

```rust
use crate::auth_schema::AppAuthSchema;
use axum::{Json, Router, routing::get};
use alibi::Alibi;
use alibi::integrations::axum::{AxumIntegration, ResolvedSession, SessionLayer};
use serde_json::{Value, json};
use std::sync::Arc;

async fn me(ResolvedSession(session): ResolvedSession) -> Json<Value> {
    Json(json!({ "id": session.user.id, "expiresAt": session.session.expires_at }))
}

async fn home(session: Option<ResolvedSession>) -> String {
    if session.is_some() { "Welcome back".into() } else { "Hi".into() }
}

fn router(auth: Arc<Alibi<AppAuthSchema>>) -> Router {
    Router::new()
        .route("/me", get(me))
        .route("/", get(home))
        .layer(SessionLayer::new(auth.clone()))
        .nest("/api/auth", auth.clone().axum_router())
        .with_state(auth)
}
```

- `ResolvedSession` wraps the `GetSessionResponse` that `/get-session` returns. Without a session it rejects with `401` (`UNAUTHORIZED`), and the layer still attaches the cookie deletions. `Option<ResolvedSession>` yields `None` instead.
- A failed lookup counts as no session, as upstream. Extracting `ResolvedSession` on a route without the layer rejects with `500`.
- Session cookies come before cookies your handler sets, and your handler's other headers win. The `cache-control`/`pragma` headers of `/get-session` are not forwarded.
- `SessionLayer::new(auth).query(GetSessionQuery { disable_cookie_cache: true, .. })` bypasses the cookie cache; `disable_refresh` suppresses renewal.
- Apply it with `route_layer` to run it only for matched routes, and keep it off the auth router, which resolves sessions itself.

## Extractors

| Extractor | When there is no valid session |
| --- | --- |
| `CurrentSession<S>` | Rejects with `401` (`Authentication required`, `Session not found or expired` or `User not found`) |
| `OptionalSession<S>` | Yields `None` — including for storage errors, so use `CurrentSession` when failures must surface |

Both expose the session as `S::User` and `S::Session`, i.e. **your** model types:

```rust
use crate::auth_schema::AppAuthSchema;
use axum::Json;
use alibi::integrations::{CurrentSession, OptionalSession};
use alibi::prelude::{AuthSession, AuthUser};
use serde_json::{Value, json};

async fn me(session: CurrentSession<AppAuthSchema>) -> Json<Value> {
    Json(json!({
        "id": session.user.id(),
        "email": session.user.email(),
        "emailVerified": session.user.email_verified(),
        "sessionExpires": session.session.expires_at().to_rfc3339(),
    }))
}

async fn greeting(session: OptionalSession<AppAuthSchema>) -> String {
    match session.0 {
        Some(current) => format!("Hi {}", current.user.name().unwrap_or("there")),
        None => "Hi".to_owned(),
    }
}
```

The extractors validate the session token from the request headers against the store. They do not read the cookie cache or renew the session; use [`SessionLayer`](#resolve-sessions-with-sessionlayer) for that. They also do not run auth-router request hooks, so they authenticate with the **session cookie**. For API keys or other credentials, call the auth endpoints (or [`dispatch_endpoint`](/guides/server-side-calls/)) instead of relying on the extractor.

### Authorization on top of authentication

Extractors only authenticate. Check roles and ownership in the handler or in your own extractor:

```rust
use crate::auth_schema::AppAuthSchema;
use axum::http::StatusCode;
use alibi::integrations::CurrentSession;
use alibi::prelude::AuthUser;

async fn admin_dashboard(
    session: CurrentSession<AppAuthSchema>,
) -> Result<&'static str, StatusCode> {
    if session.user.role() == Some("admin") {
        Ok("welcome, admin")
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}
```

For organization permissions, call the [organization endpoints](/plugins/organization/) such as `/organization/has-permission`, or use the [access-control helpers](/plugins/organization/#application-side-access-control).

## Use your own application state

When your application has its own state, implement `FromRef` and mount with `axum_router_with_state`:

```rust
use crate::auth_schema::AppAuthSchema;
use axum::{Router, extract::FromRef};
use alibi::Alibi;
use alibi::integrations::axum::AxumIntegration;
use std::sync::Arc;

#[derive(Clone)]
struct AppState {
    auth: Arc<Alibi<AppAuthSchema>>,
    // db: sqlx::PgPool, config: …
}

impl FromRef<AppState> for Arc<Alibi<AppAuthSchema>> {
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

## CORS, tracing and other layers

Apply tower layers around the nested router like any other Axum service:

```rust
use crate::auth_schema::AppAuthSchema;
use axum::{Router, http::{HeaderValue, Method, header}};
use alibi::Alibi;
use alibi::integrations::axum::AxumIntegration;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

fn router(auth: Arc<Alibi<AppAuthSchema>>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin("https://app.example.com".parse::<HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .allow_credentials(true);

    Router::new()
        .nest("/api/auth", auth.clone().axum_router().layer(cors))
        .with_state(auth)
}
```

Either this layer **or** the built-in `.cors(CorsConfig…)` on the builder — not both. Credentialed cross-origin calls also need the origin in `trusted_origins`; see [Security](/concepts/security/) and [Cross-origin applications](/guides/cross-origin/).

## Behavior to know

- **Client IP.** The adapter does not read the socket address. The client IP comes from the configured headers (`x-forwarded-for` by default) — set `advanced.ip_address` for your proxy, otherwise all clients share one [rate-limit](/concepts/rate-limit/) bucket.
- **Body limit.** Bodies are buffered up to `BodyLimitConfig::max_bytes` (1 MiB default); larger requests get `413`, including chunked uploads.
- **Disconnects.** Once a request body has been fully received, Axum hands dispatch to a supervisor task, so a client that hangs up mid-request does not leave a half-finished sign-up. Keep the Tokio runtime alive while requests drain: graceful server shutdown alone does not await disconnected work, and process exit can cancel it.
- **Request context.** Dispatch carries the framework's request context and tracing span, not arbitrary task-local values from your handlers.
- **Cookies.** Every `Set-Cookie` header from the auth response is forwarded individually.

## Full example

The [installation page](/installation/) contains a runnable Axum server, and [Basic usage](/basic-usage/) walks through the endpoints with `curl`.
