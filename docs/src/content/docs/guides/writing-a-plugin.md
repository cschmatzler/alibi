---
title: "Writing a plugin"
description: "Add your own routes, hooks, rate limits and fields by implementing the AuthPlugin trait."
---

Every feature in Alibi — including the core session and password flows — is an `AuthPlugin`. Your application can add its own: a webhook endpoint, an audit trail, a custom sign-in method, a second factor. Plugins are registered with `.plugin(...)` like the built-in ones and participate in the same request pipeline.

## The minimal plugin

A plugin has a **name**, a list of **routes**, and an `on_request` that handles them. This one serves `GET /status`, which reports whether the caller is signed in:

```rust
use async_trait::async_trait;
use better_auth::plugin::{AuthContext, AuthPlugin, AuthRoute};
use better_auth::prelude::{AuthRequest, AuthResponse, AuthUser, HttpMethod};
use better_auth::{AuthResult, AuthSchema};
use serde_json::json;

pub struct StatusPlugin;

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for StatusPlugin {
    fn name(&self) -> &'static str {
        "status"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        // Paths are relative to the auth base path; the id appears in OpenAPI.
        vec![AuthRoute::get("/status", "status")]
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Get, "/status") => {
                let body = match ctx.require_cached_session(req).await {
                    Ok((user, _session)) => json!({ "signedIn": true, "userId": user.id() }),
                    Err(_) => json!({ "signedIn": false }),
                };
                Ok(Some(AuthResponse::json(200, &body)?))
            }
            _ => Ok(None), // not ours: let other plugins handle it
        }
    }
}
```

Register it:

```rust nocheck
use crate::auth_schema::AppAuthSchema;
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(StatusPlugin)
        .build()
        .await
}
```

`GET /api/auth/status` now exists, is subject to the instance's rate limiting, origin checks and CORS, shows up in `registered_routes()` and in the [OpenAPI](/plugins/open-api/) document, and is mounted by the Axum and Poem adapters automatically (they register every plugin route).

The plugin is generic over `S: AuthSchema`, so it works with any user model. To use your own model's fields, constrain `S::User` with the traits you need, or read through `ctx.user_view(&user)`.

## What the context gives you

`AuthContext<S>` is passed to every method:

| Member | Use |
| --- | --- |
| `ctx.config` | The effective `AuthConfig` (already resolved for dynamic base URLs) |
| `ctx.database` | The `AuthStore<S>` — users, sessions, accounts, verifications and plugin records |
| `ctx.email_provider()` | The configured `EmailProvider`, if any |
| `ctx.require_cached_session(req)` | The authenticated user (`AuthenticatedUser`) and session (cache-aware); any failure, including a storage error, is `Unauthenticated`, as upstream's nested get-session |
| `ctx.require_cached_session_strict(req)` | Same, but only a missing or invalid session is `Unauthenticated`; storage and callback errors propagate |
| `ctx.require_authoritative_session(req)` | Same, bypassing caches for sensitive actions |
| `ctx.verifications()` | Create and atomically consume single-use proofs (tokens, codes) |
| `ctx.user_view(&user)`, `ctx.session_view(&session)` | Public JSON projections honoring field policies |
| `ctx.session_manager()` | Create, validate and revoke sessions |
| `ctx.metadata`, `ctx.extensions` | Typed data published by plugins at initialization |

`AuthRequest` offers `method()`, `path()`, `headers`, `query`, `body_as_json::<T>()` and `header(name)`; responses are built with `AuthResponse::json`, `text`, `html`, `new(status)` and `.with_header(..)`. Return errors with `AuthError` (`bad_request`, `forbidden`, `not_found`, …): they render in the standard `{code, message}` envelope.

## Hooks

Override any of these `AuthPlugin` methods — all have no-op defaults:

| Method | When it runs |
| --- | --- |
| `on_init(&mut AuthInitContext)` | Once at `build()`. Register field policies, metadata, user-create transforms, password-hash hooks |
| `before_request(req, ctx)` | After routing, before the handler. Return `Respond`, `InjectSession`, or `ReplaceHeaders` (this is how [bearer](/plugins/bearer/) and [API keys](/plugins/api-key/) authenticate) |
| `on_http_request(req, ctx)` | Very early, before routing and body parsing; a returned response stops processing |
| `after_request(req, ctx, response)` | After the handler; modify the response — add headers, cookies, rewrite bodies |
| `on_http_response(req, ctx, &response)` | Observe the final routed response before CORS |
| `on_user_created`, `on_session_created`, `on_user_deleted`, `on_session_deleted` | Lifecycle notifications |
| `endpoint_hooks()` | Provide [`EndpointHook`s](/concepts/hooks/#endpoint-hooks) that run for logical calls |
| `rate_limits()` | Plugin-specific [rate limit](/concepts/rate-limit/) rules |
| `session_fields()`, `user_fields()`, `account_fields()` | Contribute [additional-field policies](/concepts/field-policies/) |
| `server_endpoints()`, `on_endpoint()`, `validate_endpoint()` | Expose [server-only operations](/guides/server-side-calls/) for `dispatch_endpoint` |
| `allowed_media_types(route)` | Media types accepted for a route (default JSON only) |
| `openapi_metadata(ctx)` | Describe your routes and schemas for OpenAPI |

This plugin tags every response and counts sign-ins, with its own rate-limit rule:

```rust
use async_trait::async_trait;
use better_auth::middleware::{EndpointRateLimit, PluginRateLimit};
use better_auth::plugin::{AuthContext, AuthPlugin, AuthRoute};
use better_auth::prelude::{AuthRequest, AuthResponse, AuthSession};
use better_auth::{AuthResult, AuthSchema};

pub struct Audit;

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Audit {
    fn name(&self) -> &'static str {
        "audit"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::post("/audit/ping", "audit_ping")]
    }

    // Limit our own endpoint tighter than the default.
    fn rate_limits(&self) -> Vec<PluginRateLimit> {
        vec![PluginRateLimit {
            matches: |path| path == "/audit/ping",
            limit: EndpointRateLimit { window_seconds: 60.0, max_requests: 10.0 },
        }]
    }

    async fn on_request(
        &self,
        _req: &AuthRequest,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None) // `/audit/ping` would be handled here
    }

    async fn after_request(
        &self,
        req: &AuthRequest,
        _ctx: &AuthContext<S>,
        response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        Ok(response.with_header("x-audited-path", req.path().to_owned()))
    }

    async fn on_session_created(&self, session: &S::Session, _ctx: &AuthContext<S>) -> AuthResult<()> {
        println!("session {} created", session.id());
        Ok(())
    }
}
```

## Ordering and ownership

Plugins are initialized, and hooks run, in registration order. When two plugins register the same route, the first one wins; to *replace* a core route (as [custom session](/plugins/custom-session/) does for `GET /get-session`) register your plugin before the core one. The builder appends default core plugins **after** yours, and an explicit plugin with the same `name()` as a default replaces that default.

## Adding fields and tables

A plugin that needs a column on `users` or `sessions` declares its policy through `user_fields()` / `session_fields()` and documents the column for users to add — the schema itself is owned by the application ([Database](/concepts/database/)). A plugin that needs its own *table* should either use `ctx.verifications()` for short-lived records (no schema changes) or ask the application to provide an `AuthStore` extension; the built-in plugin tables are implemented in the SQLx and SeaORM stores.

## Testing a plugin

Build an instance with an in-memory database or [`without_database`](/databases/no-database/), call `handle_request`, and assert on the response — see [Server-side calls](/guides/server-side-calls/#testing-with-an-auth-instance).

## Frontend

For TypeScript clients, expose your endpoints with a [custom client plugin](https://www.better-auth.com/docs/concepts/plugins) so `authClient` gets typed methods for them.
