---
title: "Basic usage"
description: "Sign up, sign in, read the session, protect a route and sign out — over HTTP and from Rust."
---

The [installation example](/installation/) registers email and password authentication and mounts the auth routes under `/api/auth`. This page walks through the whole user lifecycle with `curl`, then shows the same flows from Rust.

All paths below are relative to `/api/auth` (the `AuthConfig::base_path`).

:::note[Origin header]
State-changing requests that carry cookies must also carry a trusted `Origin` (or `Referer`) header, exactly as in the TypeScript server. Browsers add it automatically; with `curl` pass `-H 'Origin: http://localhost:3000'`. A cookie-bearing request without it fails with `403 MISSING_OR_NULL_ORIGIN`, and one from an unlisted origin with `403 INVALID_ORIGIN`. See [Security](/concepts/security/).
:::

## Sign up

```bash
curl -i -c cookies.txt http://localhost:3000/api/auth/sign-up/email \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://localhost:3000' \
  -d '{"name":"Ada","email":"ada@example.com","password":"a-long-example-password"}'
```

```http
HTTP/1.1 200 OK
content-type: application/json
set-cookie: better-auth.session_token=zzKK987j…; Max-Age=604800; Path=/; HttpOnly; SameSite=Lax

{"token":"zzKK987jn0FN4maZTtNNk1gRAcONcCTE","user":{"id":"574c3df7-4751-4264-8d93-c66912fc679c","name":"Ada","email":"ada@example.com","emailVerified":false,"image":null,"createdAt":"2026-10-04T09:47:38.068Z","updatedAt":"2026-10-04T09:47:38.068Z"}}
```

Signup signs the user in by default and sets the session cookie. Turn that off with `auto_sign_in(false)`, or require a verified email first — see [Email and password](/authentication/email-password/) and [Email verification](/authentication/email-verification/).

Signing up with an address that already exists returns `422 USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL`; a password shorter than the configured minimum returns `400 PASSWORD_TOO_SHORT`.

## Sign in

```bash
curl -i -c cookies.txt http://localhost:3000/api/auth/sign-in/email \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://localhost:3000' \
  -d '{"email":"ada@example.com","password":"a-long-example-password"}'
```

```json
{"redirect":false,"token":"07gTGnxj0gFlvsKpTV7hBC3aMyH7Jnty","user":{"id":"574c3df7-…","name":"Ada","email":"ada@example.com","emailVerified":false,"image":null,"createdAt":"…","updatedAt":"…"}}
```

A wrong password returns `401` with a stable error code:

```json
{"code":"INVALID_EMAIL_OR_PASSWORD","message":"Invalid email or password"}
```

## Read the session

```bash
curl -b cookies.txt http://localhost:3000/api/auth/get-session
```

```json
{"session":{"id":"7babe437-…","expiresAt":"2026-10-11T09:47:46.014Z","token":"07gTGnxj…","createdAt":"…","updatedAt":"…","ipAddress":"","userAgent":"curl/8.22.0","userId":"574c3df7-…"},"user":{"id":"574c3df7-…","name":"Ada","email":"ada@example.com","emailVerified":false,"image":null,"createdAt":"…","updatedAt":"…"}}
```

Without a valid session the response is `null` with status 200. `GET /list-sessions` returns every active session of the user as an array.

## Protect an Axum route

`CurrentSession` is an Axum extractor that validates the cookie, loads the session and user, and rejects the request with `401` when there is none:

```rust
use crate::auth_schema::AppAuthSchema;
use axum::{Json, Router, routing::get};
use alibi::BetterAuth;
use alibi::integrations::{CurrentSession, OptionalSession, axum::AxumIntegration};
use alibi::prelude::AuthUser;
use serde_json::{Value, json};
use std::sync::Arc;

async fn profile(session: CurrentSession<AppAuthSchema>) -> Json<Value> {
    Json(json!({
        "id": session.user.id(),
        "email": session.user.email(),
    }))
}

async fn home(session: OptionalSession<AppAuthSchema>) -> String {
    match session.0 {
        Some(session) => format!("Welcome back, {}", session.user.name().unwrap_or("friend")),
        None => "Hello, stranger".to_owned(),
    }
}

fn router(auth: Arc<BetterAuth<AppAuthSchema>>) -> Router {
    Router::new()
        .nest("/api/auth", auth.clone().axum_router())
        .route("/profile", get(profile))
        .route("/", get(home))
        .with_state(auth)
}
```

```bash
curl -b cookies.txt http://localhost:3000/profile   # {"id":"574c3df7-…","email":"ada@example.com"}
curl -i http://localhost:3000/profile               # HTTP/1.1 401 Unauthorized
```

`CurrentSession` exposes `user` and `session` as your own model types (`AppAuthSchema::User` and `AppAuthSchema::Session`), so every column you added to the models is available. Other frameworks: [Poem](/integrations/poem/), [custom hosts](/integrations/other-frameworks/).

## Sign out

```bash
curl -i -b cookies.txt -c cookies.txt http://localhost:3000/api/auth/sign-out \
  -X POST -H 'Origin: http://localhost:3000'
```

The session row is deleted and the response clears every auth cookie:

```http
HTTP/1.1 200 OK
set-cookie: better-auth.session_token=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax
set-cookie: better-auth.session_data=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax
set-cookie: better-auth.dont_remember=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax

{"success":true}
```

## Call the handler from Rust

`BetterAuth::handle_request` accepts the same method, path, headers and body as an HTTP request. Use it in tests, in a framework without an adapter, or to proxy requests:

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::prelude::{AuthRequest, AuthResponse, HttpMethod};
use alibi::{AuthResult, BetterAuth};

async fn sign_in(
    auth: &BetterAuth<AppAuthSchema>,
    email: &str,
    password: &str,
) -> AuthResult<AuthResponse> {
    let mut request = AuthRequest::new(HttpMethod::Post, "/api/auth/sign-in/email");
    request
        .headers
        .insert("content-type".into(), "application/json".into());
    request
        .headers
        .insert("origin".into(), "http://localhost:3000".into());
    request.body = Some(serde_json::to_vec(&serde_json::json!({
        "email": email,
        "password": password,
    }))?);
    auth.handle_request(request).await
}
```

`AuthResponse` carries `status`, `body` and `headers`. When you return it from your own handler, forward **every** `Set-Cookie` header — see [Other frameworks](/integrations/other-frameworks/). To call operations as the server, without an HTTP request, see [Server-side calls](/guides/server-side-calls/).

## Handle errors

Errors use a stable envelope with an upper-case `code` and a human-readable `message`:

| Status | Example `code` | Meaning |
| --- | --- | --- |
| 400 | `VALIDATION_ERROR`, `PASSWORD_TOO_SHORT` | Invalid input |
| 401 | `INVALID_EMAIL_OR_PASSWORD` | Bad credentials or missing session |
| 403 | `MISSING_OR_NULL_ORIGIN`, `INVALID_ORIGIN` | Failed origin or CSRF check |
| 422 | `USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL` | Conflict with existing data |
| 429 | — (`{"message":"Too many requests. Please try again later."}`) | Rate limited; see the `X-Retry-After` header |

The Rust error type and its status mapping are described in [Errors](/reference/errors/).

## Frontend

For sign-up, sign-in, session hooks and sign-out from a browser, use the official [Better Auth basic usage guide](https://www.better-auth.com/docs/basic-usage) and [client setup](https://www.better-auth.com/docs/concepts/client). Browser apps on another origin also need [CORS and trusted origins](/guides/cross-origin/).
