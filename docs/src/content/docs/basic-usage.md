---
title: "Basic usage"
description: "Sign up, sign in, inspect sessions, and sign out."
---

The [installation example](/installation/) enables email/password and session management. Its authentication endpoints are available under `/api/auth`.

## Sign up

```bash
curl -i -c cookies.txt http://localhost:3000/api/auth/sign-up/email \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://localhost:3000' \
  -d '{"name":"Ada","email":"ada@example.com","password":"a-long-example-password"}'
```

Successful signup signs the user in by default and returns session cookies. Requiring email verification or disabling automatic sign-in changes that behavior.

## Sign in

```bash
curl -i -c cookies.txt http://localhost:3000/api/auth/sign-in/email \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://localhost:3000' \
  -d '{"email":"ada@example.com","password":"a-long-example-password"}'
```

## Get the session

```bash
curl -b cookies.txt http://localhost:3000/api/auth/get-session
```

In an Axum handler, use a typed extractor:

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::integrations::axum::CurrentSession;
use better_auth::prelude::AuthUser;

async fn profile(session: CurrentSession<AppAuthSchema>) -> String {
    format!("Signed in as {}", session.user.id())
}
```

`CurrentSession` rejects requests without a valid session with HTTP 401. Use `OptionalSession` when a route also serves anonymous users. See [Axum](/integrations/axum/) for mounting protected handlers.

## Sign out

```bash
curl -i -b cookies.txt -c cookies.txt http://localhost:3000/api/auth/sign-out \
  -X POST -H 'Origin: http://localhost:3000'
```

Forward all response cookie headers when embedding authentication in a custom HTTP host.

## Server-side Rust requests

Call the request handler from Rust with the same body and headers as an HTTP request:

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::prelude::{AuthRequest, AuthResponse, HttpMethod};
use better_auth::{AuthResult, BetterAuth};

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

Return the response to the caller, including all cookies. See [other frameworks](/integrations/other-frameworks/) for response conversion.

## Frontend

For frontend sign-up, sign-in, session hooks, and sign-out, use the official [Better Auth basic usage guide](https://www.better-auth.com/docs/basic-usage) and [client setup documentation](https://www.better-auth.com/docs/concepts/client).
