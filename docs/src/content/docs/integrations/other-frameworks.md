---
title: "Other frameworks"
description: "Embed Better Auth RS in any HTTP host by converting requests and responses, or call it directly from server code."
---

Axum and Poem have first-class adapters. Any other Rust HTTP host — Actix, Hyper, Rocket, Warp, AWS Lambda, a custom server — can embed the auth instance through one method: `BetterAuth::handle_request`.

```text
your framework request ──► AuthRequest ──► auth.handle_request() ──► AuthResponse ──► your framework response
```

You are responsible for three things: **building an `AuthRequest`** from the incoming request, **returning every header** (especially each `Set-Cookie`), and **supervising dispatch** so a client disconnect does not cancel a half-finished write.

## An end-to-end adapter over the `http` crate

The `http` types are what Hyper, Axum, Actix (via `actix-http`), Lambda and most others share. This function converts a buffered `http::Request` into an `AuthRequest`, dispatches it, and converts the result back. It uses the `http` types that Axum re-exports (`axum::http`); depend on the `http` crate directly if you do not use Axum:

```rust
use crate::auth_schema::AppAuthSchema;
use axum::http::{HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use better_auth::BetterAuth;
use better_auth::prelude::{AuthRequest, HttpMethod};
use std::collections::HashMap;

fn convert_method(method: &Method) -> Option<HttpMethod> {
    Some(match *method {
        Method::GET => HttpMethod::Get,
        Method::POST => HttpMethod::Post,
        Method::PUT => HttpMethod::Put,
        Method::DELETE => HttpMethod::Delete,
        Method::PATCH => HttpMethod::Patch,
        Method::OPTIONS => HttpMethod::Options,
        Method::HEAD => HttpMethod::Head,
        _ => return None,
    })
}

fn to_auth_request(request: Request<Vec<u8>>) -> Option<AuthRequest> {
    let (parts, body) = request.into_parts();
    let method = convert_method(&parts.method)?;

    // Join repeated headers: `Cookie` with "; ", everything else with ", ".
    let mut headers: HashMap<String, String> = HashMap::new();
    for (name, value) in &parts.headers {
        let Ok(value) = value.to_str() else { continue };
        headers
            .entry(name.as_str().to_owned())
            .and_modify(|joined| {
                joined.push_str(if name.as_str() == "cookie" { "; " } else { ", " });
                joined.push_str(value);
            })
            .or_insert_with(|| value.to_owned());
    }

    let query: HashMap<String, String> = parts
        .uri
        .query()
        .map(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect()
        })
        .unwrap_or_default();

    let body = (!body.is_empty()).then_some(body);
    Some(AuthRequest::from_parts(
        method,
        parts.uri.path().to_owned(),
        headers,
        body,
        query,
    ))
}

async fn dispatch(
    auth: &BetterAuth<AppAuthSchema>,
    request: Request<Vec<u8>>,
) -> Response<Vec<u8>> {
    let Some(request) = to_auth_request(request) else {
        return Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Vec::new())
            .unwrap_or_default();
    };

    let result = match auth.handle_request(request).await {
        Ok(result) => result,
        Err(error) => error.to_auth_response(),
    };

    let mut response = Response::new(result.body);
    *response.status_mut() = StatusCode::from_u16(result.status).unwrap_or(StatusCode::OK);
    for (name, value) in result.headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            // `append`, never `insert`: a response may carry several Set-Cookie headers.
            response.headers_mut().append(name, value);
        }
    }
    response
}
```

Notes:

- `handle_request` only returns `Err` for failures that have no HTTP shape; `AuthError::to_auth_response()` renders them as a normal error response.
- `AuthRequest::with_url(url::Url)` is optional and supplies the absolute request URL. Dynamic base URLs and `Referer`-less origin inference use it, so attach it when your host knows the full URL.
- The path is passed **with** the base path (`/api/auth/sign-in/email`); the instance strips `AuthConfig::base_path` itself.
- Mount the instance on any prefix as long as it equals `base_path`.

## Supervise dispatch

Your host owns the dispatch future. If the client disconnects and your framework drops the future, a multi-step operation can be cancelled in the middle — database writes that already happened stay committed. The Axum and Poem adapters avoid this by running dispatch in a supervised task once the body is buffered. Do the same:

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::BetterAuth;
use better_auth::prelude::{AuthRequest, AuthResponse};
use std::sync::Arc;

async fn dispatch_detached(
    auth: Arc<BetterAuth<AppAuthSchema>>,
    request: AuthRequest,
) -> AuthResponse {
    tokio::spawn(async move {
        match auth.handle_request(request).await {
            Ok(response) => response,
            Err(error) => error.to_auth_response(),
        }
    })
    .await
    .unwrap_or_else(|_| AuthResponse::new(500))
}
```

The spawned task finishes even if the caller goes away. Keep the runtime alive while such tasks drain.

## Reading the session in your own handlers

Without an adapter there are no extractors. Two options:

1. **Ask the auth instance.** Forward the browser's `Cookie` header to `GET /get-session` through `handle_request` and parse the JSON (`{"session": …, "user": …}` or `null`). It runs the same [hooks](/concepts/hooks/) as any request, so bearer tokens, API-key sessions and the cookie cache all work. Wrap it in a function and reuse it as middleware in your framework.
2. **Query the store directly.** `auth.store()` gives you the `AuthStore`, and `auth.session_manager()` resolves a signed cookie token.

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::BetterAuth;
use better_auth::prelude::{AuthRequest, HttpMethod};

/// Returns the user id of the session identified by the request's headers, if any.
async fn current_user_id(
    auth: &BetterAuth<AppAuthSchema>,
    headers: &[(&str, &str)],
) -> Option<String> {
    let mut request = AuthRequest::new(HttpMethod::Get, "/api/auth/get-session");
    for (name, value) in headers {
        if matches!(*name, "cookie" | "authorization" | "x-api-key" | "user-agent" | "x-forwarded-for") {
            request.headers.insert((*name).to_owned(), (*value).to_owned());
        }
    }
    let response = auth.handle_request(request).await.ok()?;
    let body: serde_json::Value = serde_json::from_slice(&response.body).ok()?;
    body["user"]["id"].as_str().map(str::to_owned)
}
```

Forward only the headers you intend to authenticate with.

## Trusted server operations

`BetterAuth::dispatch_endpoint` runs an operation with logical inputs instead of an HTTP request — for example creating an API key for a user, verifying a JWT, or consuming a one-time token. These operations stay on the server and are **not** HTTP routes. See [Server-side calls](/guides/server-side-calls/).

## Frontend

See the official [Better Auth client documentation](https://www.better-auth.com/docs/concepts/client).
