---
title: "Cross-origin applications"
description: "Run your frontend and the auth server on different origins: trusted origins, CORS, cookies and the alternatives."
---

A browser app at `https://app.example.com` that talks to an auth server at `https://auth.example.com` makes **cross-origin, credentialed** requests. Four things must line up: the server must trust the origin, answer CORS, send cookies the browser will accept, and the client must ask for them. Often the best answer is to avoid all of it — see [Option 1](#option-1-one-origin-recommended).

## Option 1: one origin (recommended)

Serve the auth API under your app's own origin with a reverse proxy (or your framework's routing), so the browser only ever talks to `https://app.example.com`:

```text
https://app.example.com/            → frontend
https://app.example.com/api/auth/*  → auth server (proxy_pass)
```

No CORS, no `SameSite` negotiation, first-party cookies. Set `base_url` to `https://app.example.com` and keep `base_path = "/api/auth"`. If the proxy rewrites the `Host` header, forward the original (or configure [`dynamic_base_url`](/concepts/security/#dynamic-base-urls-and-trusted-origins)) and set `advanced.ip_address` for the client IP.

## Option 2: separate origins, same site

`app.example.com` and `auth.example.com` share the registrable domain, so cookies set by the auth server are **same-site** and `SameSite=Lax` cookies are sent on `fetch` with credentials. You need trusted origins and CORS:

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::middleware::CorsConfig;
use alibi::plugins::EmailPasswordPlugin;
use alibi::sqlx::SqlxStore;
use alibi::{AuthConfig, AuthResult, BetterAuth};

fn auth_config(secret: &str) -> AuthConfig {
    AuthConfig::new(secret)
        .base_url("https://auth.example.com")
        .trusted_origin("https://app.example.com")
}

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .cors(
            CorsConfig::new()
                .allowed_origin("https://app.example.com")
                .allow_credentials(true),
        )
        .build()
        .await
}
```

1. **`trusted_origin`** lets the origin pass the [CSRF check](/concepts/security/#origin-and-csrf-checks) and lets `callbackURL`s on it be redirect targets.
2. **`CorsConfig`** answers preflight `OPTIONS` requests and adds `Access-Control-Allow-Origin` (the specific origin) and `Access-Control-Allow-Credentials: true`. The defaults allow `Content-Type`, `Authorization` and `X-Requested-With`.
3. The cookie `Domain` stays host-only (`auth.example.com`). To also read it from the app's server, share it across subdomains with `cross_sub_domain_cookies("example.com")` — only if all subdomains are trusted ([Cookies](/concepts/cookies/#share-cookies-across-subdomains)).

Client side:

```ts
import { createAuthClient } from "better-auth/client";

export const authClient = createAuthClient({
  baseURL: "https://auth.example.com/api/auth",
  fetchOptions: { credentials: "include" },
});
```

## Option 3: different sites

When the frontend and auth server are on different **sites** (`app.com` and `auth.example.org`), the session cookie is a third-party cookie and `SameSite=Lax` will not be sent on cross-site `fetch`. Either:

**3a. Use `SameSite=None; Secure`** (HTTPS only), optionally partitioned (CHIPS):

```rust
use alibi::AuthConfig;
use alibi::config::{AdvancedConfig, CookieAttributes, SameSite};

fn auth_config(secret: &str) -> AuthConfig {
    AuthConfig::new(secret)
        .base_url("https://auth.example.org")
        .trusted_origin("https://app.com")
        .advanced(AdvancedConfig {
            default_cookie_attributes: CookieAttributes {
                same_site: Some(SameSite::None),
                secure: Some(true),
                partitioned: Some(true),
                ..Default::default()
            },
            ..Default::default()
        })
}
```

Third-party cookie restrictions keep tightening (Safari and Firefox block them outright for non-partitioned cookies), so this is fragile.

**3b. Use bearer tokens** instead of cookies: add the [bearer plugin](/plugins/bearer/), read the `set-auth-token` header from sign-in responses (expose it with CORS), store the token securely and send `Authorization: Bearer …` on later calls. This works in every browser and for native apps.

## Axum: one complete example

```rust
use crate::auth_schema::AppAuthSchema;
use axum::Router;
use axum::http::{HeaderValue, Method, header};
use alibi::BetterAuth;
use alibi::integrations::axum::AxumIntegration;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

fn router(auth: Arc<BetterAuth<AppAuthSchema>>) -> Router {
    // CORS via tower-http instead of `.cors(CorsConfig…)` on the builder.
    let cors = CorsLayer::new()
        .allow_origin(HeaderValue::from_static("https://app.example.com"))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .expose_headers([header::HeaderName::from_static("set-auth-token")])
        .allow_credentials(true);

    Router::new()
        .nest("/api/auth", auth.clone().axum_router().layer(cors))
        .with_state(auth)
}
```

Use one CORS mechanism, not both. `allow_origin("*")` cannot be combined with credentials.

## OAuth and email links

- The `callbackURL`, `errorCallbackURL` and `newUserCallbackURL` you pass to `signIn.social()` can be **absolute URLs on the frontend** — they must be trusted origins.
- The provider redirects to the auth server (`/api/auth/callback/<provider>`), which sets the cookie on its own origin and redirects the browser on to your app. With separate sites, the session cookie then belongs to the auth origin only; use [bearer tokens](/plugins/bearer/), the [OAuth popup](/plugins/oauth-popup/) or a [one-time token](/plugins/one-time-token/) handoff to give the frontend a credential.
- Email links (verification, reset, magic link) point at the auth server's `base_url` and redirect to your `callbackURL`.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `403 INVALID_ORIGIN` | The app origin is missing from `trusted_origins` (check scheme, host **and port**) |
| `403 MISSING_OR_NULL_ORIGIN` | A request with cookies and no `Origin`/`Referer` — a proxy stripped it, or the call is not from a browser |
| Browser blocks the response ("CORS") | No CORS configuration, a mismatched `allowed_origin`, or `*` with credentials |
| Signed in, but `get-session` returns `null` | Cookie not sent: missing `credentials: "include"`, `SameSite`/third-party-cookie blocking, or a cookie `Domain`/`Secure` mismatch on HTTP |
| Works on localhost, fails in production | `Secure` cookies need HTTPS; `base_url` must be the real `https://` origin |
| Custom header is invisible to JavaScript | Add it to `exposed_headers` (`set-auth-token`, `set-auth-jwt`) |
