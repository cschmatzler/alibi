---
title: "Security"
description: "Trusted origins, CSRF protection, CORS, request limits, proxies and dynamic base URLs."
---

Request protection runs before any plugin handler and mirrors the TypeScript server. Most deployments need only three things: a correct `base_url`, the list of browser origins in `trusted_origins`, and — if a browser app lives on another origin — CORS.

```rust
use alibi::AuthConfig;

fn auth_config(secret: &str) -> AuthConfig {
    AuthConfig::new(secret)
        .base_url("https://auth.example.com")
        .trusted_origin("https://app.example.com")
        .trusted_origin("https://*.preview.example.com") // glob patterns are allowed
}
```

## Origin and CSRF checks

For every `POST`, `PUT`, `PATCH` and `DELETE` that carries a `Cookie` header:

1. The request needs an `Origin` header (or, failing that, a `Referer`). Otherwise: `403 MISSING_OR_NULL_ORIGIN`.
2. That origin must equal the `base_url` origin or match an entry in `trusted_origins`. Otherwise: `403 INVALID_ORIGIN`.

`POST /sign-in/email` and `POST /sign-up/email` are the "first login" endpoints: they may arrive without cookies, so the server additionally inspects Fetch Metadata. A cross-site top-level navigation (`Sec-Fetch-Site: cross-site` with `Sec-Fetch-Mode: navigate`) is rejected with `403 CROSS_SITE_NAVIGATION_LOGIN_BLOCKED`, which stops login-CSRF through auto-submitted forms.

Redirect targets in the body or query — `callbackURL`, `redirectTo`, `newUserCallbackURL`, `errorCallbackURL` — must be a safe relative path (`/dashboard`, never `//host`, backslashes or encoded slashes) or point at a trusted origin. Otherwise the request fails with `403 Invalid callbackURL` (or the matching name).

Trusted-origin patterns:

| Pattern | Matches |
| --- | --- |
| `https://app.example.com` | exactly that origin |
| `https://*.example.com` | any single-level subdomain over HTTPS |
| `*.example.com` | host-only pattern, any scheme |
| `myapp://` | a custom scheme (native apps) |

### Relax or disable checks

```rust
use alibi::AuthConfig;
use alibi::config::AdvancedConfig;

fn auth_config(secret: &str) -> AuthConfig {
    AuthConfig::new(secret).advanced(AdvancedConfig {
        // Skip origin validation only for these paths (and their descendants).
        disable_origin_check_paths: vec!["/webhooks".into()],
        ..Default::default()
    })
}
```

| Field | Effect |
| --- | --- |
| `advanced.disable_origin_check` | Skip request-origin **and** redirect-target validation everywhere. Also relaxes the first-login check unless `disable_csrf_check` is set explicitly |
| `advanced.disable_csrf_check` | Explicitly toggle CSRF. `Some(false)` keeps the first-login Fetch Metadata check even with origin checks off |
| `advanced.disable_origin_check_paths` | Per-path opt-out; does not disable cross-site-navigation protection |
| `AuthBuilder::csrf(CsrfConfig::new().enabled(false))` | Remove the middleware entirely |

Turn these off only for a trusted internal deployment; each one removes a defense a browser relies on.

## CORS

A browser app on another origin needs CORS headers and credentialed requests. Register a `CorsConfig` on the builder; by default no CORS headers are sent.

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::middleware::CorsConfig;
use alibi::sqlx::SqlxStore;
use alibi::{AuthConfig, AuthResult, Alibi};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<Alibi<AppAuthSchema>> {
    Alibi::<AppAuthSchema>::new(config)
        .store(store)
        .cors(
            CorsConfig::new()
                .allowed_origin("https://app.example.com")
                .allow_credentials(true)
                .max_age(3600),
        )
        .build()
        .await
}
```

| `CorsConfig` field | Default |
| --- | --- |
| `allowed_origins` | none (CORS headers are not added) |
| `allowed_methods` | `GET, POST, PUT, DELETE, PATCH, OPTIONS` |
| `allowed_headers` | `Content-Type, Authorization, X-Requested-With` |
| `exposed_headers` | none — add `set-auth-token` and `set-auth-jwt` for the [bearer](/plugins/bearer/) and [JWT](/plugins/jwt/) plugins (they append their own header automatically) |
| `allow_credentials` | `true` |
| `max_age` | 86400 seconds |

`allowed_origins: ["*"]` is accepted, but browsers refuse it together with credentials. Requests from origins that are not allowed receive no `Access-Control-Allow-*` headers.

CORS only tells the browser what it may read. It is **not** an authorization mechanism and does not replace `trusted_origins`, so the app origin must appear in both lists.

Plugin HTTP hooks run before the built-in preflight handling. [CAPTCHA](/plugins/captcha/#notes) skips `OPTIONS` requests so preflights still succeed. A custom plugin that rejects requests without its own header must do the same, or you should use your framework's CORS layer instead.

To use a framework CORS layer such as `tower-http`'s `CorsLayer`, leave `CorsConfig` unset and add the layer around the nested auth router. [Cross-origin applications](/guides/cross-origin/) has a complete walkthrough.

## Request size and disabled paths

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::middleware::BodyLimitConfig;
use alibi::sqlx::SqlxStore;
use alibi::{AuthConfig, AuthResult, Alibi};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<Alibi<AppAuthSchema>> {
    // Hide a route entirely: matching requests receive 404.
    let config = config.disabled_path("/sign-up/email");
    Alibi::<AppAuthSchema>::new(config)
        .store(store)
        .body_limit(BodyLimitConfig::new().max_bytes(64 * 1024)) // default is 1 MiB
        .build()
        .await
}
```

Requests whose body exceeds the limit receive `413 BODY_TOO_LARGE`. Disabled paths are matched literally against the path relative to `base_path`. `advanced.skip_trailing_slashes` makes `/sign-in/email/` resolve to the registered route.

## Proxies, client IPs and forwarded hosts

Rate limits, session metadata and brute-force protection key on the client IP. By default the first address of `x-forwarded-for` is used; configure `advanced.ip_address` to match your edge (see [Session management](/concepts/session-management/#session-metadata)).

`advanced.trust_forwarded_host` makes URL resolution honor `x-forwarded-host` and `x-forwarded-proto`. Enable it only behind a proxy that overwrites those headers; clients must not be able to reach the application directly with forged values.

## Dynamic base URLs and trusted origins

Preview deployments and multi-tenant hosts cannot use one static `base_url`. Resolve it per request from an allow-list:

```rust
use async_trait::async_trait;
use alibi::config::{BaseUrlProtocol, DynamicBaseUrl, TrustedOriginsResolver};
use alibi::prelude::AuthRequest;
use alibi::{AuthConfig, AuthResult};

struct TenantOrigins;

#[async_trait]
impl TrustedOriginsResolver for TenantOrigins {
    // Additional trusted origins for this request; they never replace the static policy.
    async fn resolve(&self, request: &AuthRequest) -> AuthResult<Vec<String>> {
        Ok(match request.headers.get("x-tenant").map(String::as_str) {
            Some("acme") => vec!["https://acme.example.com".into()],
            _ => vec![],
        })
    }
}

fn auth_config(secret: &str) -> AuthConfig {
    AuthConfig::new(secret)
        .dynamic_base_url(DynamicBaseUrl {
            allowed_hosts: vec!["app.example.com".into(), "*.preview.example.com".into()],
            protocol: Some(BaseUrlProtocol::Https),
            fallback: Some("https://app.example.com".into()),
        })
        .trusted_origins_resolver(TenantOrigins)
}
```

The `Host` header (or `x-forwarded-host` when trusted) is matched against `allowed_hosts` (`*` and `?` wildcards, ports included). On a match, links, callbacks and the cookie `Secure` attribute use it; otherwise `fallback` is used — and a fallback never makes the rejected host trusted. If there is no match and no fallback, the request fails before any side effect. `BaseUrlProtocol::Auto` accepts both schemes, but plain HTTP is only trusted for loopback hosts.

## Secrets and passwords

- `secret` (or [`managed_secrets`](/reference/secrets/)) must be at least 32 characters; `build()` rejects anything shorter.
- Passwords are hashed with scrypt by default; you can supply a [`PasswordHasher`](/authentication/email-password/#custom-password-hashing).
- Plugins that store secrets (TOTP seeds, backup codes, OAuth tokens, API keys, OTP codes) encrypt or hash them, and most expose a storage option; see each plugin page.

## Error pages

OAuth failures redirect to an error destination. Set `api_error_url` for your own page; `render_error_page` controls the built-in HTML page for `GET /error` (enabled outside `NODE_ENV=production`):

```rust
use alibi::AuthConfig;

fn auth_config(secret: &str) -> AuthConfig {
    let mut config = AuthConfig::new(secret).api_error_url("https://app.example.com/auth/error");
    config.render_error_page = false; // redirect instead of rendering HTML
    config
}
```

## Checklist

- [ ] `base_url` uses HTTPS and is the real public origin.
- [ ] Every browser origin is in `trusted_origins` (and in CORS if cross-origin).
- [ ] `advanced.ip_address` matches your proxy chain, and clients cannot reach the application without going through the proxy.
- [ ] [Rate limits](/concepts/rate-limit/) use shared storage when you run several instances.
- [ ] `disable_origin_check` / `disable_csrf_check` are **not** set in production.
- [ ] Secrets live in your secret manager and have a [rotation plan](/reference/secrets/).
