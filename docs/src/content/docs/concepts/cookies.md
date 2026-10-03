---
title: "Cookies"
description: "Session cookies, cookie caches, and encryption strategies."
---

Sessions use HTTP-only cookies. Configure cookie attributes and caching before constructing the auth store.

## Configure cookies and caching

```rust
use better_auth::AuthConfig;
use better_auth::config::{CookieCacheConfig, CookieCacheStrategy};

fn auth_config(secret: &str) -> AuthConfig {
    AuthConfig::new(secret)
        .base_url("https://auth.example.com")
        .trusted_origin("https://app.example.com")
        .session_cookie_cache(CookieCacheConfig {
            enabled: true,
            strategy: CookieCacheStrategy::Compact,
            ..Default::default()
        })
}
```

Use `cross_sub_domain_cookies("example.com")` only when those subdomains are trusted. A separate frontend origin also needs matching credentialed CORS configuration on the server.

`cross_sub_domain_cookies_from_base_url()` infers the configured or resolved URL's
hostname without its port. It does not select a registrable parent domain.
Explicit domains and per-cookie attributes retain their precedence.

`CookieAttributes` accepts floating point `max_age`, an optional UTC `expires`,
and `partitioned`. Cookie emitters such as `create_session_cookie` now return
`AuthResult<String>`; callers propagate serialization errors with `?` before
publishing headers. The published 400-day limits apply at emission, rather than
initialization. Clearing sets Max-Age to zero while retaining the other attributes.

```rust
use better_auth::{AuthConfig, AuthResult};
use better_auth::config::CookieAttributes;
use better_auth_core::utils::cookie_utils::create_session_cookie;

fn session_header(token: &str, config: &AuthConfig) -> AuthResult<String> {
    create_session_cookie(token, config)
}

let attributes = CookieAttributes {
    max_age: Some(121.9), // migrate integer literals to floating point
    partitioned: Some(true),
    ..Default::default()
};
```

Session-token issuance uses the actual session lifetime or omits Max-Age for a
browser session. Session-cache cookies use their own configured `session_data`
age; a zero age expires the cookie but retains the compact payload's 60-second
fallback. Negative ages omit Max-Age. These settings do not replace the embedded
session expiry or change the renewal policy.

## Cache strategies

| Strategy | Protection |
| --- | --- |
| `Compact` | Signed compact payload |
| `Jwt` | JWT signed with the current auth secret |
| `Jwe` | Encrypted cookie with a derived key |

`JwtPluginConfig::session_cookie_cache = true` selects the local JWT keyring for JWT caches; remote signers cannot protect these cookies.

JWE caches can read retained managed keys. The separately signed session token uses only the current secret, so rotating it invalidates existing signed cookies. Caches preserve public field policies and do not replace the authoritative checks used by sensitive operations.
