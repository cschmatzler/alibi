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

## Cache strategies

| Strategy | Protection |
| --- | --- |
| `Compact` | Signed compact payload |
| `Jwt` | JWT signed with the current auth secret |
| `Jwe` | Encrypted cookie with a derived key |

`JwtPluginConfig::session_cookie_cache = true` selects the local JWT keyring for JWT caches; remote signers cannot protect these cookies.

JWE caches can read retained managed keys. The separately signed session token uses only the current secret, so rotating it invalidates existing signed cookies. Caches preserve public field policies and do not replace the authoritative checks used by sensitive operations.
