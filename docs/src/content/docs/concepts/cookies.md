---
title: "Cookies"
description: "The cookies Better Auth sets, how to configure their attributes, and cookie-based session caches."
---

Better Auth RS keeps browser state in `HttpOnly`, `SameSite=Lax` cookies. All names share one prefix and all attributes can be overridden — globally or per cookie.

## Cookies set by the library

| Logical name | Default cookie name | Purpose |
| --- | --- | --- |
| `session_token` | `better-auth.session_token` | Signed session token |
| `session_data` | `better-auth.session_data` | [Cached session payload](#cache-the-session-in-a-cookie), when enabled |
| `dont_remember` | `better-auth.dont_remember` | Marks a "remember me: off" session |
| `account_data` | `better-auth.account_data` | Provider account data for [stateless OAuth](/databases/no-database/) flows |
| `state` / `oauth_state` | `better-auth.state` / `better-auth.oauth_state` | OAuth state during a sign-in round trip (database / cookie strategy) |
| `two_factor`, `trust_device` | `better-auth.two_factor`, `better-auth.trust_device` | [Two-factor](/plugins/two-factor/) challenge and trusted-device proof |
| `admin_session` | `better-auth.admin_session` | The admin's original session during [impersonation](/plugins/admin/#impersonation) |
| `last_used_login_method` | `better-auth.last_used_login_method` | [Last login method](/plugins/last-login-method/) hint (readable by JavaScript) |
| `<session_token>_multi-<token>` | `better-auth.session_token_multi-…` | One signed cookie per remembered account in [multi-session](/plugins/multi-session/) |

Over HTTPS every name gets the `__Secure-` prefix (for example `__Secure-better-auth.session_token`). The decision follows `AuthConfig::base_url`, or `advanced.use_secure_cookies` when set.

## Configure names and attributes

```rust
use better_auth::AuthConfig;
use better_auth::config::{
    AdvancedConfig, CookieAttributes, CookieOverride, SameSite,
};
use std::collections::HashMap;

fn auth_config(secret: &str) -> AuthConfig {
    AuthConfig::new(secret)
        .base_url("https://auth.example.com")
        .cookie_prefix("myapp") // myapp.session_token, __Secure-myapp.session_token, …
        .advanced(AdvancedConfig {
            // Applied to every cookie unless overridden below.
            default_cookie_attributes: CookieAttributes {
                same_site: Some(SameSite::None), // cross-site embeds need Secure + None
                partitioned: Some(true),         // CHIPS
                ..Default::default()
            },
            // Per-cookie overrides, keyed by logical name.
            cookies: HashMap::from([(
                "session_token".to_owned(),
                CookieOverride {
                    name: Some("sid".into()),
                    attributes: CookieAttributes {
                        max_age: Some(60.0 * 60.0 * 24.0 * 14.0),
                        ..Default::default()
                    },
                },
            )]),
            ..Default::default()
        })
}
```

`CookieAttributes` accepts `secure`, `http_only`, `same_site`, `path`, `domain`, `max_age` (seconds, may be fractional), `expires` (UTC) and `partitioned`. Values are validated when a cookie is emitted: the published 400-day cap on `Max-Age`/`Expires` applies, and clearing a cookie sets `Max-Age=0` while keeping its other attributes. Reserved prefixes are enforced — a `__Secure-` or `__Host-` cookie is always `Secure`.

Session-token cookies use the real session lifetime, or no `Max-Age` for a browser-session ("remember me" off). The session-cache cookie uses its own age (below). Neither changes how long the server-side session is valid or when it is refreshed.

## Share cookies across subdomains

```rust
use better_auth::AuthConfig;

fn auth_config(secret: &str) -> AuthConfig {
    AuthConfig::new(secret)
        .base_url("https://auth.example.com")
        .trusted_origin("https://app.example.com")
        // Cookie Domain=example.com: readable by app.example.com, www.example.com, …
        .cross_sub_domain_cookies("example.com")
}
```

Use this only when every subdomain is trusted, since any of them can then read the (HttpOnly-protected, but still sent) cookies and set cookies for the parent. `cross_sub_domain_cookies_from_base_url()` uses the hostname of the base URL (without port) as the domain; it does **not** compute a registrable parent domain — pass the parent explicitly when you need one. Browsers on a different *site* (not just a subdomain) need `SameSite=None; Secure` and credentialed CORS; see [Cross-origin applications](/guides/cross-origin/).

## Cache the session in a cookie

A cookie cache embeds the session and user in a second cookie (`session_data`) so most requests skip the database. It does not replace the database session: operations that need an authoritative answer, such as revoking sessions, still check the stored row.

```rust
use better_auth::AuthConfig;
use better_auth::config::{CookieCacheConfig, CookieCacheStrategy};

fn auth_config(secret: &str) -> AuthConfig {
    AuthConfig::new(secret).session_cookie_cache(CookieCacheConfig {
        enabled: true,
        max_age: 5.0 * 60.0, // revalidate against the database every 5 minutes
        strategy: CookieCacheStrategy::Jwe,
        version: None,
    })
}
```

| Strategy | Format | Confidentiality | Notes |
| --- | --- | --- | --- |
| `Compact` (default) | Base64url payload + HMAC-SHA256 | Signed only | Smallest; payload is readable by the client |
| `Jwt` | HS256 JWT | Signed only | Signed with the current auth secret, or with the local [JWT keyring](/plugins/jwt/) when `JwtPluginConfig::session_cookie_cache` is on |
| `Jwe` | Direct-key AES-256-CBC-HS512 | Encrypted | Hides the session and user from the client; reads retained [managed keys](/reference/secrets/) |

`max_age` is in seconds (default 300). Large caches are split into numbered chunk cookies automatically. A cached read honors public field policies — hidden [additional fields](/concepts/field-policies/) are never exposed.

Trade-offs to understand before enabling:

- **Revocation lag.** A revoked or deleted session keeps authenticating from its cache until `max_age` elapses. Set `max_age` to the staleness you can tolerate, or invalidate everything by changing the cache **version** (`CookieCacheConfig::version`, a `better_auth_core::session::cookie_cache::CookieCacheVersion` literal or async resolver).
- **Key rotation.** The session-token cookie is signed with the *current* secret only; rotating it invalidates existing cookies even when you retain old encryption keys. JWE caches can still be read with retained keys. See [Secrets](/reference/secrets/).
- **Bypass.** `GET /get-session?disableCookieCache=true` forces a database read.

## Stateless sessions

Setting `config.session = config.session.stateless()` makes the cache cookie the only session record — no session rows are written. See [No database](/databases/no-database/) for renewal, revocation and the exact guarantees.

## Frontend

For `credentials: "include"` and cross-origin cookie requirements, see [Cross-origin applications](/guides/cross-origin/) and the official [cookies guide](https://www.better-auth.com/docs/concepts/cookies).
