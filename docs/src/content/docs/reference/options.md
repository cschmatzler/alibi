---
title: "Options"
description: "Complete reference for AuthConfig, the builder, and where each option is explained."
---

`AuthConfig` is created explicitly and passed to **both** the store and the builder, so they share session, field and account policy. Builder-style methods cover the common options; the rest are public fields.

```rust
use better_auth::AuthConfig;

fn auth_config(secret: &str) -> AuthConfig {
    AuthConfig::new(secret)
        .app_name("My application")
        .base_url("https://auth.example.com")
        .base_path("/api/auth")
        .trusted_origin("https://app.example.com")
}
```

Instance-level middleware and features are registered on `AuthBuilder` ([below](#authbuilder)).

## Top level

| Field / method | Default | Purpose | Guide |
| --- | --- | --- | --- |
| `AuthConfig::new(secret)` / `secret` | — | Signing and encryption secret, at least 32 characters | [Secrets](/reference/secrets/) |
| `managed_secrets(ManagedSecrets)` | none | Versioned encryption keys with rotation | [Secrets](/reference/secrets/) |
| `app_name(…)` | `"Better Auth"` | Name used in cookie prefixes, TOTP issuers and email text | — |
| `base_url(…)` | `http://localhost:3000` | Public origin; also sets the `Secure` cookie flag from the scheme | [Installation](/installation/) |
| `dynamic_base_url(DynamicBaseUrl)` | none | Per-request base URL from an allow-list of hosts | [Security](/concepts/security/#dynamic-base-urls-and-trusted-origins) |
| `base_path(…)` | `/api/auth` | Where routes are mounted | [Installation](/installation/) |
| `trusted_origin(…)`, `trusted_origins(vec)` | none | Origins allowed for CSRF checks, CORS and redirects (glob patterns allowed) | [Security](/concepts/security/) |
| `trusted_origins_resolver(…)` | none | Async policy adding trusted origins per request | [Security](/concepts/security/) |
| `disabled_path(…)`, `disabled_paths(vec)` | none | Paths that answer `404` | [Security](/concepts/security/#request-size-and-disabled-paths) |
| `api_error_url(…)` | none | Default OAuth error destination | [Security](/concepts/security/#error-pages) |
| `render_error_page` | `true` unless `NODE_ENV=production` | Render the built-in `GET /error` page | [Security](/concepts/security/#error-pages) |
| `email_provider` | none (set via `AuthBuilder::email_provider`) | Default mail transport | [Email](/concepts/notifications/) |
| `awaited_notification_errors(…)` | `Propagate` | Fail or log when awaited delivery fails | [Email](/concepts/notifications/#delivery-failures) |
| `background_tasks(handler)` | none | Run delivery in the background | [Email](/concepts/notifications/#deliver-in-the-background) |
| `user_validation` | none | Admit or reject new identities | [Users & accounts](/concepts/users-accounts/#validate-new-identities) |
| `cookie_prefix(…)` | none | Prefix for every cookie name | [Cookies](/concepts/cookies/) |
| `cross_sub_domain_cookies(domain)`, `cross_sub_domain_cookies_from_base_url()` | off | Share cookies across subdomains | [Cookies](/concepts/cookies/#share-cookies-across-subdomains) |
| `session_cookie_cache(CookieCacheConfig)` | none | Cookie-based session cache | [Cookies](/concepts/cookies/#cache-the-session-in-a-cookie) |
| `session_expires_in`, `session_update_age`, `session_fresh_age`, `disable_session_refresh` | see Session | Shortcuts for common session settings | [Sessions](/concepts/session-management/) |
| `password_min_length(n)` | `8` | Fallback minimum password length | [Email & password](/authentication/email-password/) |
| `jwt_expires_in(…)` | 24 hours | Lifetime for core-signed JWT values | [JWT](/plugins/jwt/) |
| `advanced(AdvancedConfig)`, `disable_csrf_check`, `disable_origin_check` | see Advanced | Advanced options | [Security](/concepts/security/) |

## `session` — `SessionConfig`

| Field | Default | Purpose |
| --- | --- | --- |
| `expires_in` | 7 days | Session lifetime |
| `update_age` | `Some(1 day)` | Refresh at most this often (`None` = every read) |
| `fresh_age` | `Some(1 day)` | "Recently signed in" window; `None`/zero disables the check |
| `disable_session_refresh` | `false` | Never extend on read |
| `defer_session_refresh` | `false` | Report `needsRefresh`, refresh via `POST /get-session` |
| `cookie_name` | `better-auth.session_token` | Session cookie name |
| `cookie_secure`, `cookie_http_only`, `cookie_same_site` | from `base_url`, `true`, `Lax` | Cookie attributes |
| `cookie_cache` | none | `CookieCacheConfig { enabled, max_age (300 s), strategy (Compact/Jwt/Jwe), version }` |
| `cookie_refresh_cache` | `Disabled` | Stateless renewal: `Disabled`, `Automatic`, `UpdateAge(seconds)` |
| `stateless` | `false` | Cookie-only sessions — use `session.stateless()` |
| `secondary_storage` | none | [Secondary storage](/concepts/secondary-storage/) backend |
| `store_in_database`, `preserve_in_database` | `false` | SQL persistence alongside secondary storage |
| `additional_fields` | none | Extra [session fields](/concepts/field-policies/) |

## `user`, `account` and `verification`

| Field | Default | Purpose |
| --- | --- | --- |
| `user.additional_fields` | none | [Additional user fields](/concepts/field-policies/) |
| `account.additional_fields` | none | Additional account fields |
| `account.update_account_on_sign_in` | `true` | Refresh stored provider tokens at each sign-in |
| `account.encrypt_oauth_tokens` | `false` | Encrypt access/refresh tokens at rest |
| `account.store_account_cookie`, `account.cookie_max_age` | `false`, session cache age | Keep account data in a cookie |
| `account.store_state_strategy` | `Automatic` | OAuth state in `Cookie` or `Database` |
| `account.skip_state_cookie_check` | `false` | Skip state-cookie comparison (**insecure**) |
| `account.account_linking` | see [Users & accounts](/concepts/users-accounts/#linking-policy) | `enabled`, `trusted_providers`, `allow_different_emails`, … |
| `verification.secondary_storage`, `store_in_database` | none, `false` | [Verification storage](/concepts/secondary-storage/#verification-values) |
| `verification.store_identifier` | plain | Hash or transform stored identifiers |
| `verification.disable_cleanup` | `false` | Keep expired rows during lookup |
| `password.min_length` | `8` | Fallback minimum |
| `password.require_uppercase`, `require_lowercase`, `require_numbers`, `require_special` | `false` | [Composition rules](/authentication/email-password/#password-composition-rules) |

## `advanced` — `AdvancedConfig`

| Field | Default | Purpose |
| --- | --- | --- |
| `ip_address` | `x-forwarded-for`, `/64` IPv6 grouping | `IpAddressConfig { headers, trusted_proxies, ipv6_subnet, localhost_fallback, disable_ip_tracking }` — [Sessions](/concepts/session-management/#session-metadata) |
| `trust_forwarded_host` | `false` | Honor `x-forwarded-host`/`-proto` when resolving URLs |
| `disable_csrf_check` | `None` | Explicit CSRF toggle |
| `disable_origin_check` | `false` | Skip all origin and redirect validation (**insecure**) |
| `disable_origin_check_paths` | none | Per-path origin opt-out |
| `skip_trailing_slashes` | `false` | Resolve `/path/` to `/path` |
| `use_secure_cookies` | from `base_url` | Force the `__Secure-` prefix and `Secure` |
| `cross_sub_domain_cookies` | none | Cookie `Domain` for subdomain sharing |
| `cookies` | none | Per-cookie `CookieOverride { name, attributes }` |
| `default_cookie_attributes` | none | `CookieAttributes` for every cookie |
| `cookie_prefix` | none | Name prefix |
| `database.default_find_many_limit` | `100` | Default page size |
| `database.use_number_id` | `false` | Declares numeric ids (makes invitation email verification default on) |
| `trusted_proxy_headers` | none | Headers trusted for the client IP behind a proxy |

## `AuthBuilder`

| Method | Purpose | Guide |
| --- | --- | --- |
| `.store(store)` / `.store_arc(arc)` | The auth store (required, except with `without_database`) | [Databases](/databases/sqlx/) |
| `.plugin(plugin)` | Register a plugin | [Plugins](/concepts/plugins/) |
| `.endpoint_hook(hook)` | Logical-call hook | [Hooks](/concepts/hooks/) |
| `.rate_limit(RateLimitConfig)` | Rate-limit policy | [Rate limiting](/concepts/rate-limit/) |
| `.cors(CorsConfig)` | CORS headers | [Security](/concepts/security/#cors) |
| `.csrf(CsrfConfig)` | Toggle request protection | [Security](/concepts/security/) |
| `.body_limit(BodyLimitConfig)` | Maximum request body | [Security](/concepts/security/#request-size-and-disabled-paths) |
| `.email_provider(provider)` | Default mail transport | [Email](/concepts/notifications/) |
| `.middleware(mw)` | Custom `Middleware` (before/after request) | — |
| `.telemetry(TelemetryConfig)` | Opt-in telemetry | [Telemetry](/reference/telemetry/) |
| `AuthBuilder::without_database(config)` | In-memory store and stateless sessions | [No database](/databases/no-database/) |
| `.build().await` | Validate, initialize plugins, return `BetterAuth` | — |

## Plugin options

Plugin options live on each plugin value — see the [plugin overview](/plugins/). `AuthConfig` never needs to know about them.

For exact types and any option not listed here, read the [AuthConfig source](https://github.com/cschmatzler/better-auth-rs/blob/main/crates/core/src/config/mod.rs). Related upstream topic: [Options](https://www.better-auth.com/docs/reference/options).
