---
title: "Rate limiting"
description: "Default quotas, per-endpoint rules, dynamic policies and shared storage."
---

Rate limiting is on by default. Each client IP gets a quota **per path**: the default is 100 requests per 10 seconds, with much tighter built-in rules for credential and email endpoints. A request over quota is answered with `429` and an `X-Retry-After` header (seconds until the next request is admitted):

```http
HTTP/1.1 429 Too Many Requests
x-retry-after: 9

{"message":"Too many requests. Please try again later."}
```

## Built-in rules

| Paths | Limit |
| --- | --- |
| `/sign-in*`, `/sign-up*`, `/change-password`, `/change-email` | 3 requests / 10 s |
| `/request-password-reset`, `/send-verification-email`, `/email-otp/send-verification-otp`, `/email-otp/request-password-reset`, `/forget-password*` | 3 requests / 60 s |
| `/phone-number*` | 10 requests / 60 s |
| `/device` | 5 requests per code lifetime |
| everything else | `RateLimitConfig::default` (100 / 10 s) |

Plugins that issue codes carry their own limits too — for example the email OTP and magic-link plugins take a `rate_limit` option. Windows are **rolling**: every admitted request extends the window, and the bucket resets after the window passes without exhausting the quota.

## Configure quotas

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::EmailPasswordPlugin;
use alibi::sqlx::SqlxStore;
use alibi::{AuthConfig, AuthResult, BetterAuth};
use std::time::Duration;

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .rate_limit(
            RateLimitConfig::new()
                .default_limit(Duration::from_secs(10), 100)
                .endpoint("/sign-in/email", Duration::from_secs(60), 5)
                .endpoint("/get-session", Duration::from_secs(10), 1000),
        )
        .build()
        .await
}
```

Rules are matched against the path **relative to `base_path`** and checked in the order you add them: the first match wins and replaces both the default and any built-in rule. A pattern may use `*` (any characters) and `?` (one character); everything else is literal. For example `"/organization/*"` covers every organization endpoint.

Disable a path, or compute the rule per request:

```rust
use async_trait::async_trait;
use alibi::middleware::{EndpointRateLimit, RateLimitConfig, RateLimitResolver, RateLimitRule};
use alibi::prelude::AuthRequest;
use alibi::AuthResult;
use std::sync::Arc;

#[derive(Debug)]
struct TrustedPartners;

#[async_trait]
impl RateLimitResolver for TrustedPartners {
    // `inherited` is the rule that would otherwise apply. Return `None` to skip limiting.
    async fn resolve(
        &self,
        request: &AuthRequest,
        inherited: &EndpointRateLimit,
    ) -> AuthResult<Option<EndpointRateLimit>> {
        Ok(match request.headers.get("x-partner-key") {
            Some(_) => None,
            None => Some(inherited.clone()),
        })
    }
}

fn limits() -> RateLimitConfig {
    RateLimitConfig::new()
        .rule("/ok", RateLimitRule::Disabled)
        .rule("/api-key/*", RateLimitRule::Dynamic(Arc::new(TrustedPartners)))
}
```

`RateLimitConfig::enabled(false)` turns the middleware off entirely, and `max_buckets` (default 100 000) bounds memory. When the bucket table is full, **new** clients are rejected instead of evicting active ones — a flood of spoofed keys cannot reset a real attacker's quota.

## Client identity

Quotas are keyed by `<client ip>|<path>`. The IP comes from `advanced.ip_address` (see [Session management](/concepts/session-management/#session-metadata)): which headers to trust, which proxies to strip, and the IPv6 grouping prefix (default `/64`, so one subscriber's whole prefix shares a bucket).

- Requests with no resolvable IP share a single bucket per path (`no-trusted-ip`). Behind a proxy, configure the header, or all clients will throttle each other.
- `disable_ip_tracking: true` disables rate limiting entirely, since there is nothing to key on.
- Trusted server calls made with `dispatch_endpoint` do not pass through HTTP middleware and never consume quota.

## Share quotas

The default store is process-local memory. Run several instances? Share the counters:

| Storage | Scope | Window |
| --- | --- | --- |
| Default memory | One auth instance | Rolling |
| `MemoryRateLimitStorage` in an `Arc` | Several instances in one process | Rolling |
| `CacheRateLimitStorage` (Redis via `redis-cache`) | Every process using the cache | Fixed |
| `SqlxRateLimitStorage` / `SeaOrmRateLimitStorage` | Every process sharing the database | Rolling |

```rust
use alibi::middleware::{CacheRateLimitStorage, RateLimitConfig};
use alibi::store::RedisAdapter;
use std::sync::Arc;

async fn redis_limits(url: &str) -> Result<RateLimitConfig, Box<dyn std::error::Error>> {
    let cache = Arc::new(RedisAdapter::new(url).await?);
    Ok(RateLimitConfig::new().storage(Arc::new(CacheRateLimitStorage::new(cache))))
}
```

The cache backend must support an atomic `increment` (Redis and `MemoryCacheAdapter` do). A fixed window counts every attempt, including rejected ones. Window lengths must be positive whole seconds for Redis; an unusable TTL or a backend without atomic increments **fails closed** — the request is not admitted.

For database storage, install the table before serving requests. It has its own migration ledger (`better_auth_rate_limit_migrations`), separate from the auth schema:

```rust
use alibi::middleware::RateLimitConfig;
use alibi::sqlx::{SqlxPool, SqlxRateLimitStorage};
use alibi::store::SchemaMigrator;
use alibi::AuthResult;
use std::sync::Arc;

async fn shared_limits(pool: SqlxPool) -> AuthResult<RateLimitConfig> {
    let storage = SqlxRateLimitStorage::new(pool);
    storage.migrate().await?;
    Ok(RateLimitConfig::new().storage(Arc::new(storage)))
}
```

`SeaOrmRateLimitStorage::new(database)` works the same way. Implement the `RateLimitStorage` trait (`async fn consume(&self, key, rule) -> RateLimitDecision`) to use any other backend; it must decide and consume atomically.

To limit your own routes, consume from the same storage and return `AuthError::rate_limited(retry_after)` for a blocked decision. Its response (`to_auth_response()`, or Axum's `IntoResponse`) is a `429` carrying `X-Retry-After`, like the middleware's:

```rust
use alibi::middleware::{EndpointRateLimit, RateLimitDecision, RateLimitStorage};
use alibi::{AuthError, AuthResult};

async fn admit(storage: &dyn RateLimitStorage, client: &str) -> AuthResult<()> {
    let rule = EndpointRateLimit {
        window_seconds: 60.0,
        max_requests: 10.0,
    };
    match storage.consume(&format!("{client}|/export"), &rule).await? {
        RateLimitDecision::Allowed => Ok(()),
        RateLimitDecision::Blocked { retry_after } => Err(AuthError::rate_limited(retry_after)),
    }
}
```

## Operational notes

- Windows are floating-point seconds and counts are floating-point numbers. A zero or `NaN` *default* window or count falls back to 10 s and 100.
- Because built-in rules are very tight, tests that sign in repeatedly should either raise `/sign-in/email` or call `.rate_limit(RateLimitConfig::new().enabled(false))`.
- Plugin rate limits (OTP, magic link, API key) are separate: [Email OTP](/plugins/email-otp/), [Magic link](/plugins/magic-link/), [API key](/plugins/api-key/).
