---
title: "Rate limiting"
description: "Configure request quotas, endpoint rules, and shared storage."
---

Rate limiting defaults to 100 requests per 10 seconds, with tighter rules for sensitive endpoints.

## Set endpoint quotas

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};
use std::time::Duration;

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new())
        .rate_limit(
            RateLimitConfig::new()
                .default_limit(Duration::from_secs(10), 100)
                .endpoint("/sign-in/email", Duration::from_secs(60), 5),
        )
        .build()
        .await
}
```

Exact and wildcard overrides are ordered: the first match wins. `RateLimitRule::Disabled` bypasses a path; an asynchronous resolver can select a rule per request.

## Share quotas

| Storage | Scope |
| --- | --- |
| Default memory | One auth instance |
| Shared `MemoryRateLimitStorage` | Instances in one process |
| `CacheRateLimitStorage` | Processes using an atomic cache backend |
| SQLx / SeaORM rate-limit storage | Processes sharing a database |

Migrate database rate-limit storage before installing it; its ledger is separate from ordinary auth migrations. Memory storage bounds active buckets and rejects new ones at capacity. Redis uses fixed windows and requires positive whole-second TTLs; invalid TTLs or missing atomic increments fail closed.

`config.advanced.ip_address` determines client identity. Requests without a trusted IP share a bucket per path, and disabling IP tracking also disables rate limiting. Trusted server dispatch does not consume HTTP quotas.

See the [rate-limit audit](https://github.com/cschmatzler/better-auth-rs/blob/main/tests/compat/audits/core/request/rate-limits.md) for cleanup, numeric, and retry-header details.
