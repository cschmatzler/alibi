---
title: "Secondary storage"
description: "Keep sessions and verification values in Redis or memory, with or without SQL persistence."
---

By default sessions and verification values (reset tokens, OTP codes, magic links, OAuth state) live in SQL. **Secondary storage** moves them to a key–value cache such as Redis, which gives you O(1) session lookups, native expiry and no cleanup jobs. Sessions and verification values are configured independently.

## Configure a backend

```rust
use alibi::AuthConfig;
use alibi::store::MemoryCacheAdapter;
use std::sync::Arc;

fn auth_config(secret: &str) -> AuthConfig {
    let cache = Arc::new(MemoryCacheAdapter::new());
    let mut config = AuthConfig::new(secret);
    config.session.secondary_storage = Some(cache.clone());
    config.verification.secondary_storage = Some(cache);
    config
}
```

`MemoryCacheAdapter` is local to one process — good for development and tests. For several server processes, use the Redis adapter (`redis-cache` feature):

```toml title="Cargo.toml"
alibi = { version = "0.2.0", features = ["axum", "redis-cache"] }
```

```rust
use alibi::AuthConfig;
use alibi::store::RedisAdapter;
use std::sync::Arc;

async fn auth_config(secret: &str, redis_url: &str) -> Result<AuthConfig, redis::RedisError> {
    let redis = Arc::new(RedisAdapter::new(redis_url).await?);
    let mut config = AuthConfig::new(secret);
    config.session.secondary_storage = Some(redis.clone());
    config.verification.secondary_storage = Some(redis);
    Ok(config)
}
```

(`redis::RedisError` comes from the `redis` crate; add `redis = "1"` or box the error.)

Application models that are cached must implement `serde::Deserialize`, and the user and session models need `secondary_storage` on their `AuthEntity` attribute so they can be snapshotted:

```rust nocheck
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, sqlx::FromRow, alibi::sqlx::AuthEntity)]
#[auth(role = "session", table = "sessions", secondary_storage)]
pub struct Session { /* … */ }
```

## What gets stored

| Setting | Behavior with a secondary backend |
| --- | --- |
| default | Sessions are stored **only** in the cache |
| `session.store_in_database = true` | Also write SQL session rows (durable audit trail, cache stays authoritative) |
| `session.preserve_in_database = true` | Keep ended sessions in SQL (expired, not deleted) when they are revoked |
| `verification.store_in_database = true` | Also persist verification values in SQL |

Cached credentials and user snapshots are authoritative. A SQL fallback for a *missing* cached session exists only when both `store_in_database` and `preserve_in_database` are off; a corrupted cached credential never authenticates. `list-sessions` reads the secondary index.

## Verification values

`config.verification` also controls how short-lived proofs are stored:

| Field | Default | Effect |
| --- | --- | --- |
| `secondary_storage` | none | Cache backend for verification values. Single-use values need atomic `get_and_delete` |
| `store_in_database` | `false` | Persist in SQL as well. Without a secondary backend, SQL is always used |
| `disable_cleanup` | `false` | Keep expired rows during lookup instead of removing them. An atomic consume still invalidates an expired proof it selects |
| `store_identifier` | plain | Transform stored identifiers: store them `Hashed`, or hash only selected prefixes (for example `email-otp`) with a `alibi::verification::VerificationIdentifierPolicy` |

## Writing a backend

Implement `alibi::store::CacheAdapter`:

| Method | Required | Used for |
| --- | --- | --- |
| `set(key, value, expires_in)`, `get`, `delete`, `exists`, `expire`, `clear` | yes | All storage |
| `get_and_delete(key)` | for verification values | Single-use tokens must be consumed atomically; read-then-delete is not enough |
| `increment(key, ttl)` | for [rate limits](/concepts/rate-limit/#share-quotas) | Atomic counter; TTL set only on creation |
| `set_without_expiry(key, value)` | for permanent [API keys](/plugins/api-key/#storage) | Non-expiring writes |

Methods you do not implement return an explicit error rather than silently degrading.

## Failure modes

- A SQL transaction cannot roll back completed cache writes. If session issuance fails after the cache write, the entry stays until it expires.
- Refreshing a cached user snapshot after a committed update is best-effort.
- Treat the backend as credential storage: authenticate it, encrypt traffic and restrict network access.

[API keys](/plugins/api-key/#storage) choose their storage independently of sessions.
