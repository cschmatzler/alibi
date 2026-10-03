---
title: "Secondary storage"
description: "Store sessions and verification credentials in memory or Redis."
---

Sessions use SQL by default. Set `session.secondary_storage` to store credentials in a cache; verification credentials have their own setting.

## Configure the backend

```rust
use better_auth::AuthConfig;
use better_auth::store::MemoryCacheAdapter;
use std::sync::Arc;

fn auth_config(secret: &str) -> AuthConfig {
    let cache = Arc::new(MemoryCacheAdapter::new());
    let mut config = AuthConfig::new(secret);
    config.session.secondary_storage = Some(cache.clone());
    config.verification.secondary_storage = Some(cache);
    config
}
```

Memory storage is local to the process. Use a shared backend, such as the `redis-cache` feature's `RedisAdapter`, across server processes.

Application-owned user and session models need `serde::Deserialize` and the `secondary_storage` option on their `AuthEntity` attributes. Other schemas can implement the snapshot and session-preparation traits directly.

## SQL persistence

| Setting | Behavior with a secondary backend |
| --- | --- |
| Default | Store sessions in the secondary backend |
| `store_in_database = true` | Also persist SQL session rows |
| `preserve_in_database = true` | Retain and expire SQL rows on revocation |

Cached credentials and user snapshots are authoritative. SQL fallback for a missing cached credential is allowed only with combined storage and preservation disabled. Invalid cached credentials cannot authenticate; session lists use the secondary index.

SQL rollback cannot undo completed cache writes. Failed issuance can leave cache entries until expiry, and refreshing cached user snapshots after a committed update is best effort. Treat the backend as credential storage.

[API keys](/plugins/api-key/#storage) configure their storage independently.
