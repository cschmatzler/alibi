---
title: "API key"
description: "Issue, verify and manage scoped, rate-limited, expiring API keys for users and organizations."
---

API keys are long-lived credentials for programs: CI jobs, integrations, customers calling your public API. `ApiKeyPlugin` creates them, stores only a **hash**, authenticates requests that present one, and enforces expiry, usage quotas with refill, rate limits and resource permissions.

## Schema

```bash
better-auth-rs generate --plugins api-key -o src/auth_schema.rs
```

The `api_keys` table stores the key **hash** (never the plaintext), a short `start` fragment for display, the owner (`reference_id`), the configuration it belongs to (`config_id`), limits and counters, `permissions` and `metadata` (as JSON text), and timestamps.

The generated schema matches what the store reads and writes: the owner lives in **`reference_id`** and the configuration name in **`config_id`** (`TEXT NOT NULL DEFAULT 'default'`). The table is optional for core-only installs: user deletion removes a user's keys when `api_keys` exists and skips it otherwise.

`run_app_migrations` creates bare tables. For production, add a unique constraint on `key` and an index on `reference_id`, as the library's bundled schema (`SchemaMigrator::migrate`, see [Database](/concepts/database/#migrations)) does:

```sql
CREATE TABLE api_keys (
    id TEXT NOT NULL PRIMARY KEY, name TEXT, start TEXT, prefix TEXT,
    key TEXT NOT NULL UNIQUE,
    reference_id TEXT NOT NULL, config_id TEXT NOT NULL DEFAULT 'default',
    refill_interval REAL, refill_amount REAL, last_refill_at TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    rate_limit_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    rate_limit_time_window REAL, rate_limit_max REAL,
    request_count REAL, remaining REAL, last_request TEXT, expires_at TEXT,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    permissions TEXT, metadata TEXT
);
CREATE INDEX idx_api_keys_reference_id ON api_keys (reference_id);
```

## Setup

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::ApiKeyPlugin;
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(
            ApiKeyPlugin::builder()
                .prefix("mykey_".to_owned())
                .enable_metadata(true)
                .enable_session_for_api_keys(true)
                .build(),
        )
        .build()
        .await
}
```

`ApiKeyPlugin::builder()…build()` takes the options listed [below](#configuration); `ApiKeyPlugin::with_config(ApiKeyConfig)` is the struct equivalent.

## Create and use a key

A signed-in user creates a key. The **plaintext key is returned once** — store it now, because only a hash is kept:

```bash
curl -b cookies.txt http://localhost:3000/api/auth/api-key/create \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"name":"ci","expiresIn":86400,"metadata":{"env":"ci"}}'
```

```json
{"key":"mykey_neUohyGRuHjOEKnNbBpOMPjLiqyuPwCudhROtmXrlMJkuDvVwijbUESKOgKwNSqn","id":"e3d15303-f0ae-489a-9611-9678aae6fad3","name":"ci","start":"mykey_","prefix":"mykey_","referenceId":"dac58f63-…","configId":"default","enabled":true,"rateLimitEnabled":true,"rateLimitTimeWindow":86400000,"rateLimitMax":10,"requestCount":0,"remaining":null,"refillInterval":null,"refillAmount":null,"lastRefillAt":null,"lastRequest":null,"expiresAt":"2026-10-05T10:17:10.792Z","createdAt":"…","updatedAt":"…","permissions":null,"metadata":{"env":"ci"}}
```

The client then presents the key in the `x-api-key` header. With `enable_session_for_api_keys(true)` **any** auth endpoint treats the request as the key owner's session — including `/get-session`:

```bash
curl http://localhost:3000/api/auth/get-session -H 'x-api-key: mykey_neUohyGR…'
# {"user":{…},"session":{"id":"<key id>","token":"mykey_neUohyGR…","expiresAt":"<key expiry>",…}}
```

The virtual session is not stored; it exists for the request. Without that option, keys are verified by your own code (below) — the right choice for a public API that is *not* the auth server.

A rejected key answers with a stable code:

```json
{"code":"KEY_DISABLED","message":"API Key is disabled"}
```

| Status | `code` | Meaning |
| --- | --- | --- |
| 401 | `INVALID_API_KEY`, `KEY_DISABLED`, `KEY_EXPIRED` | Unknown, disabled or expired key (during authentication) |
| 429 | `RATE_LIMITED` (with `details.tryAgainIn` in ms), `USAGE_EXCEEDED` | Rate limit or quota exhausted |
| 403 | `INSUFFICIENT_API_KEY_PERMISSIONS`, `USER_NOT_MEMBER_OF_ORGANIZATION` | Management calls without the needed permission or membership |
| 400 | `SERVER_ONLY_PROPERTY`, `INVALID_PREFIX_LENGTH`, `NAME_REQUIRED`, `EXPIRES_IN_TOO_SMALL`, … | Invalid management input. `SERVER_ONLY_PROPERTY` means a client tried to set `remaining`, `refill*`, `rateLimit*` or `permissions` |

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api-key/create` | Create a key: `name`, `prefix`, `expiresIn` (seconds), `metadata`, `configId`, `organizationId` |
| `GET` | `/api-key/get?id=…` | One key (no secret, no hash) |
| `GET` | `/api-key/list` | The user's keys (or an organization's, with `organizationId`): `{"apiKeys":[…],"total":n}`; supports `limit`, `offset`, `sortBy`, `sortDirection`, `configId` |
| `POST` | `/api-key/update` | `keyId` plus `name`, `enabled`, `expiresIn` (null clears), `metadata` |
| `POST` | `/api-key/delete` | `{"keyId":"…"}` → `{"success":true}` |

From HTTP, `remaining`, `refillAmount`, `refillInterval`, `rateLimitEnabled`, `rateLimitTimeWindow`, `rateLimitMax`, `permissions` and `userId` are **server-only**: set them with server-side calls so users cannot grant themselves quota or scopes.

## Configuration

| Builder option | Default | Effect |
| --- | --- | --- |
| `config_id` | `"default"` | Name of this configuration |
| `references` | `User` | `ApiKeyReferences::User` or `Organization` — who owns keys |
| `prefix` | none | Prepended to every key (`mykey_…`); validated by `min/max_prefix_length` |
| `key_length` | `64` | Random characters after the prefix |
| `custom_key_generator` | none | `ApiKeyGenerator`: produce the whole key yourself |
| `disable_key_hashing` | `false` | Store keys in plaintext (not recommended) |
| `starting_characters_length`, `store_starting_characters` | `6`, `true` | Keep a visible fragment (`start`) for the UI |
| `min_prefix_length`, `max_prefix_length` | `1`, `32` | Prefix bounds |
| `min_name_length`, `max_name_length`, `require_name` | `1`, `32`, `false` | Name policy |
| `enable_metadata` | `false` | Allow `metadata` objects |
| `key_expiration` | none, 1–365 days | `KeyExpirationConfig { default_expires_in, disable_custom_expires_time, max_expires_in (days), min_expires_in (days) }` |
| `rate_limit` | on, 10 per 24 h | `RateLimitDefaults { enabled, time_window (ms), max_requests }` applied to new keys |
| `default_permissions`, `default_permissions_callback` | none | Permissions for keys created without explicit ones |
| `api_key_headers` | `["x-api-key"]` | Headers searched for the key |
| `custom_api_key_getter` | none | `ApiKeyGetter`: extract the key your own way (replaces the headers) |
| `custom_api_key_validator` | none | `ApiKeyValidator`: extra acceptance predicate, checked before quota/rate-limit writes |
| `enable_session_for_api_keys` | `false` | Authenticate auth endpoints with a key (virtual session) |
| `storage`, `fallback_to_database`, `secondary_storage`, `custom_storage` | database | See [Storage](#storage) |
| `defer_updates` | `false` | Merge secondary-storage usage updates in the background |

Quota and rate limits are per key: each request consumes one `remaining` use (if set) and one rate-limit slot per `rateLimitTimeWindow`; `refillAmount` uses are restored every `refillInterval` ms.

### Several configurations and organization keys

Register more than one configuration to run, say, user keys and organization keys side by side. Each key records its `config_id`:

```rust
use better_auth::plugins::ApiKeyPlugin;
use better_auth::plugins::api_key::{ApiKeyConfig, ApiKeyReferences};

fn api_keys() -> ApiKeyPlugin {
    let org_keys = ApiKeyConfig {
        config_id: "org".into(),
        references: ApiKeyReferences::Organization,
        prefix: Some("org_".into()),
        ..Default::default()
    };
    ApiKeyPlugin::builder().prefix("usr_".to_owned()).build().configuration(org_keys)
}
```

Organization keys need the [organization plugin](/plugins/organization/): callers pass `organizationId` and must hold the `apiKey` permission in that organization (only the creator role has it by default).

## Verify keys in your own API

Verification is a **server-only** operation, not an HTTP route. It checks hash, enabled flag, expiry, rate limit and quota (consuming one use) and, optionally, required permissions:

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::BetterAuth;
use better_auth::endpoint::EndpointOptions;
use better_auth::plugins::ApiKeyPlugin;
use better_auth::plugins::api_key::ApiKeyVerificationInput;

async fn authorize(
    auth: &BetterAuth<AppAuthSchema>,
    presented: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let result = auth
        .dispatch_endpoint(
            ApiKeyPlugin::verify_endpoint(&ApiKeyVerificationInput {
                key: presented.to_owned(),
                config_id: None,
                permissions: serde_json::from_value(serde_json::json!({ "projects": ["read"] })).ok(),
            })?,
            EndpointOptions::default(),
        )
        .await?
        .decode()?;
    // result.valid, result.error (code, message, details.tryAgainIn), result.key (public view)
    Ok(result.valid)
}
```

The returned `key` omits the plaintext and the hash. Permissions are `IndexMap<String, Vec<String>>` — resource to actions — and are checked **before** quota and rate limit are consumed.

### Create and update with server-only fields

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::BetterAuth;
use better_auth::endpoint::EndpointOptions;
use better_auth::plugins::ApiKeyPlugin;
use better_auth::plugins::api_key::CreateKeyRequest;

async fn provision(
    auth: &BetterAuth<AppAuthSchema>,
    user_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let request = CreateKeyRequest {
        user_id: Some(user_id.to_owned()),
        name: Some("partner".to_owned()),
        remaining: Some(10_000.0),
        refill_amount: Some(10_000.0),
        refill_interval: Some(30.0 * 24.0 * 3600.0 * 1000.0), // monthly, in ms
        rate_limit_max: Some(60.0),
        rate_limit_time_window: Some(60_000.0),
        permissions: serde_json::from_value(serde_json::json!({ "projects": ["read", "write"] })).ok(),
        ..Default::default()
    };
    let created = auth
        .dispatch_endpoint(ApiKeyPlugin::create_endpoint(&request)?, EndpointOptions::default())
        .await?
        .decode()?;
    Ok(created.key) // deliver this plaintext only to the key's owner
}
```

`ApiKeyPlugin::update_endpoint(&UpdateKeyRequest)` changes the same fields later, and `ApiKeyPlugin::delete_all_expired_endpoint()` forces cleanup of expired keys (expired keys are also removed opportunistically).

## Storage

| Mode | Where keys live | Notes |
| --- | --- | --- |
| Database (default) | The `api_keys` table | Atomic, durable quota and rate-limit admission |
| `ApiKeyStorageMode::SecondaryStorage` | A cache (`secondary_storage`) or your `custom_storage: Arc<dyn ApiKeyStorage>` | Fast lookups. Admission is a **non-atomic merge** — concurrent requests can slightly overshoot quota |
| Secondary + `fallback_to_database` | Cache plus database rows | Durable rows and guarded database admission with cache speed |

API-key storage is independent of [session storage](/concepts/secondary-storage/). A permanent key (no expiry) in a cache requires `set_without_expiry` support. Cache failures can leave earlier writes in place; `defer_updates` sends secondary usage writes to the app's [background-task handler](/concepts/notifications/#deliver-in-the-background). `ApiKeyStorage` has three async methods: `get`, `set(key, value, ttl)` and `delete`; implementations must propagate failures. With [no database](/databases/no-database/), keys live in memory for the instance's lifetime.

## Security notes

- Keys are bearer credentials: serve them over HTTPS only, never log them, and show the plaintext once at creation.
- Keep key hashing on (the default, see `disable_key_hashing`); the `start` fragment lets users recognize a key without exposing it.
- Give keys the **least** permissions and short expiries; rotate by creating a new key and deleting the old.
- Combine with [rate limiting](/concepts/rate-limit/) on your own API for protection beyond per-key limits.

## Frontend

See the official [API key guide](https://www.better-auth.com/docs/plugins/api-key).
