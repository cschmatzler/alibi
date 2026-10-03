---
title: "Session management"
description: "Session expiry, refresh, revocation, and storage."
---

The builder includes `SessionManagementPlugin` for session reads, sign-out, listing, and revocation.

## Configure lifetime

Configure sessions before constructing the store so both use the same options:

```rust
use better_auth::AuthConfig;
use chrono::Duration;

fn auth_config(secret: &str) -> AuthConfig {
    let mut config = AuthConfig::new(secret).base_url("http://localhost:3000");
    config.session.expires_in = Duration::days(7);
    config.session.update_age = Some(Duration::days(1));
    config
}
```

A read refreshes expiry after `update_age`. `disable_session_refresh` stops automatic refresh; `defer_session_refresh` moves refresh writes to POST `/get-session`. That method is rejected when deferral is disabled.

## Endpoints

Paths are relative to `/api/auth`:

| Method | Path | Action |
| --- | --- | --- |
| GET | `/get-session` | Read the current session |
| GET | `/list-sessions` | List active sessions |
| POST | `/sign-out` | End the current session |
| POST | `/revoke-session` | Revoke a specific token |
| POST | `/revoke-sessions` | Revoke all sessions |
| POST | `/revoke-other-sessions` | Keep only the current session |

Use [Axum extractors](/integrations/axum/) in protected handlers. Sessions use SQL by default unless [secondary storage](/concepts/secondary-storage/) or stateless mode is configured; a [cookie cache](/concepts/cookies/) can reduce reads.

## Without a database

`AuthBuilder::without_database` provisions users, accounts, verification records and sessions in instance-local memory through the ordinary authentication paths. It needs no SQL connection. The default `OAuthStateStrategy::Automatic` resolves to cookie state for this constructor and database state for an explicitly configured store, even if its session policy is stateless. Explicit `Cookie` and `Database` choices are preserved; database state in noDB mode uses ephemeral verification records:

```rust
use better_auth::{AuthBuilder, AuthConfig};
use better_auth::plugins::EmailPasswordPlugin;

let config = AuthConfig::new("a-secret-with-at-least-32-characters")
    .base_url("http://localhost:3000");
let auth = AuthBuilder::without_database(config)
    .plugin(EmailPasswordPlugin::new())
    .build()
    .await?;
```

The default session cache is an encrypted JWE, with the session lifetime as its maximum age. Automatic renewal starts when less than 20% of the cache lifetime remains. Renewal preserves the token and embedded session expiry; it extends the outer cache and token cookie lifetime. `disable_session_refresh`, deferred refresh and `disableRefresh` do not suppress cache-hit renewal. Trusted request hooks can insert `better_auth_core::session::SessionRefreshSuppressed` to suppress renewal for that request.

To retain SQL users/accounts while keeping session records in memory, set `config.session = config.session.stateless()` before constructing the store. SQL session rows are never read or written in this mode. Configure `cookie_cache` afterwards to override the strategy, age or version, and `cookie_refresh_cache` with `better_auth::config::CookieRefreshCache::{Disabled, Automatic, UpdateAge(seconds)}` to select renewal. The no-database builder preserves an already selected stateless renewal policy.

Cache bypass and cache misses use the ephemeral session records. GET reads can defer renewal to POST `/get-session`. Sign-out and revocation remove these records, but captured, authenticated cookie copies remain usable until the embedded expiry, cache version invalidation or key invalidation. Restarting loses credentials and ephemeral records while existing authenticated caches remain usable. Deployments needing immediate revocation must use durable session storage.

The built-in no-database store supports core user/account/verification provisioning. Storage for organization, two-factor, passkey, API-key and other optional plugin records requires an application store; those operations return explicit unsupported errors. Application model types retain their physical authority: handlers requiring a typed model cannot manufacture one from a cookie. Use cache-aware session APIs for cookie authority, or the native no-database schema.

## Frontend

See the official [session management guide](https://www.better-auth.com/docs/concepts/session-management).
