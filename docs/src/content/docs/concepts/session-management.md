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

Use [Axum extractors](/integrations/axum/) in protected handlers. Sessions use SQL unless [secondary storage](/concepts/secondary-storage/) is configured; a [cookie cache](/concepts/cookies/) can reduce reads.

## Frontend

See the official [session management guide](https://www.better-auth.com/docs/concepts/session-management).
