---
title: "Multi-session"
description: "Let one browser stay signed in to several accounts and switch between them."
---

By default signing in replaces the current session. `MultiSessionPlugin` keeps **every** session a browser creates as its own signed cookie, so users can hold several accounts open (personal and work, admin and regular) and switch without signing in again.

## Setup

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::plugins::MultiSessionPlugin;
use alibi::sqlx::SqlxStore;
use alibi::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(MultiSessionPlugin::new())
        .build()
        .await
}
```

No schema changes. State lives in cookies.

## How it works

On every successful sign-in the plugin adds a cookie named `<session cookie name>_multi-<lowercased token>` (for example `better-auth.session_token_multi-a2qtpwyu…`) holding the signed token, **in addition to** the normal `better-auth.session_token`, which always points at the *active* session. Signing in again with the same account replaces that account's earlier session (the old session row is deleted and its cookie dropped) rather than piling up duplicates.

## Endpoints

| Method | Path | Body | Result |
| --- | --- | --- | --- |
| `GET` | `/multi-session/list-device-sessions` | — | `[{"session":{…},"user":{…}}, …]` for every valid cookie on this browser |
| `POST` | `/multi-session/set-active` | `{"sessionToken":"…"}` | Make that session the active one (rewrites `session_token`) → `{"session":{…},"user":{…}}`. An expired or deleted session is rejected and its cookie cleared |
| `POST` | `/multi-session/revoke` | `{"sessionToken":"…"}` | Delete that session and its cookie → `{"status":true}`. If it was the active session, the next valid remembered session becomes active; with none left, the auth cookies are cleared. Needs a signed-in session |

```bash
curl -b cookies.txt http://localhost:3000/api/auth/multi-session/list-device-sessions
curl -b cookies.txt -c cookies.txt -X POST http://localhost:3000/api/auth/multi-session/set-active \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"sessionToken":"A2qTpWyuUWufawTOn98nH4Tlio9E11Ax"}'
```

A token that does not belong to a cookie on this browser is rejected with `400`, so one device cannot activate another device's session.

:::caution[Sign-out ends every remembered account]
`POST /sign-out` with this plugin installed deletes **all** sessions remembered by the browser and clears all of their cookies, not just the active one. To drop a single account, call `/multi-session/revoke`.
:::

This plugin is **account switching on one browser**. To list every session of a user across devices, use [`GET /list-sessions`](/concepts/session-management/#endpoints).

## Configuration

| `MultiSessionConfig` field | Default | Effect |
| --- | --- | --- |
| `maximum_sessions` | `5.0` | Number of accounts remembered per browser. Compared as a JavaScript number: `0` or negative stores none, fractions floor, `NaN`/infinity store all. New sessions beyond the limit are not remembered (nothing is evicted) |

```rust
use alibi::plugins::{MultiSessionConfig, MultiSessionPlugin};

fn multi() -> MultiSessionPlugin {
    MultiSessionPlugin::with_config(MultiSessionConfig { maximum_sessions: 3.0 })
}
```

Works with [custom session](/plugins/custom-session/): `mutate_device_sessions(true)` applies the transform to each entry returned by `list-device-sessions`.

## Notes

- Cookies are scoped like the session cookie (`HttpOnly`, same domain/path), so [cookie attributes](/concepts/cookies/) apply to them too.
- Each additional account adds one cookie of ~100–150 bytes; watch the browser's cookie size limits with high `maximum_sessions`.
- Impersonation ([Admin](/plugins/admin/#impersonation)) uses its own `admin_session` cookie rather than multi-session.

## Frontend

See the official [Multi-session guide](https://www.better-auth.com/docs/plugins/multi-session).
