---
title: "One-time token"
description: "Hand a session to another app or domain with a short-lived, single-use token."
---

A one-time token (OTT) lets an already signed-in session be **handed off** to a place that cannot share its cookie — another domain, a native app, a desktop client, an embedded webview. The signed-in side generates a token and passes it over a trusted channel (a redirect URL, a deep link); the receiving side exchanges it exactly once for the session.

## Setup

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::one_time_token::OneTimeTokenPlugin;
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(OneTimeTokenPlugin::new())
        .build()
        .await
}
```

No schema changes; tokens are verification rows. Import the plugin from `better_auth::plugins::one_time_token`.

## Endpoints

| Method | Path | Auth | Result |
| --- | --- | --- | --- |
| `GET` | `/one-time-token/generate` | session | `{"token":"wlwm2v3ad0oUex1bKtDAG8s9UXpLu5uc"}` |
| `POST` | `/one-time-token/verify` | none | Body `{"token":"…"}` → `{"session":{…},"user":{…}}` and the session cookie |

```bash
# On the signed-in side
curl -b cookies.txt http://localhost:3000/api/auth/one-time-token/generate
# {"token":"wlwm2v3ad0oUex1bKtDAG8s9UXpLu5uc"}

# On the receiving side
curl -i -c other.txt http://localhost:3000/api/auth/one-time-token/verify \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"token":"wlwm2v3ad0oUex1bKtDAG8s9UXpLu5uc"}'
```

Verification **does not create a new session**: the token resolves to the *existing* session (same id, same expiry), sets that session's cookie on the receiver and returns it. Consuming a token a second time fails with `400 {"message":"Invalid token"}`; so do expired tokens and tokens whose session has since been revoked.

## Configuration

`OneTimeTokenConfig` with `OneTimeTokenPlugin::with_config`:

| Field | Default | Effect |
| --- | --- | --- |
| `expires_in` | 3 minutes | Token lifetime (`chrono::Duration`) |
| `storage` | `Plain` | `Plain`, `Hashed`, or `Custom(Arc<dyn HashOneTimeToken>)` — how the token is stored |
| `generator` | random | `GenerateOneTimeToken`: custom (async) token generation |
| `disable_client_request` | `false` | Disable `GET /one-time-token/generate`; tokens can then be issued only by server code |
| `disable_set_session_cookie` | `false` | `verify` returns the session but does not set a cookie (for native clients that store the token themselves) |
| `set_ott_header_on_new_session` | `false` | Add a `set-ott` header with a fresh token to every response that creates a session |

```rust
use better_auth::plugins::one_time_token::{OneTimeTokenConfig, OneTimeTokenPlugin, OneTimeTokenStorage};
use chrono::Duration;

fn ott() -> OneTimeTokenPlugin {
    OneTimeTokenPlugin::with_config(OneTimeTokenConfig {
        expires_in: Duration::seconds(60),
        storage: OneTimeTokenStorage::Hashed,
        set_ott_header_on_new_session: true, // sign-in responses also carry `set-ott: <token>`
        ..Default::default()
    })
}
```

`set_ott_header_on_new_session` is handy for the "sign in in a system browser, then return to the native app" pattern: the sign-in response already contains the token to place in the deep link.

## Server-only helpers

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::BetterAuth;
use better_auth::endpoint::EndpointOptions;
use better_auth::plugins::one_time_token::OneTimeTokenPlugin;

async fn exchange(
    auth: &BetterAuth<AppAuthSchema>,
    token: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let session = auth
        .dispatch_endpoint(OneTimeTokenPlugin::verify_endpoint(token), EndpointOptions::default())
        .await?
        .decode()?;
    Ok(serde_json::json!({ "user": session.user.id }))
}
```

`OneTimeTokenPlugin::generate_for_session` and `verify_token` work directly on a session you have already authenticated.

## Security notes

- The token is a bearer credential for the session — deliver it over HTTPS, in a fragment or deep link rather than a logged query string, and consume it immediately.
- Keep `expires_in` short; three minutes is generous for a redirect.
- Prefer `Hashed` storage so a database read cannot reveal pending tokens.
- Consuming a token authenticates; it does not authorize. Apply your normal permission checks afterwards.

## Frontend

See the official [One-time token guide](https://www.better-auth.com/docs/plugins/one-time-token).
