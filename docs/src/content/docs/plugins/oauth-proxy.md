---
title: "OAuth proxy"
description: "Use one registered OAuth callback for preview, staging and local hosts."
---

OAuth providers require every redirect URI to be registered in advance. That is painful when each pull request gets its own preview URL. `OAuthProxyPlugin` solves it: the provider always redirects to your **production** auth server, which finishes the code exchange and forwards the (encrypted) result to the preview host that started the flow.

## How it works

```text
preview host                 provider                 production host
    │  sign-in/social           │                           │
    ├─ redirect_uri = production callback ───────────────►  │
    │                           │◄───── user signs in ──────┤
    │                           ├── code ──────────────────►│  exchanges the code
    │◄── redirect to preview /callback/{provider}/oauth-proxy ── encrypted profile + tokens
    │  verifies, creates the user and the session cookie on the preview host
```

The production host exchanges the code, builds an encrypted payload (profile, tokens, state), and redirects to the preview host's `GET /callback/{provider}/oauth-proxy`. The preview host decrypts it, checks its age and its own signed state, and completes the sign-in locally. Normal (non-proxied) flows are unaffected.

## Setup

Run the **same plugin on both hosts**. This is the preview instance, pointing at production:

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::oauth::OAuthProvider;
use better_auth::plugins::{OAuthPlugin, OAuthProxyConfig, OAuthProxyPlugin};
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
    client_id: &str,
    client_secret: &str,
    shared_secret: &str,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(
            OAuthPlugin::new()
                .add_provider("google", OAuthProvider::google(client_id, client_secret)),
        )
        .plugin(OAuthProxyPlugin::with_config(OAuthProxyConfig {
            production_url: Some("https://auth.example.com".into()),
            current_url: Some("https://preview-123.example.com".into()),
            secret: Some(shared_secret.into()),
            ..Default::default()
        }))
        .build()
        .await
}
```

Checklist:

1. Register **only the production callback** (`https://auth.example.com/api/auth/callback/google`) with the provider.
2. Add the preview origin to `trusted_origin`s of the production server (and the preview host's own origin on the preview server), so redirects are accepted.
3. Share a `secret` between hosts if their ordinary `BETTER_AUTH_SECRET`s differ. The payload is encrypted with it; without `secret`, each host's auth secret is used and must match.
4. Use database-backed OAuth state (the default when a store is configured); the proxy cooperates with cookie-state deployments too, restoring the saved error callback on mismatch.

## Configuration

| `OAuthProxyConfig` field | Default | Effect |
| --- | --- | --- |
| `production_url` | none | Origin of the host registered with providers; the auth base path is appended |
| `current_url` | the request origin if trusted | Origin of this host. Set it explicitly on preview deployments |
| `max_age_seconds` | `60.0` | How old a forwarded payload may be before the preview host rejects it (clock skew tolerance is 10 s) |
| `secret` | the auth secret | Dedicated key to encrypt the forwarded payload; must be identical on both hosts |

The plugin registers `GET /callback/{provider}/oauth-proxy` (and the legacy `GET /oauth-proxy-callback`).

## Security notes

- The forwarded payload is encrypted, time-limited and bound to the OAuth `state` the preview host issued; replaying or tampering fails.
- The proxy does **not** remove provider registration or redirect validation: unknown preview origins are rejected unless trusted.
- Only enable the proxy in environments that need it; production should not accept arbitrary preview origins. Prefer an explicit allow-list of preview hosts.

## Frontend

See the official [OAuth proxy guide](https://www.better-auth.com/docs/plugins/oauth-proxy).
