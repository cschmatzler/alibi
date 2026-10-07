---
title: "Magic link"
description: "Passwordless sign-in through a single-use link sent by email."
---

`MagicLinkPlugin` signs a user in when they open a link delivered to their mailbox. Following the link proves control of the address, so it also **verifies the email** and creates the account on first use.

## Setup

You provide delivery: a `SendMagicLink` callback receives the address and the link. This example forwards it to an `EmailProvider`. Add `async-trait = "0.1"`.

```rust
use crate::auth_schema::AppAuthSchema;
use async_trait::async_trait;
use alibi::CallbackContext;
use alibi::email::EmailProvider;
use alibi::plugins::magic_link::MagicLinkDelivery;
use alibi::plugins::{MagicLinkConfig, MagicLinkPlugin, SendMagicLink};
use alibi::sqlx::SqlxStore;
use alibi::{AuthConfig, AuthResult, BetterAuth};
use std::sync::Arc;

struct Mailer(Arc<dyn EmailProvider>);

#[async_trait]
impl SendMagicLink for Mailer {
    async fn send(&self, delivery: &MagicLinkDelivery, _: &CallbackContext) -> AuthResult<()> {
        self.0
            .send(&delivery.email, "Your sign-in link", "", &format!("Sign in: {}", delivery.url))
            .await
    }
}

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
    mail: Arc<dyn EmailProvider>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(MagicLinkPlugin::new(MagicLinkConfig {
            send_magic_link: Some(Arc::new(Mailer(mail))),
            expires_in: 300.0,
            ..Default::default()
        }))
        .build()
        .await
}
```

No schema changes are needed; tokens live in the `verifications` table.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/sign-in/magic-link` | Request a link: `email`, optional `name`, `callbackURL`, `newUserCallbackURL`, `errorCallbackURL`, `metadata` |
| `GET` | `/magic-link/verify` | Consume the link: `token`, plus the callback URLs carried in the link |

```bash
curl -i http://localhost:3000/api/auth/sign-in/magic-link \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"email":"ada@example.com","name":"Ada","callbackURL":"/dashboard","newUserCallbackURL":"/welcome","errorCallbackURL":"/login?error=1"}'
# {"status":true}
```

The user receives `https://auth.example.com/api/auth/magic-link/verify?token=<32 letters>&callbackURL=%2Fdashboard&newUserCallbackURL=%2Fwelcome&errorCallbackURL=…`. Opening it:

- consumes the token (single use), creates the user if the address is unknown (`emailVerified: true`), signs the user in and sets the session cookie;
- **redirects** (`302`) to `callbackURL` — or `newUserCallbackURL` for a brand-new user — resolved against your base URL (`Location: https://auth.example.com/welcome`); without callbacks it returns `{"token":…,"user":…}` JSON;
- on failure redirects to `errorCallbackURL` with `?error=INVALID_TOKEN` (or another code, such as `new_user_signup_disabled`).

All callback URLs must be relative or on a [trusted origin](/concepts/security/).

If the address already belongs to a user whose email was **unverified**, the successful link proves ownership, and any credentials or sessions that existed before the proof are revoked — a squatter who registered someone else's address cannot keep access.

## Configuration

`MagicLinkConfig`:

| Field | Default | Effect |
| --- | --- | --- |
| `send_magic_link` | none | **Required in practice.** `SendMagicLink::send(&MagicLinkDelivery, &CallbackContext)`; `MagicLinkDelivery` has `email`, `url`, `token`, `metadata` |
| `expires_in` | `300.0` | Lifetime in seconds (floating point); `0`/`NaN` select 300 |
| `storage` | `Plain` | `Plain`, `Hashed`, or `Custom(Arc<dyn MagicLinkTokenHasher>)` — what is stored in `verifications` |
| `generate_token` | random 32 letters | Custom `MagicLinkTokenGenerator` |
| `rate_limit` | 5 / 60 s | `EndpointRateLimit` for the plugin's endpoints |
| `disable_sign_up` | `false` | Only existing users may sign in; unknown addresses get `new_user_signup_disabled` |

Prefer `MagicLinkTokenStorage::Hashed` so a database leak does not expose usable links. The `metadata` object in the request is passed through to your callback — for example to choose an email template.

`send_magic_link` is awaited by default and its errors fail the request; see [notification policy](/concepts/notifications/). The callback receives a `CallbackContext` for the original request.

## Frontend

See the official [magic link guide](https://www.better-auth.com/docs/plugins/magic-link).
