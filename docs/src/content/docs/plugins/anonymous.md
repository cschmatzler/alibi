---
title: "Anonymous"
description: "Let visitors use your app as a guest and upgrade to a real account without losing their data."
---

`AnonymousPlugin` creates a temporary user with a generated identity and a normal session. When that visitor later signs in or signs up with a real method, you get a callback to move their data and the anonymous user is cleaned up.

## Schema

```bash
alibi generate --plugins anonymous -o src/auth_schema.rs
```

Adds the nullable `users.is_anonymous` column (`isAnonymous` in API output, default `false`).

## Setup

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::plugins::AnonymousPlugin;
use alibi::sqlx::SqlxStore;
use alibi::{AuthConfig, AuthResult, Alibi};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<Alibi<AppAuthSchema>> {
    Alibi::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(AnonymousPlugin::new())
        .build()
        .await
}
```

## Endpoints

| Method | Path | Result |
| --- | --- | --- |
| `POST` | `/sign-in/anonymous` | Creates an anonymous user and session: `{"token":"…","user":{… "isAnonymous":true}}` |
| `POST` | `/delete-anonymous-user` | Deletes the current anonymous user and clears the session |

```bash
curl -i -c cookies.txt -X POST http://localhost:3000/api/auth/sign-in/anonymous \
  -H 'Origin: http://localhost:3000'
```

The generated user has `name: "Anonymous"` and an email of the form `<random>@anonymous.placeholder.invalid` (or `temp-<random>@your-domain` when you set `email_domain_name`). An already-anonymous session calling the endpoint again fails with `400 ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY`.

## Upgrade to a real account

When a request that **issues a session** completes while an anonymous session is active — `/sign-in/*`, `/sign-up/*`, OAuth `/callback`, magic-link and email-OTP verification, One Tap, passkey authentication, phone-number and email verification — the plugin:

1. calls your `LinkAnonymousAccount` callback with both users and both sessions;
2. then deletes the anonymous user (unless `disable_delete_anonymous_user`).

Use the callback to move data the guest created:

```rust
use async_trait::async_trait;
use alibi::plugins::{AnonymousConfig, AnonymousLink, AnonymousPlugin, LinkAnonymousAccount};
use alibi::prelude::AuthRequest;
use alibi::AuthResult;
use std::sync::Arc;

struct MoveCart;

#[async_trait]
impl LinkAnonymousAccount for MoveCart {
    async fn link(&self, accounts: &AnonymousLink, _request: &AuthRequest) -> AuthResult<()> {
        // Reassign guest-owned rows before the anonymous user disappears.
        println!(
            "move data from {} to {}",
            accounts.anonymous_user.id, accounts.new_user.id
        );
        Ok(())
    }
}

fn anonymous() -> AnonymousPlugin {
    AnonymousPlugin::with_config(AnonymousConfig {
        email_domain_name: Some("guest.example.com".into()),
        on_link_account: Some(Arc::new(MoveCart)),
        ..Default::default()
    })
}
```

An error from the callback fails the request, so the anonymous user is **not** deleted; keep the callback idempotent.

## Configuration

| `AnonymousConfig` field | Default | Effect |
| --- | --- | --- |
| `email_domain_name` | none | Generate `temp-<random>@<domain>` instead of the `.invalid` placeholder |
| `identity` | none | `AnonymousIdentity`: async `email()` and `name(&AuthRequest)` generators. A generated email must be valid |
| `on_link_account` | none | `LinkAnonymousAccount` callback described above |
| `disable_delete_anonymous_user` | `false` | Keep anonymous users after linking and disable `/delete-anonymous-user` |

## Security notes

- Anonymous users are real users with real sessions. Decide in your application what they may do — check `user.is_anonymous()` in handlers, or restrict by role.
- Generated anonymous emails are not verified and must not be treated as contact addresses; sending mail to them is wasteful at best.
- Combine with [rate limiting](/concepts/rate-limit/) or [CAPTCHA](/plugins/captcha/) on `/sign-in/anonymous` to prevent mass-creation of guest users, and clean up stale ones with a periodic query on `is_anonymous` and `created_at`.

## Frontend

See the official [Anonymous guide](https://www.better-auth.com/docs/plugins/anonymous).
