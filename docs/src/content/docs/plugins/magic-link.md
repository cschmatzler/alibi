---
title: "Magic link"
description: "Sign in through a single-use link delivered to an email address."
---

`MagicLinkPlugin` sends email credentials for passwordless sign-in.

## Setup

Add `async-trait = "0.1"` to your dependencies. This example forwards delivery to your application's `EmailProvider` and installs the plugin on the auth instance.

```rust
use crate::auth_schema::AppAuthSchema;
use async_trait::async_trait;
use better_auth::CallbackContext;
use better_auth::email::EmailProvider;
use better_auth::plugins::magic_link::MagicLinkDelivery;
use better_auth::plugins::{MagicLinkConfig, MagicLinkPlugin, SendMagicLink};
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};
use std::sync::Arc;

struct Mailer(Arc<dyn EmailProvider>);

#[async_trait]
impl SendMagicLink for Mailer {
    async fn send(&self, delivery: &MagicLinkDelivery, _: &CallbackContext) -> AuthResult<()> {
        self.0
            .send(&delivery.email, "Sign in", "", &delivery.url.clone())
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

## Endpoints and options

Request a link at `/sign-in/magic-link`. The supplied URL completes verification at `/magic-link/verify` and issues session cookies.

`expires_in` uses floating-point seconds. See [delivery policies](/concepts/notifications/) for awaited errors and [passwordless configuration](/guides/passwordless-migration/) for numeric options.

## Frontend

See the official [magic-link guide](https://www.better-auth.com/docs/plugins/magic-link).
