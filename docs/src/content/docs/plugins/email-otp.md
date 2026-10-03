---
title: "Email OTP"
description: "Authenticate or verify email with a one-time code."
---

`EmailOtpPlugin` sends email credentials for sign-in or email verification.

## Setup

Add `async-trait = "0.1"` to your dependencies. This example forwards delivery to your application's `EmailProvider` and installs the plugin on the auth instance.

```rust
use crate::auth_schema::AppAuthSchema;
use async_trait::async_trait;
use better_auth::CallbackContext;
use better_auth::email::EmailProvider;
use better_auth::plugins::email_otp::EmailOtpDelivery;
use better_auth::plugins::{EmailOtpConfig, EmailOtpPlugin, SendEmailOtp};
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};
use std::sync::Arc;

struct Mailer(Arc<dyn EmailProvider>);

#[async_trait]
impl SendEmailOtp for Mailer {
    async fn send(&self, delivery: &EmailOtpDelivery, _: &CallbackContext) -> AuthResult<()> {
        self.0
            .send(
                &delivery.email,
                "Sign in",
                "",
                &format!("Your code is {}", delivery.otp),
            )
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
        .plugin(EmailOtpPlugin::new(EmailOtpConfig {
            send_verification_otp: Some(Arc::new(Mailer(mail))),
            expires_in: 300.0,
            ..Default::default()
        }))
        .build()
        .await
}
```

## Endpoints and options

Send a code at `/email-otp/send-verification-otp` and complete sign-in at `/sign-in/email-otp`. The request selects the code purpose. Verification, reset, and email-change flows have separate endpoints.

`expires_in` uses floating-point seconds. See [delivery policies](/concepts/notifications/) for awaited errors and [passwordless configuration](/guides/passwordless-migration/) for numeric options.

## Frontend

See the official [email-otp guide](https://www.better-auth.com/docs/plugins/email-otp).
