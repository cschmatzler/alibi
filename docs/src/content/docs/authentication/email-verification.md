---
title: "Email verification"
description: "Deliver verification links and require verified email identities."
---

Require verified email addresses by configuring delivery on the verification module and connecting it to password sign-in.

## Setup

Add `async-trait = "0.1"`. This example delivers links through your application's `EmailProvider`:

```rust
use crate::auth_schema::AppAuthSchema;
use async_trait::async_trait;
use better_auth::email::EmailProvider;
use better_auth::plugins::email_verification::SendVerificationEmail;
use better_auth::plugins::{EmailPasswordPlugin, EmailVerificationConfig, EmailVerificationPlugin};
use better_auth::sqlx::SqlxStore;
use better_auth::wire::UserView;
use better_auth::{AuthConfig, AuthResult, BetterAuth};
use std::sync::Arc;

struct VerificationMailer(Arc<dyn EmailProvider>);

#[async_trait]
impl SendVerificationEmail for VerificationMailer {
    async fn send(&self, user: &UserView, url: &str, _: &str) -> AuthResult<()> {
        let email = user
            .email
            .as_deref()
            .ok_or_else(|| better_auth::AuthError::bad_request("Email required"))?;
        self.0.send(email, "Verify your email", "", url).await
    }
}

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
    mail: Arc<dyn EmailProvider>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    let verification = EmailVerificationConfig {
        send_on_sign_in: true,
        send_verification_email: Some(Arc::new(VerificationMailer(mail))),
        ..Default::default()
    };
    let password = EmailPasswordPlugin::new()
        .require_email_verification(true)
        .with_email_verification(Arc::new(EmailVerificationPlugin::with_config(
            verification.clone(),
        )));

    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(password)
        .plugin(EmailVerificationPlugin::with_config(verification))
        .build()
        .await
}
```

Request delivery at `/send-verification-email`; the supplied link completes `/verify-email`. `auto_sign_in_after_verification` controls whether verification also issues a session.

Delivery errors fail the request by default. See [notification policies](/concepts/notifications/) for background delivery and error handling.

## Frontend

See the official [email verification guide](https://www.better-auth.com/docs/authentication/email-password).
