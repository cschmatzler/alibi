---
title: "Phone number"
description: "Verify phone numbers and authenticate with phone credentials."
---

`PhoneNumberPlugin` verifies phone numbers and supports phone-based authentication.

## Setup

Generate the phone fields and apply your migrations:

```bash
better-auth-rs generate --plugins phone-number -o src/auth_schema.rs
```

Add `async-trait = "0.1"` to your dependencies. The `SmsSender` below is an application interface for your SMS service.

```rust
use crate::auth_schema::AppAuthSchema;
use async_trait::async_trait;
use better_auth::CallbackContext;
use better_auth::plugins::phone_number::PhoneOtpDelivery;
use better_auth::plugins::{PhoneNumberConfig, PhoneNumberPlugin, SendPhoneOtp};
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};
use std::sync::Arc;

#[async_trait]
trait SmsSender: Send + Sync {
    async fn send(&self, to: &str, message: &str) -> AuthResult<()>;
}

struct OtpSender(Arc<dyn SmsSender>);

#[async_trait]
impl SendPhoneOtp for OtpSender {
    async fn send(&self, delivery: &PhoneOtpDelivery, _: &CallbackContext) -> AuthResult<()> {
        self.0
            .send(
                &delivery.phone_number,
                &format!("Your code is {}", delivery.code),
            )
            .await
    }
}

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
    sms: Arc<dyn SmsSender>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(PhoneNumberPlugin::new(PhoneNumberConfig {
            send_otp: Some(Arc::new(OtpSender(sms))),
            expires_in: 300.0,
            ..Default::default()
        }))
        .build()
        .await
}
```

## Endpoints and options

Send a code at `/phone-number/send-otp` and verify it at `/phone-number/verify`. Password-based phone login uses `/sign-in/phone-number`.

Lifetimes use floating-point seconds. Your application can replace local code verification with `PhoneOtpVerifier`; that implementation owns expiry, replay, and attempt checks.

## Frontend

See the official [phone number guide](https://www.better-auth.com/docs/plugins/phone-number).
