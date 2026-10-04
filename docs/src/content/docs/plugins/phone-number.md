---
title: "Phone number"
description: "Verify phone numbers with SMS codes, sign in with phone and password, and reset passwords by phone."
---

`PhoneNumberPlugin` stores a unique phone number on the user, verifies it with a one-time code that **you** deliver (SMS, WhatsApp, voice), and supports password sign-in by phone and phone-based password reset. The library never talks to an SMS provider.

## Schema

```bash
better-auth-rs generate --plugins phone-number -o src/auth_schema.rs
```

Adds `users.phone_number` and `users.phone_number_verified`. Add a **unique index** on `phone_number`. The phone number cannot be changed through `/update-user`; changes go through the verification flow (`POST /update-user` with a `phoneNumber` fails with `400 PHONE_NUMBER_CANNOT_BE_UPDATED`).

## Setup

Implement `SendPhoneOtp` with your SMS service. Add `async-trait = "0.1"`.

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
            .send(&delivery.phone_number, &format!("Your code is {}", delivery.code))
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

## Endpoints

| Method | Path | Body | Purpose |
| --- | --- | --- | --- |
| `POST` | `/phone-number/send-otp` | `phoneNumber` | Send a verification code |
| `POST` | `/phone-number/verify` | `phoneNumber`, `code`, optional `disableSession`, `updatePhoneNumber` | Verify the code; may create a user and session |
| `POST` | `/sign-in/phone-number` | `phoneNumber`, `password`, optional `rememberMe` | Password sign-in by phone |
| `POST` | `/phone-number/request-password-reset` | `phoneNumber` | Send a reset code |
| `POST` | `/phone-number/reset-password` | `phoneNumber`, `otp`, `newPassword` | Set a new password |

```bash
curl http://localhost:3000/api/auth/phone-number/send-otp \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"phoneNumber":"+4915112345678"}'
# {"message":"code sent"}   — your callback receives the code

curl -i -c cookies.txt http://localhost:3000/api/auth/phone-number/verify \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"phoneNumber":"+4915112345678","code":"482913"}'
# {"status":true,"token":"…","user":{…,"phoneNumber":"+4915112345678","phoneNumberVerified":true}}
```

What `/phone-number/verify` does depends on the situation:

- **A user already has this number** (set at sign-up with `phoneNumber`, or earlier): the number is marked verified and a **new session** is issued for that user.
- **A signed-in user sends `updatePhoneNumber: true`:** the verified number is attached to the current user (replacing their old one) and the current session token is returned.
- **No user has the number** and `sign_up_on_verification` is configured: a user is created with the placeholder email and name you supply, marked verified, and signed in.
- **No user has the number and nothing creates one:** the request fails with `500 FAILED_TO_UPDATE_USER`, because there is no user to mark verified. Attach numbers to accounts first.
- `disableSession: true` verifies without issuing a session.

A wrong, expired or already used code returns `400 OTP_NOT_FOUND` / `INVALID_OTP`; after `allowed_attempts` wrong guesses the code is invalidated.

A phone number reaches a user in one of three ways: pass `phoneNumber` to `/sign-up/email`, verify with `updatePhoneNumber: true` while signed in, or let `sign_up_on_verification` create phone-only users. Password sign-in by phone (`/sign-in/phone-number`) then needs a credential account — which sign-up with a password creates, and which [password reset by phone](#password-reset-by-phone) can create for phone-only users.

## Configuration

| `PhoneNumberConfig` field | Default | Effect |
| --- | --- | --- |
| `send_otp` | none | `SendPhoneOtp` for verification codes (required) |
| `send_password_reset_otp` | `send_otp` | Separate sender for reset codes |
| `verify_otp` | none | `PhoneOtpVerifier`: delegate verification to a provider such as Twilio Verify. **It replaces local checks, including expiry, replay and attempts** |
| `phone_number_validator` | none | `PhoneNumberValidator` — return `false` for `400 INVALID_PHONE_NUMBER` |
| `sign_up_on_verification` | none | `PhoneSignupIdentity` with `temporary_email(phone)` and optional `temporary_name(phone)` |
| `callback_on_verification` | none | `PhoneVerificationHook` called after a successful verification |
| `require_verification` | `false` | Refuse `/sign-in/phone-number` until the number is verified (and send a code) |
| `otp_length` | `6.0` | Digits |
| `expires_in` | `300.0` | Seconds |
| `allowed_attempts` | `3.0` | Wrong guesses allowed; `0` or negative rejects even an unused code |

Normalize numbers (E.164) in your validator or before calling the API: the stored value is compared as typed, and the unique index treats `+49151…` and `0151…` as different users. All endpoints are rate limited to 10 requests per minute per client ([built-in rules](/concepts/rate-limit/#built-in-rules)).

### Delegate to a verification provider

```rust
use async_trait::async_trait;
use better_auth::CallbackContext;
use better_auth::plugins::phone_number::{PhoneNumberConfig, PhoneOtpDelivery, PhoneOtpVerifier};
use better_auth::AuthResult;
use std::sync::Arc;

struct ProviderVerify;

#[async_trait]
impl PhoneOtpVerifier for ProviderVerify {
    // `delivery.code` is what the user typed; ask the provider whether it is valid.
    async fn verify(&self, delivery: &PhoneOtpDelivery, _: &CallbackContext) -> AuthResult<bool> {
        Ok(delivery.code == "000000" && delivery.phone_number.starts_with("+1"))
    }
}

fn config() -> PhoneNumberConfig {
    PhoneNumberConfig {
        verify_otp: Some(Arc::new(ProviderVerify)),
        ..Default::default()
    }
}
```

### Password reset by phone

`POST /phone-number/request-password-reset` sends a code through `send_password_reset_otp` (or `send_otp`), and `POST /phone-number/reset-password` with `{"phoneNumber","otp","newPassword"}` stores the new password. It inherits the password hasher and length limits of the [email & password](/authentication/email-password/) plugin and revokes sessions when `PasswordManagementPlugin::revoke_sessions_on_password_reset` is on.

## Server-only helper

`PhoneNumberPlugin::consume_otp(ctx, phone_number, code)` checks and consumes a code without creating users or sessions — use it for your own flows (for example confirming a phone number before a payout). It is not an HTTP route.

## Frontend

See the official [phone number guide](https://www.better-auth.com/docs/plugins/phone-number).
