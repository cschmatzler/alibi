---
title: "Email OTP"
description: "One-time codes by email for sign-in, email verification, password reset and email change."
---

`EmailOtpPlugin` issues short numeric codes and uses them for four flows. Each code is bound to a **type**, so a sign-in code cannot be used to reset a password.

## Setup

Provide a `SendEmailOtp` callback. Add `async-trait = "0.1"`.

```rust
use crate::auth_schema::AppAuthSchema;
use async_trait::async_trait;
use alibi::CallbackContext;
use alibi::email::EmailProvider;
use alibi::plugins::email_otp::EmailOtpDelivery;
use alibi::plugins::{EmailOtpConfig, EmailOtpPlugin, SendEmailOtp};
use alibi::sqlx::SqlxStore;
use alibi::{AuthConfig, AuthResult, Alibi};
use std::sync::Arc;

struct Mailer(Arc<dyn EmailProvider>);

#[async_trait]
impl SendEmailOtp for Mailer {
    async fn send(&self, delivery: &EmailOtpDelivery, _: &CallbackContext) -> AuthResult<()> {
        let subject = match delivery.otp_type.as_str() {
            "sign-in" => "Your sign-in code",
            "forget-password" => "Reset your password",
            "change-email" => "Confirm your new email",
            _ => "Verify your email",
        };
        self.0
            .send(&delivery.email, subject, "", &format!("Your code is {}", delivery.otp))
            .await
    }
}

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
    mail: Arc<dyn EmailProvider>,
) -> AuthResult<Alibi<AppAuthSchema>> {
    Alibi::<AppAuthSchema>::new(config)
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

No schema changes; codes are stored in `verifications` with the identifier `<type>-otp-<email>` and an attempt counter.

## Flows and endpoints

| Flow | Request the code | Complete |
| --- | --- | --- |
| **Sign in** | `POST /email-otp/send-verification-otp` `{"email","type":"sign-in"}` | `POST /sign-in/email-otp` `{"email","otp"}` — creates the user if needed (unless `disable_sign_up`) |
| **Verify email** | `POST /email-otp/send-verification-otp` with `"type":"email-verification"` | `POST /email-otp/verify-email` `{"email","otp"}` → `{"status":true,"token":null,"user":{…}}` (`token` holds a session token only with auto sign-in) |
| **Reset password** | `POST /email-otp/request-password-reset` `{"email"}` (deprecated alias `POST /forget-password/email-otp`) | `POST /email-otp/reset-password` `{"email","otp","password"}` |
| **Change email** (opt in) | `POST /email-otp/request-email-change` `{"newEmail","otp"?}` | `POST /email-otp/change-email` `{"newEmail","otp"}` |
| Check a code | — | `POST /email-otp/check-verification-otp` `{"email","type","otp"}` — validates without signing anyone in (needs an existing user: `400 USER_NOT_FOUND` otherwise) |

```bash
curl http://localhost:3000/api/auth/email-otp/send-verification-otp \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"email":"ada@example.com","type":"sign-in"}'
# {"success":true}   — your callback receives the code

curl -i -c cookies.txt http://localhost:3000/api/auth/sign-in/email-otp \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"email":"ada@example.com","otp":"482913","name":"Ada"}'
# {"token":"…","user":{…}}
```

Requesting a code always answers `{"success":true}` — whether or not the mailbox has an account — so the endpoint does not reveal registered addresses. Wrong, expired or exhausted codes fail with `400 INVALID_OTP`, and a code is consumed on success. `name`, `image`, `username` and `displayUsername` on `/sign-in/email-otp` apply only when the call creates a user.

## Configuration

| `EmailOtpConfig` field | Default | Effect |
| --- | --- | --- |
| `send_verification_otp` | none | Your `SendEmailOtp` delivery callback |
| `otp_length` | `6.0` | Number of digits |
| `expires_in` | `300.0` | Lifetime in seconds |
| `allowed_attempts` | `3.0` | Wrong guesses before the code is invalidated |
| `storage` | `Plain` | `Plain`, `Hashed`, `Encrypted`, or `Custom(Arc<dyn EmailOtpCodec>)` |
| `generate_otp` | random digits | `EmailOtpGenerator`; return `None` to fall back to the default |
| `resend_strategy` | `Rotate` | `Rotate` issues a fresh code per request; `Reuse` re-sends the live one |
| `rate_limit` | 3 / 60 s | Limit for the plugin's send endpoints |
| `disable_sign_up` | `false` | Do not create users on `/sign-in/email-otp` |
| `send_verification_on_sign_up` | `false` | Send a verification code when a user signs up by password |
| `override_default_email_verification` | `false` | Use OTP instead of links for the core email-verification flow |
| `change_email_enabled` | `false` | Enable the email-change endpoints |
| `verify_current_email` | `false` | Require the current address to be verified before changing it |
| `auto_sign_in_after_verification` | `false` | Return a session from `/email-otp/verify-email` |
| `before_email_verification`, `after_email_verification` | none | Hooks around marking the email verified |
| `password_hasher` | scrypt | Used by `/email-otp/reset-password`; length limits come from the email/password plugin |
| `revoke_sessions_on_password_reset`, `on_password_reset` | `false`, none | Same semantics as [password reset](/authentication/email-password/#reset-a-forgotten-password) |

`otp_length`, `expires_in` and `allowed_attempts` use JavaScript-number semantics: fractions round, `NaN` or non-positive lengths fail code generation, and an `allowed_attempts` of `0` or `NaN` uses 3. Prefer `Hashed` storage: the code is never recoverable from the database (and `get_verification_otp` below will refuse to read it).

### Custom code storage

```rust
use async_trait::async_trait;
use alibi::plugins::email_otp::{EmailOtpCodec, EmailOtpStorage};
use alibi::AuthResult;
use std::sync::Arc;

struct PepperedHash;

#[async_trait]
impl EmailOtpCodec for PepperedHash {
    async fn store(&self, otp: &str) -> AuthResult<String> {
        Ok(format!("v1:{}", otp.chars().rev().collect::<String>())) // use a real keyed hash
    }
    async fn verify(&self, stored: &str, otp: &str) -> AuthResult<bool> {
        Ok(self.store(otp).await? == stored)
    }
    async fn retrieve(&self, _stored: &str) -> AuthResult<Option<String>> {
        Ok(None) // irreversible
    }
}

fn storage() -> EmailOtpStorage {
    EmailOtpStorage::Custom(Arc::new(PepperedHash))
}
```

## Server-only helpers

Two operations exist only on the server — handy for tests, support tools or custom delivery. Keep a clone of the plugin and call it with the instance context:

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::plugins::email_otp::EmailOtpType;
use alibi::plugins::{EmailOtpConfig, EmailOtpPlugin};
use alibi::{AuthResult, Alibi};

async fn issue_support_code(
    auth: &Alibi<AppAuthSchema>,
    plugin: &EmailOtpPlugin,
    email: &str,
) -> AuthResult<String> {
    // Creates and stores a code; does not send it or check that the account exists.
    plugin.create_verification_otp(auth.context(), email, EmailOtpType::SignIn).await
}

fn plugin() -> EmailOtpPlugin {
    EmailOtpPlugin::new(EmailOtpConfig::default())
}
```

`get_verification_otp` returns the live plaintext (or decryptable) code without consuming it; it errors for hashed storage.

## Related

- Numeric options are shared with [magic links](/plugins/magic-link/) and [phone numbers](/plugins/phone-number/).
- Delivery errors and background delivery: [notification policy](/concepts/notifications/).

## Frontend

See the official [email OTP guide](https://www.better-auth.com/docs/plugins/email-otp).
