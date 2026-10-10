---
title: "Email verification"
description: "Send verification links, require verified emails for sign-in, and react to verification events."
---

Email verification proves that a user controls the address they signed up with. The `EmailVerificationPlugin` is installed by default; you configure it to deliver links and connect it to password sign-in.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/send-verification-email` | Send a link to `{"email":"…","callbackURL":"…"}` |
| `GET` | `/verify-email?token=…&callbackURL=…` | Consume the link: marks the email verified, then redirects or returns JSON |

`POST /send-verification-email` always answers `{"status":true}` and takes at least 500 ms, whether or not the address is registered or already verified, so it cannot be used to enumerate users. Links look like `https://auth.example.com/api/auth/verify-email?token=<jwt>&callbackURL=%2Fdashboard`; the token is a JWT signed with the current auth secret and expires after `verification_token_expiry` (default 1 hour).

On `GET /verify-email`:

- with a `callbackURL`, the browser is redirected there (`302`) — on failure to `…?error=INVALID_TOKEN` (or the matching error code);
- without one, success returns JSON and failure returns `401` with the error code.

## Require verified emails

Delivery needs a sender. This example forwards the link through your `EmailProvider`, requires verification before password sign-in, and re-sends the link when an unverified user tries to sign in:

```rust
use crate::auth_schema::AppAuthSchema;
use async_trait::async_trait;
use alibi::email::EmailProvider;
use alibi::plugins::email_verification::SendVerificationEmail;
use alibi::plugins::{EmailPasswordPlugin, EmailVerificationConfig, EmailVerificationPlugin};
use alibi::sqlx::SqlxStore;
use alibi::wire::UserView;
use alibi::{AuthConfig, AuthError, AuthResult, Alibi};
use std::sync::Arc;

struct VerificationMailer(Arc<dyn EmailProvider>);

#[async_trait]
impl SendVerificationEmail for VerificationMailer {
    async fn send(&self, user: &UserView, url: &str, _token: &str) -> AuthResult<()> {
        let email = user
            .email
            .as_deref()
            .ok_or_else(|| AuthError::bad_request("Email required"))?;
        self.0
            .send(email, "Verify your email", "", &format!("Confirm your address: {url}"))
            .await
    }
}

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
    mail: Arc<dyn EmailProvider>,
) -> AuthResult<Alibi<AppAuthSchema>> {
    let verification = EmailVerificationConfig {
        send_on_sign_in: true,
        send_verification_email: Some(Arc::new(VerificationMailer(mail))),
        ..Default::default()
    };
    let password = EmailPasswordPlugin::new()
        .enable_signup(true)
        .require_email_verification(true)
        .with_email_verification(Arc::new(EmailVerificationPlugin::with_config(
            verification.clone(),
        )));

    Alibi::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(password)
        .plugin(EmailVerificationPlugin::with_config(verification))
        .build()
        .await
}
```

With `require_email_verification(true)`:

1. `POST /sign-up/email` creates the user but **does not** sign them in — the response is `200` with `"token":null` and no cookie — and sends a verification link.
2. `POST /sign-in/email` for an unverified user fails with `403 EMAIL_NOT_VERIFIED` (and, with `send_on_sign_in`, sends a fresh link).
3. Following the link verifies the address; the user can now sign in. Set `auto_sign_in_after_verification: true` to issue a session at that moment.

If you have no custom sender but did set an `EmailProvider` on the builder, verification emails are delivered through it with a default template. Delivery failures fail the request unless you choose another [notification policy](/concepts/notifications/).

## Options

`EmailVerificationConfig` (builder methods of the same names exist on `EmailVerificationPlugin`):

| Field | Default | Effect |
| --- | --- | --- |
| `verification_token_expiry` | 1 hour | Lifetime of the link |
| `send_email_notifications` | `true` | Master switch for automatic sends |
| `send_on_sign_up` | unset | Send at sign-up. Unset follows `require_email_verification` |
| `send_on_sign_in` | `false` | Re-send when an unverified user signs in (needs `with_email_verification` on the email/password plugin) |
| `require_verification_for_signin` | `false` | Alternative switch to require verification at sign-in |
| `auto_verify_new_users` | `false` | Mark new users verified immediately (for trusted channels) |
| `auto_sign_in_after_verification` | `false` | Create a session when the link is followed and return its token |
| `send_verification_email` | none | Your `SendVerificationEmail`; otherwise the builder's `EmailProvider` is used |
| `before_email_verification` / `after_email_verification` | none | Async hooks `Fn(&UserView) -> Future<Output = AuthResult<()>>` around the update |

### React to verification

```rust
use alibi::plugins::EmailVerificationConfig;
use std::sync::Arc;

fn verification() -> EmailVerificationConfig {
    EmailVerificationConfig {
        after_email_verification: Some(Arc::new(|user| {
            let id = user.id.clone();
            Box::pin(async move {
                println!("{id} verified their email");
                Ok(())
            })
        })),
        ..Default::default()
    }
}
```

An error from `before_email_verification` stops the verification. OAuth providers that report a verified email, [email OTP](/plugins/email-otp/) and [magic links](/plugins/magic-link/) also mark the address verified; email OTP can take over the whole flow with `override_default_email_verification`.

## Frontend

See the official [email verification guide](https://www.better-auth.com/docs/concepts/email#email-verification).
