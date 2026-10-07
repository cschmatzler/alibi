---
title: "Email and background tasks"
description: "Deliver verification, reset and OTP messages, choose an error policy, and run delivery in the background."
---

Alibi does not send email itself. Features that need to reach a user — email verification, password reset, magic links, OTP codes, invitations — call **your** code. You provide it in one of two ways:

| Mechanism | Used by |
| --- | --- |
| An `EmailProvider` on the builder (one transport for everything) | [Email verification](/authentication/email-verification/), change-email and delete-account links |
| A dedicated callback on the plugin | Password reset (`SendResetPassword`), [email OTP](/plugins/email-otp/), [magic link](/plugins/magic-link/), [phone OTP](/plugins/phone-number/), [two-factor OTP](/plugins/two-factor/), [organization invitations](/plugins/organization/) |

## Implement an email provider

`EmailProvider` has a single method: recipient, subject, HTML body and plain-text body (either body may be empty).

```rust
use crate::auth_schema::AppAuthSchema;
use async_trait::async_trait;
use better_auth::email::EmailProvider;
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthError, AuthResult, BetterAuth};

struct HttpMailer {
    client: reqwest::Client,
    api_key: String,
}

#[async_trait]
impl EmailProvider for HttpMailer {
    async fn send(&self, to: &str, subject: &str, html: &str, text: &str) -> AuthResult<()> {
        let response = self
            .client
            .post("https://mail.example.com/v1/send")
            .bearer_auth(&self.api_key)
            .json(&serde_json::json!({ "to": to, "subject": subject, "html": html, "text": text }))
            .send()
            .await
            .map_err(|error| AuthError::internal(format!("mail transport failed: {error}")))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(AuthError::internal(format!("mail API returned {}", response.status())))
        }
    }
}

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
    mailer: HttpMailer,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .email_provider(mailer)
        .build()
        .await
}
```

For local development use `better_auth::email::ConsoleEmailProvider`, which prints `[EMAIL] To: … | Subject: … | Body: …` to stderr. Never log message bodies in production — they contain live credentials.

Dedicated callbacks usually forward to the same provider. Keep an `Arc<dyn EmailProvider>` in your callback struct, as the [email verification](/authentication/email-verification/) and [OTP](/plugins/email-otp/) pages do.

## Callback context

Callbacks for email OTP, magic links and phone codes receive a `&CallbackContext`. It exposes:

- `request` — the original HTTP request, if any (trusted server calls have none);
- `request_hook` — the [request hook context](/concepts/hooks/#read-the-originating-request);
- `endpoint` — the logical endpoint call;
- `context::<YourAuthSchema>()` — the initialized auth instance and its store, for example to look up the user's locale.

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::CallbackContext;

fn preferred_language(context: &CallbackContext) -> &'static str {
    let accept = context
        .request
        .as_ref()
        .and_then(|request| request.headers.get("accept-language"))
        .map(String::as_str)
        .unwrap_or("en");
    if accept.starts_with("de") { "de" } else { "en" }
}

fn instance_ready(context: &CallbackContext) -> bool {
    context.context::<AppAuthSchema>().is_some()
}
```

## Delivery failures

By default, delivery is **awaited** and a failure fails the request: the user sees an error, so they know to retry. Choose the policy on `AuthConfig`:

```rust
use better_auth::{AuthConfig, AwaitedNotificationErrorPolicy};

fn auth_config(secret: &str) -> AuthConfig {
    AuthConfig::new(secret)
        .awaited_notification_errors(AwaitedNotificationErrorPolicy::LogAndContinue)
}
```

| Policy | Behavior when a callback returns `Err` |
| --- | --- |
| `Propagate` (default) | The error fails the request. Auth state written before the failure is kept |
| `LogAndContinue` | Log the failure and finish the response normally |

An explicit "send verification email" request always propagates delivery errors. Issued proofs and committed email changes are **not** rolled back when delivery fails — resending issues a fresh proof. Writes of an uncommitted sign-up roll back under the default policy.

## Deliver in the background

Waiting for an SMTP server inside a request is slow. Supply a `BackgroundTaskHandler` and delivery starts immediately but is no longer awaited by the request; its failures are logged instead of surfaced. The handler receives a *completion* future for work that is **already running** — dropping it does not cancel the task, and you can keep it to await during shutdown:

```rust
use better_auth::{AuthConfig, AuthResult, BackgroundTaskCompletion, BackgroundTaskHandler};
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;

#[derive(Default)]
struct Pending(Mutex<Vec<JoinHandle<AuthResult<()>>>>);

impl BackgroundTaskHandler for Pending {
    fn handle(&self, completion: BackgroundTaskCompletion) -> AuthResult<()> {
        if let Ok(mut tasks) = self.0.lock() {
            tasks.retain(|task| !task.is_finished());
            tasks.push(tokio::spawn(completion));
        }
        Ok(())
    }
}

impl Pending {
    /// Call during graceful shutdown.
    async fn drain(&self) {
        let tasks = self.0.lock().map(|mut tasks| std::mem::take(&mut *tasks)).unwrap_or_default();
        for task in tasks {
            let _ = task.await;
        }
    }
}

fn auth_config(secret: &str, pending: Arc<Pending>) -> AuthConfig {
    AuthConfig::new(secret).background_tasks(pending)
}
```

On serverless platforms, hand the completion to the platform's `waitUntil` equivalent instead of `tokio::spawn`. The task keeps the originating request context and tracing span. Background delivery needs a Tokio runtime.

## Frontend

Links in emails open your frontend through `callbackURL` parameters — see the official [email verification guide](https://www.better-auth.com/docs/concepts/email).
