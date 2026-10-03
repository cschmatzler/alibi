---
title: "Email and background tasks"
description: "Delivery callbacks, errors, and background task ownership."
---

Password-reset and email-verification callbacks are awaited by default. A delivery error fails the request.

## Choose an error policy

```rust
use better_auth::{AuthConfig, AwaitedNotificationErrorPolicy};

fn auth_config(secret: &str) -> AuthConfig {
    AuthConfig::new(secret)
        .awaited_notification_errors(AwaitedNotificationErrorPolicy::LogAndContinue)
}
```

`LogAndContinue` logs lifecycle delivery failures and continues the response. Explicit verification delivery still propagates awaited errors.

Configure `background_tasks` with a `BackgroundTaskHandler` to observe already-running delivery work. Issued proofs or committed email changes are not removed after delivery fails; uncommitted signup writes roll back under the default policy.

The [email verification](/authentication/email-verification/), [OTP](/plugins/email-otp/), and [magic-link](/plugins/magic-link/) examples show callback implementations and registration.
