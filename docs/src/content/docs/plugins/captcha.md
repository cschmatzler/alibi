---
title: "CAPTCHA"
description: "Challenge requests before authentication writes."
---

`CaptchaPlugin` verifies challenges before request parsing or authentication writes.

## Setup

Pass your server-side Turnstile secret when building the auth instance:

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::captcha::TurnstileConfig;
use better_auth::plugins::{CaptchaConfig, CaptchaPlugin, CaptchaProvider};
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
    secret: &str,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(CaptchaPlugin::new(CaptchaConfig::new(
            CaptchaProvider::CloudflareTurnstile(TurnstileConfig::new(secret)),
        )))
        .build()
        .await
}
```

## Options

The default protects signup, password sign-in, and password reset. Set endpoint patterns to change the protected routes; `*` and `**` are supported. Tokens arrive in `x-captcha-response`.

Other provider configurations support reCAPTCHA, hCaptcha, CaptchaFox, and application-owned BotID callbacks. Verification uses the configured client-IP policy and a ten-second provider deadline.

## Frontend

See the official [CAPTCHA guide](https://www.better-auth.com/docs/plugins/captcha).
