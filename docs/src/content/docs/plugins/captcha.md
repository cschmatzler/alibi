---
title: "CAPTCHA"
description: "Require a CAPTCHA or bot-detection proof before sign-up, sign-in and other sensitive requests."
---

`CaptchaPlugin` blocks automated abuse (credential stuffing, mass sign-up, reset-email bombing) by requiring a provider-verified proof on selected endpoints. Verification happens **first** — before the request body is parsed and before any authentication write — so a failed proof has no side effects.

Supported providers: **Cloudflare Turnstile**, **Google reCAPTCHA**, **hCaptcha**, **CaptchaFox** and **Vercel BotID**.

## Setup

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::captcha::TurnstileConfig;
use better_auth::plugins::{CaptchaConfig, CaptchaPlugin, CaptchaProvider};
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
    turnstile_secret: &str,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(CaptchaPlugin::new(CaptchaConfig::new(
            CaptchaProvider::CloudflareTurnstile(TurnstileConfig::new(turnstile_secret)),
        )))
        .build()
        .await
}
```

No schema and no routes. Your **secret key** stays on the server; the widget on the page uses the public *site key*.

## How clients pass the proof

The browser widget produces a token. The client sends it in the `x-captcha-response` header of the protected request:

```bash
curl -i http://localhost:3000/api/auth/sign-in/email \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -H 'x-captcha-response: 0.AbCdEf…' \
  -d '{"email":"ada@example.com","password":"a-long-example-password"}'
```

With the official client: `fetchOptions: { headers: { "x-captcha-response": token } }`. Failures:

| Status | Code | Meaning |
| --- | --- | --- |
| `400` | `MISSING_RESPONSE` | The header is absent |
| `403` | `VERIFICATION_FAILED` | The provider rejected the token (or its score, action or hostname checks failed) |
| `500` | `UNKNOWN_ERROR` | The provider could not be reached or answered with something unusable. The call fails **closed** |

Verification honors the client IP resolved by `advanced.ip_address` (sent to the provider as `remoteip`) and gives the provider ten seconds to answer.

## Choose the protected endpoints

By default the plugin protects `/sign-up/email`, `/sign-in/email` and `/request-password-reset`. Set `endpoints` to replace that list. Patterns are relative to `base_path` and support `*` (within one segment) and `**` (across segments):

```rust
use better_auth::plugins::captcha::TurnstileConfig;
use better_auth::plugins::{CaptchaConfig, CaptchaPlugin, CaptchaProvider};

fn captcha(secret: &str) -> CaptchaPlugin {
    let mut config = CaptchaConfig::new(CaptchaProvider::CloudflareTurnstile(TurnstileConfig::new(secret)));
    config.endpoints = vec![
        "/sign-up/**".into(),       // /sign-up/email and any future sign-up route
        "/sign-in/*".into(),        // /sign-in/email, /sign-in/magic-link, …
        "/request-password-reset".into(),
        "/email-otp/send-verification-otp".into(),
    ];
    CaptchaPlugin::new(config)
}
```

An empty list means "the three defaults". Trusted server calls through `dispatch_endpoint` are not HTTP requests and are not checked.

## Providers

```rust
use better_auth::plugins::captcha::{RecaptchaConfig, SiteKeyCaptchaConfig, TurnstileConfig};
use better_auth::plugins::CaptchaProvider;

fn providers(secret: &str) -> Vec<CaptchaProvider> {
    let mut turnstile = TurnstileConfig::new(secret);
    turnstile.expected_action = Some("login".into());
    turnstile.allowed_hostnames = vec!["app.example.com".into()];

    let mut recaptcha = RecaptchaConfig::new(secret);
    recaptcha.min_score = 0.7; // v3 score threshold (default 0.5)

    let mut hcaptcha = SiteKeyCaptchaConfig::new(secret);
    hcaptcha.site_key = Some("10000000-ffff-ffff-ffff-000000000001".into());

    vec![
        CaptchaProvider::CloudflareTurnstile(turnstile),
        CaptchaProvider::GoogleRecaptcha(recaptcha),
        CaptchaProvider::HCaptcha(hcaptcha),
        CaptchaProvider::CaptchaFox(SiteKeyCaptchaConfig::new(secret)),
    ]
}
```

| Provider | Config | Extra checks |
| --- | --- | --- |
| Cloudflare Turnstile | `TurnstileConfig::new(secret)` | `expected_action`, `allowed_hostnames` |
| Google reCAPTCHA | `RecaptchaConfig::new(secret)` | `min_score` (0.5), `expected_action`, `allowed_hostnames` |
| hCaptcha, CaptchaFox | `SiteKeyCaptchaConfig::new(secret)` | optional `site_key` |
| Vercel BotID | `BotIdConfig { check_bot_id, validate_request }` | Your `CheckBotId` runs BotID; `ValidateBotIdRequest` can apply policy to the verdict |

Every HTTP provider carries `http: CaptchaHttpOptions { secret_key, site_verify_url }`. Set `site_verify_url` to route verification through your own proxy, and use `CaptchaPlugin::with_http_client(reqwest::Client)` to apply proxy and TLS settings to the verification calls:

```rust
use better_auth::plugins::captcha::TurnstileConfig;

fn proxied(secret: &str) -> Result<TurnstileConfig, url::ParseError> {
    let mut config = TurnstileConfig::new(secret);
    config.http.site_verify_url = Some("https://captcha-proxy.internal/verify".parse()?);
    Ok(config)
}
```

## Notes

- **CORS preflight.** CAPTCHA skips `OPTIONS` requests so `AuthBuilder::cors(...)` can answer browser preflights. Protected POST requests still require a provider-verified token. Configure the allowed origin and add `x-captcha-response` to `CorsConfig::allowed_headers` when the browser sends that header. CORS grants headers only to allowed origins; a skipped CAPTCHA check does not authorize a cross-origin request.
- A CAPTCHA complements, not replaces, [rate limiting](/concepts/rate-limit/).
- The plugin keeps no record of used tokens. Providers make tokens single use, so rely on the provider's verification to reject a replay.
- Layer it with [Have I Been Pwned](/plugins/have-i-been-pwned/) and with rate limits on [anonymous sign-in](/plugins/anonymous/#security-notes).

## Frontend

See the official [CAPTCHA guide](https://www.better-auth.com/docs/plugins/captcha).
