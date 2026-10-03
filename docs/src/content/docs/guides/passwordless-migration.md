---
title: "Passwordless configuration"
description: "Numeric policies and callback contexts for OTP and magic links."
---

OTP and magic-link expiration settings use seconds as `f64`. Set lengths and attempt budgets with floating-point literals too:

```rust
use better_auth::plugins::email_otp::EmailOtpConfig;

fn otp_config() -> EmailOtpConfig {
    EmailOtpConfig {
        otp_length: 6.0,
        allowed_attempts: 3.0,
        expires_in: 300.0,
        ..Default::default()
    }
}
```

`PhoneNumberConfig` uses the same numeric types; `MagicLinkConfig::expires_in` also takes seconds. See the [numeric policy audit](https://github.com/cschmatzler/better-auth-rs/blob/main/tests/compat/audits/plugins/email-otp/passwordless-numeric.md) for fractional, nonfinite, and zero-value behavior.

## Delivery callbacks

Email, phone, and magic-link callbacks receive `&CallbackContext`. It exposes the original request, admitted endpoint input, and the initialized context through `context::<YourAuthSchema>()`. Trusted calls without HTTP input have no request.

See the complete implementations for [email OTP](/plugins/email-otp/), [phone numbers](/plugins/phone-number/), and [magic links](/plugins/magic-link/).
