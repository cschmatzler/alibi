---
title: "Two-factor authentication"
description: "Add TOTP, email/SMS one-time codes and backup codes as a second sign-in factor."
---

`TwoFactorPlugin` adds a second factor after password (or any other first-factor) sign-in. Users can enrol an authenticator app (TOTP), receive one-time codes you deliver by email or SMS, and keep single-use backup codes for emergencies. Optionally a verified browser is "trusted" so the second factor is skipped for 30 days.

## Schema

```bash
better-auth-rs generate --plugins two-factor -o src/auth_schema.rs
```

Adds `users.two_factor_enabled` and the `two_factor` table: `secret`, `backup_codes` (encrypted by default), `verified`, `failed_verification_count`, `locked_until`, timestamps.

## Setup

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::{EmailPasswordPlugin, TwoFactorPlugin};
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(TwoFactorPlugin::new().issuer("My application".to_owned()))
        .build()
        .await
}
```

## The user journey

**1. Enrol (signed in).**

```bash
curl -b cookies.txt http://localhost:3000/api/auth/two-factor/enable \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"password":"a-long-example-password"}'
```

```json
{"method":"totp","totpURI":"otpauth://totp/My%20application:ada@example.com?secret=JBSWY3DPEHPK3PXP&issuer=My%20application&digits=6&period=30","backupCodes":["a1b2c-d3e4f","…"]}
```

Render `totpURI` as a QR code and show the backup codes **once**. Two-factor is not active yet: it is marked enabled only after the user proves possession of the secret:

```bash
curl -b cookies.txt http://localhost:3000/api/auth/two-factor/verify-totp \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"code":"482913"}'
# {"token":"…","user":{…}}
```

Confirming the first code activates two-factor for the user (`skip_verification_on_enable: true` activates it immediately instead). A wrong code answers `401 INVALID_CODE`.

**2. Sign in.** After enrolment, `POST /sign-in/email` does **not** create a session. It answers with a challenge and sets a short-lived `two_factor` cookie:

```json
{"twoFactorRedirect":true,"twoFactorMethods":["totp"]}
```

`twoFactorMethods` lists the factors this user can complete: `totp` once an authenticator secret is confirmed, and `otp` whenever `send_otp` is configured. Backup codes are always accepted at `/two-factor/verify-backup-code` and are not listed. The client then calls one of the verification endpoints **with that cookie**, and receives the session:

| Method | Endpoint | Body |
| --- | --- | --- |
| Authenticator app | `POST /two-factor/verify-totp` | `{"code":"482913","trustDevice":true}` |
| Emailed/SMS code | `POST /two-factor/send-otp`, then `POST /two-factor/verify-otp` | `{"code":"482913"}` |
| Backup code | `POST /two-factor/verify-backup-code` | `{"code":"a1b2c-d3e4f","disableSession":false}` |

Successful verification clears the challenge cookie, sets the session cookie and returns `{"token":…,"user":…}`. `trustDevice: true` also sets a signed `trust_device` cookie; while it is valid (30 days, refreshed on each sign-in) the second factor is skipped. A reused backup code fails with `401 INVALID_BACKUP_CODE`; a missing or expired challenge cookie with `401 INVALID_TWO_FACTOR_COOKIE`.

## Endpoints

| Method | Path | Body | Purpose |
| --- | --- | --- | --- |
| `POST` | `/two-factor/enable` | `password`, optional `method` (`totp`/`otp`), `issuer` | Create secret and backup codes; `method: "otp"` enables code delivery immediately |
| `POST` | `/two-factor/get-totp-uri` | `password` | Re-read the authenticator URI |
| `POST` | `/two-factor/generate-backup-codes` | `password` | Replace backup codes → `{"status":true,"backupCodes":[…]}` |
| `POST` | `/two-factor/disable` | `password` | Remove two-factor |
| `POST` | `/two-factor/verify-totp` | `code`, `trustDevice` | Enrolment confirmation or sign-in step → `{token, user}` |
| `POST` | `/two-factor/send-otp` | `trustDevice` | Deliver a code through `send_otp` |
| `POST` | `/two-factor/verify-otp` | `code`, `trustDevice` | Sign-in step |
| `POST` | `/two-factor/verify-backup-code` | `code`, `disableSession`, `trustDevice` | Sign-in step (code is consumed) |

`enable`, `get-totp-uri`, `generate-backup-codes` and `disable` require the user's **password**. Users without a password (social or passwordless accounts) need `allow_passwordless`, or the narrower `totp_allow_passwordless` / `backup_allow_passwordless`.

## Deliver one-time codes

Email/SMS codes need your delivery callback (`/two-factor/send-otp` is unavailable without it):

```rust
use async_trait::async_trait;
use better_auth::plugins::{SendTwoFactorOtp, TwoFactorPlugin};
use better_auth::wire::UserView;
use better_auth::AuthResult;
use std::sync::Arc;

struct OtpMailer;

#[async_trait]
impl SendTwoFactorOtp for OtpMailer {
    async fn send(&self, user: &UserView, otp: &str) -> AuthResult<()> {
        println!("send code {otp} to {:?}", user.email);
        Ok(())
    }
}

fn two_factor() -> TwoFactorPlugin {
    TwoFactorPlugin::new()
        .issuer("My application".to_owned())
        .custom_send_otp(Arc::new(OtpMailer))
        .otp_digits(6.0)
        .otp_period_minutes(5.0)
}
```

## Configuration

Scalar options have builder methods of the same name, taking the plain value (`.issuer("…".to_owned())`, `.otp_digits(6.0)`); delivery uses `.custom_send_otp(Arc<dyn SendTwoFactorOtp>)`. The storage options and `custom_backup_codes_generate` are fields of `TwoFactorConfig` — build with `TwoFactorPlugin::with_config(TwoFactorConfig { backup_storage: …, ..Default::default() })`. Defaults:

| Option | Default | Effect |
| --- | --- | --- |
| `issuer` / `totp_issuer` | app name | Issuer in enrolment / existing-URI TOTP links |
| `totp_digits`, `totp_period` | `6`, `30` s | TOTP parameters |
| `totp_disabled` | `false` | Turn off TOTP entirely (OTP and backup codes only) |
| `skip_verification_on_enable` | `false` | Enable without a confirming code |
| `backup_code_amount`, `backup_code_length` | `10`, `10` | Number and length of backup codes (formatted `xxxxx-xxxxx`) |
| `backup_storage` | `Encrypted` | `Encrypted`, `Plain`, or `CustomCipher(Arc<dyn TwoFactorBackupCipher>)` |
| `custom_backup_codes_generate` | none | Closure producing your own codes |
| `send_otp` | none | `SendTwoFactorOtp` delivery |
| `otp_digits`, `otp_period_minutes`, `otp_allowed_attempts` | `6`, `3`, `5` | Code format, lifetime (minutes) and attempt budget |
| `otp_storage` | default | `Plain`, `Hashed`, `Encrypted`, `CustomHash(…)`, `CustomCipher(…)` |
| `two_factor_cookie_max_age` | `600` s | How long the sign-in challenge cookie lives |
| `trust_device_max_age` | `2 592 000` s (30 d) | Trusted-device proof lifetime |
| `allow_passwordless` | `false` | Allow password-less users to manage factors |
| `account_lockout` | on, 10 attempts, 900 s | `AccountLockoutConfig`: lock sign-in verification after consecutive failures across factors |

```rust
use better_auth::plugins::TwoFactorPlugin;
use better_auth::plugins::two_factor::AccountLockoutConfig;

fn strict() -> TwoFactorPlugin {
    TwoFactorPlugin::new()
        .account_lockout(AccountLockoutConfig {
            enabled: true,
            max_failed_attempts: 5.0,
            duration_seconds: 1800.0,
        })
        .trust_device_max_age(7.0 * 24.0 * 3600.0)
}
```

Numeric options follow JavaScript number semantics (fractions allowed, `0` selecting documented defaults for OTP settings). TOTP secrets are encrypted with the auth [secret](/reference/secrets/); keep old keys in the ring until enrolled secrets have been re-saved.

## Server-only operations

Two operations are not HTTP routes; call them through [`dispatch_endpoint`](/guides/server-side-calls/):

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::BetterAuth;
use better_auth::endpoint::EndpointOptions;
use better_auth::plugins::TwoFactorPlugin;

async fn backup_codes(
    auth: &BetterAuth<AppAuthSchema>,
    user_id: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let output = auth
        .dispatch_endpoint(
            TwoFactorPlugin::view_backup_codes_endpoint(user_id),
            EndpointOptions::default(),
        )
        .await?
        .decode()?;
    Ok(output.backup_codes)
}
```

`TwoFactorPlugin::generate_totp_endpoint(secret)` returns the current TOTP for a secret — useful in tests.

## Security notes

- Backup codes are single use and stored encrypted; regenerating invalidates the old set.
- Failed sign-in verifications count across TOTP, OTP and backup codes; after the limit the user is locked out until `locked_until`.
- Disabling two-factor requires the password, preventing a hijacked session from silently removing the factor.
- A trusted-device cookie is a bearer proof for that browser; set `trust_device_max_age` lower for sensitive apps.
- Passkeys are the stronger second factor for phishing resistance — see [Passkey](/plugins/passkey/).

## Frontend

See the official [Two-factor guide](https://www.better-auth.com/docs/plugins/2fa).
