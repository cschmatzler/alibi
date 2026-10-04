---
title: "Have I Been Pwned"
description: "Reject passwords that appear in known data breaches, without ever sending the password anywhere."
---

`HaveIBeenPwnedPlugin` checks new passwords against the [Pwned Passwords](https://haveibeenpwned.com/Passwords) corpus. It uses the k-anonymity range API: the server sends only the **first five characters of the password's SHA-1 hash** and compares the returned suffixes locally. The password itself never leaves your server.

## Setup

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::{EmailPasswordPlugin, HaveIBeenPwnedPlugin};
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(HaveIBeenPwnedPlugin::new())
        .build()
        .await
}
```

No schema and no routes. The plugin installs a *password hash hook*: before any password is hashed on a protected endpoint, it is checked, and a compromised one is rejected:

```http
HTTP/1.1 400 Bad Request

{"code":"PASSWORD_COMPROMISED","message":"The password you entered has been compromised. Please choose a different password."}
```

## Protected endpoints

By default the check runs where a password is **chosen**:

`/sign-up/email`, `/change-password`, `/reset-password`, `/email-otp/reset-password`, `/phone-number/reset-password`, `/admin/create-user`, `/admin/set-user-password`

Sign-in is never checked (hashing there only verifies). Restrict or extend the list with `paths` (exact paths relative to `base_path`).

## Configuration

`HaveIBeenPwnedConfig`:

| Field | Default | Effect |
| --- | --- | --- |
| `enabled` | `true` | Master switch |
| `paths` | the list above | Exact endpoint paths that trigger the check |
| `custom_password_compromised_message` | built-in text | Message in the `PASSWORD_COMPROMISED` error |
| `client` | the public range API | `PwnedPasswordClient` — your HTTP client and/or mirror |

```rust
use better_auth::plugins::{HaveIBeenPwnedConfig, HaveIBeenPwnedPlugin, PwnedPasswordClient};

fn pwned() -> Result<HaveIBeenPwnedPlugin, url::ParseError> {
    // A self-hosted mirror of the range API, with your own timeouts and proxy settings.
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .unwrap_or_default();
    let client = PwnedPasswordClient::new(http, "https://pwned.internal.example.com/range/".parse()?);

    Ok(HaveIBeenPwnedPlugin::with_config(HaveIBeenPwnedConfig {
        paths: Some(vec!["/sign-up/email".into(), "/change-password".into()]),
        custom_password_compromised_message: Some("Choose a password that has not appeared in a breach.".into()),
        client,
        ..Default::default()
    }))
}
```

You can also call the check yourself, for example in a custom registration form:

```rust
use better_auth::plugins::haveibeenpwned::is_password_compromised;

async fn warn_user(password: &str) -> bool {
    is_password_compromised(password).await.unwrap_or(false)
}
```

## Failure behavior

If the range service cannot be reached or answers with something unusable, the request **fails** with the provider's status or a generic "Failed to check password. Please try again later." error rather than silently allowing a possibly breached password. Use a short timeout, a mirror, or `enabled: false` in environments without outbound access.

## Notes

- The check sees the original UTF-8 password, before normalization and hashing.
- Pair it with a sensible minimum length ([Email & password](/authentication/email-password/#options)) — long unique passwords matter more than composition rules.
- Existing passwords are only checked when they are next set.

## Frontend

See the official [Have I Been Pwned guide](https://www.better-auth.com/docs/plugins/have-i-been-pwned).
