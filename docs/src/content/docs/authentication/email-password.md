---
title: "Email & password"
description: "Password sign-up and sign-in, password policy, reset and change flows, and custom hashing."
---

`EmailPasswordPlugin` enables credential authentication. The core plugins for sessions, password reset and email verification are already installed by the builder; this plugin turns on the sign-in and sign-up routes.

## Setup

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(
            EmailPasswordPlugin::new()
                .enable_signup(true)
                .password_min_length(12),
        )
        .build()
        .await
}
```

Without `enable_signup(true)`, `POST /sign-up/email` fails with `400 EMAIL_PASSWORD_SIGN_UP_DISABLED`; without registering the plugin at all, password sign-in is off.

## Endpoints

| Method | Path | Body | Result |
| --- | --- | --- | --- |
| `POST` | `/sign-up/email` | `name`, `email`, `password`, optional `image`, `callbackURL`, `rememberMe`, additional fields | Creates the user and credential account; signs in unless disabled |
| `POST` | `/sign-in/email` | `email`, `password`, optional `callbackURL`, `rememberMe` | Verifies the password and issues a session |
| `POST` | `/sign-in/username`, `/is-username-available` | See [Username](/plugins/username/) | Only with `enable_username(true)` |
| `POST` | `/request-password-reset`, `/reset-password`, `GET /reset-password/{token}` | See [below](#reset-a-forgotten-password) | Password reset |
| `POST` | `/change-password`, `/verify-password` | See [below](#change-or-verify-a-password) | Authenticated password operations |

```bash
curl -i -c cookies.txt http://localhost:3000/api/auth/sign-up/email \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"name":"Ada","email":"ada@example.com","password":"a-long-example-password"}'
```

Both `/sign-up/email` and `/sign-in/email` also accept `application/x-www-form-urlencoded`, so plain HTML forms work. Emails are lowercased before lookup. When two-factor authentication is enabled for the user, `/sign-in/email` answers `{"twoFactorRedirect":true,"twoFactorMethods":["totp", …]}` and sets a pending-challenge cookie instead of a session; see [Two-factor](/plugins/two-factor/).

## Options

`EmailPasswordPlugin` builder methods (or fields of `EmailPasswordConfig` with `with_config`):

| Option | Default | Effect |
| --- | --- | --- |
| `enabled(bool)` | `true` | Master switch. The always-installed default instance is `false` |
| `enable_signup(bool)` | `false` | Allow `/sign-up/email` |
| `auto_sign_in(bool)` | `true` | Sign the user in after sign-up. When `false`, sign-up returns the user without a session |
| `require_email_verification(bool)` | `false` | Refuse sign-in (and sign-up sessions) until the email is verified. See [Email verification](/authentication/email-verification/) |
| `password_min_length(n)` | 8 | Minimum length, counted in UTF-16 units; `0` means the default |
| `password_max_length(n)` | 128 | Maximum length; `0` means the default |
| `password_hasher(Arc<dyn PasswordHasher>)` | scrypt | See [custom hashing](#custom-password-hashing) |
| `enable_username(bool)` / `username_config(…)` | off | [Username](/plugins/username/) sign-in |
| `on_existing_user_signup(callback)` | none | Called when someone signs up with an address that already exists |
| `custom_synthetic_user(callback)` | none | Shapes the decoy response described below |
| `with_email_verification(plugin)` | none | Send a verification email on sign-in; see [Email verification](/authentication/email-verification/) |

### Password composition rules

Length comes from the plugin; composition rules come from `AuthConfig::password` and apply to sign-up, reset and change in every plugin:

```rust
use better_auth::AuthConfig;

fn auth_config(secret: &str) -> AuthConfig {
    let mut config = AuthConfig::new(secret);
    config.password.require_uppercase = true;
    config.password.require_lowercase = true;
    config.password.require_numbers = true;
    config.password.require_special = true;
    config
}
```

Violations return `400` with a message such as `Password must contain at least one number`. Pair the rules with the [compromised-password check](/plugins/have-i-been-pwned/), which is more effective than composition rules alone.

## Enumeration-safe sign-up

If `require_email_verification` is on (or `auto_sign_in` is off), signing up with an **existing** address does not fail with `422`. The server answers with a decoy `200` response — a user object with a fresh random `id` and no `token` — so an attacker cannot learn which addresses are registered. The real owner learns about the attempt through a callback you provide:

```rust
use better_auth::plugins::EmailPasswordPlugin;
use std::sync::Arc;

fn email_password() -> EmailPasswordPlugin {
    EmailPasswordPlugin::new()
        .enable_signup(true)
        .require_email_verification(true)
        .on_existing_user_signup(Arc::new(|user, request| {
            Box::pin(async move {
                // Tell the account owner that someone tried to register their address.
                println!("signup attempt for {:?} from {:?}", user.email, request.headers.get("user-agent"));
                Ok(())
            })
        }))
}
```

Callback errors are logged; the response stays generic. Use `custom_synthetic_user` to add application fields to the decoy user so its shape matches real responses.

## Reset a forgotten password

The reset flow is provided by the always-installed `PasswordManagementPlugin`. `POST /request-password-reset` exists only when you configure a sender:

```rust
use crate::auth_schema::AppAuthSchema;
use async_trait::async_trait;
use better_auth::email::EmailProvider;
use better_auth::plugins::{PasswordManagementPlugin, SendResetPassword};
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};
use chrono::Duration;
use std::sync::Arc;

struct ResetMailer(Arc<dyn EmailProvider>);

#[async_trait]
impl SendResetPassword for ResetMailer {
    async fn send(&self, user: &serde_json::Value, url: &str, _token: &str) -> AuthResult<()> {
        let to = user["email"].as_str().unwrap_or_default();
        self.0.send(to, "Reset your password", "", &format!("Reset it here: {url}")).await
    }
}

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
    mail: Arc<dyn EmailProvider>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(
            PasswordManagementPlugin::new()
                .send_reset_password(Arc::new(ResetMailer(mail)))
                .reset_token_expiry(Duration::minutes(30))
                .revoke_sessions_on_password_reset(true),
        )
        .build()
        .await
}
```

The flow:

1. `POST /request-password-reset` with `{"email":"…","redirectTo":"https://app.example.com/reset"}`. The response is always `{"status":true,"message":"If this email exists in our system, check your email for the reset link"}` — whether or not the user exists — and your callback receives the link `{base}/api/auth/reset-password/{token}?callbackURL={redirectTo}`.
2. The user opens the link. `GET /reset-password/{token}` validates it and redirects to `redirectTo?token={token}` — or to `redirectTo?error=INVALID_TOKEN` when the token is bad or expired. `redirectTo` must be a [trusted redirect target](/concepts/security/).
3. Your page posts `POST /reset-password` with `{"newPassword":"…","token":"…"}` → `{"status":true}`.

`PasswordManagementPlugin` options:

| Option | Default | Effect |
| --- | --- | --- |
| `send_reset_password(…)` | none | Required to enable `/request-password-reset` |
| `reset_token_expiry(Duration)` | 1 hour | Token lifetime; takes precedence over `reset_token_expiry_hours` |
| `revoke_sessions_on_password_reset(bool)` | `false` | Delete every session of the user after a reset |
| `on_password_reset(callback)` | none | Runs after the new password is stored (before revocation); an error propagates |
| `require_current_password(bool)` | `true` | Verify `currentPassword` on `/change-password` |
| `password_hasher(…)` | scrypt | Hasher for `/change-password`; `/reset-password` prefers the email/password plugin's hasher |

The token is single-use and stored as a verification row (`reset-password:<token>`). Delivery follows the [notification policy](/concepts/notifications/).

## Change or verify a password

Both require a session.

```bash
curl -b cookies.txt http://localhost:3000/api/auth/change-password \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"currentPassword":"a-long-example-password","newPassword":"an-even-longer-password","revokeOtherSessions":true}'
# {"token":"…","user":{…}}   (a new session token when other sessions were revoked)

curl -b cookies.txt http://localhost:3000/api/auth/verify-password \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"password":"a-long-example-password"}'
# {"status":true}
```

`/verify-password` lets you re-check the password before a sensitive action in your own UI.

## Custom password hashing

Passwords are hashed with scrypt in the same format as the TypeScript `better-auth` (`<hex salt>:<hex key>`, N=2¹⁴, r=16, p=1, 64-byte key, NFKC-normalized input), so credentials migrated from a TypeScript deployment verify unchanged. To use another algorithm — or to accept legacy hashes while upgrading them — implement `PasswordHasher`:

```rust
use async_trait::async_trait;
use better_auth::plugins::{EmailPasswordPlugin, PasswordManagementPlugin};
use better_auth::{AuthResult, PasswordHasher, ScryptHasher};
use std::sync::Arc;

/// Verifies legacy `$legacy$…` hashes and the current scrypt format;
/// always hashes new passwords with scrypt.
struct MigratingHasher;

fn verify_legacy(hash: &str, password: &str) -> bool {
    // Call into your previous algorithm here.
    hash == format!("$legacy${password}")
}

#[async_trait]
impl PasswordHasher for MigratingHasher {
    async fn hash(&self, password: &str) -> AuthResult<String> {
        ScryptHasher.hash(password).await
    }

    async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
        if hash.starts_with("$legacy$") {
            return Ok(verify_legacy(hash, password));
        }
        ScryptHasher.verify(hash, password).await
    }
}

fn password_plugins() -> (EmailPasswordPlugin, PasswordManagementPlugin) {
    let hasher = Arc::new(MigratingHasher);
    (
        EmailPasswordPlugin::new().password_hasher(hasher.clone()),
        // `/change-password` uses this plugin's own hasher setting.
        PasswordManagementPlugin::new().password_hasher(hasher),
    )
}
```

Set the hasher on **both** plugins: `/sign-up` and `/sign-in` use the email/password plugin's, `/change-password` uses the password-management plugin's, and `/reset-password` and the OTP/phone reset flows prefer the email/password plugin's. To reject passwords *before* hashing — for example against a breach list — register a `PasswordHashHook`, which is how the [Have I Been Pwned](/plugins/have-i-been-pwned/) plugin works.

## Frontend

See the official [email and password guide](https://www.better-auth.com/docs/authentication/email-password).
