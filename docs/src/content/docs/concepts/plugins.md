---
title: "Plugins"
description: "How plugins are registered, which ones are always installed, and how to inspect what is active."
---

Everything beyond the core session machinery is a plugin. A plugin owns a set of routes, may add schema fields, and can hook into requests, sign-in and user lifecycle events. You register plugins with `.plugin(...)` and finish with `.build().await`.

## Register plugins

Generate and migrate any schema the plugin needs ([Database](/concepts/database/#plugin-schema)), then add it to the builder:

```bash
better-auth-rs generate --plugins admin,two-factor -o src/auth_schema.rs
```

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::{AdminPlugin, EmailPasswordPlugin, TwoFactorPlugin};
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(TwoFactorPlugin::new())
        .plugin(AdminPlugin::new())
        .build()
        .await
}
```

`build()` initializes plugins in the order you registered them. Most plugins accept configuration in two equivalent forms — chained builder methods, or a config struct:

```rust
use better_auth::plugins::{AdminConfig, AdminPlugin};

fn admin_plugins() -> (AdminPlugin, AdminPlugin) {
    // 1. Chained builder methods (one per option)
    let chained = AdminPlugin::new()
        .default_role("member")
        .allow_impersonating_admins(true);
    // 2. A config struct
    let from_struct = AdminPlugin::with_config(AdminConfig {
        default_role: "member".into(),
        allow_impersonating_admins: true,
        ..Default::default()
    });
    (chained, from_struct)
}
```

Plugins whose configuration includes callbacks or trait objects (email OTP, magic link, phone number, JWT, CAPTCHA, SIWE, …) take a config struct and use `..Default::default()` for the rest; the API key plugin uses `ApiKeyPlugin::builder()…build()`. Each plugin page lists its options.

## Plugins that are always installed

The builder appends these core plugins unless you register your own of the same name:

| Plugin | Name | Provides |
| --- | --- | --- |
| `SessionManagementPlugin` | `session-management` | `/get-session`, `/sign-out`, `/list-sessions`, `/revoke-*`, `/update-session` |
| `EmailPasswordPlugin` (disabled) | `email-password` | Routes registered but credential login is **off** until you configure it |
| `PasswordManagementPlugin` | `password-management` | `/request-password-reset`, `/reset-password`, `/change-password`, `/verify-password` |
| `EmailVerificationPlugin` | `email-verification` | `/send-verification-email`, `/verify-email` |
| `AccountManagementPlugin` | `account-management` | `/list-accounts`, `/unlink-account` |
| `OAuthPlugin` (no providers) | `oauth` | `/sign-in/social`, `/link-social`, `/callback/{provider}`, token endpoints |
| `UserManagementPlugin` | `user-management` | `/update-user`, `/change-email`, `/delete-user` |

Registering one of these yourself **replaces** the default with your configuration: `.plugin(EmailPasswordPlugin::new().enable_signup(true))` enables password sign-in, and `.plugin(UserManagementPlugin::new().change_email_enabled(true))` enables email changes. Explicit plugins are consulted before the defaults when a request is dispatched.

## Order matters in two places

- **Route ownership.** When two plugins serve the same route, the first registered wins. [Custom session](/plugins/custom-session/) relies on this: register it *before* `SessionManagementPlugin` to take over `GET /get-session`.
- **Hooks.** `before_request`, `after_request` and endpoint hooks run in registration order.

## Inspect the running instance

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::BetterAuth;

fn describe(auth: &BetterAuth<AppAuthSchema>) {
    println!("plugins: {:?}", auth.plugin_names());
    for route in auth.registered_routes() {
        println!("{:?} {}", route.method, route.path);
    }
}
```

Every route in the instance, with request and response schemas, is also available as an [OpenAPI document](/plugins/open-api/), and the complete table of routes is in the [HTTP API reference](/reference/http-api/).

## Catalog at a glance

| I need to… | Plugin |
| --- | --- |
| Sign in with email and password, usernames | [Email & password](/authentication/email-password/), [Username](/plugins/username/) |
| Sign in without a password | [Magic link](/plugins/magic-link/), [Email OTP](/plugins/email-otp/), [Passkey](/plugins/passkey/), [Phone number](/plugins/phone-number/), [SIWE](/plugins/siwe/) |
| Sign in with Google, GitHub, … | [Social sign-on](/authentication/social-sign-on/), [Generic OAuth](/authentication/generic-oauth/), [One Tap](/plugins/one-tap/) |
| Require a second factor | [Two-factor](/plugins/two-factor/) |
| Authenticate machines and CLIs | [API key](/plugins/api-key/), [Device authorization](/plugins/device-authorization/), [Bearer](/plugins/bearer/), [JWT](/plugins/jwt/) |
| Run multi-tenant apps | [Organization](/plugins/organization/), [Admin](/plugins/admin/) |
| Harden sign-up | [CAPTCHA](/plugins/captcha/), [Have I Been Pwned](/plugins/have-i-been-pwned/) |

The complete list is the [plugin overview](/plugins/). To build your own, read [Writing a plugin](/guides/writing-a-plugin/).

## Frontend

See the official [client plugin documentation](https://www.better-auth.com/docs/concepts/client#plugins).
