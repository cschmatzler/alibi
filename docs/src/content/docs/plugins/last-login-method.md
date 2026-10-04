---
title: "Last login method"
description: "Remember which sign-in method a visitor used last, to highlight it on the login page."
---

Returning visitors appreciate a hint like "Continue with Google — last used". `LastLoginMethodPlugin` records the method after every successful sign-in in a cookie (and optionally on the user row). It is a **presentation hint only**: it proves nothing about the current request.

## Setup

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::LastLoginMethodPlugin;
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(LastLoginMethodPlugin::new())
        .build()
        .await
}
```

After a sign-in, the response carries a **non-HttpOnly** cookie (so frontend JavaScript can read it):

```http
set-cookie: better-auth.last_used_login_method=email; SameSite=Lax; Path=/; Max-Age=2592000
```

The recorded values are:

| Method value | Set by |
| --- | --- |
| `email` | `/sign-in/email`, `/sign-up/email` |
| `<provider id>` | OAuth callbacks, e.g. `google`, `github` |
| `email-otp` | `/sign-in/email-otp` |
| `magic-link` | `/magic-link/verify` |
| `passkey` | `/passkey/verify-authentication` |
| `siwe` | `/siwe/*` |

Other flows record nothing unless you provide a resolver. In the browser, read the cookie and highlight that button:

```ts
const last = authClient.getLastUsedLoginMethod();      // official client plugin
```

## Persist it on the user

```bash
better-auth-rs generate --plugins last-login-method -o src/auth_schema.rs
```

adds `users.last_login_method`. Enable storage with `store_in_database`:

```rust
use better_auth::plugins::{LastLoginMethodConfig, LastLoginMethodPlugin};

fn last_login() -> LastLoginMethodPlugin {
    LastLoginMethodPlugin::with_config(LastLoginMethodConfig {
        store_in_database: true,
        ..Default::default()
    })
}
```

The database value is updated for the signed-in user after each sign-in and is returned as `lastLoginMethod`. It cannot be set by clients (`400 FIELD_NOT_ALLOWED` when sent at sign-up).

## Configuration

| `LastLoginMethodConfig` field | Default | Effect |
| --- | --- | --- |
| `cookie_name` | `better-auth.last_used_login_method` | Cookie name |
| `max_age` | `2592000.0` (30 days) | Cookie lifetime in seconds |
| `store_in_database` | `false` | Also persist on the user row |
| `resolver` | none | `ResolveLastLoginMethod`: map the completed request to a method name (`None` falls back to the built-in rules; an empty string records nothing) |
| `before_store_cookie` | none | `BeforeStoreLastLoginMethodCookie`: return `false` to skip the cookie, for example without cookie consent. The session itself is unaffected |

```rust
use async_trait::async_trait;
use better_auth::plugins::{
    BeforeStoreLastLoginMethodCookie, LastLoginMethodConfig, LastLoginMethodContext,
    LastLoginMethodPlugin, ResolveLastLoginMethod,
};
use better_auth::AuthResult;
use std::sync::Arc;

struct Names;

impl ResolveLastLoginMethod for Names {
    fn resolve(&self, context: &LastLoginMethodContext) -> AuthResult<Option<String>> {
        // Report phone sign-ins too.
        Ok(context
            .route_path
            .starts_with("/phone-number/verify")
            .then(|| "phone".to_owned()))
    }
}

struct RequireConsent;

#[async_trait]
impl BeforeStoreLastLoginMethodCookie for RequireConsent {
    async fn before_store(&self, context: &LastLoginMethodContext, _method: &str) -> AuthResult<bool> {
        Ok(context.request.headers.get("cookie").is_some_and(|c| c.contains("consent=1")))
    }
}

fn last_login() -> LastLoginMethodPlugin {
    LastLoginMethodPlugin::with_config(LastLoginMethodConfig {
        resolver: Some(Arc::new(Names)),
        before_store_cookie: Some(Arc::new(RequireConsent)),
        ..Default::default()
    })
}
```

`LastLoginMethodContext` carries the request (`request`), the matched `route_path` and `params`, the endpoint `body`, and — at the completed-response stage — the `response` and the `new_session`.

## Notes

- The cookie is readable by scripts and forgeable by the client. Use it only to order login buttons — never as evidence of how someone authenticated.
- It holds a method name, not an identifier, so it is not personal data in itself; consider consent rules in your jurisdiction.

## Frontend

See the official [Last login method guide](https://www.better-auth.com/docs/plugins/last-login-method).
