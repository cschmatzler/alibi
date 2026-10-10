---
title: "Server-side calls"
description: "Call auth operations from your own Rust code: handle_request, trusted dispatch_endpoint, and plugin server-only APIs."
---

Not every auth operation should be reachable over HTTP. Creating an API key *for* a user, verifying an API key, minting a service JWT, reading backup codes, adding a member without an invitation — these are **server-only** operations. Alibi gives your Rust code two ways to call into an auth instance without a network hop.

| API | Input | Use it for |
| --- | --- | --- |
| `handle_request(AuthRequest)` | A full HTTP-shaped request | Embedding in a framework, proxying, tests, "ask the auth server who this is" |
| `dispatch_endpoint(ServerEndpoint, EndpointOptions)` | Logical inputs and optional headers | Trusted server operations and any endpoint a plugin exposes in typed form |

## `handle_request`

Build an `AuthRequest`, get an `AuthResponse`. It runs exactly the pipeline an HTTP request would — middleware, rate limits, CSRF, plugin hooks — so use it when you want those behaviors:

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::prelude::{AuthRequest, HttpMethod};
use alibi::{AuthResult, Alibi};
use serde_json::Value;

/// Resolve the session behind a `Cookie` header.
async fn session_for(auth: &Alibi<AppAuthSchema>, cookie: &str) -> AuthResult<Option<Value>> {
    let mut request = AuthRequest::new(HttpMethod::Get, "/api/auth/get-session");
    request.headers.insert("cookie".into(), cookie.to_owned());
    let response = auth.handle_request(request).await?;
    let body: Value = serde_json::from_slice(&response.body)?;
    Ok((!body.is_null()).then_some(body))
}
```

## `dispatch_endpoint`

Plugins that expose server-only operations publish typed constructors that return a `ServerEndpoint<Output>`. You pass it to `dispatch_endpoint` with optional `EndpointOptions`:

```rust
use alibi::endpoint::EndpointOptions;

fn options() -> EndpointOptions {
    EndpointOptions {
        headers: None,   // logical headers, e.g. a Cookie or Authorization to authenticate the call
        request: None,   // an optional real AuthRequest, for callbacks that need it
        method: None,    // override the logical method
    }
}
```

The output is an `EndpointOutput<T>`; `decode()` turns it into the typed value `T`, `value()` gives the raw JSON, and failures are `EndpointError { error, headers, body }`.

**Example: sign a service token and verify it** with the [JWT plugin](/plugins/jwt/):

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::Alibi;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::jwt::JwtPlugin;

async fn roundtrip(auth: &Alibi<AppAuthSchema>, token: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let verified = auth
        .dispatch_endpoint(
            JwtPlugin::verify_endpoint(token, Some("https://auth.example.com".to_owned())),
            EndpointOptions::default(),
        )
        .await?
        .decode()?;
    Ok(verified.payload.is_some())
}
```

**Authenticating a dispatched call.** Operations that act on behalf of a user need credentials, supplied as logical **headers** — never as a shortcut that skips verification:

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::Alibi;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::one_time_token::OneTimeTokenPlugin;
use std::collections::HashMap;

async fn handoff_token(auth: &Alibi<AppAuthSchema>, cookie: &str) -> Result<String, Box<dyn std::error::Error>> {
    let output = auth
        .dispatch_endpoint(
            OneTimeTokenPlugin::generate_endpoint(),
            EndpointOptions {
                headers: Some(HashMap::from([("cookie".to_owned(), cookie.to_owned())])),
                ..Default::default()
            },
        )
        .await?
        .decode()?;
    Ok(output.token)
}
```

Without the headers the call fails with `Unauthorized`, exactly like the HTTP route. Only verified credentials (a valid signed session cookie, a bearer token, …) or installed plugin code can establish a session; a `userId` in the input never does.

Dispatch goes through the **same hooks** as HTTP calls: [endpoint hooks](/concepts/hooks/#endpoint-hooks) registered on the builder and by plugins run for dispatched calls too (with `call.request()` empty). It does **not** pass through HTTP middleware (body limit, rate limits, CORS, CSRF), because there is no HTTP request.

### Server-only operations by plugin

| Plugin | Constructor | Purpose |
| --- | --- | --- |
| [API key](/plugins/api-key/) | `ApiKeyPlugin::create_endpoint`, `update_endpoint`, `verify_endpoint`, `delete_all_expired_endpoint` | Provision keys with quota and permissions; verify presented keys |
| [JWT](/plugins/jwt/) | `JwtPlugin::sign_endpoint`, `verify_endpoint`, `token_endpoint`, `jwks_endpoint` | Service tokens; verify tokens |
| [One-time token](/plugins/one-time-token/) | `OneTimeTokenPlugin::generate_endpoint`, `verify_endpoint` | Session handoff |
| [Two-factor](/plugins/two-factor/) | `TwoFactorPlugin::view_backup_codes_endpoint`, `generate_totp_endpoint` | Support tooling and tests |
| [Organization](/plugins/organization/) | `OrganizationPlugin::create_endpoint`, `add_member_endpoint`, `remove_member_endpoint`, `delete_endpoint` | Provisioning without a member session |
| [Email OTP](/plugins/email-otp/) | `EmailOtpPlugin::create_verification_otp`, `get_verification_otp` (instance methods) | Issue or read a code |
| [Phone number](/plugins/phone-number/) | `PhoneNumberPlugin::consume_otp` (instance method) | Check a code |
| [OAuth](/authentication/social-sign-on/) | `OAuthAccountApi::get_access_token`, `refresh_token`, `account_info` | Provider tokens for a known user id |

Instance methods take the initialized context — `auth.context()` — and need the plugin value you registered; keep a clone (or construct a second identical instance) next to the auth instance:

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::Alibi;
use alibi::plugins::email_otp::EmailOtpType;
use alibi::plugins::{EmailOtpConfig, EmailOtpPlugin};

async fn code_for_support(
    auth: &Alibi<AppAuthSchema>,
    plugin: &EmailOtpPlugin,
    email: &str,
) -> alibi::AuthResult<String> {
    plugin.create_verification_otp(auth.context(), email, EmailOtpType::SignIn).await
}

fn plugin() -> EmailOtpPlugin {
    EmailOtpPlugin::new(EmailOtpConfig::default())
}
```

## Reading the store directly

`auth.store()` returns the `AuthStore`, the same trait the plugins use. Prefer the auth operations above for anything with security semantics (hashing passwords, issuing sessions). Use the store for reads and for your own bookkeeping.

## Testing with an auth instance

An instance built with [`AuthBuilder::without_database`](/databases/no-database/) or an in-memory SQLite database makes fast integration tests; call `handle_request` with `Origin` set and, to avoid the built-in strict sign-in limits, build with `.rate_limit(RateLimitConfig::new().enabled(false))`:

```rust
use alibi::middleware::RateLimitConfig;
use alibi::plugins::EmailPasswordPlugin;
use alibi::store::StatelessSchema;
use alibi::{AuthBuilder, AuthConfig, AuthResult, Alibi};

async fn test_instance() -> AuthResult<Alibi<StatelessSchema>> {
    let config = AuthConfig::new("test-secret-with-at-least-32-characters").base_url("http://localhost:3000");
    AuthBuilder::without_database(config)
        .rate_limit(RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .build()
        .await
}
```
