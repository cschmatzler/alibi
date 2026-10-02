# Better Auth RS

The most comprehensive authentication framework for Rust. Inspired by [Better Auth](https://www.better-auth.com/).

> [!WARNING]
> **v1 is in alpha.** The current release (`1.0.0-alpha.3`) is under active
> development. APIs, wire formats, and database schemas may change without
> notice between alpha releases, and production use is not recommended yet.
> Please report issues and feedback on [GitHub](https://github.com/better-auth-rs/better-auth-rs/issues).

The pinned compatibility target is `better-auth@1.7.6`. The TypeScript
runtime plus `better-auth/client` harness remain the source of truth for
wire behavior.

[![Crates.io](https://img.shields.io/crates/v/better-auth.svg)](https://crates.io/crates/better-auth)
[![Documentation](https://docs.rs/better-auth/badge.svg)](https://docs.rs/better-auth)
[![CI](https://github.com/better-auth-rs/better-auth-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/better-auth-rs/better-auth-rs/actions/workflows/ci.yml)
[![License](https://img.shields.io/crates/l/better-auth.svg)](LICENSE-MIT)
[![better-auth compatibility](https://img.shields.io/badge/better--auth-v1.7.6-blue?logo=typescript&logoColor=white)](https://www.npmjs.com/package/better-auth/v/1.7.6)

## Features

- **Plugin Architecture** — compose only the auth features you need
- **Type Safety** — leverages Rust's type system for compile-time guarantees
- **Async First** — built on Tokio with full async/await support
- **App-Owned SeaORM Schema** — auth entities live in your SeaORM model graph
- **Framework Integration** — first-class Axum support with session extractors
- **OpenAPI** — auto-generated API specification
- **Middleware** — CSRF, CORS, rate limiting, body size limits
- **Database Hooks** — intercept create/update/delete operations

## Quick Start

```toml
[dependencies]
better-auth = { version = "1.0.0-alpha.3", features = ["axum", "seaorm2"] }
```

Generate the schema scaffolding with the CLI:

```bash
cargo install better-auth-cli
better-auth-rs generate -o src/auth_schema.rs
```

Or write it by hand — the `AuthEntity` derive generates all trait impls:

```rust,ignore
use better_auth::{AuthConfig, AuthSchema, BetterAuth};
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::seaorm::{AuthEntity, Database, SeaOrmStore};
use better_auth::seaorm::sea_orm::entity::prelude::*;

// Only include the fields you need — plugin fields are optional.
// The AuthEntity macro adapts: missing fields return sensible defaults.
#[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
#[auth(role = "user")]
#[sea_orm(table_name = "users")]
pub struct UserModel {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub email_verified: bool,
    pub image: Option<String>,
    pub created_at: DateTimeUtc,
    pub updated_at: DateTimeUtc,
    // Plugin fields — add only if you use the plugin:
    // pub username: Option<String>,          // username plugin
    // pub two_factor_enabled: bool,          // two-factor plugin
    // pub role: Option<String>,              // admin plugin
    // pub banned: bool,                      // admin plugin
    // Extra app-specific fields work too:
    // pub locale: Option<String>,
}

// ... session, account, verification entities ...

#[derive(AuthSchema)]
#[auth(user = "crate::UserModel")]
#[auth(session = "crate::SessionModel")]
#[auth(account = "crate::AccountModel")]
#[auth(verification = "crate::VerificationModel")]
pub struct AppAuthSchema;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    let config = AuthConfig::new("your-very-secure-secret-key-at-least-32-chars-long")
        .base_url("http://localhost:3000");
    let store = SeaOrmStore::<AppAuthSchema>::new(config.clone(), database);

    let auth = BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .build()
        .await?;

    Ok(())
}
```

Your app owns the auth entities and migrations — Better Auth adapts to whatever schema you define.

Configure application fields through `config.user.additional_fields`,
`config.session.additional_fields` and `config.account.additional_fields`.
`FieldConfig` supports required/default/input/returned policies, logical-to-physical
column names, input validation, awaited adapter transforms and `on_update`.
Plugins can declare the same policies through their field registries. Promise-like
asynchronous endpoint validation is explicitly rejected, matching the pinned
runtime; asynchronous storage transforms are awaited.

Record-aware store operations return `AdapterRecord<M>`: `stored()` retains the
physical model and its identity/ownership/credential getters, while
`raw_snapshot()` retains declared output, including hidden fields and undefined
presence for trusted callbacks. Public user/session/account projection applies
returned-field filtering separately, and public account output always removes
credentials. Register `AdapterAfterHook` during initialization to observe retained
write output after commit; transaction rollback discards those observations.
Typed store methods and SeaORM hooks continue to expose physical models.

Password-reset and email-verification delivery callbacks are awaited by default;
their errors fail the request. Set
`config.awaited_notification_errors(AwaitedNotificationErrorPolicy::LogAndContinue)`
to log lifecycle delivery failures and continue the response, matching the pinned
Better Auth 1.7.6 notification helper. Explicit verification delivery still
propagates awaited errors. Set `config.background_tasks` to observe already
running delivery as background work. Already-issued reset proofs or committed
email-change state remain stored after a delivery failure; uncommitted signup
writes roll back when the default propagation policy fails the request.

Passwordless `SendEmailOtp::send`, `EmailOtpGenerator::generate`,
`SendMagicLink::send`, `SendPhoneOtp::send`, `PhoneOtpVerifier::verify`, and
`PhoneVerificationHook::verified` receive a final `&CallbackContext` argument.
Update application implementations to accept that argument. Its `request` and
`request_hook.request` retain the actual native request and original transport
input; `endpoint` separately exposes the admitted logical input, including hook
transformations. `context::<YourAuthSchema>()` returns the initialized native
context and real store, or `None` for a different schema. Trusted calls without
HTTP input have no fabricated request. Background email/phone delivery owns this
context until completion, even when its completion observer is dropped. Magic
link delivery awaits directly; its token generator and the phone validator keep
their existing scalar inputs.

The in-memory rate limiter defaults to 100 requests per 10 seconds, with tighter
built-in rules for sign-in, sign-up, identity changes and email delivery.
`RateLimitConfig::endpoint` supports exact paths and glob overrides; exact paths
win, then the most specific glob (lexical order breaks ties). Set `max_buckets`
to bound active client/path entries; the default is 100,000. Expired entries are
removed automatically, and new buckets receive 429 at capacity rather than
resetting active quotas. This limiter is per process; multi-instance deployments
need a shared limiter upstream. Configure trusted IP headers and proxy CIDRs
through `config.advanced.ip_address`; the limiter uses the same parsed address
as session metadata. Auth mount paths are handled by `AuthBuilder`.

Telemetry is disabled by default. To opt in, implement the asynchronous
`telemetry::TelemetrySink` and configure
`AuthBuilder::telemetry(telemetry::TelemetryConfig::new(your_sink))`.
Successful initialization awaits one bounded event with library version,
platform and installed plugin names. The application owns delivery and can
publish its own events with `BetterAuth::publish_telemetry`; sink errors log a
constant warning and do not fail authentication. No environment switch,
network endpoint, configuration dump or project fingerprint is implicit.

## Plugins

Better Auth RS ships with a rich set of plugins. Enable only what you need:

| Plugin | Description |
|--------|-------------|
| **Email/Password** | Sign up/sign in with email & password, username support |
| **Session Management** | Session listing, revocation, and token refresh |
| **Password Management** | Password reset, change, and set flows |
| **Email Verification** | Email verification workflows |
| **Account Management** | Account linking and unlinking |
| **Organization** | Multi-tenant organizations with RBAC |
| **OAuth** | Social sign-in via OAuth 2.0 providers |
| **Two-Factor** | TOTP-based 2FA with backup codes |
| **Passkey** | WebAuthn passkey authentication |
| **API Key** | API key generation, rotation, and revocation |
| **Admin** | User management and administrative operations |

CAPTCHA admission runs before endpoint parsing and authentication writes. Enable
`CaptchaPlugin` with a `CaptchaConfig` and the provider's typed configuration;
`captcha::TurnstileConfig::new(secret)` selects Turnstile, and equivalent
configurations support reCAPTCHA, hCaptcha, CaptchaFox, and application-owned
BotID callbacks. Empty endpoint configuration protects email signup, sign-in,
and password-reset requests; custom patterns accept `*` and `**`. Send the
verification token in `x-captcha-response`. BotID uses its trusted callback
instead. Provider response headers and BotID checks have ten-second deadlines.
Verification uses the configured IP policy.

## Feature Flags

| Feature | Description |
|---------|-------------|
| `axum` | Axum web framework integration |
| `seaorm2` | SeaORM database integration |
| `redis-cache` | Redis session/cache backend |

## Crate Structure

| Crate | Description |
|-------|-------------|
| [`better-auth`](https://crates.io/crates/better-auth) | Main crate — re-exports and framework integration |
| [`better-auth-core`](https://crates.io/crates/better-auth-core) | Core auth runtime, store, middleware, and error handling |
| [`better-auth-api`](https://crates.io/crates/better-auth-api) | Plugin implementations |
| [`better-auth-seaorm`](https://crates.io/crates/better-auth-seaorm) | SeaORM store, entity traits, and `AuthEntity` derive macro |
| [`better-auth-cli`](https://crates.io/crates/better-auth-cli) | CLI tools (`better-auth-rs generate`) |

Username policy is configured through `EmailPasswordPlugin::username_config(UsernameConfig { .. })`.
It supports UTF-16 length bounds, case preservation or a synchronous custom normalizer,
awaited username/display-name validators, display-name inclusion and normalization,
immutable usernames, and read-only username input. The default remains lowercase ASCII
usernames with lengths 3–30. Validation order follows the pinned username plugin:
signup/update validate raw input unless `PostNormalization` is selected; sign-in
normalizes before validation only when `PreNormalization` is explicitly selected.
Availability always validates raw input before its normalized lookup. Callback failures
propagate, and ordinary callback errors produce an empty HTTP 500.

## Development

Install [devenv](https://devenv.sh/getting-started/) and
[direnv](https://direnv.net/docs/hook.html) with its shell hook enabled.
The repository's `.envrc` activates the development environment automatically.
Allow it once, then run the complete test gate:

```bash
direnv allow
devenv shell -- ./scripts/check.sh
```

You can also enter the environment manually with `devenv shell`.
Rust tooling and lint rules come from the private `cschmatzler/rust` flake.
Local development requires GitHub SSH access; CI uses the `RUST_STYLE_TOKEN`
secret to fetch the locked revision. `devenv.lock` pins the environment.

See [Compatibility testing](tests/compat/README.md) for focused checks and the
compatibility contract.

## License

Licensed under either of:

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.
