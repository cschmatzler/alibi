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

## Secondary session storage

Set `AuthConfig::session.secondary_storage` to an `Arc<dyn CacheAdapter>`;
`MemoryCacheAdapter` and the `redis-cache` feature's `RedisAdapter` provide
native implementations. Sessions then live in that backend by default.
Set `session.store_in_database = true` to also persist SQL session rows.
Set `session.preserve_in_database = true` to retain and expire those rows on
revocation. Without a secondary backend, sessions always use the database.

Cached credentials and their typed user snapshots are authoritative. Combined
storage permits a database fallback for a missing cached credential only when
preservation is disabled; session lists still use the secondary index. Cached
malformed, expired, inactive, or mismatched credentials cannot authenticate.
The backend holds sensitive credentials and must be trusted and isolated.

Bundled SeaORM user/session models support this directly. Application-owned
`AuthEntity` user/session models opt in with
`#[auth(role = "user", secondary_storage)]` or the corresponding session role;
each model field must support serialization and deserialization. Other schemas
can implement the explicit `AuthUser`/`AuthSession` snapshot capabilities and
session-store preparation capabilities. Existing schemas remain unchanged.

Secondary writes happen during issuance and updates, including SQL transactions.
A SQL rollback cannot roll back an already completed cache write. Failed signup
issues no response credential, but earlier index or credential writes can remain
until expiry. User snapshot refresh after a committed update is best effort.
Use the same backend in `config.verification.secondary_storage` when verification
credentials should also use secondary storage and atomic consumption.

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

The supported native integration is Axum (`AxumIntegration`, including application
state and session extractors). Other Rust HTTP hosts can call
`BetterAuth::handle_request` with an `AuthRequest` and forward the complete
`AuthResponse`: status, body bytes and all header entries, including repeated
`Set-Cookie`. This direct future belongs to the caller; cancelling it can leave
already committed writes; independently owned background callbacks already
launched can continue. Retain it in an owned task when dispatch must continue
after a client disconnect. Axum already supervises accepted, fully buffered
requests; runtime/process shutdown can still cancel them.

Use `BetterAuth::dispatch_endpoint` for trusted server operations, with logical
headers/input and an optional physical request. Keep that interface on the
server; a server-only operation does not become an HTTP route. JavaScript
framework cookie stores, server-component refresh suppression, reactive client
stores and TypeScript inference helpers are explicit embedding boundaries.
Shared HTTP semantics are checked with the pinned official Better Auth client;
see the [native integration audit](tests/compat/audits/native-integrations.md).

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

Passwordless numeric configuration uses `f64`: `EmailOtpConfig` and
`PhoneNumberConfig` expose `otp_length`, `allowed_attempts`, and `expires_in`
(seconds); `MagicLinkConfig::expires_in` also accepts seconds. When migrating,
replace `Duration::seconds(300)` with `300.0`, and integer lengths/budgets with
floating-point literals such as `6.0` and `3.0`. This preserves fractional and
nonfinite policies without converting them to unsigned integers. See the
[passwordless numeric audit](tests/compat/audits/passwordless-numeric.md) for
plugin-specific zero/NaN defaults and safe generation limits.

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

Rate limiting is enabled by default: 100 requests per 10 seconds, with tighter
core and installed email OTP, magic-link, phone, two-factor and device rules.
`RateLimitConfig::endpoint` inserts ordered exact/wildcard overrides; the first
match wins, including a wildcard inserted before an exact path. `rule` accepts
`RateLimitRule::Disabled` or an asynchronous `RateLimitResolver`, which receives
the real request and inherited core/plugin limit. Returning `None` bypasses that
request without resetting its quota. `EndpointRateLimit` exposes `f64`
`window_seconds` and `max_requests`; duration/integer builder methods remain
available. Zero/NaN global defaults fall back to 10 seconds/100; raw custom rules
preserve those values. Email OTP and magic-link plugin zero/NaN policy values
use their respective defaults.

Default memory storage is local to an auth instance and bounds active buckets
at 100,000 (`max_buckets` configures this). Allowed requests extend inactivity
expiry; rejected requests do not. At capacity, new buckets fail closed rather
than evicting active clients. Share an `Arc<MemoryRateLimitStorage>` through
`RateLimitConfig::storage` for common rolling quotas across instances in one
process. `CacheRateLimitStorage` uses the existing cache's atomic `increment`
for fixed windows across processes. `RedisAdapter` implements this with one Lua
operation and a positive whole-second TTL set only on creation. Fractional or
invalid Redis TTLs fail closed; cache adapters without atomic increment also
fail closed. Applications can implement `RateLimitStorage::consume` directly
for their own atomic backend.

`better_auth_seaorm::SeaOrmRateLimitStorage::new(connection)` supports shared
SQLite/PostgreSQL rolling quotas. Call `storage.migrate().await?` explicitly
before installing it; its table and ledger are independent of ordinary auth
migrations and do not require changes to `AuthSchema`. New/reset buckets prune
expired rows older than the longest configured/observed window. Each row retains
its issued expiry, so a shorter-window process cannot prune another instance’s
live quota. Infinite windows remain nonexpiring. Middleware publishes static and
plugin windows before requests, and the backend observes dynamic windows.
Cleanup failures retain the admitted request and retry on a later new/reset
bucket. Storage failures stop dispatch with a generic error. Exact 429 bodies
and `X-Retry-After` remain shared with Source; memory/database report remaining
rolling seconds, while cache storage reports the complete fixed window.

Configure trusted IP headers/proxy CIDRs through `config.advanced.ip_address`;
rate limits and session metadata use the same normalized client identity.
Requests without a trusted IP share a bucket per path. Disabling IP tracking
also disables rate limiting. Auth mount paths are handled by `AuthBuilder`;
trusted server-only dispatch does not consume HTTP quotas.

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
