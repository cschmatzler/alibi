---
title: "Introduction"
description: "What Better Auth RS is, how its pieces fit together, and where to start."
---

Better Auth RS is an authentication framework for Rust backends. It implements the HTTP contract of [Better Auth](https://www.better-auth.com/) — the same endpoints, payloads, cookies and error codes — on top of your own database, your own models and your own web framework.

You assemble an auth instance from four parts:

| Part | What it does | Where to configure it |
| --- | --- | --- |
| `AuthConfig` | Secrets, base URL, trusted origins, session, cookie and account policy | [Options](/reference/options/) |
| A store | Reads and writes your user, session, account and verification models | [SQLx](/databases/sqlx/), [SeaORM](/databases/seaorm/), [no database](/databases/no-database/) |
| Plugins | Add sign-in methods and features: passwords, OAuth, passkeys, organizations, API keys | [Plugin catalog](/plugins/) |
| A framework adapter | Mounts the auth routes and extracts the current session | [Axum](/integrations/axum/), [Poem](/integrations/poem/), [other](/integrations/other-frameworks/) |

```rust
use better_auth::plugins::{EmailPasswordPlugin, TwoFactorPlugin};
use better_auth::{AuthBuilder, AuthResult, AuthSchema, BetterAuth};

async fn build<S: AuthSchema>(builder: AuthBuilder<S>) -> AuthResult<BetterAuth<S>> {
    builder
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(TwoFactorPlugin::new())
        .build()
        .await
}
```

:::caution[Unreleased]
Better Auth RS is used directly from Git. APIs, wire formats and generated schemas may change before a release. Pin a reviewed commit with `rev = "<commit>"` for reproducible builds.
:::

## How a request flows

```text
HTTP request
   │
   ▼
Framework adapter (Axum / Poem / your own)    builds an AuthRequest
   │
   ▼
Transport      disabled paths → body limit → rate limit → plugin HTTP hooks
   │
   ▼
Routing        CORS preflight → custom middleware → route lookup
   │
   ▼
Protection     origin and CSRF checks → plugin before_request → endpoint hooks
   │
   ▼
Handler        the plugin that owns the route, reading and writing your store
   │
   ▼
Completion     plugin after_request → CORS headers → AuthResponse (status, body, every Set-Cookie)
```

Every route is owned by exactly one plugin. The builder installs the core plugins for sessions, users, accounts, password reset and email verification; everything else you register explicitly. Credential sign-in stays disabled until you add `EmailPasswordPlugin`.

## What is included

| Area | Capabilities |
| --- | --- |
| Credentials | [Email and password](/authentication/email-password/), [usernames](/plugins/username/), [phone numbers](/plugins/phone-number/), [anonymous users](/plugins/anonymous/) |
| Passwordless | [Magic links](/plugins/magic-link/), [email OTP](/plugins/email-otp/), [passkeys](/plugins/passkey/), [Sign in with Ethereum](/plugins/siwe/) |
| Social and federated | [36 built-in OAuth providers](/authentication/social-sign-on/), [generic OAuth/OIDC](/authentication/generic-oauth/), [Google One Tap](/plugins/one-tap/), [popup flows](/plugins/oauth-popup/), [OAuth proxy](/plugins/oauth-proxy/) |
| Second factors | [TOTP, email OTP and backup codes](/plugins/two-factor/) |
| Sessions and tokens | [Cookie caches](/concepts/cookies/), [secondary storage](/concepts/secondary-storage/), [stateless sessions](/databases/no-database/), [bearer tokens](/plugins/bearer/), [JWTs](/plugins/jwt/), [one-time tokens](/plugins/one-time-token/), [multiple sessions](/plugins/multi-session/) |
| Machine access | [API keys](/plugins/api-key/), [device authorization](/plugins/device-authorization/) |
| Administration | [Admin](/plugins/admin/), [organizations, teams and roles](/plugins/organization/) |
| Hardening | [Rate limiting](/concepts/rate-limit/), [CSRF and origin checks](/concepts/security/), [CAPTCHA](/plugins/captcha/), [compromised-password checks](/plugins/have-i-been-pwned/) |

## Compatibility

HTTP behavior targets **better-auth@1.7.7** and is verified by running the official TypeScript client against both the pinned upstream runtime and this implementation. Rust-specific APIs — schemas, plugin builders, delivery callbacks, framework extractors, server-side dispatch — are native to this crate. See [Compatibility](/reference/compatibility/) for the exact boundary and what is out of scope.

## Where to go next

1. [Install the crate, generate a schema and start a server](/installation/).
2. [Sign up, sign in and read a session](/basic-usage/).
3. Understand [users and accounts](/concepts/users-accounts/), [sessions](/concepts/session-management/) and [cookies](/concepts/cookies/).
4. Add features from the [plugin catalog](/plugins/).
5. Harden the deployment with [security](/concepts/security/) and [rate limiting](/concepts/rate-limit/).

## Frontend

Better Auth RS serves the same API as the TypeScript server, so the official client works unchanged. See the Better Auth [client setup](https://www.better-auth.com/docs/concepts/client) and [frontend guides](https://www.better-auth.com/docs/basic-usage). For browsers on a different origin, read [Cross-origin applications](/guides/cross-origin/).
