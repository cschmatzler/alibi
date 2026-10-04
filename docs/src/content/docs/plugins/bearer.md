---
title: "Bearer"
description: "Authenticate API calls with the session token in an Authorization header instead of a cookie."
---

Cookies are the default carrier for sessions, but mobile apps, CLIs and server-to-server clients prefer a header. `BearerPlugin` lets any request send `Authorization: Bearer <session token>`; the token is turned into the session cookie *before* routing, so every endpoint and hook behaves exactly as if the browser had sent the cookie.

## Setup

```rust
use crate::auth_schema::AppAuthSchema;
use better_auth::plugins::BearerPlugin;
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(BearerPlugin::new())
        .build()
        .await
}
```

No schema and no routes: the plugin only transforms requests and responses.

## How it works

**Getting a token.** Any response that sets the session cookie (sign-in, sign-up, OTP verification, OAuth callback, …) also carries the signed token in a `set-auth-token` header, and exposes it to browsers through `Access-Control-Expose-Headers`:

```bash
curl -i http://localhost:3000/api/auth/sign-in/email \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"email":"ada@example.com","password":"a-long-example-password"}'
```

```http
HTTP/1.1 200 OK
set-cookie: better-auth.session_token=YdZxZvDL….9IjTjaDb…; Max-Age=604800; Path=/; HttpOnly; SameSite=Lax
set-auth-token: YdZxZvDL1zrIDnH1W20obWeNhEE7aGRY.9IjTjaDb9g00qk14p8IEgPYBS3tsk3DEO6T5fUnPanM=
```

**Using it.**

```bash
curl http://localhost:3000/api/auth/get-session \
  -H 'Authorization: Bearer YdZxZvDL1zrIDnH1W20obWeNhEE7aGRY.9IjTjaDb9g00qk14p8IEgPYBS3tsk3DEO6T5fUnPanM='
```

The scheme is case-insensitive. A token of the form `<token>.<signature>` (what `set-auth-token` returns) is verified against the auth secret. A bare token without a signature is signed by the server and accepted — **unless** `require_signature` is set. An invalid header leaves ordinary cookies untouched, so a browser with a good cookie keeps working.

## Configuration

```rust
use better_auth::plugins::{BearerConfig, BearerPlugin};

fn bearer() -> BearerPlugin {
    BearerPlugin::with_config(BearerConfig {
        // Accept only tokens that carry the server's signature.
        require_signature: true,
    })
}
```

| `BearerConfig` field | Default | Effect |
| --- | --- | --- |
| `require_signature` | `false` | Ignore unsigned bearer tokens. Enable it when tokens are only ever obtained from `set-auth-token` |

## In your own routes

The bearer conversion happens in the auth router. The Axum and Poem **extractors** read the session cookie only, so they will not see an `Authorization` header on routes outside the auth router. To authenticate bearer requests on your own routes, ask the auth instance — see [reading the session in your own handlers](/integrations/other-frameworks/#reading-the-session-in-your-own-handlers) — or run the check as middleware before your handlers.

For **cross-origin browser** clients, add `set-auth-token` to the allowed/exposed CORS headers (the plugin adds it to `Access-Control-Expose-Headers` itself) and allow `Authorization` in `allowed_headers`; see [Security](/concepts/security/#cors).

## Which token is which?

| Credential | Plugin | Format | Use |
| --- | --- | --- | --- |
| Session token (bearer) | Bearer | opaque, server-side session | First-party apps and CLIs; revocable immediately |
| JWT | [JWT](/plugins/jwt/) | signed, self-contained | Other services that verify without calling you |
| API key | [API key](/plugins/api-key/) | opaque, hashed at rest | Programmatic access with scopes and quotas |
| One-time token | [One-time token](/plugins/one-time-token/) | opaque, single use | Cross-domain session handoff |

A device flow's `access_token` ([Device authorization](/plugins/device-authorization/)) is a session token and works as a bearer token.

## Security notes

- A bearer token **is** a session: protect it like a password, send it only over HTTPS and never put it in URLs or logs.
- Revoking the session (`/sign-out`, `/revoke-session`) invalidates the bearer token immediately.
- Keep tokens in the platform's secure storage (Keychain, Keystore), not in `localStorage`, for browser-like clients that cannot use `HttpOnly` cookies.

## Frontend

See the official [Bearer guide](https://www.better-auth.com/docs/plugins/bearer).
