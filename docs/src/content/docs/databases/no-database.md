---
title: "No database"
description: "Run without a database using instance-local storage and cookie-only sessions, or keep SQL users with stateless sessions."
---

Two related modes avoid storing sessions on the server:

| Mode | Users, accounts | Sessions | Use it for |
| --- | --- | --- | --- |
| **No database** — `AuthBuilder::without_database` | In memory, lost on restart | The cookie only | Prototypes, tests, demos, edge workers fronting an external identity provider |
| **Stateless sessions** — `config.session.stateless()` | Your SQL store | The cookie only | Scaling reads without a session table, when delayed revocation is acceptable |

In both modes the session lives in an encrypted cookie, so neither can revoke a session immediately. If you need immediate sign-out, read [Revocation and replay](#revocation-and-replay) before choosing either.

## Start without a database

```rust
use alibi::plugins::EmailPasswordPlugin;
use alibi::store::StatelessSchema;
use alibi::{AuthBuilder, AuthConfig, AuthResult, Alibi};

async fn build_auth() -> AuthResult<Alibi<StatelessSchema>> {
    let config = AuthConfig::new("a-secret-with-at-least-32-characters")
        .base_url("http://localhost:3000");
    AuthBuilder::without_database(config)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .build()
        .await
}
```

`without_database` constructs the built-in in-memory store and sets `session.stateless()` and `account.store_account_cookie` for you. The schema type is `StatelessSchema`, whose user, session and account models are the public wire views (`UserView`, `SessionView`, `AccountView`), so extractors work without any generated code:

```rust
use axum::Json;
use alibi::integrations::CurrentSession;
use alibi::store::StatelessSchema;
use alibi::wire::UserView;

async fn me(session: CurrentSession<StatelessSchema>) -> Json<UserView> {
    Json(session.user)
}
```

What you get, verified against a running instance:

```text
POST /sign-up/email   → 200 {"token":"BWkaAnFZ…","user":{…}}
                        set-cookie: better-auth.session_token=…
                        set-cookie: better-auth.session_data=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwia2lkIjoi…   (a JWE)
GET  /get-session     → 200 {"session":{…},"user":{…}}
```

### What is stored in memory

The built-in store persists, **per process and only until restart**:

- users, credential and provider accounts, verification values;
- two-factor secrets, passkeys, API keys, device codes and JWKS keys;
- organizations, members, invitations, teams and dynamic roles.

Other optional records — wallet addresses for [SIWE](/plugins/siwe/), for example — need an application store, and operations that require them return an explicit "unsupported" error. Records are lost on restart, and **not shared** between processes: run a single instance, or use stateless sessions with a shared SQL store instead.

## Stateless sessions with SQL users

To keep users and accounts in SQL while sessions live only in the cookie, make the policy stateless **before** constructing the store:

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::plugins::EmailPasswordPlugin;
use alibi::sqlx::{SqlxPool, SqlxStore};
use alibi::{AuthConfig, AuthResult, Alibi};

async fn build_auth(secret: &str, pool: SqlxPool) -> AuthResult<Alibi<AppAuthSchema>> {
    let mut config = AuthConfig::new(secret).base_url("https://auth.example.com");
    config.session = config.session.stateless();
    let store = SqlxStore::<AppAuthSchema>::new(config.clone(), pool);
    Alibi::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .build()
        .await
}
```

No SQL session rows are read or written in this mode. A typed application session model therefore cannot be manufactured from a cookie: handlers that need your own `Session` model have no row to load. Use the cache-aware APIs (the session in the cookie) or the `StatelessSchema` wire views.

## How the cookie cache behaves

`stateless()` installs sensible defaults:

| Setting | Default |
| --- | --- |
| `cookie_cache` | enabled, `Jwe` strategy, `max_age` = `session.expires_in` |
| `cookie_refresh_cache` | `Automatic`: renew when less than 20 % of the lifetime remains |

Renewal extends the outer cookie lifetime, not the embedded session expiry: the token and the original expiry stay the same. Override the policy afterwards:

```rust
use alibi::AuthConfig;
use alibi::config::{CookieCacheConfig, CookieCacheStrategy, CookieRefreshCache};

fn auth_config(secret: &str) -> AuthConfig {
    let mut config = AuthConfig::new(secret);
    config.session = config.session.stateless();
    config.session.cookie_cache = Some(CookieCacheConfig {
        enabled: true,
        max_age: 60.0 * 60.0 * 24.0, // one day
        strategy: CookieCacheStrategy::Jwe,
        version: None,
    });
    // Renew when less than an hour remains.
    config.session.cookie_refresh_cache = CookieRefreshCache::UpdateAge(3600.0);
    config
}
```

`disable_session_refresh`, deferred refresh and `?disableRefresh` do **not** stop cache-hit renewal. A trusted request hook can insert `alibi::session::SessionRefreshSuppressed` to suppress it for one request. The no-database builder keeps a stateless renewal policy you already selected.

## Revocation and replay

Without a server-side session record there is nothing to delete. Signing out clears the browser's cookies and removes instance-local records, but:

- A **copy** of the cookie that was captured earlier stays valid until its embedded expiry, until you change the cache `version`, or until the signing key changes. In the instance above, a replayed cookie still returned the session after `/sign-out`.
- Restarting a no-database instance loses users and credentials, yet already issued, authenticated cookies keep working until they expire.
- Revoking all sessions of a user (`/revoke-sessions`, ban, password reset) cannot invalidate cookies already in the wild.

If you need immediate revocation, use durable [session storage](/concepts/session-management/#where-sessions-live) — database rows or [secondary storage](/concepts/secondary-storage/). Mitigate with a short `max_age`, a `version` you bump to invalidate everything, and [key rotation](/reference/secrets/).

## OAuth in stateless mode

With no server store, the default OAuth state strategy resolves to an encrypted **cookie** (an explicitly configured SQL store keeps database state even if sessions are stateless). Provider tokens for later API calls are kept in the `account_data` cookie. See [Social sign-on](/authentication/social-sign-on/#state-and-cookies).

## Frontend

The browser sees the same cookies and endpoints as in any other mode; no client changes are needed.
