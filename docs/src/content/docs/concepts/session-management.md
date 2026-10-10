---
title: "Session management"
description: "Session lifetime, refresh, freshness, listing, revocation and where sessions are stored."
---

A session proves that a browser or client is signed in. By default it is a row in your `sessions` table plus a signed `HttpOnly` cookie holding the session token. The core `SessionManagementPlugin` is installed on every instance and serves the endpoints below.

## Lifetime and refresh

Configure sessions on `AuthConfig` **before** constructing the store, so the store and the builder see the same policy:

```rust
use alibi::AuthConfig;
use chrono::Duration;

fn auth_config(secret: &str) -> AuthConfig {
    let mut config = AuthConfig::new(secret).base_url("https://auth.example.com");
    config.session.expires_in = Duration::days(30);       // total lifetime
    config.session.update_age = Some(Duration::days(1));  // extend at most once a day
    config.session.fresh_age = Some(Duration::minutes(10)); // "recent sign-in" window
    config
}
```

| `SessionConfig` field | Default | Meaning |
| --- | --- | --- |
| `expires_in` | 7 days | Lifetime of a new or refreshed session |
| `update_age` | 1 day | A read extends the session once it is older than this. `None` extends on every read |
| `disable_session_refresh` | `false` | Never extend sessions on read |
| `defer_session_refresh` | `false` | Report `needsRefresh` on `GET` and perform writes only on `POST /get-session` |
| `fresh_age` | 1 day | Window in which a session counts as fresh; `None` or zero disables the check |
| `cookie_name` | `better-auth.session_token` | Session cookie name (prefixed with `__Secure-` over HTTPS; a configured `__Secure-` prefix is dropped rather than doubled) |
| `cookie_secure`, `cookie_http_only`, `cookie_same_site` | derived from `base_url`, `true`, `Lax` | Cookie attributes; see [Cookies](/concepts/cookies/) |
| `cookie_cache` | none | Cache session data in a cookie to skip database reads |
| `secondary_storage`, `store_in_database`, `preserve_in_database` | none | Keep sessions in Redis or memory; see [Secondary storage](/concepts/secondary-storage/) |
| `stateless` | `false` | No server-side session store; see [No database](/databases/no-database/) |
| `additional_fields` | none | Extra session columns; see [Additional fields](/concepts/field-policies/) |

Builder shortcuts exist for the common ones: `session_expires_in`, `session_update_age`, `session_fresh_age`, `disable_session_refresh` and `session_cookie_cache`.

A refresh moves `expires_at` to *now + `expires_in`* and updates `updated_at`. It happens during `GET /get-session` (and any other authenticated read) when `expires_at − expires_in + update_age` has passed. Append `?disableRefresh=true` to a `get-session` request to read without extending, and `?disableCookieCache=true` to bypass a [cookie cache](/concepts/cookies/#cache-the-session-in-a-cookie).

### Deferred refresh

Writing to the database on a `GET` is awkward behind CDNs and read replicas. With `defer_session_refresh = true`, `GET /get-session` stays read-only and returns `needsRefresh: true` when a refresh is due; the client then calls `POST /get-session` to perform it. Without the flag, `POST /get-session` is rejected with `405 METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED`.

```rust
use alibi::AuthConfig;

fn auth_config(secret: &str) -> AuthConfig {
    let mut config = AuthConfig::new(secret);
    config.session.defer_session_refresh = true;
    config
}
```

## Endpoints

Paths are relative to `/api/auth`. All of them need the session cookie (or a [bearer token](/plugins/bearer/)).

| Method | Path | Body | Action |
| --- | --- | --- | --- |
| `GET` | `/get-session` | — | Current session and user, or `null` |
| `POST` | `/get-session` | — | Same, performing a deferred refresh (requires `defer_session_refresh`) |
| `GET` | `/list-sessions` | — | Every active session of the user |
| `POST` | `/update-session` | session fields | Update [additional session fields](/concepts/field-policies/) |
| `POST` | `/sign-out` | optional `callbackURL`, `disableRedirect`, `state` | End the current session and clear cookies |
| `POST` | `/revoke-session` | `{"token":"…"}` | Revoke one session by token |
| `POST` | `/revoke-sessions` | — | Revoke all sessions |
| `POST` | `/revoke-other-sessions` | — | Revoke everything except the current session |

```bash
# Revoke every other device
curl -b cookies.txt -X POST http://localhost:3000/api/auth/revoke-other-sessions \
  -H 'Origin: http://localhost:3000'
# {"status":true}

# Revoke a specific session
curl -b cookies.txt -X POST http://localhost:3000/api/auth/revoke-session \
  -H 'Content-Type: application/json' -H 'Origin: http://localhost:3000' \
  -d '{"token":"07gTGnxj0gFlvsKpTV7hBC3aMyH7Jnty"}'
```

`GET /list-sessions` requires a [fresh](#session-freshness) session and omits sessions created by [admin impersonation](/plugins/admin/#impersonation). Session tokens are 32 alphanumeric characters.

### Choose which endpoints exist

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::plugins::SessionManagementPlugin;
use alibi::sqlx::SqlxStore;
use alibi::{AuthConfig, AuthResult, Alibi};

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<Alibi<AppAuthSchema>> {
    Alibi::<AppAuthSchema>::new(config)
        .store(store)
        .plugin(
            SessionManagementPlugin::new()
                .enable_session_listing(false)   // no /list-sessions
                .enable_session_revocation(false), // no /revoke-*
        )
        .build()
        .await
}
```

To disable any single route outright, use `AuthConfig::disabled_path("/list-sessions")`; matching requests receive `404`.

## Session freshness

Some operations require a *fresh* session — one created within `fresh_age`: listing sessions, registering a [passkey](/plugins/passkey/) for an existing user, and [deleting the account](/concepts/users-accounts/#delete-an-account) without supplying the password. A stale session receives `403 SESSION_NOT_FRESH` (or `400 Session expired. Re-authenticate…` for deletion) and the user has to sign in again. Set `fresh_age = None` to turn the rule off.

## Remember me

`rememberMe: false` on `/sign-in/email`, `/sign-in/username` or `/sign-up/email` issues a browser-session cookie with no `Max-Age` and a signed `dont_remember` cookie that keeps later refreshes from making it persistent. The server-side session still expires after `expires_in`.

## Custom sign-in flows

After your application verifies its own sign-in proof and resolves the user ID, use `alibi::session` to issue a session through the initialized instance. The existing session hooks and admin-plugin ban policy still apply. This API needs only the top-level `better-auth` dependency.

```rust
use alibi::prelude::{AuthResponse, AuthSession};
use alibi::session::{SessionIssueError, create_session_cookie, issue_user_session};
use alibi::{AuthResult, AuthSchema, Alibi};

async fn sign_in_verified_user<S: AuthSchema>(
    auth: &Alibi<S>,
    user_id: &str,
) -> AuthResult<AuthResponse> {
    let issued = issue_user_session(auth.context(), user_id, None, None)
        .await
        .map_err(SessionIssueError::into_auth_error)?;
    let cookie = create_session_cookie(issued.session.token(), auth.config())?;
    Ok(AuthResponse::new(204).with_header("set-cookie", cookie))
}
```

`issue_user_session` returns `IssuedSession<S>` with the user and session in your schema's types. Match `SessionIssueError::Banned { message }` separately from `SessionIssueError::Auth(error)` when your flow needs a distinct banned-user response, or use `into_auth_error` as above. `create_session_cookie` signs the token and uses the configured cookie name, lifetime and attributes; it can fail if those attributes are invalid.

## Session metadata

Each session records the client's IP address and user agent. The IP comes from `advanced.ip_address`: the headers to trust (default `x-forwarded-for`), the proxies to strip from the right of a forwarded chain, the IPv6 grouping prefix and an opt-out. Configure it when behind a proxy:

```rust
use alibi::AuthConfig;
use alibi::config::{AdvancedConfig, IpAddressConfig};

fn auth_config(secret: &str) -> AuthConfig {
    AuthConfig::new(secret).advanced(AdvancedConfig {
        ip_address: IpAddressConfig {
            headers: vec!["cf-connecting-ip".into(), "x-forwarded-for".into()],
            trusted_proxies: vec!["10.0.0.0/8".into()],
            ..Default::default()
        },
        ..Default::default()
    })
}
```

The same resolved address keys [rate limits](/concepts/rate-limit/). Only enable headers that your edge replaces or strips; a client-controlled `x-forwarded-for` is trivially spoofed.

## Where sessions live

| Mode | Source of truth | Reads | Revocation | Configure |
| --- | --- | --- | --- | --- |
| Database (default) | `sessions` table | One query per request | Immediate | — |
| Database + cookie cache | `sessions` table | Cookie, database after `max_age` | Within `max_age` | [Cookies](/concepts/cookies/#cache-the-session-in-a-cookie) |
| Secondary storage | Redis / memory | Cache lookup | Immediate | [Secondary storage](/concepts/secondary-storage/) |
| Stateless | The cookie itself | No server state | Only by expiry or key rotation | [No database](/databases/no-database/) |

## Use the session in your application

Axum and Poem extractors give you the authenticated `user` and `session` in your own model types:

```rust
use crate::auth_schema::AppAuthSchema;
use alibi::integrations::CurrentSession;
use alibi::prelude::{AuthSession, AuthUser};

async fn whoami(session: CurrentSession<AppAuthSchema>) -> String {
    format!(
        "{} — session expires {}",
        session.user.email().unwrap_or("(no email)"),
        session.session.expires_at(),
    )
}
```

Details: [Axum](/integrations/axum/), [Poem](/integrations/poem/). For a custom host, resolve the session by dispatching a `get-session` request through [`handle_request`](/integrations/other-frameworks/).

## Frontend

See the official [session management guide](https://www.better-auth.com/docs/concepts/session-management).
