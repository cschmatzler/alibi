---
title: "Hooks"
description: "Database hooks for physical writes, endpoint hooks for logical calls, and request context."
---

Alibi has two hook layers, and choosing the right one matters:

| Layer | Fires on | Use it to |
| --- | --- | --- |
| **Database hooks** | Every write to the user, session, account or verification model — whichever flow causes it | Normalize or enrich data, cancel a write, mirror changes to your own tables |
| **Endpoint hooks** | A logical endpoint call (`sign_up_email`, `sign_out`, …), over HTTP **or** through server-side dispatch | Validate input, short-circuit with a response, audit completed operations |

Both traits use `#[async_trait]`; add `async-trait = "0.1"` to your dependencies.

## Database hooks

Implement `DatabaseHooks<Schema, Backend>` and wrap the store with `.hook(...)`. Every method has a default no-op, so implement only what you need. This hook lowercases emails and supplies a display name when none was given:

```rust
use crate::auth_schema::AppAuthSchema;
use async_trait::async_trait;
use alibi::prelude::CreateUser;
use alibi::sqlx::{SqlxBackend, SqlxStore};
use alibi::store::{DatabaseHookContext, DatabaseHooks, HookControl};
use alibi::{AuthConfig, AuthResult, BetterAuth};

struct NormalizeUsers;

#[async_trait]
impl DatabaseHooks<AppAuthSchema, SqlxBackend> for NormalizeUsers {
    async fn before_create_user(
        &self,
        user: &mut CreateUser,
        _: &DatabaseHookContext<'_, SqlxBackend>,
    ) -> AuthResult<HookControl> {
        user.email = user.email.take().map(|email| email.to_lowercase());
        user.name.get_or_insert_with(|| "New user".into());
        Ok(HookControl::Continue)
    }
}

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store.hook(NormalizeUsers))
        .build()
        .await
}
```

SeaORM uses the same trait with `SeaOrmBackend` (`alibi::seaorm`).

Events exist in `before_*` / `after_*` pairs for **create**, **update** and **delete** of each model — `user`, `session`, `account` and `verification` (plus `after_update_session_missing` for updates that matched no row). `before_*` hooks receive the mutable input and return `HookControl::Continue` or `HookControl::Cancel`; a cancelled write is not performed and the endpoint reports the operation as failed (cancelling a user creation answers `400 FAILED_TO_CREATE_USER`).

The `DatabaseHookContext` gives you:

| Field | Meaning |
| --- | --- |
| `config` | The `AuthConfig` in effect |
| `db` | The backend connection, for your own queries |
| `tx` | The active transaction, when the write is part of one |
| `request` | The `RequestHookContext` of the HTTP request that caused the write, if any |

Semantics worth knowing:

- Writes that belong to a transaction run their **after** hooks only after the commit; a rollback discards them. Errors from after-hooks are returned to the caller **after** the writes committed, so keep them idempotent.
- Use `tx` (not `db`) for writes that must commit or roll back with the auth write.
- `AdapterAfterHook` observes retained write output (including fields excluded from public responses). Never forward those values to a client.

### Read the originating request

`DatabaseHookContext::request` carries the HTTP request that caused the write, so a hook can record *who and from where*. This hook writes an audit line for each new session (and tolerates writes with no HTTP origin, such as server-side dispatch):

```rust
use crate::auth_schema::AppAuthSchema;
use async_trait::async_trait;
use alibi::prelude::AuthSession;
use alibi::sqlx::SqlxBackend;
use alibi::store::{DatabaseHookContext, DatabaseHooks};
use alibi::AuthResult;

struct AuditSessions;

#[async_trait]
impl DatabaseHooks<AppAuthSchema, SqlxBackend> for AuditSessions {
    async fn after_create_session(
        &self,
        session: &<AppAuthSchema as alibi::AuthSchema>::Session,
        ctx: &DatabaseHookContext<'_, SqlxBackend>,
    ) -> AuthResult<()> {
        let user_agent = ctx
            .request
            .as_ref()
            .and_then(|request| request.headers.get("user-agent"))
            .map(String::as_str)
            .unwrap_or("server");
        eprintln!("session {} opened by {user_agent}", session.id());
        Ok(())
    }
}
```

`RequestHookContext` exposes the original `request`, `method`, `path`, `headers`, `query`, raw `body` and `meta` (client IP and user agent). Other callbacks get the same data through `CallbackContext` ([Email and background tasks](/concepts/notifications/#callback-context)).

## Endpoint hooks

An `EndpointHook` sees a *logical call*: operation id, parsed body and query, and headers. Register it with `.endpoint_hook(...)`; hooks run in registration order, before the hooks of installed plugins.

```rust
use crate::auth_schema::AppAuthSchema;
use async_trait::async_trait;
use alibi::endpoint::{BeforeEndpointAction, EndpointCall, EndpointHook, EndpointResponse};
use alibi::plugin::AuthContext;
use alibi::sqlx::SqlxStore;
use alibi::{AuthConfig, AuthError, AuthResult, BetterAuth};

#[derive(serde::Deserialize)]
struct SignUpBody {
    email: String,
}

struct BlockDisposableEmails;

#[async_trait]
impl EndpointHook<AppAuthSchema> for BlockDisposableEmails {
    // Run `before` only for sign-up calls.
    fn matches_before(
        &self,
        call: &EndpointCall,
        _: &AuthContext<AppAuthSchema>,
    ) -> AuthResult<bool> {
        Ok(call.path() == Some("/sign-up/email"))
    }

    async fn before(
        &self,
        call: &EndpointCall,
        _: &AuthContext<AppAuthSchema>,
    ) -> AuthResult<Option<BeforeEndpointAction>> {
        let body: SignUpBody = call.body_as()?;
        if body.email.ends_with("@mailinator.com") {
            return Ok(Some(BeforeEndpointAction::Reject(EndpointResponse::error(
                AuthError::bad_request("Disposable email addresses are not allowed"),
            ))));
        }
        Ok(None) // continue to the handler
    }
}

struct OperationLog;

#[async_trait]
impl EndpointHook<AppAuthSchema> for OperationLog {
    async fn after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<AppAuthSchema>,
        response: EndpointResponse,
    ) -> AuthResult<EndpointResponse> {
        // Log the operation name only: never log request bodies or credentials.
        eprintln!("completed auth operation: {}", call.operation_id());
        Ok(response)
    }
}

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .endpoint_hook(BlockDisposableEmails)
        .endpoint_hook(OperationLog)
        .build()
        .await
}
```

`before` can return:

| Action | Effect |
| --- | --- |
| `None` | Continue to the next hook and the handler |
| `Patch(EndpointContextPatch)` | Replace the body, query, headers, path or method seen downstream |
| `Respond(EndpointResponse)` | Short-circuit with a successful response |
| `Reject(EndpointResponse)` | Short-circuit with an error and its complete public body |

`after` receives the handler's response (success or API error) and returns the response to use. An API error returned from `after` replaces the result and continues; an ordinary failure aborts the remaining hooks. `matches_before` and `matches_after` are synchronous filters; an error from a matcher is logged and masked as a generic `500`.

Endpoint hooks see the logical call; the original HTTP request stays separate in `EndpointCall::request()`. Because hooks also wrap server-side dispatch, `call.request()` is `None` for trusted calls.

## Which one should I use?

| I want to… | Use |
| --- | --- |
| Reject sign-ups by email domain | Endpoint `before` (HTTP-level input) or a `user_validation` policy ([Users and accounts](/concepts/users-accounts/#validate-new-identities)) |
| Set a default on every created user, including OAuth users | Database `before_create_user` |
| Write an audit row for every new session | Database `after_create_session` |
| Add a header or log after every response | Endpoint `after`, or a plugin `after_request` ([writing a plugin](/guides/writing-a-plugin/)) |
| Block deletion of special accounts | `UserManagementPlugin::before_delete` ([Users and accounts](/concepts/users-accounts/#delete-an-account)) |
| Observe org or API-key lifecycle | The plugin's own hooks ([Organization](/plugins/organization/#lifecycle-hooks), [API key](/plugins/api-key/)) |
