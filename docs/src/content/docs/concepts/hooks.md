---
title: "Hooks"
description: "Endpoint hooks, database hooks, and retained adapter records."
---

Use endpoint hooks for logical requests and database hooks for physical writes. Add `async-trait = "0.1"` to implement either interface.

## Register a database hook

This hook supplies a display name when user creation omits one:

```rust
use crate::auth_schema::AppAuthSchema;
use async_trait::async_trait;
use better_auth::prelude::CreateUser;
use better_auth::sqlx::SqlxBackend;
use better_auth::sqlx::SqlxStore;
use better_auth::store::{DatabaseHookContext, DatabaseHooks, HookControl};
use better_auth::{AuthConfig, AuthResult, BetterAuth};

struct DefaultName;

#[async_trait]
impl DatabaseHooks<AppAuthSchema, SqlxBackend> for DefaultName {
    async fn before_create_user(
        &self,
        user: &mut CreateUser,
        _: &DatabaseHookContext<'_, SqlxBackend>,
    ) -> AuthResult<HookControl> {
        user.name.get_or_insert_with(|| "New user".into());
        Ok(HookControl::Continue)
    }
}

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store.hook(DefaultName))
        .build()
        .await
}
```

SeaORM uses the same interface with `SeaOrmBackend`. Hooks receive the configuration, backend connection, and active transaction when present. Returning `HookControl::Cancel` rejects the write.

## Register an endpoint hook

This hook records completed operation names without logging request bodies or credentials:

```rust
use crate::auth_schema::AppAuthSchema;
use async_trait::async_trait;
use better_auth::endpoint::{EndpointCall, EndpointHook, EndpointResponse};
use better_auth::plugin::AuthContext;
use better_auth::sqlx::SqlxStore;
use better_auth::{AuthConfig, AuthResult, BetterAuth};

struct OperationLog;

#[async_trait]
impl EndpointHook<AppAuthSchema> for OperationLog {
    async fn after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<AppAuthSchema>,
        response: EndpointResponse,
    ) -> AuthResult<EndpointResponse> {
        eprintln!("Completed auth operation: {}", call.operation_id());
        Ok(response)
    }
}

async fn build_auth(
    config: AuthConfig,
    store: SqlxStore<AppAuthSchema>,
) -> AuthResult<BetterAuth<AppAuthSchema>> {
    BetterAuth::<AppAuthSchema>::new(config)
        .store(store)
        .endpoint_hook(OperationLog)
        .build()
        .await
}
```

Endpoint hooks see logical calls; the original native request remains separate. Transactional database after-hooks run after commit and are discarded on rollback. `AdapterAfterHook` observes retained write output, which may contain fields excluded from public responses.