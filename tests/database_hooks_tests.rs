#![cfg(test)]
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "database hook tests intentionally fail fast on fixture setup and use direct JSON indexing for focused assertions"
)]

#[cfg(test)]
#[path = "database_hooks_tests/tests.rs"]
mod tests;

use async_trait::async_trait;
use better_auth::error::{AuthResult, DatabaseError};
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::prelude::{AuthRequest, AuthUser, CreateUser, HttpMethod};
use better_auth::{AuthBuilder, AuthConfig};
use better_auth_seaorm::sea_orm::sea_query::{Alias, ColumnDef, Expr, ExprTrait, Query, Table};
use better_auth_seaorm::sea_orm::{ConnectionTrait, Database, DatabaseConnection};
use better_auth_seaorm::{HookControl, SeaOrmHookContext, SeaOrmHooks, SeaOrmStore};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

#[derive(Clone)]
struct OrderingHook {
    label: &'static str,
    events: Arc<Mutex<Vec<&'static str>>>,
}

#[async_trait]
impl SeaOrmHooks<TestSchema> for OrderingHook {
    async fn before_create_user(
        &self,
        _user: &mut CreateUser,
        _ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        self.events
            .lock()
            .expect("hook events mutex should lock")
            .push(self.label);
        Ok(HookControl::Continue)
    }
}

#[derive(Clone)]
struct RequestContextHook {
    seen: Arc<Mutex<Vec<(bool, String)>>>,
}

#[async_trait]
impl SeaOrmHooks<TestSchema> for RequestContextHook {
    async fn before_create_user(
        &self,
        _user: &mut CreateUser,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        let entry = (
            ctx.request.is_some(),
            ctx.request
                .as_ref()
                .map_or_else(|| "<none>".to_owned(), |request| request.path.clone()),
        );
        self.seen
            .lock()
            .expect("request context mutex should lock")
            .push(entry);
        Ok(HookControl::Continue)
    }
}

#[derive(Clone)]
struct ProvisioningService {
    db: DatabaseConnection,
    tx_seen: Arc<AtomicBool>,
}

impl ProvisioningService {
    async fn provision(
        &self,
        user: &impl AuthUser,
        ctx: &SeaOrmHookContext<'_>,
    ) -> Result<(), DatabaseError> {
        let statement = Query::insert()
            .into_table(Alias::new("app_workspaces"))
            .columns([Alias::new("user_id"), Alias::new("name")])
            .values_panic([user.id().into_owned().into(), "Default Workspace".into()])
            .to_owned();

        self.tx_seen.store(ctx.tx.is_some(), Ordering::SeqCst);
        assert!(
            ctx.tx.is_none(),
            "creation after hooks run only after commit"
        );
        let committed_user = Query::select()
            .column(Alias::new("id"))
            .from(Alias::new("users"))
            .and_where(Expr::col(Alias::new("id")).eq(user.id().into_owned()))
            .to_owned();
        assert_eq!(
            self.db
                .query_all(&committed_user)
                .await
                .map_err(|err| DatabaseError::Query(err.to_string()))?
                .len(),
            1
        );

        let _ignored_to_string = self
            .db
            .execute(&statement)
            .await
            .map_err(|err| DatabaseError::Query(err.to_string()))?;

        Ok(())
    }
}

struct OnboardingHook {
    service: ProvisioningService,
}

#[async_trait]
impl SeaOrmHooks<TestSchema> for OnboardingHook {
    async fn after_create_user(
        &self,
        user: &<TestSchema as better_auth_core::AuthSchema>::User,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        self.service
            .provision(user, ctx)
            .await
            .map_err(better_auth::AuthError::Database)
    }
}

#[derive(Clone)]
struct DeleteCaptureHook {
    emails: Arc<Mutex<Vec<Option<String>>>>,
}

#[async_trait]
impl SeaOrmHooks<TestSchema> for DeleteCaptureHook {
    async fn before_delete_user(
        &self,
        user: &<TestSchema as better_auth_core::AuthSchema>::User,
        _ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        self.emails
            .lock()
            .expect("delete capture mutex should lock")
            .push(user.email().map(str::to_owned));
        Ok(HookControl::Continue)
    }
}

fn test_config() -> AuthConfig {
    AuthConfig::new("test-secret-key-that-is-at-least-32-characters-long")
        .base_url("http://localhost:3000")
}

async fn test_database() -> DatabaseConnection {
    let database = Database::connect("sqlite::memory:")
        .await
        .expect("sqlite test database should connect");
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .expect("sqlite test migrations should run");
    database
}

async fn test_store(config: &AuthConfig) -> SeaOrmStore<TestSchema> {
    SeaOrmStore::<TestSchema>::new(config.clone(), test_database().await)
}

fn signup_request(email: &str) -> AuthRequest {
    let mut request = AuthRequest::new(HttpMethod::Post, "/sign-up/email");
    request.body = Some(
        serde_json::json!({
            "email": email,
            "password": "Password123!",
            "name": "Test User",
        })
        .to_string()
        .into_bytes(),
    );
    drop(
        request
            .headers
            .insert("content-type".to_owned(), "application/json".to_owned()),
    );
    request
}

async fn create_app_workspace_table(database: &DatabaseConnection) {
    let statement = Table::create()
        .table(Alias::new("app_workspaces"))
        .if_not_exists()
        .col(ColumnDef::new(Alias::new("user_id")).string().not_null())
        .col(ColumnDef::new(Alias::new("name")).string().not_null())
        .to_owned();

    let _ignored_result = database
        .execute(&statement)
        .await
        .expect("app workspace table should be created");
}

async fn app_workspace_rows_for_user(database: &DatabaseConnection, user_id: &str) -> usize {
    let statement = Query::select()
        .column(Alias::new("user_id"))
        .from(Alias::new("app_workspaces"))
        .and_where(Expr::col(Alias::new("user_id")).eq(user_id))
        .to_owned();

    database
        .query_all(&statement)
        .await
        .expect("workspace rows should load")
        .len()
}
