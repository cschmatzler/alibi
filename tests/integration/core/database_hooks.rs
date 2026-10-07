#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "database hook tests intentionally fail fast on fixture setup and use direct JSON indexing for focused assertions"
)]

use alibi::error::{AuthResult, DatabaseError};
use alibi::plugins::EmailPasswordPlugin;
use alibi::prelude::{AuthRequest, AuthUser, CreateUser, HttpMethod};
use alibi::{AuthBuilder, AuthConfig};
use alibi_seaorm::sea_orm::sea_query::{Alias, ColumnDef, Expr, ExprTrait, Query, Table};
use alibi_seaorm::sea_orm::{ConnectionTrait, Database, DatabaseConnection};
use alibi_seaorm::{DatabaseHooks, HookControl, SeaOrmBackend, SeaOrmHookContext, SeaOrmStore};
use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

type TestSchema = alibi_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

#[derive(Clone)]
struct OrderingHook {
    label: &'static str,
    events: Arc<Mutex<Vec<&'static str>>>,
}

#[async_trait]
impl DatabaseHooks<TestSchema, SeaOrmBackend> for OrderingHook {
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
impl DatabaseHooks<TestSchema, SeaOrmBackend> for RequestContextHook {
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
impl DatabaseHooks<TestSchema, SeaOrmBackend> for OnboardingHook {
    async fn after_create_user(
        &self,
        user: &<TestSchema as alibi_core::AuthSchema>::User,
        ctx: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        self.service
            .provision(user, ctx)
            .await
            .map_err(alibi::AuthError::Database)
    }
}

#[derive(Clone)]
struct DeleteCaptureHook {
    emails: Arc<Mutex<Vec<Option<String>>>>,
}

#[async_trait]
impl DatabaseHooks<TestSchema, SeaOrmBackend> for DeleteCaptureHook {
    async fn before_delete_user(
        &self,
        user: &<TestSchema as alibi_core::AuthSchema>::User,
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
    alibi_seaorm::store::__private_test_support::migrator::run_migrations(&database)
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

#[cfg(test)]
mod tests {
    use super::*;

    // Upstream reference: packages/better-auth/src/db/db.test.ts :: describe("db") and packages/better-auth/src/plugins/organization/organization-hook.test.ts; adapted to the Rust database hook surface.
    #[tokio::test]
    async fn plugin_database_hooks_run_before_builder_hooks() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let config = test_config();
        let store = test_store(&config)
            .await
            .hook(OrderingHook {
                label: "plugin",
                events: Arc::clone(&events),
            })
            .hook(OrderingHook {
                label: "builder",
                events: Arc::clone(&events),
            });
        let auth = AuthBuilder::<TestSchema>::new(config)
            .store(store)
            .build()
            .await
            .expect("auth should build");

        drop(
            auth.store()
                .create_user(
                    CreateUser::new()
                        .with_email("ordering@example.com")
                        .with_name("Ordering"),
                )
                .await
                .expect("user should be created"),
        );

        assert_eq!(
            *events.lock().expect("events mutex should lock"),
            vec!["plugin", "builder"]
        );
    }

    // Upstream reference: packages/better-auth/src/db/db.test.ts :: describe("db") and packages/better-auth/src/plugins/organization/organization-hook.test.ts; adapted to the Rust database hook surface.
    #[tokio::test]
    async fn request_context_is_present_for_requests_and_absent_for_direct_store_calls() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let config = test_config();
        let store = test_store(&config).await.hook(RequestContextHook {
            seen: Arc::clone(&seen),
        });
        let auth = AuthBuilder::<TestSchema>::new(config)
            .store(store)
            .plugin(EmailPasswordPlugin::new())
            .build()
            .await
            .expect("auth should build");

        let response = auth
            .handle_request(signup_request("request-context@example.com"))
            .await
            .expect("sign-up request should succeed");
        assert_eq!(response.status, 200);

        drop(
            auth.store()
                .create_user(
                    CreateUser::new()
                        .with_email("direct-store@example.com")
                        .with_name("Direct Store"),
                )
                .await
                .expect("direct store call should succeed"),
        );

        assert_eq!(
            *seen.lock().expect("request context mutex should lock"),
            vec![
                (true, "/sign-up/email".to_owned()),
                (false, "<none>".to_owned()),
            ]
        );
    }

    // Upstream reference: packages/better-auth/src/db/db.test.ts :: describe("db") and packages/better-auth/src/plugins/organization/organization-hook.test.ts; adapted to the Rust database hook surface.
    #[tokio::test]
    async fn onboarding_hook_provisions_app_data_after_the_auth_transaction_commits() {
        let database = test_database().await;
        create_app_workspace_table(&database).await;

        let tx_seen = Arc::new(AtomicBool::new(false));
        let config = test_config();
        let store =
            SeaOrmStore::<TestSchema>::new(config.clone(), database.clone()).hook(OnboardingHook {
                service: ProvisioningService {
                    db: database.clone(),
                    tx_seen: Arc::clone(&tx_seen),
                },
            });
        let auth = AuthBuilder::<TestSchema>::new(config)
            .store(store)
            .plugin(EmailPasswordPlugin::new())
            .build()
            .await
            .expect("auth should build");

        let response = auth
            .handle_request(signup_request("onboarding@example.com"))
            .await
            .expect("sign-up request should succeed");
        assert_eq!(response.status, 200);

        let body: serde_json::Value =
            serde_json::from_slice(&response.body).expect("response body should be valid JSON");
        let user_id = body["user"]["id"]
            .as_str()
            .expect("user id should be present");

        assert_eq!(app_workspace_rows_for_user(&database, user_id).await, 1);
        assert!(!tx_seen.load(Ordering::SeqCst));
    }

    // Upstream reference: packages/better-auth/src/db/db.test.ts :: describe("db") and packages/better-auth/src/plugins/organization/organization-hook.test.ts; adapted to the Rust database hook surface.
    #[tokio::test]
    async fn delete_hooks_receive_the_loaded_user_entity() {
        let emails = Arc::new(Mutex::new(Vec::new()));
        let config = test_config();
        let store = test_store(&config).await.hook(DeleteCaptureHook {
            emails: Arc::clone(&emails),
        });
        let auth = AuthBuilder::<TestSchema>::new(config)
            .store(store)
            .build()
            .await
            .expect("auth should build");

        let user = auth
            .store()
            .create_user(
                CreateUser::new()
                    .with_email("delete-capture@example.com")
                    .with_name("Delete Capture"),
            )
            .await
            .expect("user should be created");

        auth.store()
            .delete_user(&user.id())
            .await
            .expect("user should be deleted");

        assert_eq!(
            *emails.lock().expect("delete capture mutex should lock"),
            vec![Some("delete-capture@example.com".to_owned())]
        );
    }
}
