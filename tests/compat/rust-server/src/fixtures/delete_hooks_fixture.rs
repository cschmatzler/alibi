//! Actual database deletion hooks and an application-owned durable receipt.
use crate::TestSchema;
use alibi::seaorm::{
    DatabaseConnection, DatabaseHooks, HookControl,
    sea_orm::{ConnectionTrait, Statement},
};
use alibi::{AuthAccount, AuthSchema, AuthSession, AuthUser};
use alibi::{
    AuthBuilder, AuthConfig, AuthError, AuthResult,
    integrations::axum::AxumIntegration,
    plugins::{AdminPlugin, EmailPasswordPlugin, SessionManagementPlugin, UserManagementPlugin},
};
use axum::{Json, Router, routing::get};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
#[derive(Default)]
struct State {
    model: String,
    mode: String,
    events: Vec<Value>,
}
struct Hooks(Arc<Mutex<State>>);
impl Hooks {
    fn before(&self, model: &str, id: &str) -> AuthResult<HookControl> {
        let mut state = self.0.lock().unwrap();
        if state.model != model {
            return Ok(HookControl::Continue);
        }
        state
            .events
            .push(json!({"model":model,"phase":"before","rowId":id}));
        match state.mode.as_str() {
            "cancel" => Ok(HookControl::Cancel),
            "before-error" => Err(AuthError::CallbackFailure(Box::new(AuthError::internal(
                "Application delete before rejected",
            )))),
            _ => Ok(HookControl::Continue),
        }
    }
    async fn after(
        &self,
        model: &str,
        id: &str,
        context: &crate::backend::HookContext<'_>,
    ) -> AuthResult<()> {
        let reject = {
            let mut state = self.0.lock().unwrap();
            if state.model != model {
                return Ok(());
            }
            state
                .events
                .push(json!({"model":model,"phase":"after","rowId":id}));
            state.mode == "after-error"
        };
        _ = crate::backend::hook_execute(
            context.db,
            "INSERT INTO application_delete_receipts (model,row_id) VALUES (?,?)",
            vec![model.into(), id.into()],
        )
        .await?;
        if reject {
            return Err(AuthError::CallbackFailure(Box::new(AuthError::internal(
                "Application delete after rejected",
            ))));
        }
        Ok(())
    }
}
#[async_trait::async_trait]
impl DatabaseHooks<TestSchema, crate::backend::Backend> for Hooks {
    async fn before_delete_user(
        &self,
        row: &<TestSchema as AuthSchema>::User,
        _: &crate::backend::HookContext<'_>,
    ) -> AuthResult<HookControl> {
        self.before("user", row.id().as_ref())
    }
    async fn after_delete_user(
        &self,
        row: &<TestSchema as AuthSchema>::User,
        ctx: &crate::backend::HookContext<'_>,
    ) -> AuthResult<()> {
        self.after("user", row.id().as_ref(), ctx).await
    }
    async fn before_delete_session(
        &self,
        row: &<TestSchema as AuthSchema>::Session,
        _: &crate::backend::HookContext<'_>,
    ) -> AuthResult<HookControl> {
        self.before("session", row.id().as_ref())
    }
    async fn after_delete_session(
        &self,
        row: &<TestSchema as AuthSchema>::Session,
        ctx: &crate::backend::HookContext<'_>,
    ) -> AuthResult<()> {
        self.after("session", row.id().as_ref(), ctx).await
    }
    async fn before_delete_account(
        &self,
        row: &<TestSchema as AuthSchema>::Account,
        _: &crate::backend::HookContext<'_>,
    ) -> AuthResult<HookControl> {
        self.before("account", row.id().as_ref())
    }
    async fn after_delete_account(
        &self,
        row: &<TestSchema as AuthSchema>::Account,
        ctx: &crate::backend::HookContext<'_>,
    ) -> AuthResult<()> {
        self.after("account", row.id().as_ref(), ctx).await
    }
}
pub(crate) async fn router(base: &AuthConfig, database: DatabaseConnection) -> AuthResult<Router> {
    database
        .execute_raw(Statement::from_string(
            database.get_database_backend(),
            "CREATE TABLE IF NOT EXISTS application_delete_receipts (model TEXT, row_id TEXT)",
        ))
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    let state = Arc::new(Mutex::new(State::default()));
    let config = base
        .clone()
        .base_path("/__test/profiles/delete-hooks/api/auth");
    let store = crate::backend::store::<TestSchema>(config.clone(), database.clone())
        .with_hooks(vec![Arc::new(Hooks(state.clone()))]);
    let auth = Arc::new(
        AuthBuilder::<TestSchema>::new(config)
            .store(store)
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new())
            .plugin(SessionManagementPlugin::new())
            .plugin(AdminPlugin::new())
            .plugin(UserManagementPlugin::new())
            .build()
            .await?,
    );
    let routes = auth.clone().axum_router().with_state(auth);
    let read_state = state.clone();
    let read_database = database.clone();
    Ok(Router::new().nest("/__test/profiles/delete-hooks/api/auth",routes).route("/__test/delete-hooks/control",get(move || {let state=read_state.clone();let database=read_database.clone();async move {let rows=database.query_all_raw(Statement::from_string(database.get_database_backend(),"SELECT model,row_id FROM application_delete_receipts")).await.unwrap();Json(json!({"events":state.lock().unwrap().events,"receipts":rows.iter().map(|row|json!({"model":row.try_get::<String>("","model").unwrap(),"rowId":row.try_get::<String>("","row_id").unwrap()})).collect::<Vec<_>>()}))}}).post(move |Json(input):Json<Value>| {let state=state.clone();let database=database.clone();async move { {let mut state=state.lock().unwrap();state.model=input["model"].as_str().unwrap().into();state.mode=input["mode"].as_str().unwrap().into();state.events.clear();}database.execute_raw(Statement::from_string(database.get_database_backend(),"DELETE FROM application_delete_receipts")).await.unwrap();Json(json!({"events":[],"receipts":[]}))}})))
}
