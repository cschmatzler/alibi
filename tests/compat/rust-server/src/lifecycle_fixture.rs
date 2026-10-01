use super::TestSchema;
use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use better_auth::{AuthError, BetterAuth};
use better_auth_core::entity::{AuthAccount, AuthSession, AuthUser};
use better_auth_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute, BeforeRequestAction,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub(super) struct LifecycleFixture(Arc<Mutex<Vec<Value>>>);

impl LifecycleFixture {
    fn record(&self, value: Value) {
        self.0.lock().expect("lifecycle fixture lock").push(value);
    }

    pub(super) fn observer(&self) -> LifecycleObserver {
        LifecycleObserver(self.clone())
    }

    pub(super) fn router(&self) -> Router<Arc<BetterAuth<TestSchema>>> {
        let fixture = self.clone();
        Router::new().route("/__test/lifecycle", get(move |State(auth): State<Arc<BetterAuth<TestSchema>>>, Query(query): Query<std::collections::HashMap<String, String>>| {
            let fixture = fixture.clone();
            async move {
                let events = std::mem::take(&mut *fixture.0.lock().expect("lifecycle fixture lock"));
                let state: AuthResult<Value> = async {
                    let Some(email) = query.get("email") else { return Ok(Value::Null); };
                    let Some(user) = auth.store().get_user_by_email(email).await? else {
                        return Ok(json!({"userId":null,"accounts":[],"sessions":[]}));
                    };
                    let accounts = auth.store().get_user_accounts(&user.id()).await?;
                    let sessions = auth.store().get_user_sessions(&user.id()).await?;
                    Ok(json!({"userId":user.id(),"accounts":accounts.iter().map(|row|json!({"id":row.id(),"userId":row.user_id(),"providerId":row.provider_id()})).collect::<Vec<_>>(),"sessions":sessions.iter().map(|row|json!({"id":row.id(),"userId":row.user_id(),"token":row.token()})).collect::<Vec<_>>()}))
                }.await;
                match state {
                    Ok(state) => Json(json!({"events":events,"state":state})).into_response(),
                    Err(error) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"message":error.to_string()}))).into_response(),
                }
            }
        }))
    }
}

use axum::response::IntoResponse;

#[async_trait]
impl AuthPlugin<TestSchema> for LifecycleFixture {
    fn name(&self) -> &'static str {
        "lifecycle-fixture"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn before_request(
        &self,
        request: &AuthRequest,
        _ctx: &AuthContext<TestSchema>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        let Some(mode) = request.headers.get("x-parity-lifecycle") else {
            return Ok(None);
        };
        self.record(json!({"stage":"before","path":request.path()}));
        if mode == "stop" {
            return Ok(Some(BeforeRequestAction::Respond(AuthResponse::json(
                200,
                &json!({"stopped":true}),
            )?)));
        }
        Ok(None)
    }
    async fn on_request(
        &self,
        _request: &AuthRequest,
        _ctx: &AuthContext<TestSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
    async fn after_request(
        &self,
        request: &AuthRequest,
        _ctx: &AuthContext<TestSchema>,
        response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        let Some(mode) = request.headers.get("x-parity-lifecycle") else {
            return Ok(response);
        };
        self.record(json!({"stage":"after","path":request.path(),"status":response.status}));
        request.queue_response_header("x-lifecycle-queued", "visible");
        request.queue_response_header(
            "set-cookie",
            "lifecycle=value; HttpOnly; Path=/; SameSite=Lax",
        );
        if mode == "reject" {
            return Err(AuthError::forbidden("fixture after rejection"));
        }
        Ok(response)
    }
}

pub(super) struct LifecycleObserver(LifecycleFixture);
#[async_trait]
impl AuthPlugin<TestSchema> for LifecycleObserver {
    fn name(&self) -> &'static str {
        "lifecycle-observer"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_request(
        &self,
        _request: &AuthRequest,
        _ctx: &AuthContext<TestSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
    async fn after_request(
        &self,
        request: &AuthRequest,
        _ctx: &AuthContext<TestSchema>,
        mut response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        if !request.headers.contains_key("x-parity-lifecycle") {
            return Ok(response);
        }
        let visible = response.headers.get("x-lifecycle-queued").cloned();
        self.0.record(json!({"stage":"observe","path":request.path(),"header":visible,"status":response.status,"cookieCount":response.headers.get_all("set-cookie").count()}));
        _ = response.headers.insert(
            "x-lifecycle-observed",
            visible.unwrap_or_else(|| "missing".into()),
        );
        Ok(response)
    }
}
