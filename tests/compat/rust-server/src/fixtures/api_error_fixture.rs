//! Observe actual public HTTP handler return/error results at the host boundary.
use crate::TestSchema;
use alibi::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use alibi_core::{AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute, HttpMethod};
use alibi_seaorm::DatabaseConnection;
use axum::{Json, Router, routing::post};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
struct Failure(Arc<Mutex<Vec<Value>>>);
#[async_trait::async_trait]
impl AuthPlugin<TestSchema> for Failure {
    fn name(&self) -> &'static str {
        "application-failure"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::post("/fixture-failure", "fixture_failure")]
    }
    async fn on_request(
        &self,
        request: &AuthRequest,
        _context: &AuthContext<TestSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        if request.path() != "/fixture-failure" {
            return Ok(None);
        }
        self.0.lock().unwrap().push(json!({"path":request.path(), "method":format!("{:?}",request.method()).to_uppercase(), "marker":request.headers.get("x-error-marker")}));
        if request.body_as_json::<Value>()?["kind"] == "coded" {
            return Err(AuthError::Api {
                status: 403,
                code: Some("APPLICATION_DENIED".into()),
                message: "Application handler rejected".into(),
            });
        }
        Err(AuthError::internal("Application handler failed"))
    }
}
pub(crate) async fn router(base: &AuthConfig, database: DatabaseConnection) -> AuthResult<Router> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut profiles = HashMap::new();
    for mode in ["masked", "throw"] {
        // Native has no onAPIError.throw setting; observe the supported handler as-is.
        let config = base
            .clone()
            .base_path(format!("/__test/profiles/api-error-{mode}/api/auth"));
        let auth = AuthBuilder::<TestSchema>::new(config.clone())
            .store(crate::backend::store::<TestSchema>(
                config,
                database.clone(),
            ))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(Failure(events.clone()))
            .build()
            .await?;
        profiles.insert(mode, Arc::new(auth));
    }
    let origin = base.base_url.clone();
    Ok(Router::new().route("/__test/api-error/invoke", post(move |Json(input): Json<Value>| {let events=events.clone();let profiles=profiles.clone();let origin=origin.clone();async move {
        let mode=input["mode"].as_str().unwrap(); events.lock().unwrap().clear();
        let mut request=AuthRequest::new(HttpMethod::Post,"/fixture-failure").with_url(url::Url::parse(&format!("{origin}/__test/profiles/api-error-{mode}/api/auth/fixture-failure")).unwrap());
        request.headers.insert("content-type".into(),"application/json".into()); request.headers.insert("origin".into(),origin); request.headers.insert("x-error-marker".into(),input["marker"].as_str().unwrap().into()); request.body=Some(serde_json::to_vec(&json!({"kind":input["kind"]})).unwrap());
        match profiles[mode].handle_request(request).await {
            Ok(response) => {let text=String::from_utf8_lossy(&response.body);let body=serde_json::from_str::<Value>(&text).unwrap_or_else(|_| json!(text));Json(json!({"outcome":"returned","status":response.status,"body":body,"headers":{"content-type":response.headers.get("Content-Type").or_else(||response.headers.get("content-type")),"set-cookie":response.headers.get_all("Set-Cookie").collect::<Vec<_>>()},"events":*events.lock().unwrap()}))},
            Err(error) => Json(json!({"outcome":"thrown","message":error.to_string(),"events":*events.lock().unwrap()})),
        }
    }})))
}
