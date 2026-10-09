//! Real configured router policy, application hooks and ordinary SQL sessions.
use crate::TestSchema;
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::{EmailPasswordPlugin, SessionManagementPlugin};
use alibi::{AuthBuilder, AuthConfig, AuthResult};
use alibi::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute, BeforeRequestAction,
};
use alibi::seaorm::DatabaseConnection;
use axum::{Json, Router, routing::get};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;

struct ApplicationObserver {
    events: Arc<Mutex<Vec<Value>>>,
    base_path: String,
}
#[async_trait::async_trait]
impl AuthPlugin<TestSchema> for ApplicationObserver {
    fn name(&self) -> &'static str {
        "dispatch-application"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/owned/{id}", "owned"),
            AuthRoute::post("/sign-in/child", "child"),
            AuthRoute::post("/sign-in-peer", "peer"),
        ]
    }
    fn allowed_media_types(&self, route: &AuthRoute) -> Vec<&'static str> {
        if route.method == alibi::HttpMethod::Post {
            vec![" Application/JSON "]
        } else {
            vec!["application/json"]
        }
    }
    async fn before_request(
        &self,
        req: &AuthRequest,
        _: &AuthContext<TestSchema>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        let original = alibi::hooks::current_request_hook_context();
        let path = original
            .as_ref()
            .map_or(req.path(), |context| context.path.as_str());
        let path = path.strip_prefix(&self.base_path).unwrap_or(path);
        self.events
            .lock()
            .await
            .push(json!({"path":path,"method":format!("{:?}", req.method()).to_uppercase()}));
        Ok(None)
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        _: &AuthContext<TestSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        if matches!(req.path(), "/sign-in/child" | "/sign-in-peer") {
            return Ok(Some(AuthResponse::json(
                200,
                &json!({"payload": req.body_as_json::<Value>()?}),
            )?));
        }
        if req.path().starts_with("/owned/") {
            return Ok(Some(AuthResponse::json(
                200,
                &json!({"id":req.path().rsplit('/').next()}),
            )?));
        }
        Ok(None)
    }
}
pub(crate) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<Router> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut router = Router::new();
    for mode in [
        "default",
        "csrf-off",
        "origin-off",
        "origin-off-explicit-csrf",
        "origin-path",
        "trailing",
        "disabled-email",
        "disabled-template",
        "disabled-literal",
    ] {
        let path = format!("/__test/profiles/dispatch-{mode}/api/auth");
        let mut configured = config.clone().base_path(&path);
        if mode == "csrf-off" {
            configured = configured.disable_csrf_check(true);
        }
        if matches!(mode, "origin-off" | "origin-off-explicit-csrf") {
            configured = configured.disable_origin_check(true);
        }
        if mode == "origin-off-explicit-csrf" {
            configured = configured.disable_csrf_check(false);
        }
        configured.advanced.skip_trailing_slashes = mode == "trailing";
        if mode == "origin-path" {
            configured.advanced.disable_origin_check_paths = vec!["/sign-in/".into()];
        }
        configured.disabled_paths = match mode {
            "disabled-email" => vec!["/sign-in/email".into()],
            "disabled-template" => vec!["/owned/:id".into()],
            "disabled-literal" => vec!["/owned/item".into()],
            _ => Vec::new(),
        };
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(configured.clone())
                .store(crate::backend::store(configured, database.clone()))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(SessionManagementPlugin::new())
                .plugin(ApplicationObserver {
                    events: events.clone(),
                    base_path: path.clone(),
                })
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    Ok(router.route(
        "/__test/dispatch-events",
        get(move || {
            let events = events.clone();
            async move { Json(std::mem::take(&mut *events.lock().await)) }
        }),
    ))
}
