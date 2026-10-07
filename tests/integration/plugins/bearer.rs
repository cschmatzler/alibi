//! Public native dispatch must propagate verified headers to completed hooks.

use alibi::{AuthBuilder, AuthConfig, plugins::BearerPlugin};
use alibi_core::store::{SessionStore, UserStore};
use alibi_core::utils::cookie_utils::sign_cookie_value;
use alibi_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute, CreateSession,
    CreateUser, HttpMethod,
};
use alibi_seaorm::{Database, SeaOrmStore};
use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};
type Schema = alibi_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

struct ApplicationObserver;
#[async_trait]
impl AuthPlugin<Schema> for ApplicationObserver {
    fn name(&self) -> &'static str {
        "application-observer"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::get("/probe", "applicationProbe")]
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<Schema>,
    ) -> AuthResult<Option<AuthResponse>> {
        let (user, _) = ctx.require_session(req).await?;
        Ok(Some(AuthResponse::json(
            200,
            &serde_json::json!({"userId":user.id,"cookie":req.header("cookie")}),
        )?))
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        _ctx: &AuthContext<Schema>,
        mut response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        drop(response.headers.insert(
            "x-application-cookie",
            req.header("cookie").cloned().unwrap_or_default(),
        ));
        drop(response.headers.insert("x-application-path", req.path()));
        Ok(response)
    }
}

#[tokio::test]
async fn native_bearer_headers_reach_endpoint_and_completed_application_hook() {
    let config = AuthConfig::new("native-bearer-contract-secret-at-least-32-characters")
        .base_path("/native/auth");
    let database = Database::connect("sqlite::memory:").await.unwrap();
    alibi_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap();
    let store = Arc::new(SeaOrmStore::<Schema>::new(config.clone(), database));
    let user = store
        .create_user(
            CreateUser::new()
                .with_email("owner@bearer.fixture.test")
                .with_name("Owner"),
        )
        .await
        .unwrap();
    let session = store
        .create_session(CreateSession {
            user_id: user.id.clone(),
            token: None,
            expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
            additional_fields: Default::default(),
            active_team_id: None,
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await
        .unwrap();
    let expected = format!(
        "retained=hello%20world; {}={}",
        config.session.cookie_name,
        sign_cookie_value(&session.token, &config.secret)
    );
    let auth = AuthBuilder::<Schema>::new(config)
        .store_arc(store)
        .plugin(BearerPlugin::new())
        .plugin(ApplicationObserver)
        .build()
        .await
        .unwrap();
    let request = AuthRequest::from_parts(
        HttpMethod::Get,
        "/native/auth/probe".into(),
        HashMap::from([
            ("Authorization".into(), format!("Bearer {}", session.token)),
            ("Cookie".into(), "retained=hello%20world".into()),
        ]),
        None,
        HashMap::new(),
    );
    let response = auth.handle_request(request).await.unwrap();
    assert_eq!(response.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body.get("userId"), Some(&serde_json::json!(user.id)));
    assert_eq!(body.get("cookie"), Some(&serde_json::json!(expected)));
    assert_eq!(
        response.headers.get("x-application-cookie"),
        Some(&expected)
    );
    assert_eq!(
        response
            .headers
            .get("x-application-path")
            .map(String::as_str),
        Some("/probe")
    );
}
