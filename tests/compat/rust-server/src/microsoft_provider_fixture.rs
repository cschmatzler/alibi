//! Existing generic configuration before the dedicated Microsoft factory repair.
use crate::TestSchema;
use axum::{Json, Router, routing::get};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::oauth::{OAuthAuthorizationPolicy, OAuthProvider};
use better_auth::plugins::{EmailPasswordPlugin, OAuthPlugin, SessionManagementPlugin};
use better_auth::{AuthBuilder, AuthConfig, AuthResult};
use better_auth_seaorm::{DatabaseConnection, SeaOrmStore};
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
pub(super) struct Fixture;
impl Fixture {
    pub(super) async fn reset(&self) {}
}
pub(super) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<(Router, Fixture)> {
    let path = "/__test/profiles/social-microsoft-default/api/auth";
    let settings = config.clone().base_path(path);
    let provider = OAuthProvider {
        client_id: "fixture-social-client".into(),
        client_secret: "fixture-social-secret".into(),
        additional_client_ids: Vec::new(),
        hosted_domain: None,
        require_email_verification: false,
        auth_url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize".into(),
        token_url: "https://login.microsoftonline.com/common/oauth2/v2.0/token".into(),
        user_info_url: None,
        scopes: Vec::new(),
        authorization: Some(OAuthAuthorizationPolicy::default()),
        authorization_params: Vec::new(),
        account_subject: None,
        map_user_info: None,
        get_user_info: None,
        refresh_access_token: None,
        verify_id_token: None,
        id_token: None,
        disable_id_token_sign_in: false,
        disable_implicit_sign_up: false,
        disable_sign_up: false,
        override_user_info_on_sign_in: false,
    };
    let auth = Arc::new(
        AuthBuilder::<TestSchema>::new(settings.clone())
            .store(SeaOrmStore::<TestSchema>::new(settings, database))
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new().enable_username(false))
            .plugin(SessionManagementPlugin::new())
            .plugin(OAuthPlugin::new().add_provider("microsoft", provider))
            .build()
            .await?,
    );
    let router = Router::new()
        .nest(path, auth.clone().axum_router().with_state(auth))
        .route(
            "/__test/microsoft/receipts",
            get(|| async { Json(json!([])) }),
        );
    Ok((router, Fixture))
}
