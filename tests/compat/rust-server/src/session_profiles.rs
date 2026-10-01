//! Explicit session configurations and trusted persisted-clock controls.
use crate::TestSchema;
use axum::{Json, Router, http::StatusCode, routing::post};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::password_management::SendResetPassword;
use better_auth::plugins::{
    AdminPlugin, EmailPasswordPlugin, OrganizationPlugin, PasswordManagementPlugin,
    SessionManagementPlugin, TwoFactorPlugin, UserManagementPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, AuthResult};
use better_auth_seaorm::store::entities::session;
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, sea_query::Expr},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionClock {
    token: String,
    expires_at: DateTime<Utc>,
    created_at: Option<DateTime<Utc>>,
}

pub(super) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
    reset_sender: Arc<dyn SendResetPassword>,
) -> AuthResult<Router> {
    let mut router = Router::new();
    for name in [
        "session-deferred",
        "session-no-refresh",
        "session-deferred-no-refresh",
        "session-no-freshness",
        "session-cookie-cleanup",
    ] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut config = config.clone().base_path(&path);
        config.session.defer_session_refresh = name.starts_with("session-deferred");
        config.session.disable_session_refresh = name.ends_with("no-refresh");
        if name == "session-no-freshness" {
            config.session.fresh_age = Some(chrono::Duration::zero());
        }
        if name == "session-cookie-cleanup" {
            config.account.store_account_cookie = true;
            config.account.store_state_strategy = better_auth::config::OAuthStateStrategy::Cookie;
        }
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(SeaOrmStore::<TestSchema>::new(config, database.clone()))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new())
                .plugin(SessionManagementPlugin::new())
                .plugin(PasswordManagementPlugin::new().send_reset_password(reset_sender.clone()))
                .plugin(
                    UserManagementPlugin::new()
                        .delete_user_enabled(true)
                        .require_delete_verification(false),
                )
                .plugin(AdminPlugin::new())
                .plugin(TwoFactorPlugin::new())
                .plugin(OrganizationPlugin::new())
                .build()
                .await?,
        );
        let routes = auth.clone().axum_router().with_state(auth);
        router = router.nest(&path, routes);
    }
    Ok(router.route(
        "/__test/expire-session",
        post(move |Json(body): Json<SessionClock>| {
            let database = database.clone();
            async move {
                let mut update = session::Entity::update_many()
                    .col_expr(session::Column::ExpiresAt, Expr::value(body.expires_at))
                    .filter(session::Column::Token.eq(body.token));
                if let Some(created_at) = body.created_at {
                    update = update.col_expr(session::Column::CreatedAt, Expr::value(created_at));
                }
                match update.exec(&database).await {
                    Ok(result) => (
                        StatusCode::OK,
                        Json(json!({"updated":result.rows_affected})),
                    ),
                    Err(error) => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(Value::String(error.to_string())),
                    ),
                }
            }
        }),
    ))
}
