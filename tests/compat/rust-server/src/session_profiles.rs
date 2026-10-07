//! Explicit session configurations and trusted persisted-clock controls.
use crate::TestSchema;
use axum::{Json, Router, http::StatusCode, routing::post};
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::api_key::{ApiKeyConfig, ApiKeyPlugin};
use alibi::plugins::multi_session::MultiSessionPlugin;
use alibi::plugins::one_time_token::OneTimeTokenPlugin;
use alibi::plugins::password_management::SendResetPassword;
use alibi::plugins::{
    AdminPlugin, EmailPasswordPlugin, OrganizationPlugin, PasswordManagementPlugin,
    SessionManagementPlugin, TwoFactorPlugin, UserManagementPlugin,
};
use alibi::{AuthBuilder, AuthConfig, AuthResult};
use alibi_core::store::{CacheAdapter, MemoryCacheAdapter};
use alibi_seaorm::sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, sea_query::Expr,
};
use alibi_seaorm::store::entities::session;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
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
    let mut caches = HashMap::<String, Arc<dyn CacheAdapter>>::new();
    for name in [
        "session-secondary-only",
        "session-secondary-preserve-only",
        "session-secondary-combined",
        "session-secondary-preserved",
        "session-deferred",
        "session-no-refresh",
        "session-deferred-no-refresh",
        "session-no-freshness",
        "session-cookie-cleanup",
        "account-unlink-all",
    ] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut config = config.clone().base_path(&path);
        if name.starts_with("session-secondary-") {
            let cache: Arc<dyn CacheAdapter> = Arc::new(MemoryCacheAdapter::new());
            config.session.secondary_storage = Some(cache.clone());
            config.verification.secondary_storage = Some(cache.clone());
            config.session.store_in_database =
                name.ends_with("combined") || name.ends_with("preserved");
            config.session.preserve_in_database = name.contains("preserve");
            drop(caches.insert(name.to_owned(), cache));
        }
        config.session.defer_session_refresh = name.starts_with("session-deferred");
        config.session.disable_session_refresh = name.ends_with("no-refresh");
        if name == "session-no-freshness" {
            config.session.fresh_age = Some(chrono::Duration::zero());
        }
        if name == "session-cookie-cleanup" {
            config.account.store_account_cookie = true;
            config.account.store_state_strategy = alibi::config::OAuthStateStrategy::Cookie;
        }
        if name == "account-unlink-all" {
            config.account.account_linking.allow_unlinking_all = true;
        }
        let mut builder = AuthBuilder::<TestSchema>::new(config.clone())
            .store(crate::backend::store::<TestSchema>(
                config,
                database.clone(),
            ))
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
            .plugin(OrganizationPlugin::new());
        if name == "account-unlink-all" {
            builder = builder.plugin(alibi::plugins::AccountManagementPlugin::new());
        }
        if name.starts_with("session-secondary-") {
            builder = builder
                .plugin(MultiSessionPlugin::new())
                .plugin(OneTimeTokenPlugin::new())
                .plugin(ApiKeyPlugin::with_config(ApiKeyConfig {
                    enable_session_for_api_keys: true,
                    ..Default::default()
                }));
        }
        let auth = Arc::new(builder.build().await?);
        let routes = auth.clone().axum_router().with_state(auth);
        router = router.nest(&path, routes);
    }
    let caches = Arc::new(caches);
    router = router.route(
        "/__test/secondary-session/control",
        post(move |Json(body): Json<Value>| {
            let caches = caches.clone();
            async move {
                let profile = body
                    .get("profile")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let token = body
                    .get("token")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let Some(cache) = caches.get(profile) else {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error":"Unknown profile"})),
                    );
                };
                let result = if body.get("action").and_then(Value::as_str) == Some("remove") {
                    cache.delete(token).await.map(|()| Value::Null)
                } else {
                    cache
                        .get(token)
                        .await
                        .map(|value| json!({"present":value.is_some()}))
                };
                match result {
                    Ok(value) => (StatusCode::OK, Json(value)),
                    Err(error) => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error":error.to_string()})),
                    ),
                }
            }
        }),
    );
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
