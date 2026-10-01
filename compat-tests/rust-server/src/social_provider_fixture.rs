//! Actual immutable built-in provider policies and local provider transport.
use crate::TestSchema;
use axum::{
    extract::State,
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::oauth::OAuthProvider;
use better_auth::plugins::{EmailPasswordPlugin, OAuthPlugin, SessionManagementPlugin};
use better_auth::{AuthBuilder, AuthConfig, AuthResult};
use better_auth_seaorm::sea_orm::{EntityTrait, QueryOrder};
use better_auth_seaorm::store::entities::{account, session, user};
use better_auth_seaorm::{DatabaseConnection, SeaOrmStore};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone, Default)]
pub(super) struct Fixture {
    profile: Arc<Mutex<Value>>,
    receipts: Arc<Mutex<Vec<Value>>>,
}
impl Fixture {
    pub(super) async fn reset(&self) {
        *self.profile.lock().await = json!({});
        self.receipts.lock().await.clear();
    }
}
fn date(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub(super) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<(Router, Fixture)> {
    let fixture = Fixture::default();
    let mut router = Router::new();
    for name in ["google", "github", "discord"] {
        for mode in [
            "default",
            "configured",
            "disabled",
            "disabled-configured",
            "permissions",
            "bot",
            "zero",
            "fractional",
            "infinite",
            "prompt",
            "empty-prompt",
        ] {
            if name != "discord"
                && !["default", "configured", "disabled", "disabled-configured"].contains(&mode)
            {
                continue;
            }
            let path = format!("/__test/profiles/social-{name}-{mode}/api/auth");
            let settings = config.clone().base_path(&path);
            let mut provider = match name {
                "google" => OAuthProvider::google("fixture-social-client", "fixture-social-secret"),
                "github" => OAuthProvider::github("fixture-social-client", "fixture-social-secret"),
                _ => OAuthProvider::discord("fixture-social-client", "fixture-social-secret"),
            };
            if name == "discord" {
                provider.token_url = format!("{}/__test/social-provider/token", config.base_url);
                provider.user_info_url = Some(format!(
                    "{}/__test/social-provider/userinfo",
                    config.base_url
                ));
            }
            let policy = provider.authorization.as_mut().ok_or_else(|| {
                better_auth::AuthError::internal("Missing builtin fixture policy")
            })?;
            policy.disable_default_scopes = mode.starts_with("disabled");
            if mode == "configured" || mode == "disabled-configured" {
                policy.configured_scopes.push("configured-scope".into());
            }
            if mode == "bot" {
                policy.configured_scopes.push("bot".into());
            }
            policy.discord_permissions = match mode {
                "permissions" | "bot" => Some(8.0),
                "zero" => Some(0.0),
                "fractional" => Some(1.5),
                "infinite" => Some(f64::INFINITY),
                _ => None,
            };
            policy.prompt = match mode {
                "prompt" => Some("consent".into()),
                "empty-prompt" => Some(String::new()),
                _ => None,
            };
            let auth = Arc::new(
                AuthBuilder::<TestSchema>::new(settings.clone())
                    .store(SeaOrmStore::<TestSchema>::new(settings, database.clone()))
                    .rate_limit(RateLimitConfig::new().enabled(false))
                    .plugin(EmailPasswordPlugin::new().enable_username(false))
                    .plugin(SessionManagementPlugin::new())
                    .plugin(OAuthPlugin::new().add_provider(name, provider))
                    .build()
                    .await?,
            );
            router = router.nest(&path, auth.clone().axum_router().with_state(auth));
        }
    }
    for mode in [
        "default",
        "configured",
        "disabled",
        "disabled-configured",
        "issuer",
        "issuer-slashes",
    ] {
        let path = format!("/__test/profiles/social-gitlab-{mode}/api/auth");
        let settings = config.clone().base_path(&path);
        let mut provider = if mode.starts_with("issuer") {
            OAuthProvider::gitlab_with_issuer(
                "fixture-social-client",
                "fixture-social-secret",
                &format!(
                    "{}/__test/social-provider/gitlab{}",
                    config.base_url,
                    if mode == "issuer-slashes" { "///" } else { "" }
                ),
            )
        } else {
            OAuthProvider::gitlab("fixture-social-client", "fixture-social-secret")
        };
        let policy = provider
            .authorization
            .as_mut()
            .ok_or_else(|| better_auth::AuthError::internal("Missing GitLab policy"))?;
        policy.disable_default_scopes = mode.starts_with("disabled");
        if mode == "configured" || mode == "disabled-configured" {
            policy.configured_scopes.push("configured-scope".into());
        }
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(settings.clone())
                .store(SeaOrmStore::<TestSchema>::new(settings, database.clone()))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(SessionManagementPlugin::new())
                .plugin(OAuthPlugin::new().add_provider("gitlab", provider))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let store = database.clone();
    let observer = fixture.clone();
    let control = fixture.clone();
    router = router.route("/__test/social-provider/profile", post(move |Json(value): Json<Value>| { let control = control.clone(); async move {
        *control.profile.lock().await = value.clone(); Json(json!({"status": true, "profile": value}))
    }})).route("/__test/social-provider/state", get(move || { let store = store.clone(); let observer = observer.clone(); async move {
        let users = user::Entity::find().order_by_asc(user::Column::CreatedAt).all(&store).await;
        let accounts = account::Entity::find().order_by_asc(account::Column::CreatedAt).all(&store).await;
        let sessions = session::Entity::find().order_by_asc(session::Column::CreatedAt).all(&store).await;
        match (users, accounts, sessions) {
            (Ok(users), Ok(accounts), Ok(sessions)) => Ok(Json(json!({
                "users": users.into_iter().map(|row| json!({"id": row.id, "name": row.name, "email": row.email, "emailVerified": row.email_verified, "image": row.image, "createdAt": date(row.created_at), "updatedAt": date(row.updated_at)})).collect::<Vec<_>>(),
                "accounts": accounts.into_iter().map(|row| json!({"id": row.id, "userId": row.user_id, "accountId": row.account_id, "providerId": row.provider_id, "accessToken": row.access_token, "refreshToken": row.refresh_token, "idToken": row.id_token, "scope": row.scope, "accessTokenExpiresAt": row.access_token_expires_at.map(date), "refreshTokenExpiresAt": row.refresh_token_expires_at.map(date), "createdAt": date(row.created_at), "updatedAt": date(row.updated_at)})).collect::<Vec<_>>(),
                "sessions": sessions.into_iter().map(|row| json!({"id": row.id, "userId": row.user_id, "token": row.token, "expiresAt": date(row.expires_at), "createdAt": date(row.created_at), "updatedAt": date(row.updated_at), "ipAddress": row.ip_address, "userAgent": row.user_agent})).collect::<Vec<_>>(),
                "receipts": observer.receipts.lock().await.clone(),
            }))),
            _ => Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR),
        }
    }}));
    let provider = Router::new()
        .route("/__test/social-provider/gitlab/oauth/token", post(|State(state): State<Fixture>, headers: HeaderMap, body: String| async move {
            let form = url::form_urlencoded::parse(body.as_bytes()).into_owned().collect::<std::collections::BTreeMap<_,_>>();
            let refresh = form.get("grant_type").is_some_and(|value| value == "refresh_token");
            state.receipts.lock().await.push(json!({"path": "/__test/social-provider/gitlab/oauth/token", "method": "POST", "authorization": headers.get("authorization").and_then(|v| v.to_str().ok()), "contentType": headers.get("content-type").and_then(|v| v.to_str().ok()), "body": form}));
            Json(if refresh { json!({"access_token": "fixture-gitlab-refreshed-access", "refresh_token": "fixture-gitlab-refreshed-refresh", "token_type": "Bearer", "scope": "read_user refreshed-scope", "expires_in": 1800}) } else { json!({"access_token": "fixture-gitlab-access", "refresh_token": "fixture-gitlab-refresh", "token_type": "Bearer", "scope": "read_user issued-scope", "expires_in": 3600}) })
        }))
        .route("/__test/social-provider/gitlab/api/v4/user", get(|State(state): State<Fixture>, headers: HeaderMap| async move {
            state.receipts.lock().await.push(json!({"path": "/__test/social-provider/gitlab/api/v4/user", "method": "GET", "authorization": headers.get("authorization").and_then(|v| v.to_str().ok()), "contentType": headers.get("content-type").and_then(|v| v.to_str().ok()), "body": null}));
            Json(state.profile.lock().await.clone())
        }))
        .route("/__test/social-provider/token", post(|State(state): State<Fixture>, headers: HeaderMap, body: String| async move {
            state.receipts.lock().await.push(json!({"path": "/token", "method": "POST", "authorization": headers.get("authorization").and_then(|v| v.to_str().ok()), "contentType": headers.get("content-type").and_then(|v| v.to_str().ok()), "body": url::form_urlencoded::parse(body.as_bytes()).into_owned().collect::<std::collections::BTreeMap<_,_>>() }));
            Json(json!({"access_token": "fixture-discord-access", "token_type": "Bearer", "scope": "identify email", "expires_in": 3600}))
        }))
        .route("/__test/social-provider/userinfo", get(|State(state): State<Fixture>, headers: HeaderMap| async move {
            state.receipts.lock().await.push(json!({"path": "/userinfo", "method": "GET", "authorization": headers.get("authorization").and_then(|v| v.to_str().ok()), "contentType": headers.get("content-type").and_then(|v| v.to_str().ok()), "body": null}));
            Json(state.profile.lock().await.clone())
        })).with_state(fixture.clone());
    Ok((router.merge(provider), fixture))
}
