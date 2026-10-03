//! Actual managed-key runtimes sharing the ordinary fixture database.
use crate::TestSchema;
use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::Query,
    response::IntoResponse,
    routing::{get, post},
};
use better_auth::plugins::jwt::JwtPlugin;
use better_auth::plugins::{
    EmailPasswordPlugin, MultiSessionPlugin, OAuthPlugin, SessionManagementPlugin, TwoFactorConfig,
    TwoFactorPlugin,
    email_otp::{EmailOtpConfig, EmailOtpDelivery, EmailOtpPlugin, EmailOtpStorage, SendEmailOtp},
};
use better_auth::{
    AuthBuilder, AuthConfig, AuthResult, integrations::axum::AxumIntegration,
    middleware::RateLimitConfig,
};
use better_auth_core::ManagedSecrets;
use better_auth_seaorm::DatabaseConnection;
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::Mutex;
const OLD: &str = "managed-old-reader-key-at-least-32-characters";
const CURRENT: &str = "compat-test-only-key-not-real-minimum-32chars";
const LEGACY: &str = "managed-legacy-reader-key-at-least-32-characters";
struct TokenHook(Arc<AtomicUsize>);
#[async_trait]
impl better_auth_seaorm::DatabaseHooks<TestSchema, crate::backend::Backend> for TokenHook {
    async fn before_create_session(
        &self,
        session: &mut better_auth_core::CreateSession,
        _: &crate::backend::HookContext<'_>,
    ) -> AuthResult<better_auth_seaorm::HookControl> {
        let counter = self.0.fetch_add(1, Ordering::SeqCst) + 1;
        session.token = Some(format!("managed{counter:025}"));
        Ok(better_auth_seaorm::HookControl::Continue)
    }
}
#[derive(Clone, Default)]
struct Delivery(Arc<Mutex<HashMap<String, String>>>);
#[async_trait]
impl SendEmailOtp for Delivery {
    async fn send(
        &self,
        delivery: &EmailOtpDelivery,
        _: &better_auth_core::CallbackContext,
    ) -> AuthResult<()> {
        _ = self
            .0
            .lock()
            .await
            .insert(delivery.email.clone(), delivery.otp.clone());
        Ok(())
    }
}
#[derive(serde::Deserialize)]
struct Lookup {
    email: String,
}
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct StateLookup {
    user_id: String,
}
pub(crate) async fn router(
    base: &AuthConfig,
    database: DatabaseConnection,
    oauth: impl Fn() -> OAuthPlugin,
) -> AuthResult<Router> {
    let delivery = Delivery::default();
    let state_db = database.clone();
    let counter = Arc::new(AtomicUsize::new(0));
    let mut router = Router::new();
    let mut profiles = HashMap::new();
    for mode in ["old", "retained", "retired", "legacy", "bare"] {
        let path = format!("/__test/profiles/managed-{mode}/api/auth");
        let mut config = base.clone().base_path(&path);
        config.session.cookie_cache = Some(better_auth_core::CookieCacheConfig {
            enabled: !["old", "bare"].contains(&mode),
            ..Default::default()
        });
        config.secret = LEGACY.into();
        config.account.encrypt_oauth_tokens = true;
        config.account.store_account_cookie = true;
        config.account.store_state_strategy = better_auth_core::OAuthStateStrategy::Cookie;
        config.managed_secrets = match mode {
            "old" => Some(ManagedSecrets::new(0, OLD)),
            "retained" => Some(ManagedSecrets::new(2, CURRENT).retain(0, OLD)),
            "retired" => Some(ManagedSecrets::new(2, CURRENT)),
            "legacy" => Some(
                ManagedSecrets::new(2, CURRENT)
                    .retain(0, OLD)
                    .legacy(LEGACY),
            ),
            _ => None,
        };
        let otp = EmailOtpConfig {
            storage: EmailOtpStorage::Encrypted,
            send_verification_otp: Some(Arc::new(delivery.clone())),
            ..Default::default()
        };
        let factor = TwoFactorConfig {
            skip_verification_on_enable: true,
            custom_backup_codes_generate: Some(Arc::new(|| {
                Ok(vec!["backup-one".into(), "backup-two".into()])
            })),
            ..Default::default()
        };
        let jwt = JwtPlugin::new();
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(
                    crate::backend::store::<TestSchema>(config, database.clone())
                        .hook(TokenHook(counter.clone())),
                )
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(EmailOtpPlugin::new(otp))
                .plugin(oauth())
                .plugin(jwt.clone())
                .plugin(SessionManagementPlugin::new())
                .plugin(TwoFactorPlugin::with_config(factor))
                .plugin(MultiSessionPlugin::new())
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth.clone()));
        profiles.insert(format!("managed-{mode}"), (auth, jwt));
    }
    router = router.route(
        "/__test/managed-secrets/jwk",
        post(move |Json(body): Json<serde_json::Value>| {
            let profiles = profiles.clone();
            async move {
                let Some((auth, jwt)) = body
                    .get("profile")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|profile| profiles.get(profile))
                else {
                    return (
                        axum::http::StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error":"Unknown profile"})),
                    )
                        .into_response();
                };
                match jwt.create_jwk(None, None, auth.context()).await {
                    Ok(_) => (
                        axum::http::StatusCode::OK,
                        Json(serde_json::json!({"created":true})),
                    )
                        .into_response(),
                    Err(error) => (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error":error.to_string()})),
                    )
                        .into_response(),
                }
            }
        }),
    );
    router=router.route("/__test/managed-secrets/state",get(move |Query(input):Query<StateLookup>| {
        let db=state_db.clone();
        async move {
            use better_auth_seaorm::sea_orm::{EntityTrait,QueryFilter,QueryOrder,ColumnTrait};
            use better_auth_seaorm::store::entities::{account,jwk,user,session};
            let result=async {
                let users=user::Entity::find().filter(user::Column::Id.eq(input.user_id.clone())).all(&db).await?;
                let sessions=session::Entity::find().filter(session::Column::UserId.eq(input.user_id.clone())).order_by_asc(session::Column::CreatedAt).all(&db).await?;
                let accounts=account::Entity::find().filter(account::Column::UserId.eq(input.user_id)).order_by_asc(account::Column::CreatedAt).all(&db).await?;
                let keys=jwk::Entity::find().order_by_asc(jwk::Column::CreatedAt).all(&db).await?;
                Ok::<_,better_auth_seaorm::sea_orm::DbErr>(serde_json::json!({
                    "users":users.into_iter().map(|u|serde_json::json!({"id":u.id,"name":u.name,"email":u.email,"emailVerified":u.email_verified,"image":u.image,"twoFactorEnabled":u.two_factor_enabled,"createdAt":u.created_at,"updatedAt":u.updated_at})).collect::<Vec<_>>(),
                    "sessions":sessions.into_iter().map(|s|serde_json::json!({"id":s.id,"userId":s.user_id,"token":s.token,"expiresAt":s.expires_at,"ipAddress":s.ip_address,"userAgent":s.user_agent,"createdAt":s.created_at,"updatedAt":s.updated_at})).collect::<Vec<_>>(),
                    "accounts":accounts.into_iter().map(|a|serde_json::json!({"id":a.id,"userId":a.user_id,"accountId":a.account_id,"providerId":a.provider_id,"accessToken":a.access_token,"refreshToken":a.refresh_token,"idToken":a.id_token,"accessTokenExpiresAt":a.access_token_expires_at,"refreshTokenExpiresAt":a.refresh_token_expires_at,"scope":a.scope,"password":a.password,"createdAt":a.created_at,"updatedAt":a.updated_at})).collect::<Vec<_>>(),
                    "keys":keys.into_iter().map(|k|serde_json::json!({"id":k.id,"publicKey":serde_json::from_str::<serde_json::Value>(&k.public_key).unwrap_or_default(),"privateKey":serde_json::from_str::<serde_json::Value>(&k.private_key).unwrap_or_default(),"createdAt":k.created_at,"expiresAt":k.expires_at,"alg":k.alg,"crv":k.crv})).collect::<Vec<_>>()
                }))
            }.await;
            match result {Ok(value)=>Json(value).into_response(),Err(error)=>(axum::http::StatusCode::INTERNAL_SERVER_ERROR,Json(serde_json::json!({"error":error.to_string()}))).into_response()}
        }
    }));
    Ok(router.route(
        "/__test/managed-secrets/delivery",
        get(move |Query(input): Query<Lookup>| {
            let delivery = delivery.clone();
            async move {
                match delivery.0.lock().await.get(&input.email).cloned() {
                    Some(otp) => (
                        axum::http::StatusCode::OK,
                        Json(serde_json::json!({"otp":otp})),
                    )
                        .into_response(),
                    None => (
                        axum::http::StatusCode::NOT_FOUND,
                        Json(serde_json::json!({"error":"No delivery"})),
                    )
                        .into_response(),
                }
            }
        }),
    ))
}
