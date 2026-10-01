use crate::TestSchema;
use axum::{Json, Router, body::Bytes, http::StatusCode, response::IntoResponse, routing::post};
use better_auth::plugins::two_factor::TwoFactorConfig;
use better_auth::{
    AuthBuilder, AuthConfig, AuthResult, BetterAuth,
    integrations::axum::AxumIntegration,
    middleware::RateLimitConfig,
    plugins::{EmailPasswordPlugin, SessionManagementPlugin, TwoFactorPlugin},
};
use better_auth_core::utils::json::{self, JsValue};
use better_auth_seaorm::{DatabaseConnection, SeaOrmStore};
use serde_json::json;
use std::{collections::HashMap, sync::Arc};
type Auth = Arc<BetterAuth<TestSchema>>;

pub(super) async fn router(
    base: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<Router<Auth>> {
    let mut router = Router::new();
    let mut profiles = HashMap::new();
    for name in [
        "two-factor-totp-default",
        "two-factor-totp-config",
        "two-factor-totp-disabled",
        "two-factor-totp-zero",
    ] {
        let configured = name == "two-factor-totp-config";
        let zero = name == "two-factor-totp-zero";
        let plugin = TwoFactorPlugin::with_config(TwoFactorConfig {
            issuer: Some("Enrollment Issuer".to_owned()),
            totp_issuer: configured.then(|| "Authenticator Issuer".to_owned()),
            totp_digits: if zero {
                0
            } else if configured {
                8
            } else {
                6
            },
            totp_period: if zero {
                0
            } else if configured {
                45
            } else {
                30
            },
            totp_disabled: name == "two-factor-totp-disabled",
            ..Default::default()
        });
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut config = base.clone().base_path(&path);
        config.app_name = "Fixture Auth".to_owned();
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(SeaOrmStore::<TestSchema>::new(config, database.clone()))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(
                    EmailPasswordPlugin::new()
                        .enable_signup(true)
                        .enable_username(false),
                )
                .plugin(SessionManagementPlugin::new())
                .plugin(plugin.clone())
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
        let _ = profiles.insert(name.to_owned(), plugin);
    }
    let profiles = Arc::new(profiles);
    Ok(router.route(
        "/__test/two-factor-totp",
        post(move |body: Bytes| {
            let profiles = profiles.clone();
            async move {
                let value = json::from_slice::<JsValue>(&body).ok();
                let Some(secret) = value
                    .as_ref()
                    .and_then(|value| value.get("secret"))
                    .and_then(JsValue::as_str)
                else {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"message":"secret required"})),
                    )
                        .into_response();
                };
                let name = value
                    .as_ref()
                    .and_then(|value| value.get("profile"))
                    .and_then(JsValue::as_str)
                    .unwrap_or("two-factor-totp-default");
                let Some(plugin) = profiles.get(name) else {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"message":"unknown fixture profile"})),
                    )
                        .into_response();
                };
                match plugin.generate_totp(secret) {
                    Ok(code) => Json(json!({"code":code})).into_response(),
                    Err(error) => error.into_response(),
                }
            }
        }),
    ))
}
