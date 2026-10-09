use crate::TestSchema;
use alibi::plugins::two_factor::TwoFactorConfig;
use alibi::seaorm::DatabaseConnection;
use alibi::utils::json::{self, JsValue};
use alibi::{
    AuthBuilder, AuthConfig, AuthResult, BetterAuth,
    integrations::axum::AxumIntegration,
    middleware::RateLimitConfig,
    plugins::{EmailPasswordPlugin, SessionManagementPlugin, TwoFactorPlugin},
};
use axum::{Json, Router, body::Bytes, http::StatusCode, response::IntoResponse, routing::post};
use serde_json::json;
use std::{collections::HashMap, sync::Arc};
type Auth = Arc<BetterAuth<TestSchema>>;
struct SessionFailure;
#[async_trait::async_trait]
impl alibi::seaorm::DatabaseHooks<TestSchema, crate::backend::Backend> for SessionFailure {
    async fn before_create_session(
        &self,
        _session: &mut alibi::CreateSession,
        context: &crate::backend::HookContext<'_>,
    ) -> AuthResult<alibi::seaorm::HookControl> {
        if let Some(request) = context
            .request
            .as_ref()
            .filter(|request| request.path.ends_with("/two-factor/verify-totp"))
        {
            if let Some(failure) = request.headers.get("x-two-factor-session") {
                if failure == "cancel" {
                    return Ok(alibi::seaorm::HookControl::Cancel);
                }
                return Err(alibi::AuthError::forbidden(
                    "session creation cancelled by database hook",
                ));
            }
        }
        Ok(alibi::seaorm::HookControl::Continue)
    }
}

pub(crate) async fn router(
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
        "two-factor-totp-fraction",
        "two-factor-totp-negative-period",
        "two-factor-totp-infinite-period",
        "two-factor-totp-negative-infinite-period",
        "two-factor-totp-large-period",
        "two-factor-totp-nan",
        "two-factor-totp-invalid-digits",
        "two-factor-totp-infinite-digits",
        "two-factor-totp-tiny-period",
    ] {
        let raw: (f64, f64) = match name {
            "two-factor-totp-fraction" => (3.5, 30.5),
            "two-factor-totp-negative-period" => (6.0, -30.0),
            "two-factor-totp-infinite-period" => (6.0, f64::INFINITY),
            "two-factor-totp-negative-infinite-period" => (6.0, -f64::INFINITY),
            "two-factor-totp-large-period" => (6.0, 1e30),
            "two-factor-totp-nan" => (f64::NAN, f64::NAN),
            "two-factor-totp-invalid-digits" => (-1.0, 30.0),
            "two-factor-totp-infinite-digits" => (f64::INFINITY, 30.0),
            "two-factor-totp-tiny-period" => (6.0, f64::from_bits(1)),
            _ => (0.0, 0.0),
        };
        let numeric = !matches!(
            name,
            "two-factor-totp-default"
                | "two-factor-totp-config"
                | "two-factor-totp-zero"
                | "two-factor-totp-disabled"
        );
        let configured = name == "two-factor-totp-config";
        let zero = name == "two-factor-totp-zero";
        let plugin = TwoFactorPlugin::with_config(TwoFactorConfig {
            issuer: Some("Enrollment Issuer".to_owned()),
            totp_issuer: configured.then(|| "Authenticator Issuer".to_owned()),
            skip_verification_on_enable: numeric && name != "two-factor-totp-fraction",
            totp_digits: if numeric {
                raw.0
            } else if zero {
                0.0
            } else if configured {
                8.0
            } else {
                6.0
            },
            totp_period: if numeric {
                raw.1
            } else if zero {
                0.0
            } else if configured {
                45.0
            } else {
                30.0
            },
            totp_disabled: name == "two-factor-totp-disabled",
            ..Default::default()
        });
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut config = base.clone().base_path(&path);
        config.app_name = "Fixture Auth".to_owned();
        let store = crate::backend::store::<TestSchema>(config.clone(), database.clone());
        let store = if name == "two-factor-totp-fraction" {
            store.with_hooks(vec![Arc::new(SessionFailure)])
        } else {
            store
        };
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(store)
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
