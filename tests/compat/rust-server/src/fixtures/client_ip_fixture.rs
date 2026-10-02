//! Actual configured IP policies and physical session observations.
use crate::TestSchema;
use axum::{Json, Router, routing::get};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::{
    AdminPlugin, ApiKeyPlugin, DeviceAuthorizationPlugin, EmailPasswordPlugin,
    EmailVerificationPlugin, PasskeyPlugin, SessionManagementPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, AuthResult, BetterAuth};
use better_auth_core::{AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthRoute};
use better_auth_seaorm::sea_orm::{EntityTrait, QueryOrder};
use better_auth_seaorm::store::entities::session;
use better_auth_seaorm::{DatabaseConnection, SeaOrmStore};
use chrono::SecondsFormat;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

struct ApplicationEndpoint;
#[async_trait::async_trait]
impl AuthPlugin<TestSchema> for ApplicationEndpoint {
    fn name(&self) -> &'static str {
        "client-ip-application"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/client-ip-rate-check", "rate_check"),
            AuthRoute::get("/client-ip-rate-empty", "rate_empty"),
            AuthRoute::get("/client-ip-rate-duplicate", "rate_duplicate"),
        ]
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        _: &AuthContext<TestSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        if matches!(
            req.path(),
            "/client-ip-rate-check" | "/client-ip-rate-empty" | "/client-ip-rate-duplicate"
        ) {
            Ok(Some(AuthResponse::json(200, &json!({"ok":true}))?))
        } else {
            Ok(None)
        }
    }
}

pub(crate) async fn router(
    base: &AuthConfig,
    db: DatabaseConnection,
    sender: Arc<dyn better_auth::plugins::email_verification::SendVerificationEmail>,
) -> AuthResult<Router<Arc<BetterAuth<TestSchema>>>> {
    let mut router = Router::new();
    for name in [
        "default",
        "ordered",
        "trusted",
        "v6proxy",
        "mixed",
        "invalid",
        "full",
        "excess",
        "zero",
        "negative",
        "fractional",
        "nan",
        "disabled",
        "empty",
    ] {
        let path = format!("/__test/profiles/client-ip-{name}/api/auth");
        let mut config = base.clone().base_path(&path);
        if name == "ordered" {
            config.advanced.ip_address.headers =
                vec!["X-Client-IP".into(), "x-forwarded-for".into()];
        }
        if name == "empty" {
            config.advanced.ip_address.headers.clear();
        }
        config.advanced.ip_address.disable_ip_tracking = name == "disabled";
        config.advanced.ip_address.trusted_proxies = match name {
            "trusted" => vec!["10.0.0.0/8", "192.0.2.9"],
            "v6proxy" => vec!["2001:db8:ffff::/48"],
            "mixed" => vec!["bad-address", "10.0.0.0/8", "::ffff:192.0.2.9/32"],
            "invalid" => vec![
                "10.0.0.1/33",
                "10.0.0.1/-1",
                "10.0.0.1/8x",
                "::ffff:192.0.2.9/128",
            ],
            _ => vec![],
        }
        .into_iter()
        .map(str::to_owned)
        .collect();
        config.advanced.ip_address.ipv6_subnet = match name {
            "full" => 128.0,
            "excess" => 129.0,
            "zero" => 0.0,
            "negative" => -1.0,
            "fractional" => 65.9,
            "nan" => f64::NAN,
            _ => 64.0,
        };
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(SeaOrmStore::<TestSchema>::new(config, db.clone()))
                .rate_limit(
                    RateLimitConfig::new()
                        .default_limit(Duration::from_secs(60), 10000)
                        .endpoint("/sign-up/email", Duration::from_secs(60), 10000)
                        .endpoint("/sign-in/email", Duration::from_secs(60), 10000)
                        .endpoint("/client-ip-rate-check", Duration::from_secs(60), 2)
                        .endpoint("/client-ip-rate-empty", Duration::from_secs(60), 2)
                        .endpoint("/client-ip-rate-duplicate", Duration::from_secs(60), 2),
                )
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(SessionManagementPlugin::new())
                .plugin(DeviceAuthorizationPlugin::new())
                .plugin(PasskeyPlugin::new())
                .plugin(AdminPlugin::new())
                .plugin(
                    ApiKeyPlugin::builder()
                        .enable_session_for_api_keys(true)
                        .build(),
                )
                .plugin(
                    EmailVerificationPlugin::new()
                        .auto_sign_in_after_verification(true)
                        .custom_send_verification_email(sender.clone()),
                )
                .plugin(ApplicationEndpoint)
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    Ok(router.route(
        "/__test/client-ip/sessions",
        get(move || {
            let db = db.clone();
            async move {
                let rows = session::Entity::find()
                    .order_by_asc(session::Column::CreatedAt)
                    .order_by_asc(session::Column::Id)
                    .all(&db)
                    .await
                    .map_err(|error| {
                        (
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                            error.to_string(),
                        )
                    })?;
                Ok::<_, (axum::http::StatusCode, String)>(Json(rows.into_iter().map(|row| json!({
                "id":row.id,"token":row.token,"userId":row.user_id,
                "expiresAt":row.expires_at.to_rfc3339_opts(SecondsFormat::Millis,true),
                "createdAt":row.created_at.to_rfc3339_opts(SecondsFormat::Millis,true),
                "updatedAt":row.updated_at.to_rfc3339_opts(SecondsFormat::Millis,true),
                "ipAddress":row.ip_address,"userAgent":row.user_agent,
            })).collect::<Vec<Value>>()))
            }
        }),
    ))
}
