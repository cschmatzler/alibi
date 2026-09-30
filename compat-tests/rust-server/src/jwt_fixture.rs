use std::{collections::HashMap, sync::Arc};

use axum::{
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::jwt::{
    JwtAlgorithm, JwtAudience, JwtClaimsConfig, JwtExpiration, JwtPlugin, JwtPluginConfig,
    JwtSignOptions,
};
use better_auth::plugins::{
    AccountManagementPlugin, AdminPlugin, ApiKeyPlugin, DeviceAuthorizationPlugin,
    EmailPasswordPlugin, EmailVerificationPlugin, OrganizationPlugin, PasskeyPlugin,
    PasswordManagementPlugin, SessionManagementPlugin, TwoFactorPlugin, UserManagementPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult, BetterAuth};
use better_auth_seaorm::sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use better_auth_seaorm::store::entities::jwk;
use better_auth_seaorm::{DatabaseConnection, SeaOrmStore};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::TestSchema;

type Auth = Arc<BetterAuth<TestSchema>>;

const PROFILES: &[&str] = &[
    "jwt-default",
    "jwt-es256",
    "jwt-es512",
    "jwt-rs256",
    "jwt-ps256",
    "jwt-claims",
    "jwt-path-header",
    "jwt-plain-rotation",
];

#[derive(Deserialize)]
struct ServerOperation {
    operation: String,
    profile: Option<String>,
    payload: Option<Map<String, Value>>,
    token: Option<String>,
    issuer: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExpireKey {
    id: String,
    expires_at: DateTime<Utc>,
}

fn failure(error: impl std::fmt::Display) -> axum::response::Response {
    tracing::error!(%error, "JWT fixture operation failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"message":"Internal server error"})),
    )
        .into_response()
}

pub(super) async fn router(
    base: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<Router<Auth>> {
    let mut router = Router::new();
    let mut profiles = HashMap::new();
    for name in PROFILES {
        let mut config = JwtPluginConfig::default();
        config.key_pair.algorithm = match *name {
            "jwt-es256" => JwtAlgorithm::Es256,
            "jwt-es512" => JwtAlgorithm::Es512,
            "jwt-rs256" => JwtAlgorithm::Rs256,
            "jwt-ps256" => JwtAlgorithm::Ps256,
            _ => JwtAlgorithm::EdDsa,
        };
        if *name == "jwt-claims" {
            config.claims = JwtClaimsConfig {
                issuer: Some("fixture-issuer".to_owned()),
                audience: Some(JwtAudience::One("fixture-audience".to_owned())),
                expiration: JwtExpiration::After(Duration::seconds(60)),
            };
        }
        if *name == "jwt-path-header" {
            config.jwks_path = "/.well-known/jwks.json".to_owned();
            config.disable_setting_jwt_header = true;
        }
        if *name == "jwt-plain-rotation" {
            config.disable_private_key_encryption = true;
            config.rotation_interval = Some(Duration::hours(1));
            config.grace_period = Duration::hours(1);
        }
        let jwt = JwtPlugin::with_config(config);
        let path = format!("/__test/profiles/{name}/api/auth");
        let config = base.clone().base_path(&path);
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(SeaOrmStore::<TestSchema>::new(config, database.clone()))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_signup(true))
                .plugin(SessionManagementPlugin::new())
                .plugin(AccountManagementPlugin::new())
                .plugin(DeviceAuthorizationPlugin::new())
                .plugin(ApiKeyPlugin::builder().enable_metadata(true).build())
                .plugin(OrganizationPlugin::new())
                .plugin(AdminPlugin::new())
                .plugin(PasskeyPlugin::new())
                .plugin(PasswordManagementPlugin::new())
                .plugin(EmailVerificationPlugin::new())
                .plugin(
                    UserManagementPlugin::new()
                        .change_email_enabled(true)
                        .delete_user_enabled(true)
                        .require_delete_verification(false),
                )
                .plugin(TwoFactorPlugin::new())
                .plugin(jwt.clone())
                .build()
                .await?,
        );
        let routes: Router<Auth> = auth.clone().axum_router().with_state(auth.clone());
        router = router.nest(&path, routes);
        let _ = profiles.insert((*name).to_owned(), (auth, jwt));
    }
    let profiles = Arc::new(profiles);
    router = router.route("/__test/jwt", post(move |Json(body): Json<ServerOperation>| {
        let profiles = profiles.clone();
        async move {
            let operation = async {
                let (auth, jwt) = profiles.get(body.profile.as_deref().unwrap_or("jwt-default"))
                    .ok_or_else(|| AuthError::bad_request("unknown fixture profile"))?;
                match body.operation.as_str() {
                    "sign" => Ok(json!({"token":jwt.sign_jwt(body.payload.ok_or_else(|| AuthError::bad_request("payload is required"))?, &JwtSignOptions::default(), None, auth.context()).await?})),
                    "verify" => Ok(json!({"payload":jwt.verify_jwt(body.token.as_deref().ok_or_else(|| AuthError::bad_request("token is required"))?,body.issuer.as_deref(),None,auth.context()).await?})),
                    _ => Err(AuthError::bad_request("invalid server operation")),
                }
            }.await;
            match operation { Ok(value) => Json(value).into_response(), Err(error) => failure(error) }
        }
    }));
    let state_db = database.clone();
    router = router.route("/__test/jwks-state", get(move || {
        let database = state_db.clone();
        async move {
            match jwk::Entity::find().order_by_asc(jwk::Column::CreatedAt).all(&database).await {
                Ok(keys) => Json(json!(keys.into_iter().map(|key| json!({
                    "id":key.id,"publicKey":serde_json::from_str::<Value>(&key.public_key).unwrap_or(Value::Null),
                    "privateKeyEncrypted":serde_json::from_str::<Value>(&key.private_key).is_ok_and(|value|value.is_string()),
                    "createdAt":key.created_at,"expiresAt":key.expires_at,"alg":key.alg,"crv":key.crv,
                })).collect::<Vec<_>>())).into_response(),
                Err(error) => failure(error),
            }
        }
    }));
    router = router.route(
        "/__test/expire-jwk",
        post(move |Json(body): Json<ExpireKey>| {
            let database = database.clone();
            async move {
                match jwk::Entity::update_many()
                    .filter(jwk::Column::Id.eq(body.id))
                    .col_expr(
                        jwk::Column::ExpiresAt,
                        better_auth_seaorm::sea_orm::sea_query::Expr::value(body.expires_at),
                    )
                    .exec(&database)
                    .await
                {
                    Ok(_) => Json(json!({"status":true})).into_response(),
                    Err(error) => failure(error),
                }
            }
        }),
    );
    Ok(router)
}
