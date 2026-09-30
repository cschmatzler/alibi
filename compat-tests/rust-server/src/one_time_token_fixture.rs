use std::{collections::HashMap, sync::Arc};

use axum::{
    extract::Query,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::one_time_token::{
    OneTimeTokenConfig, OneTimeTokenPlugin, OneTimeTokenSession, OneTimeTokenStorage,
};
use better_auth::plugins::{
    AccountManagementPlugin, AdminPlugin, ApiKeyPlugin, DeviceAuthorizationPlugin,
    EmailPasswordPlugin, EmailVerificationPlugin, OrganizationPlugin, PasskeyPlugin,
    PasswordManagementPlugin, SessionManagementPlugin, TwoFactorPlugin, UserManagementPlugin,
};
use better_auth::{
    AuthBuilder, AuthConfig, AuthError, AuthRequest, AuthResult, BetterAuth, HttpMethod,
};
use better_auth_seaorm::sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set,
};
use better_auth_seaorm::store::entities::{account, session, two_factor, user, verification};
use better_auth_seaorm::{DatabaseConnection, SeaOrmStore};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::TestSchema;

type Auth = Arc<BetterAuth<TestSchema>>;
const PROFILES: &[&str] = &[
    "ott-default",
    "ott-hashed",
    "ott-no-cookie",
    "ott-server-header",
];

#[derive(Deserialize)]
struct ServerOperation {
    operation: String,
    profile: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserSelector {
    user_id: String,
}
#[derive(Deserialize)]
struct VerificationSelector {
    identifier: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerificationOperation {
    action: String,
    identifier: String,
    value: Option<String>,
    expires_at: DateTime<Utc>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExpireSession {
    token: String,
    expires_at: DateTime<Utc>,
}

fn failure(error: impl std::fmt::Display) -> axum::response::Response {
    tracing::error!(%error,"one-time-token fixture operation failed");
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
        let ott = OneTimeTokenPlugin::with_config(OneTimeTokenConfig {
            storage: if *name == "ott-hashed" {
                OneTimeTokenStorage::Hashed
            } else {
                OneTimeTokenStorage::Plain
            },
            disable_client_request: *name == "ott-server-header",
            disable_set_session_cookie: *name == "ott-no-cookie",
            set_ott_header_on_new_session: *name == "ott-server-header",
            ..Default::default()
        });
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
                .plugin(ott.clone())
                .build()
                .await?,
        );
        let routes: Router<Auth> = auth.clone().axum_router().with_state(auth.clone());
        router = router.nest(&path, routes);
        let _ = profiles.insert((*name).to_owned(), (auth, ott));
    }
    let profiles = Arc::new(profiles);
    router = router.route(
        "/__test/one-time-token",
        post(
            move |headers: HeaderMap, Json(body): Json<ServerOperation>| {
                let profiles = profiles.clone();
                async move {
                    let operation = async {
                        if body.operation != "generate" {
                            return Err(AuthError::bad_request("invalid server operation"));
                        }
                        let (auth, ott) = profiles
                            .get(body.profile.as_deref().unwrap_or("ott-default"))
                            .ok_or_else(|| AuthError::bad_request("unknown fixture profile"))?;
                        let mut request =
                            AuthRequest::new(HttpMethod::Post, "/__test/one-time-token");
                        for (name, value) in &headers {
                            if let Ok(value) = value.to_str() {
                                let _ = request.headers.insert(name.as_str(), value);
                            }
                        }
                        let (user, session) = auth
                            .context()
                            .session_without_refresh(&request)
                            .await?
                            .ok_or(AuthError::Unauthenticated)?;
                        let token = ott
                            .generate_for_session(
                                &OneTimeTokenSession {
                                    user: auth.context().user_view(&user),
                                    session: auth.context().session_view(&session),
                                },
                                Some(&request),
                                auth.context(),
                            )
                            .await?;
                        Ok(json!({"token":token}))
                    }
                    .await;
                    match operation {
                        Ok(value) => Json(value).into_response(),
                        Err(error) => failure(error),
                    }
                }
            },
        ),
    );
    let state_db = database.clone();
    router=router.route("/__test/user-state",get(move |Query(selector):Query<UserSelector>| {
        let database=state_db.clone();
        async move {
            let operation=async {
                let user=user::Entity::find_by_id(selector.user_id.clone()).one(&database).await?;
                let Some(user)=user else { return Ok::<_,better_auth_seaorm::sea_orm::DbErr>(Value::Null); };
                let accounts=account::Entity::find().filter(account::Column::UserId.eq(&selector.user_id)).order_by_asc(account::Column::ProviderId).order_by_asc(account::Column::AccountId).all(&database).await?;
                let sessions=session::Entity::find().filter(session::Column::UserId.eq(&selector.user_id)).order_by_asc(session::Column::CreatedAt).all(&database).await?;
                let two_factor_exists=two_factor::Entity::find().filter(two_factor::Column::UserId.eq(&selector.user_id)).one(&database).await?.is_some();
                Ok(json!({"user":{"id":user.id,"email":user.email,"emailVerified":user.email_verified,"twoFactorEnabled":user.two_factor_enabled},
                    "accounts":accounts.into_iter().map(|row|json!({"id":row.id,"userId":row.user_id,"accountId":row.account_id,"providerId":row.provider_id})).collect::<Vec<_>>(),
                    "sessions":sessions.into_iter().map(|row|json!({"id":row.id,"userId":row.user_id,"token":row.token,"expiresAt":row.expires_at})).collect::<Vec<_>>(),"twoFactorExists":two_factor_exists}))
            }.await;
            match operation { Ok(value)=>Json(value).into_response(),Err(error)=>failure(error) }
        }
    }));
    let verification_db = database.clone();
    router=router.route("/__test/verification-state",get(move |Query(selector):Query<VerificationSelector>| {
        let database=verification_db.clone();
        async move {
            match verification::Entity::find().filter(verification::Column::Identifier.eq(selector.identifier)).order_by_desc(verification::Column::CreatedAt).all(&database).await {
                Ok(rows)=>Json(json!(rows.into_iter().map(|row|json!({"id":row.id,"identifier":row.identifier,"value":row.value,"expiresAt":row.expires_at,"createdAt":row.created_at,"updatedAt":row.updated_at})).collect::<Vec<_>>())).into_response(),
                Err(error)=>failure(error),
            }
        }
    }));
    let mutation_db = database.clone();
    router = router.route(
        "/__test/verification-state",
        post(move |Json(body): Json<VerificationOperation>| {
            let database = mutation_db.clone();
            async move {
                let operation = async {
                    if body.action == "seed" {
                        let _ = verification::ActiveModel {
                            id: Set(format!(
                                "fixture-{}-{}",
                                Utc::now().timestamp_nanos_opt().unwrap_or_default(),
                                body.identifier
                            )),
                            identifier: Set(body.identifier),
                            value: Set(body
                                .value
                                .ok_or_else(|| AuthError::bad_request("value is required"))?),
                            expires_at: Set(body.expires_at),
                            created_at: Set(Utc::now()),
                            updated_at: Set(Utc::now()),
                        }
                        .insert(&database)
                        .await
                        .map_err(|error| AuthError::internal(error.to_string()))?;
                    } else if body.action == "expire" {
                        let _ = verification::Entity::update_many()
                            .filter(verification::Column::Identifier.eq(body.identifier))
                            .col_expr(
                                verification::Column::ExpiresAt,
                                better_auth_seaorm::sea_orm::sea_query::Expr::value(
                                    body.expires_at,
                                ),
                            )
                            .exec(&database)
                            .await
                            .map_err(|error| AuthError::internal(error.to_string()))?;
                    } else {
                        return Err(AuthError::bad_request("unknown action"));
                    }
                    Ok(json!({"status":true}))
                }
                .await;
                match operation {
                    Ok(value) => Json(value).into_response(),
                    Err(error) => failure(error),
                }
            }
        }),
    );
    router = router.route(
        "/__test/expire-session",
        post(move |Json(body): Json<ExpireSession>| {
            let database = database.clone();
            async move {
                match session::Entity::update_many()
                    .filter(session::Column::Token.eq(body.token))
                    .col_expr(
                        session::Column::ExpiresAt,
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
