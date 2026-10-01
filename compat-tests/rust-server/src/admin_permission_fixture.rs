//! Actual immutable admin role policy configurations.
use crate::TestSchema;
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use better_auth::__private_core::store::{AccountStore, SessionStore, UserStore};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::{
    AdminConfig, AdminPlugin, EmailPasswordPlugin, RolePermissions, SessionManagementPlugin,
    TwoFactorPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, AuthResult};
use better_auth_seaorm::{DatabaseConnection, SeaOrmStore};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc};

pub(super) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<Router> {
    let mut router = Router::new();
    for name in [
        "admin-standard",
        "admin-deny-all",
        "admin-exact-role",
        "admin-empty-role",
        "admin-role-manager",
        "admin-role-creator",
    ] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let config = config.clone().base_path(&path);
        let roles = if name.starts_with("admin-role-") {
            HashMap::from([
                (
                    "manager".into(),
                    RolePermissions::new().allow("user", ["get", "create", "set-role", "update"]),
                ),
                (
                    "creator".into(),
                    RolePermissions::new().allow("user", ["create"]),
                ),
                ("user".into(), RolePermissions::new().allow("user", ["get"])),
                ("".into(), RolePermissions::new().allow("user", ["get"])),
            ])
        } else if name == "admin-empty-role" {
            HashMap::from([("user".into(), RolePermissions::new().allow("user", ["get"]))])
        } else {
            HashMap::new()
        };
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(SeaOrmStore::<TestSchema>::new(config, database.clone()))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new())
                .plugin(SessionManagementPlugin::new())
                .plugin(TwoFactorPlugin::new())
                .plugin(AdminPlugin::with_config(AdminConfig {
                    default_role: match name {
                        "admin-role-manager" => "manager",
                        "admin-role-creator" => "creator",
                        "admin-exact-role" => "user, admin",
                        "admin-empty-role" => "",
                        _ => "admin",
                    }
                    .into(),
                    roles: match name {
                        "admin-empty-role" | "admin-role-manager" | "admin-role-creator" => {
                            Some(roles)
                        }
                        "admin-deny-all" => Some(HashMap::new()),
                        _ => None,
                    },
                    ..AdminConfig::default()
                }))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let state_store = Arc::new(SeaOrmStore::<TestSchema>::new(config.clone(), database));
    Ok(router.merge(
        Router::new()
            .route("/__test/admin-role-state", get(state))
            .with_state(state_store),
    ))
}

#[derive(Deserialize)]
struct StateQuery {
    email: String,
}
async fn state(
    State(store): State<Arc<SeaOrmStore<TestSchema>>>,
    Query(query): Query<StateQuery>,
) -> Result<Json<Value>, better_auth::AuthError> {
    let Some(user) = store.get_user_by_email(&query.email).await? else {
        return Ok(Json(json!({"user":null,"accounts":[],"sessions":[]})));
    };
    let mut accounts = store.get_user_accounts(&user.id).await?;
    accounts.sort_by(|a, b| {
        a.provider_id
            .cmp(&b.provider_id)
            .then(a.created_at.cmp(&b.created_at))
    });
    let mut sessions = store.get_user_sessions(&user.id).await?;
    sessions.sort_by_key(|session| session.created_at);
    Ok(Json(
        json!({"user":{"id":user.id,"email":user.email,"name":user.name,"role":user.role},"accounts":accounts.into_iter().map(|a|json!({"id":a.id,"userId":a.user_id,"providerId":a.provider_id,"accountId":a.account_id})).collect::<Vec<_>>(),"sessions":sessions.into_iter().map(|s|json!({"id":s.id,"userId":s.user_id,"token":s.token,"impersonatedBy":s.impersonated_by})).collect::<Vec<_>>()}),
    ))
}
