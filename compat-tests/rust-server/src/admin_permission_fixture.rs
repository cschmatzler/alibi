//! Actual immutable admin role policy configurations.
use crate::TestSchema;
use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
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
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc};

struct ApplicationDateErrors;
#[async_trait::async_trait]
impl better_auth_seaorm::SeaOrmHooks<TestSchema> for ApplicationDateErrors {
    async fn before_update_user(
        &self,
        _id: &str,
        update: &mut better_auth_core::UpdateUser,
        _context: &better_auth_seaorm::SeaOrmHookContext<'_>,
    ) -> AuthResult<better_auth_seaorm::HookControl> {
        if update.banned == Some(true) {
            return Err(better_auth_core::AuthError::Upstream {
                status: 403,
                code: "APPLICATION_BAN_REFUSED",
                message: "Invalid Date",
            });
        }
        Ok(better_auth_seaorm::HookControl::Continue)
    }
    async fn before_create_session(
        &self,
        session: &mut better_auth_core::CreateSession,
        _context: &better_auth_seaorm::SeaOrmHookContext<'_>,
    ) -> AuthResult<better_auth_seaorm::HookControl> {
        if session.impersonated_by.is_some() {
            return Err(better_auth_core::AuthError::Upstream {
                status: 500,
                code: "APPLICATION_SESSION_REFUSED",
                message: "Invalid Date",
            });
        }
        Ok(better_auth_seaorm::HookControl::Continue)
    }
}

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
        "admin-duration-zero",
        "admin-duration-fractional",
        "admin-duration-negative",
        "admin-duration-invalid",
        "admin-duration-nan",
        "admin-duration-hook-error",
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
        let store = SeaOrmStore::<TestSchema>::new(config.clone(), database.clone());
        let store = if name == "admin-duration-hook-error" {
            store.hook(ApplicationDateErrors)
        } else {
            store
        };
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(store)
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
                    default_ban_reason: match name {
                        "admin-duration-zero" => Some(String::new()),
                        "admin-duration-fractional" => Some("configured reason".into()),
                        _ => None,
                    },
                    default_ban_expires_in: match name {
                        "admin-duration-zero" => Some(0.0),
                        "admin-duration-fractional" => Some(300.875),
                        "admin-duration-negative" => Some(-60.25),
                        "admin-duration-invalid" => Some(f64::INFINITY),
                        "admin-duration-nan" => Some(f64::NAN),
                        _ => None,
                    },
                    impersonation_session_duration: match name {
                        "admin-duration-zero" => Some(0.0),
                        "admin-duration-fractional" => Some(120.75),
                        "admin-duration-negative" => Some(-10.5),
                        "admin-duration-invalid" => Some(f64::INFINITY),
                        "admin-duration-nan" => Some(f64::NAN),
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
        json!({"user":{"id":user.id,"email":user.email,"name":user.name,"role":user.role,"banned":user.banned,"banReason":user.ban_reason,"banExpires":user.ban_expires,"createdAt":user.created_at,"updatedAt":user.updated_at},"accounts":accounts.into_iter().map(|a|json!({"id":a.id,"userId":a.user_id,"providerId":a.provider_id,"accountId":a.account_id})).collect::<Vec<_>>(),"sessions":sessions.into_iter().map(|s|json!({"id":s.id,"userId":s.user_id,"token":s.token,"impersonatedBy":s.impersonated_by,"createdAt":s.created_at,"expiresAt":s.expires_at})).collect::<Vec<_>>()}),
    ))
}
