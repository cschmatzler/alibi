//! Actual immutable admin role policy configurations.
use crate::TestSchema;
use axum::Router;
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::{
    AdminConfig, AdminPlugin, EmailPasswordPlugin, RolePermissions, SessionManagementPlugin,
    TwoFactorPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, AuthResult};
use better_auth_seaorm::{DatabaseConnection, SeaOrmStore};
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
    ] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let config = config.clone().base_path(&path);
        let roles = if name == "admin-empty-role" {
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
                        "admin-exact-role" => "user, admin",
                        "admin-empty-role" => "",
                        _ => "admin",
                    }
                    .into(),
                    roles: match name {
                        "admin-empty-role" => Some(roles),
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
    Ok(router)
}
