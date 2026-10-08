//! Account linking policy fixtures, outside the public route inventory.

use crate::TestSchema;
use axum::Router;
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::oauth::OAuthPlugin;
use alibi::plugins::{AccountManagementPlugin, EmailPasswordPlugin, SessionManagementPlugin};
use alibi::{AuthBuilder, AuthConfig, AuthResult};
use alibi_seaorm::DatabaseConnection;
use std::sync::Arc;

pub(crate) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
    oauth: impl Fn() -> OAuthPlugin,
) -> AuthResult<Router> {
    let mut router = Router::new();
    for name in ["account-linking-different-emails"] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut settings = config.clone().base_path(&path);
        settings.account.account_linking.allow_different_emails = true;
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(settings.clone())
                .store(crate::backend::store::<TestSchema>(settings, database.clone()))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false).enable_signup(true))
                .plugin(SessionManagementPlugin::new())
                .plugin(AccountManagementPlugin::new())
                .plugin(oauth())
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    Ok(router)
}
