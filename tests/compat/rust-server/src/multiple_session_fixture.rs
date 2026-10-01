//! Equivalent configured session-token generation and multiple-session runtimes.
use crate::TestSchema;
use axum::Router;
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::{
    EmailPasswordPlugin, MultiSessionConfig, MultiSessionPlugin, SessionManagementPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, AuthResult, prelude::CreateSession};
use better_auth_seaorm::{SeaOrmStore, sea_orm::DatabaseConnection};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct TokenHook(Arc<AtomicUsize>);
#[async_trait::async_trait]
impl better_auth_seaorm::SeaOrmHooks<TestSchema> for TokenHook {
    async fn before_create_session(
        &self,
        session: &mut CreateSession,
        _: &better_auth_seaorm::SeaOrmHookContext<'_>,
    ) -> AuthResult<better_auth_seaorm::HookControl> {
        let count = self.0.fetch_add(1, Ordering::SeqCst) + 1;
        let rank = match count % 3 {
            1 => 3,
            2 => 1,
            _ => 2,
        };
        session.token = Some(format!("{rank:04}{count:028}"));
        Ok(better_auth_seaorm::HookControl::Continue)
    }
}
pub(super) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
    counter: Arc<AtomicUsize>,
) -> AuthResult<Router> {
    let mut router = Router::new();
    for name in ["multi-session", "multi-session-limited"] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let config = config.clone().base_path(&path);
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(
                    SeaOrmStore::<TestSchema>::new(config, database.clone())
                        .hook(TokenHook(counter.clone())),
                )
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(SessionManagementPlugin::new())
                .plugin(MultiSessionPlugin::with_config(MultiSessionConfig {
                    maximum_sessions: if name == "multi-session-limited" {
                        2
                    } else {
                        5
                    },
                }))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    Ok(router)
}
