//! Real session issuance with deterministic application-owned token hooks.
use crate::TestSchema;
use axum::Router;
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::{
    ApiKeyConfig, ApiKeyPlugin, BearerConfig, BearerPlugin, EmailPasswordPlugin,
    MultiSessionPlugin, SessionManagementPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, AuthResult, prelude::CreateSession};
use better_auth_seaorm::{SeaOrmStore, sea_orm::DatabaseConnection};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct TokenHook(Arc<AtomicUsize>);
struct ApplicationExposure;
#[async_trait::async_trait]
impl better_auth_core::AuthPlugin<TestSchema> for ApplicationExposure {
    fn name(&self) -> &'static str {
        "application-exposure"
    }
    fn routes(&self) -> Vec<better_auth_core::AuthRoute> {
        Vec::new()
    }
    async fn on_request(
        &self,
        _: &better_auth_core::AuthRequest,
        _: &better_auth_core::AuthContext<TestSchema>,
    ) -> AuthResult<Option<better_auth_core::AuthResponse>> {
        Ok(None)
    }
    async fn after_request(
        &self,
        _: &better_auth_core::AuthRequest,
        _: &better_auth_core::AuthContext<TestSchema>,
        mut response: better_auth_core::AuthResponse,
    ) -> AuthResult<better_auth_core::AuthResponse> {
        drop(response.headers.insert(
            "access-control-expose-headers",
            "X-First, X-First, X-Second",
        ));
        Ok(response)
    }
}
#[async_trait::async_trait]
impl better_auth_seaorm::SeaOrmHooks<TestSchema> for TokenHook {
    async fn before_create_session(
        &self,
        session: &mut CreateSession,
        _: &better_auth_seaorm::SeaOrmHookContext<'_>,
    ) -> AuthResult<better_auth_seaorm::HookControl> {
        session.token = Some(format!(
            "bearer{:026}",
            self.0.fetch_add(1, Ordering::SeqCst) + 1
        ));
        Ok(better_auth_seaorm::HookControl::Continue)
    }
}
pub(crate) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
    counter: Arc<AtomicUsize>,
) -> AuthResult<Router> {
    let mut router = Router::new();
    for name in ["bearer-default", "bearer-signed", "bearer-composition"] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let config = config.clone().base_path(&path);
        let builder = AuthBuilder::<TestSchema>::new(config.clone())
            .store(
                SeaOrmStore::<TestSchema>::new(config, database.clone())
                    .hook(TokenHook(counter.clone())),
            )
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new().enable_username(false))
            .plugin(SessionManagementPlugin::new());
        let builder = if name == "bearer-signed" {
            builder.plugin(ApplicationExposure)
        } else {
            builder
        };
        let builder = builder.plugin(BearerPlugin::with_config(BearerConfig {
            require_signature: name == "bearer-signed",
        }));
        let builder = if name == "bearer-composition" {
            builder
                .plugin(MultiSessionPlugin::new())
                .plugin(ApiKeyPlugin::with_config(ApiKeyConfig {
                    enable_session_for_api_keys: true,
                    ..Default::default()
                }))
        } else {
            builder
        };
        let auth = Arc::new(builder.build().await?);
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    Ok(router)
}
