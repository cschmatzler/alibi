//! Real session issuance with deterministic application-owned token hooks.
use crate::TestSchema;
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::{
    ApiKeyConfig, ApiKeyPlugin, BearerConfig, BearerPlugin, EmailPasswordPlugin,
    MultiSessionPlugin, SessionManagementPlugin,
};
use alibi::{AuthBuilder, AuthConfig, AuthResult, prelude::CreateSession};
use alibi_seaorm::sea_orm::DatabaseConnection;
use axum::Router;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct TokenHook(Arc<AtomicUsize>);
struct ApplicationExposure;
#[async_trait::async_trait]
impl alibi_core::AuthPlugin<TestSchema> for ApplicationExposure {
    fn name(&self) -> &'static str {
        "application-exposure"
    }
    fn routes(&self) -> Vec<alibi_core::AuthRoute> {
        Vec::new()
    }
    async fn on_request(
        &self,
        _: &alibi_core::AuthRequest,
        _: &alibi_core::AuthContext<TestSchema>,
    ) -> AuthResult<Option<alibi_core::AuthResponse>> {
        Ok(None)
    }
    async fn after_request(
        &self,
        _: &alibi_core::AuthRequest,
        _: &alibi_core::AuthContext<TestSchema>,
        mut response: alibi_core::AuthResponse,
    ) -> AuthResult<alibi_core::AuthResponse> {
        drop(response.headers.insert(
            "access-control-expose-headers",
            "X-First, X-First, X-Second",
        ));
        Ok(response)
    }
}
#[async_trait::async_trait]
impl alibi_seaorm::DatabaseHooks<TestSchema, crate::backend::Backend> for TokenHook {
    async fn before_create_session(
        &self,
        session: &mut CreateSession,
        _: &crate::backend::HookContext<'_>,
    ) -> AuthResult<alibi_seaorm::HookControl> {
        session.token = Some(format!(
            "bearer{:026}",
            self.0.fetch_add(1, Ordering::SeqCst) + 1
        ));
        Ok(alibi_seaorm::HookControl::Continue)
    }
}
pub(crate) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
    counter: Arc<AtomicUsize>,
) -> AuthResult<Router> {
    let mut router = Router::new();
    for name in [
        "bearer-default",
        "bearer-signed",
        "bearer-composition",
        "bearer-renamed-cookie",
        "bearer-secure-cookie",
    ] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut config = config.clone().base_path(&path);
        if name == "bearer-renamed-cookie" {
            config.advanced.cookies.insert(
                "session_token".into(),
                alibi_core::CookieOverride {
                    name: Some("configured-bearer-token".into()),
                    ..Default::default()
                },
            );
        }
        if name == "bearer-secure-cookie" {
            config.advanced.use_secure_cookies = Some(true);
            config.advanced.cookie_prefix = Some("bearer-app".into());
        }
        let builder = AuthBuilder::<TestSchema>::new(config.clone())
            .store(
                crate::backend::store::<TestSchema>(config, database.clone())
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
