//! Actual managed-key runtimes sharing the ordinary fixture database.
use crate::TestSchema;
use async_trait::async_trait;
use axum::{Json, Router, extract::Query, response::IntoResponse, routing::get};
use better_auth::plugins::{
    EmailPasswordPlugin, TwoFactorConfig, TwoFactorPlugin,
    email_otp::{EmailOtpConfig, EmailOtpDelivery, EmailOtpPlugin, EmailOtpStorage, SendEmailOtp},
};
use better_auth::{
    AuthBuilder, AuthConfig, AuthResult, integrations::axum::AxumIntegration,
    middleware::RateLimitConfig,
};
use better_auth_core::ManagedSecrets;
use better_auth_seaorm::{DatabaseConnection, SeaOrmStore};
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::Mutex;
const OLD: &str = "managed-old-reader-key-at-least-32-characters";
const CURRENT: &str = "compat-test-only-key-not-real-minimum-32chars";
const LEGACY: &str = "managed-legacy-reader-key-at-least-32-characters";
struct TokenHook(Arc<AtomicUsize>);
#[async_trait]
impl better_auth_seaorm::SeaOrmHooks<TestSchema> for TokenHook {
    async fn before_create_session(
        &self,
        session: &mut better_auth_core::CreateSession,
        _: &better_auth_seaorm::SeaOrmHookContext<'_>,
    ) -> AuthResult<better_auth_seaorm::HookControl> {
        let counter = self.0.fetch_add(1, Ordering::SeqCst) + 1;
        session.token = Some(format!("managed{counter:025}"));
        Ok(better_auth_seaorm::HookControl::Continue)
    }
}
#[derive(Clone, Default)]
struct Delivery(Arc<Mutex<HashMap<String, String>>>);
#[async_trait]
impl SendEmailOtp for Delivery {
    async fn send(
        &self,
        delivery: &EmailOtpDelivery,
        _: &better_auth_core::CallbackContext,
    ) -> AuthResult<()> {
        _ = self
            .0
            .lock()
            .await
            .insert(delivery.email.clone(), delivery.otp.clone());
        Ok(())
    }
}
#[derive(serde::Deserialize)]
struct Lookup {
    email: String,
}
pub(super) async fn router(base: &AuthConfig, database: DatabaseConnection) -> AuthResult<Router> {
    let delivery = Delivery::default();
    let counter = Arc::new(AtomicUsize::new(0));
    let mut router = Router::new();
    for mode in ["old", "retained", "retired", "legacy", "bare"] {
        let path = format!("/__test/profiles/managed-{mode}/api/auth");
        let mut config = base.clone().base_path(&path);
        config.secret = LEGACY.into();
        config.managed_secrets = match mode {
            "old" => Some(ManagedSecrets::new(0, OLD)),
            "retained" => Some(ManagedSecrets::new(2, CURRENT).retain(0, OLD)),
            "retired" => Some(ManagedSecrets::new(2, CURRENT)),
            "legacy" => Some(
                ManagedSecrets::new(2, CURRENT)
                    .retain(0, OLD)
                    .legacy(LEGACY),
            ),
            _ => None,
        };
        let otp = EmailOtpConfig {
            storage: EmailOtpStorage::Encrypted,
            send_verification_otp: Some(Arc::new(delivery.clone())),
            ..Default::default()
        };
        let factor = TwoFactorConfig {
            skip_verification_on_enable: true,
            custom_backup_codes_generate: Some(Arc::new(|| {
                Ok(vec!["backup-one".into(), "backup-two".into()])
            })),
            ..Default::default()
        };
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(
                    SeaOrmStore::<TestSchema>::new(config, database.clone())
                        .hook(TokenHook(counter.clone())),
                )
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(EmailOtpPlugin::new(otp))
                .plugin(TwoFactorPlugin::with_config(factor))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    Ok(router.route(
        "/__test/managed-secrets/delivery",
        get(move |Query(input): Query<Lookup>| {
            let delivery = delivery.clone();
            async move {
                match delivery.0.lock().await.get(&input.email).cloned() {
                    Some(otp) => (
                        axum::http::StatusCode::OK,
                        Json(serde_json::json!({"otp":otp})),
                    )
                        .into_response(),
                    None => (
                        axum::http::StatusCode::NOT_FOUND,
                        Json(serde_json::json!({"error":"No delivery"})),
                    )
                        .into_response(),
                }
            }
        }),
    ))
}
