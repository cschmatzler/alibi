//! Plugin-registered adapter defaults apply to validated user creation through HTTP.
#![allow(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "tests assert independently specified wire fields and fixtures"
)]
use super::*;
use alibi_core::hooks::RequestHookContext;
use alibi_core::user_validation::{UserInfoValidator, UserValidationData, UserValidationRejection};
use alibi_core::{AuthContext, AuthInitContext, AuthPlugin, AuthResult, AuthRoute};
use async_trait::async_trait;

backend_tests!(registered_adapter_default_fills_omitted_user_fields);
postgres_tests!(registered_adapter_default_fills_omitted_user_fields);

struct DefaultImage;

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for DefaultImage {
    fn name(&self) -> &'static str {
        "default-image"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_init(&self, ctx: &mut AuthInitContext<S>) -> AuthResult<()> {
        ctx.register_user_creation_adapter_default(|mut user| {
            let _ = user.image.get_or_insert_with(|| "default.png".into());
            Ok(user)
        });
        Ok(())
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

struct AdmitAll;

#[async_trait]
impl UserInfoValidator for AdmitAll {
    async fn validate(
        &self,
        _: &mut UserValidationData,
        _: &RequestHookContext,
    ) -> AuthResult<Option<UserValidationRejection>> {
        Ok(None)
    }
}

async fn registered_adapter_default_fills_omitted_user_fields<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.user_validation = Some(Arc::new(AdmitAll));
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new())
        .plugin(DefaultImage)
        .build()
        .await?;
    let issued = signup(&auth, "defaults@example.test").await;
    assert_eq!(body(&issued)["user"]["image"], "default.png");
    assert_eq!(
        db.text(
            "SELECT image FROM users WHERE email = $1",
            &["defaults@example.test"]
        )
        .await?
        .as_deref(),
        Some("default.png")
    );
    Ok(())
}
