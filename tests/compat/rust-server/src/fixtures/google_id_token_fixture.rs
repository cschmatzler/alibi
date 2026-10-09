//! Real default Google verification with application-owned local key transport.
use crate::TestSchema;
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::oauth::{OAuthIdTokenVerifier, OAuthPlugin, OAuthProvider};
use alibi::plugins::{
    AdminPlugin, EmailPasswordPlugin, EmailVerificationPlugin, OrganizationPlugin,
    SessionManagementPlugin, TwoFactorPlugin,
};
use alibi::{AuthBuilder, AuthConfig, AuthResult};
use alibi::seaorm::DatabaseConnection;
use async_trait::async_trait;
use axum::Router;
use std::sync::Arc;
struct ApplicationVerifier(bool);
#[async_trait]
impl OAuthIdTokenVerifier for ApplicationVerifier {
    async fn verify_id_token(&self, _: &str, _: Option<&str>) -> Result<bool, String> {
        Ok(self.0)
    }
}
pub(crate) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<Router> {
    let mut router = Router::new();
    for name in [
        "google-id-default",
        "google-granted-scopes-enabled",
        "google-granted-scopes-disabled",
        "google-id-array",
        "google-id-empty-array",
        "google-id-domain",
        "google-id-domain-any",
        "google-id-disabled",
        "google-id-override",
        "google-id-no-signup",
        "google-id-no-implicit-signup",
    ] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let configured = config.clone().base_path(&path);
        let mut provider =
            OAuthProvider::google("google-default-client", "local-google-default-secret");
        if name == "google-granted-scopes-disabled" {
            provider
                .authorization_params
                .retain(|(key, _)| key != "include_granted_scopes");
        }
        if name == "google-id-array" {
            provider = provider.with_client_ids(vec![
                "google-default-client".into(),
                "google-secondary-client".into(),
            ]);
        }
        if name == "google-id-empty-array" {
            provider = provider.with_client_ids(Vec::new());
        }
        if name == "google-id-domain" {
            provider = provider.with_hosted_domain("workspace.fixture.test");
        }
        if name == "google-id-domain-any" {
            provider = provider.with_hosted_domain("*");
        }
        // Select only a key transport, preserving the factory's actual verifier policy.
        if let Some(policy) = provider.id_token.as_mut() {
            policy.jwks_source = crate::fixtures::one_tap_fixture::local_keys(&config.base_url);
        }
        if name == "google-id-no-signup" {
            // Factory options are still authoritative for ID-token signup even
            // where the code-grant factory policy does not honor those options.
            provider.authorization = Some(alibi::plugins::oauth::OAuthAuthorizationPolicy {
                disable_sign_up_option: Some(true),
                honor_factory_options: false,
                ..Default::default()
            });
        }
        provider.disable_implicit_sign_up = name == "google-id-no-implicit-signup";
        provider.disable_id_token_sign_in = name == "google-id-disabled";
        if name == "google-id-disabled" {
            provider.verify_id_token = Some(Arc::new(ApplicationVerifier(true)));
        }
        if name == "google-id-override" {
            provider.verify_id_token = Some(Arc::new(ApplicationVerifier(false)));
        }
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(configured.clone())
                .store(crate::backend::store::<TestSchema>(
                    configured,
                    database.clone(),
                ))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new())
                .plugin(SessionManagementPlugin::new())
                .plugin(AdminPlugin::new())
                .plugin(OrganizationPlugin::new())
                .plugin(TwoFactorPlugin::new())
                .plugin(EmailVerificationPlugin::new())
                .plugin(OAuthPlugin::new().add_provider("google", provider))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    Ok(router)
}
