//! Application provisioning after successful SSO account and session creation.
use alibi_core::{AuthResult, store::SsoProvider, wire::UserView};
use serde_json::Value;
use std::sync::Arc;

/// Successful SSO identity, protocol profile, and optional OIDC tokens.
#[derive(Clone, Debug)]
pub struct SsoProvisioningData {
    pub user: UserView,
    /// User provisioning receives mapped user info. Organization role policies receive
    /// mapped OIDC user info or raw SAML assertion attributes, matching Better Auth.
    pub user_info: Value,
    pub token: Option<crate::oauth::OAuthTokenSet>,
    pub provider: SsoProvider,
}
#[async_trait::async_trait]
pub trait SsoUserProvisioner: Send + Sync {
    async fn provision(&self, data: SsoProvisioningData) -> AuthResult<()>;
}
#[derive(Clone)]
pub struct SsoProvisioner(pub Arc<dyn SsoUserProvisioner>);
impl std::fmt::Debug for SsoProvisioner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SsoProvisioner")
            .finish_non_exhaustive()
    }
}

impl super::SsoPlugin {
    pub(super) async fn provision(
        &self,
        issued: &crate::oauth::handlers::ProcessOAuthUserResult,
        user: &crate::oauth::OAuthUserInfo,
        token: Option<&crate::oauth::OAuthTokenSet>,
        provider: &SsoProvider,
    ) -> AuthResult<()> {
        if (issued.is_register || self.config.provision_user_on_every_login)
            && let Some(provisioner) = &self.config.provision_user
        {
            provisioner
                .0
                .provision(SsoProvisioningData {
                    user: issued.user.clone(),
                    user_info: Value::Object(user.public_profile(true)),
                    token: token.cloned(),
                    provider: provider.clone(),
                })
                .await?;
        }
        Ok(())
    }
}
