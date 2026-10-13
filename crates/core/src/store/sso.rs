//! Durable enterprise identity-provider configuration.
use crate::{AuthError, AuthResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SsoProvider {
    pub id: String,
    pub issuer: String,
    pub domain: String,
    pub provider_id: String,
    pub user_id: Option<String>,
    pub organization_id: Option<String>,
    pub oidc_config: Option<String>,
    pub saml_config: Option<String>,
    pub domain_verified: Option<bool>,
}
#[async_trait]
pub trait SsoProviderStore: Send + Sync {
    async fn list_sso_providers(&self) -> AuthResult<Vec<SsoProvider>> {
        Err(AuthError::config(
            "SSO persistence is not supported by this store",
        ))
    }
    async fn create_sso_provider(&self, _provider: SsoProvider) -> AuthResult<SsoProvider> {
        Err(AuthError::config(
            "SSO persistence is not supported by this store",
        ))
    }
    async fn get_sso_provider(&self, _provider_id: &str) -> AuthResult<Option<SsoProvider>> {
        Err(AuthError::config(
            "SSO persistence is not supported by this store",
        ))
    }
    async fn list_sso_providers_by_user(&self, _user_id: &str) -> AuthResult<Vec<SsoProvider>> {
        Err(AuthError::config(
            "SSO persistence is not supported by this store",
        ))
    }
}
