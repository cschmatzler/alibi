use super::{OAuthProviderConfig, OAuthProviderPlugin};
use alibi_core::CallbackContext;
use alibi_core::endpoint::EndpointError;
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct OAuthExtensionClientAuthentication {
    pub assertion_types: Option<Vec<String>>,
    pub strategy: Arc<dyn OAuthClientAuthenticationStrategy>,
}

pub struct OAuthClientAssertionInput<'a> {
    pub context: CallbackContext,
    pub options: &'a OAuthProviderConfig,
    pub assertion: &'a str,
    pub assertion_type: &'a str,
    pub client_id: Option<&'a str>,
    pub expected_audience: &'a str,
}

#[derive(Debug, Clone)]
pub struct OAuthVerifiedClientAssertion {
    pub client_id: String,
    pub confirmation: Option<Value>,
}

#[async_trait]
pub trait OAuthClientAuthenticationStrategy: Send + Sync + std::fmt::Debug {
    async fn authenticate(
        &self,
        input: OAuthClientAssertionInput<'_>,
    ) -> Result<OAuthVerifiedClientAssertion, EndpointError>;
}

impl OAuthProviderPlugin {
    pub(super) fn supported_auth_methods(&self, include_none: bool) -> Vec<String> {
        super::unique(
            include_none
                .then_some("none")
                .into_iter()
                .chain([
                    "client_secret_basic",
                    "client_secret_post",
                    "private_key_jwt",
                ])
                .map(str::to_owned)
                .chain(
                    self.config
                        .extensions
                        .iter()
                        .flat_map(|extension| extension.client_authentication.keys().cloned()),
                )
                .collect(),
        )
    }
    pub(super) fn is_extension_auth_method(&self, method: &str) -> bool {
        self.config
            .extensions
            .iter()
            .any(|extension| extension.client_authentication.contains_key(method))
    }
    pub(super) fn client_authentication_strategy(
        &self,
        assertion_type: &str,
    ) -> Option<(&str, &OAuthExtensionClientAuthentication)> {
        if assertion_type == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
            return None;
        }
        self.config
            .extensions
            .iter()
            .flat_map(|extension| &extension.client_authentication)
            .find(|(method, strategy)| {
                strategy.assertion_types.as_ref().map_or_else(
                    || method.as_str() == assertion_type,
                    |types| types.iter().any(|value| value == assertion_type),
                )
            })
            .map(|(method, strategy)| (method.as_str(), strategy))
    }
}
