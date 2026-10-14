//! Application-configured provider selection without creating adapter rows.
use super::{
    AuthContext, AuthResult, AuthSchema, SsoDefaultProvider, SsoPlugin, SsoProvider, Value,
};
impl SsoPlugin {
    pub(super) fn configured_provider(
        &self,
        id: Option<&str>,
        domain: Option<&str>,
    ) -> AuthResult<Option<SsoProvider>> {
        self.config
            .default_providers
            .iter()
            .find(|provider| {
                id.map_or_else(
                    || {
                        domain
                            .is_some_and(|domain| super::domains::matches(domain, &provider.domain))
                    },
                    |id| provider.provider_id == id,
                )
            })
            .map(|provider| self.runtime_provider(provider))
            .transpose()
    }
    fn runtime_provider(&self, provider: &SsoDefaultProvider) -> AuthResult<SsoProvider> {
        let issuer = provider
            .saml_config
            .as_ref()
            .and_then(|config| config.get("issuer"))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .or_else(|| {
                provider
                    .oidc_config
                    .as_ref()
                    .and_then(|config| config.get("issuer"))
                    .and_then(Value::as_str)
            })
            .unwrap_or_default();
        Ok(SsoProvider {
            id: String::new(),
            provider_id: provider.provider_id.clone(),
            domain: provider.domain.clone(),
            issuer: issuer.into(),
            user_id: Some("default".into()),
            organization_id: None,
            oidc_config: provider
                .oidc_config
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?,
            saml_config: provider
                .saml_config
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?,
            domain_verified: self.config.domain_verification.then_some(true),
        })
    }
    pub(super) async fn find_provider<S: AuthSchema>(
        &self,
        id: &str,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<SsoProvider>> {
        if let Some(provider) = self.configured_provider(Some(id), None)? {
            return Ok(Some(provider));
        }
        ctx.database.get_sso_provider(id).await
    }
}
