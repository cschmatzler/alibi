//! Verified-domain organization assignment after actual core social callback completion.
use super::{
    AuthContext, AuthResult, AuthSchema, AuthUser, EndpointCall, EndpointResponse, SsoPlugin,
};
#[async_trait::async_trait]
impl<S: AuthSchema> alibi_core::endpoint::EndpointHook<S> for SsoPlugin {
    fn matches_after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        _: &EndpointResponse,
    ) -> AuthResult<bool> {
        Ok(call
            .path()
            .is_some_and(|path| path.starts_with("/callback/")))
    }
    async fn after(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
        response: EndpointResponse,
    ) -> AuthResult<EndpointResponse> {
        if !self.config.domain_verification
            || self.config.organization_provisioning.disabled
            || ctx
                .get_metadata(crate::organization::METADATA_ENABLED)
                .is_none()
        {
            return Ok(response);
        }
        let Some(completed) = call
            .extensions()
            .get::<crate::helpers::CompletedSession<S>>()
        else {
            return Ok(response);
        };
        let Some(user) = ctx
            .database
            .get_user_by_id_record(completed.user.id().as_ref())
            .await?
        else {
            return Ok(response);
        };
        if !user.email_verified() {
            return Ok(response);
        }
        let Some(domain) = user.email().and_then(super::domains::email_domain) else {
            return Ok(response);
        };
        let mut providers: Vec<_> = ctx
            .database
            .list_sso_providers()
            .await?
            .into_iter()
            .filter(|provider| {
                provider.domain_verified == Some(true)
                    && provider
                        .organization_id
                        .as_deref()
                        .is_some_and(|id| !id.is_empty())
                    && super::domains::matches(&domain, &provider.domain)
            })
            .collect();
        let organizations: std::collections::HashSet<_> = providers
            .iter()
            .filter_map(|provider| provider.organization_id.as_deref())
            .collect();
        if organizations.len() != 1 {
            return Ok(response);
        }
        providers.sort_by(|left, right| left.provider_id.cmp(&right.provider_id));
        if let Some(provider) = providers.first() {
            self.provision_organization(
                &ctx.trusted_user_view(&user),
                provider,
                ctx,
                &serde_json::json!({}),
                None,
            )
            .await?;
        }
        Ok(response)
    }
}
