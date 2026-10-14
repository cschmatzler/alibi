//! SSO lifecycle hooks around ordinary sign-out and social callback completion.
use super::{
    AuthContext, AuthResult, AuthSchema, AuthUser, EndpointCall, EndpointResponse, SsoPlugin,
};
#[async_trait::async_trait]
impl<S: AuthSchema> alibi_core::endpoint::EndpointHook<S> for SsoPlugin {
    fn matches_before(&self, call: &EndpointCall, _: &AuthContext<S>) -> AuthResult<bool> {
        Ok(call.path() == Some("/sign-out"))
    }
    async fn before(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<alibi_core::endpoint::BeforeEndpointAction>> {
        if self.config.saml_enable_single_logout {
            self.clear_saml_signout_tracking(call, ctx).await?;
        }
        Ok(None)
    }
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
        if let Some(completed) = call
            .extensions()
            .get::<crate::helpers::CompletedSession<S>>()
        {
            self.assign_social_domain_organization(completed.user.id().as_ref(), ctx)
                .await?;
        }
        Ok(response)
    }
}
impl SsoPlugin {
    pub(super) async fn assign_social_domain_organization<S: AuthSchema>(
        &self,
        user_id: &str,
        ctx: &AuthContext<S>,
    ) -> AuthResult<()> {
        if !self.config.domain_verification
            || self.config.organization_provisioning.disabled
            || ctx
                .get_metadata(crate::organization::METADATA_ENABLED)
                .is_none()
        {
            return Ok(());
        }
        let Some(user) = ctx.database.get_user_by_id_record(user_id).await? else {
            return Ok(());
        };
        if !user.email_verified() {
            return Ok(());
        }
        let Some(domain) = user.email().and_then(super::domains::email_domain) else {
            return Ok(());
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
            return Ok(());
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
        Ok(())
    }
}
