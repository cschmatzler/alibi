//! Organization membership policies for SSO provider-bound identities.
#[derive(Clone, Debug)]
pub struct SsoOrganizationProvisioning {
    pub disabled: bool,
    pub default_role: String,
    pub get_role: Option<SsoRoleResolver>,
}
impl Default for SsoOrganizationProvisioning {
    fn default() -> Self {
        Self {
            disabled: false,
            default_role: "member".into(),
            get_role: None,
        }
    }
}

impl super::SsoPlugin {
    pub(super) async fn provision_organization<S: alibi_core::AuthSchema>(
        &self,
        user: &alibi_core::wire::UserView,
        provider: &alibi_core::store::SsoProvider,
        ctx: &alibi_core::AuthContext<S>,
        profile: &serde_json::Value,
        token: Option<&crate::oauth::OAuthTokenSet>,
    ) -> alibi_core::AuthResult<()> {
        if self.config.organization_provisioning.disabled
            || ctx
                .get_metadata(crate::organization::METADATA_ENABLED)
                .is_none()
        {
            return Ok(());
        }
        let Some(organization_id) = provider
            .organization_id
            .as_deref()
            .filter(|id| !id.is_empty())
        else {
            return Ok(());
        };
        if ctx
            .database
            .get_member(organization_id, &user.id)
            .await?
            .is_some()
        {
            return Ok(());
        }
        if let Some(email) = user.email.as_deref()
            && ctx
                .database
                .get_pending_invitation(organization_id, &email.to_lowercase())
                .await?
                .is_some()
        {
            return Ok(());
        }
        let role = if let Some(resolver) = &self.config.organization_provisioning.get_role {
            resolver
                .0
                .get_role(super::SsoProvisioningData {
                    user: user.clone(),
                    user_info: profile.clone(),
                    token: token.cloned(),
                    provider: provider.clone(),
                })
                .await?
        } else {
            let role = &self.config.organization_provisioning.default_role;
            if role.is_empty() {
                "member".into()
            } else {
                role.clone()
            }
        };
        _ = ctx
            .database
            .create_member(alibi_core::CreateMember::new(
                organization_id,
                &user.id,
                role,
            ))
            .await?;
        Ok(())
    }
}

/// An application role policy sees the authenticated user and protocol profile.
#[async_trait::async_trait]
pub trait SsoOrganizationRoleResolver: Send + Sync {
    async fn get_role(&self, data: super::SsoProvisioningData) -> alibi_core::AuthResult<String>;
}
#[derive(Clone)]
pub struct SsoRoleResolver(pub std::sync::Arc<dyn SsoOrganizationRoleResolver>);
impl std::fmt::Debug for SsoRoleResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SsoRoleResolver")
            .finish_non_exhaustive()
    }
}
