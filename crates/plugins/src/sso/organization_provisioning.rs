//! Organization membership policies for SSO provider-bound identities.
#[derive(Clone, Debug)]
pub struct SsoOrganizationProvisioning {
    pub disabled: bool,
    pub default_role: String,
}
impl Default for SsoOrganizationProvisioning {
    fn default() -> Self {
        Self {
            disabled: false,
            default_role: "member".into(),
        }
    }
}

impl super::SsoPlugin {
    pub(super) async fn provision_organization<S: alibi_core::AuthSchema>(
        &self,
        user: &alibi_core::wire::UserView,
        provider: &alibi_core::store::SsoProvider,
        ctx: &alibi_core::AuthContext<S>,
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
        let role = &self.config.organization_provisioning.default_role;
        _ = ctx
            .database
            .create_member(alibi_core::CreateMember::new(
                organization_id,
                &user.id,
                if role.is_empty() {
                    "member"
                } else {
                    role.as_str()
                },
            ))
            .await?;
        Ok(())
    }
}
