use crate::store::{
    ApiKeyStore, DeviceCodeStore, InvitationCreateOptions, InvitationStore, JwkStore,
    ListOrganizationMembersParams, MemberPageQuery, MemberStore, OrganizationRoleStore,
    OrganizationStore, PasskeyStore, PluginStore, TeamStore, TwoFactorStore,
};
use crate::types::{
    AddTeamMemberResult, CreateOrganizationRole, OrganizationRole, OrganizationRoleSelector,
    UpdateOrganizationRole, UpdatePasskeyAuthentication,
};
use crate::{
    ApiKey, AuthResult, AuthSchema, ConsumeApiKeyResult, CreateApiKey, CreateDeviceCode,
    CreateInvitation, CreateJwk, CreateMember, CreateOrganization, CreatePasskey, CreateTeam,
    CreateTwoFactor, CreateWalletAddress, DeviceCode, Invitation, InvitationStatus, Jwk, Member,
    Organization, Passkey, Team, TeamMember, TwoFactor, UpdateApiKey, UpdateDeviceCode,
    UpdateOrganization, UpdateTeam, UpdateTwoFactor, WalletAddress, WalletAddressStore,
};
use async_trait::async_trait;
use std::sync::Arc;
impl<S: AuthSchema> Clone for PluginStore<S> {
    fn clone(&self) -> Self {
        Self {
            ephemeral_sessions: Arc::clone(&self.ephemeral_sessions),
            inner: Arc::clone(&self.inner),
            config: Arc::clone(&self.config),
            transforms: self.transforms.clone(),
            session_callbacks: self.session_callbacks.clone(),
            session_fields: self.session_fields.clone(),
            adapter_fields: self.adapter_fields.clone(),
            projection_context: Arc::clone(&self.projection_context),
        }
    }
}

#[async_trait]
impl<S: AuthSchema> OrganizationStore for PluginStore<S> {
    async fn create_organization(&self, org: CreateOrganization) -> AuthResult<Organization> {
        self.inner.create_organization(org).await
    }
    async fn get_organization_by_id(&self, id: &str) -> AuthResult<Option<Organization>> {
        self.inner.get_organization_by_id(id).await
    }
    async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<Organization>> {
        self.inner.get_organization_by_slug(slug).await
    }
    async fn list_organizations_by_ids(&self, ids: &[String]) -> AuthResult<Vec<Organization>> {
        self.inner.list_organizations_by_ids(ids).await
    }
    async fn update_organization(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Organization> {
        self.inner.update_organization(id, update).await
    }
    async fn patch_organization_if_present(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Option<Organization>> {
        self.inner.patch_organization_if_present(id, update).await
    }
    async fn update_organization_if_present(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Option<Organization>> {
        self.inner.update_organization_if_present(id, update).await
    }
    async fn delete_organization(&self, id: &str) -> AuthResult<()> {
        self.inner.delete_organization(id).await
    }
    async fn list_user_organizations(&self, user_id: &str) -> AuthResult<Vec<Organization>> {
        self.inner.list_user_organizations(user_id).await
    }
}

#[async_trait]
impl<S: AuthSchema> MemberStore for PluginStore<S> {
    async fn create_member(&self, member: CreateMember) -> AuthResult<Member> {
        self.inner.create_member(member).await
    }
    async fn get_member(&self, organization_id: &str, user_id: &str) -> AuthResult<Option<Member>> {
        self.inner.get_member(organization_id, user_id).await
    }
    async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<Member>> {
        self.inner.get_member_by_id(id).await
    }
    async fn update_member_role(&self, member_id: &str, role: &str) -> AuthResult<Member> {
        self.inner.update_member_role(member_id, role).await
    }
    async fn update_member_role_if_present(
        &self,
        member_id: &str,
        role: &str,
    ) -> AuthResult<Option<Member>> {
        self.inner
            .update_member_role_if_present(member_id, role)
            .await
    }
    async fn delete_member(&self, member_id: &str) -> AuthResult<()> {
        self.inner.delete_member(member_id).await
    }
    async fn delete_member_with_context(
        &self,
        member_id: &str,
        organization_id: &str,
        user_id: &str,
        remove_team_members: bool,
    ) -> AuthResult<()> {
        self.inner
            .delete_member_with_context(member_id, organization_id, user_id, remove_team_members)
            .await
    }
    async fn list_organization_members_page(
        &self,
        organization_id: &str,
        limit: usize,
    ) -> AuthResult<Vec<Member>> {
        self.inner
            .list_organization_members_page(organization_id, limit)
            .await
    }
    async fn list_organization_members(&self, org_id: &str) -> AuthResult<Vec<Member>> {
        self.inner.list_organization_members(org_id).await
    }
    async fn query_organization_members(
        &self,
        params: &ListOrganizationMembersParams,
    ) -> AuthResult<(Vec<Member>, usize)> {
        self.inner.query_organization_members(params).await
    }
    async fn query_organization_members_page(
        &self,
        params: &MemberPageQuery,
    ) -> AuthResult<(Vec<Member>, usize)> {
        self.inner.query_organization_members_page(params).await
    }
    async fn count_organization_members(&self, org_id: &str) -> AuthResult<i64> {
        self.inner.count_organization_members(org_id).await
    }
    async fn count_organization_owners(&self, org_id: &str) -> AuthResult<i64> {
        self.inner.count_organization_owners(org_id).await
    }
}

#[async_trait]
impl<S: AuthSchema> InvitationStore for PluginStore<S> {
    async fn create_invitation(&self, invitation: CreateInvitation) -> AuthResult<Invitation> {
        self.inner.create_invitation(invitation).await
    }
    async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<Invitation>> {
        self.inner.get_invitation_by_id(id).await
    }
    async fn create_invitation_with_options(
        &self,
        invitation: CreateInvitation,
        options: InvitationCreateOptions,
    ) -> AuthResult<Invitation> {
        self.inner
            .create_invitation_with_options(invitation, options)
            .await
    }
    async fn pending_invitation_page(
        &self,
        org_id: &str,
        email: Option<&str>,
    ) -> AuthResult<Vec<Invitation>> {
        self.inner.pending_invitation_page(org_id, email).await
    }
    async fn update_invitation_expiry(
        &self,
        id: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<Invitation> {
        self.inner.update_invitation_expiry(id, expires_at).await
    }
    async fn get_pending_invitation(
        &self,
        org_id: &str,
        email: &str,
    ) -> AuthResult<Option<Invitation>> {
        self.inner.get_pending_invitation(org_id, email).await
    }
    async fn update_invitation_status(
        &self,
        id: &str,
        status: InvitationStatus,
    ) -> AuthResult<Invitation> {
        self.inner.update_invitation_status(id, status).await
    }
    async fn update_invitation_status_if_status(
        &self,
        id: &str,
        expected: InvitationStatus,
        status: InvitationStatus,
    ) -> AuthResult<Option<Invitation>> {
        self.inner
            .update_invitation_status_if_status(id, expected, status)
            .await
    }
    async fn list_organization_invitations(&self, org_id: &str) -> AuthResult<Vec<Invitation>> {
        self.inner.list_organization_invitations(org_id).await
    }
    async fn count_pending_organization_invitations(&self, org_id: &str) -> AuthResult<i64> {
        self.inner
            .count_pending_organization_invitations(org_id)
            .await
    }
    async fn list_user_invitations(&self, email: &str) -> AuthResult<Vec<Invitation>> {
        self.inner.list_user_invitations(email).await
    }
    async fn accept_invitation_with_teams(
        &self,
        invitation_id: &str,
        user_id: &str,
        session_token: &str,
        team_limits: &[(String, Option<f64>)],
        membership_limit: Option<usize>,
    ) -> AuthResult<Option<(Invitation, Member)>> {
        self.inner
            .accept_invitation_with_teams(
                invitation_id,
                user_id,
                session_token,
                team_limits,
                membership_limit,
            )
            .await
    }
    async fn update_invitation_team_ids(
        &self,
        id: &str,
        team_ids: Option<String>,
    ) -> AuthResult<Invitation> {
        self.inner.update_invitation_team_ids(id, team_ids).await
    }
}

#[async_trait]
impl<S: AuthSchema> TwoFactorStore for PluginStore<S> {
    async fn update_two_factor(
        &self,
        id: &str,
        update: UpdateTwoFactor,
    ) -> AuthResult<Option<TwoFactor>> {
        self.inner.update_two_factor(id, update).await
    }
    async fn increment_two_factor_failure(&self, id: &str) -> AuthResult<Option<TwoFactor>> {
        self.inner.increment_two_factor_failure(id).await
    }
    async fn set_two_factor_lock_if_count_at_least(
        &self,
        id: &str,
        threshold: f64,
        until: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<Option<TwoFactor>> {
        self.inner
            .set_two_factor_lock_if_count_at_least(id, threshold, until)
            .await
    }
    async fn clear_expired_two_factor_lock(
        &self,
        id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<Option<TwoFactor>> {
        self.inner.clear_expired_two_factor_lock(id, now).await
    }
    async fn reset_two_factor_failures(&self, id: &str) -> AuthResult<()> {
        self.inner.reset_two_factor_failures(id).await
    }
    async fn compare_and_swap_two_factor_backup_codes(
        &self,
        id: &str,
        expected: &str,
        replacement: &str,
    ) -> AuthResult<bool> {
        self.inner
            .compare_and_swap_two_factor_backup_codes(id, expected, replacement)
            .await
    }
    async fn create_two_factor(&self, two_factor: CreateTwoFactor) -> AuthResult<TwoFactor> {
        self.inner.create_two_factor(two_factor).await
    }
    async fn get_two_factor_by_user_id(&self, user_id: &str) -> AuthResult<Option<TwoFactor>> {
        self.inner.get_two_factor_by_user_id(user_id).await
    }
    async fn update_two_factor_backup_codes(
        &self,
        user_id: &str,
        backup_codes: &str,
    ) -> AuthResult<TwoFactor> {
        self.inner
            .update_two_factor_backup_codes(user_id, backup_codes)
            .await
    }
    async fn delete_two_factor(&self, user_id: &str) -> AuthResult<()> {
        self.inner.delete_two_factor(user_id).await
    }
}

#[async_trait]
impl<S: AuthSchema> ApiKeyStore for PluginStore<S> {
    async fn consume_api_key_usage_from_snapshot(
        &self,
        observed: &ApiKey,
        global_rate_limit_enabled: bool,
    ) -> AuthResult<ConsumeApiKeyResult> {
        self.inner
            .consume_api_key_usage_from_snapshot(observed, global_rate_limit_enabled)
            .await
    }
    async fn create_api_key(&self, input: CreateApiKey) -> AuthResult<ApiKey> {
        self.inner.create_api_key(input).await
    }
    async fn get_api_key_by_id(&self, id: &str) -> AuthResult<Option<ApiKey>> {
        self.inner.get_api_key_by_id(id).await
    }
    async fn get_api_key_by_hash(&self, hash: &str) -> AuthResult<Option<ApiKey>> {
        self.inner.get_api_key_by_hash(hash).await
    }
    async fn list_api_keys_by_reference(&self, reference_id: &str) -> AuthResult<Vec<ApiKey>> {
        self.inner.list_api_keys_by_reference(reference_id).await
    }
    async fn update_api_key(&self, id: &str, update: UpdateApiKey) -> AuthResult<ApiKey> {
        self.inner.update_api_key(id, update).await
    }
    async fn delete_api_key(&self, id: &str) -> AuthResult<()> {
        self.inner.delete_api_key(id).await
    }
    async fn delete_expired_api_keys(&self) -> AuthResult<usize> {
        self.inner.delete_expired_api_keys().await
    }
    async fn consume_api_key_usage(
        &self,
        id: &str,
        global_rate_limit_enabled: bool,
    ) -> AuthResult<ConsumeApiKeyResult> {
        self.inner
            .consume_api_key_usage(id, global_rate_limit_enabled)
            .await
    }
}

#[async_trait]
impl<S: AuthSchema> PasskeyStore for PluginStore<S> {
    async fn create_passkey(&self, input: CreatePasskey) -> AuthResult<Passkey> {
        self.inner.create_passkey(input).await
    }
    async fn get_passkey_by_id(&self, id: &str) -> AuthResult<Option<Passkey>> {
        self.inner.get_passkey_by_id(id).await
    }
    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> AuthResult<Option<Passkey>> {
        self.inner.get_passkey_by_credential_id(credential_id).await
    }
    async fn list_passkeys_by_user(&self, user_id: &str) -> AuthResult<Vec<Passkey>> {
        self.inner.list_passkeys_by_user(user_id).await
    }
    async fn update_passkey_authentication(
        &self,
        id: &str,
        update: UpdatePasskeyAuthentication,
    ) -> AuthResult<Option<Passkey>> {
        self.inner.update_passkey_authentication(id, update).await
    }
    async fn update_passkey_name(&self, id: &str, name: &str) -> AuthResult<Passkey> {
        self.inner.update_passkey_name(id, name).await
    }
    async fn delete_passkey(&self, id: &str) -> AuthResult<()> {
        self.inner.delete_passkey(id).await
    }
}

#[async_trait]
impl<S: AuthSchema> DeviceCodeStore for PluginStore<S> {
    async fn create_device_code(&self, input: CreateDeviceCode) -> AuthResult<DeviceCode> {
        self.inner.create_device_code(input).await
    }
    async fn create_device_code_with_fields(
        &self,
        input: CreateDeviceCode,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> AuthResult<DeviceCode> {
        self.inner
            .create_device_code_with_fields(input, fields)
            .await
    }
    async fn device_code_fields(
        &self,
        id: &str,
    ) -> AuthResult<serde_json::Map<String, serde_json::Value>> {
        self.inner.device_code_fields(id).await
    }
    async fn consume_device_code(
        &self,
        id: &str,
        status: &str,
        ownership: &serde_json::Map<String, serde_json::Value>,
    ) -> AuthResult<Option<DeviceCode>> {
        self.inner.consume_device_code(id, status, ownership).await
    }
    async fn get_device_code_by_device_code(
        &self,
        device_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        self.inner.get_device_code_by_device_code(device_code).await
    }
    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        self.inner.get_device_code_by_user_code(user_code).await
    }
    async fn update_device_code(
        &self,
        id: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<DeviceCode> {
        self.inner.update_device_code(id, update).await
    }
    async fn update_device_code_if_status(
        &self,
        id: &str,
        current_status: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<bool> {
        self.inner
            .update_device_code_if_status(id, current_status, update)
            .await
    }
    async fn claim_device_code(&self, id: &str, user_id: &str) -> AuthResult<bool> {
        self.inner.claim_device_code(id, user_id).await
    }
    async fn delete_device_code(&self, id: &str) -> AuthResult<()> {
        self.inner.delete_device_code(id).await
    }
    async fn delete_device_code_if_status(&self, id: &str, status: &str) -> AuthResult<bool> {
        self.inner.delete_device_code_if_status(id, status).await
    }
}

#[async_trait]
impl<S: AuthSchema> TeamStore for PluginStore<S> {
    async fn create_team(&self, data: CreateTeam) -> AuthResult<Team> {
        self.inner.create_team(data).await
    }
    async fn get_team(
        &self,
        organization_id: Option<&str>,
        team_id: &str,
    ) -> AuthResult<Option<Team>> {
        self.inner.get_team(organization_id, team_id).await
    }
    async fn list_teams(&self, organization_id: &str) -> AuthResult<Vec<Team>> {
        self.inner.list_teams(organization_id).await
    }
    async fn update_team(
        &self,
        organization_id: &str,
        team_id: &str,
        update: UpdateTeam,
    ) -> AuthResult<Team> {
        self.inner
            .update_team(organization_id, team_id, update)
            .await
    }
    async fn delete_team(&self, organization_id: &str, team_id: &str) -> AuthResult<bool> {
        self.inner.delete_team(organization_id, team_id).await
    }
    async fn get_team_member(
        &self,
        team_id: &str,
        user_id: &str,
    ) -> AuthResult<Option<TeamMember>> {
        self.inner.get_team_member(team_id, user_id).await
    }
    async fn add_team_member(
        &self,
        team_id: &str,
        user_id: &str,
        maximum: Option<f64>,
    ) -> AuthResult<AddTeamMemberResult> {
        self.inner.add_team_member(team_id, user_id, maximum).await
    }
    async fn remove_team_member(&self, team_id: &str, user_id: &str) -> AuthResult<usize> {
        self.inner.remove_team_member(team_id, user_id).await
    }
    async fn list_team_members(&self, team_id: &str) -> AuthResult<Vec<TeamMember>> {
        self.inner.list_team_members(team_id).await
    }
    async fn list_user_teams(&self, user_id: &str) -> AuthResult<Vec<Team>> {
        self.inner.list_user_teams(user_id).await
    }
}

#[async_trait]
impl<S: AuthSchema> OrganizationRoleStore for PluginStore<S> {
    async fn create_organization_role(
        &self,
        data: CreateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        self.inner.create_organization_role(data).await
    }
    async fn get_organization_role(
        &self,
        organization_id: &str,
        selector: &OrganizationRoleSelector,
    ) -> AuthResult<Option<OrganizationRole>> {
        self.inner
            .get_organization_role(organization_id, selector)
            .await
    }
    async fn list_organization_roles(
        &self,
        organization_id: &str,
    ) -> AuthResult<Vec<OrganizationRole>> {
        self.inner.list_organization_roles(organization_id).await
    }
    async fn count_organization_roles(&self, organization_id: &str) -> AuthResult<usize> {
        self.inner.count_organization_roles(organization_id).await
    }
    async fn has_organization_role_members(
        &self,
        organization_id: &str,
        role: &str,
    ) -> AuthResult<bool> {
        self.inner
            .has_organization_role_members(organization_id, role)
            .await
    }
    async fn update_organization_role(
        &self,
        organization_id: &str,
        selector: &OrganizationRoleSelector,
        update: UpdateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        self.inner
            .update_organization_role(organization_id, selector, update)
            .await
    }
    async fn delete_organization_role(
        &self,
        organization_id: &str,
        selector: &OrganizationRoleSelector,
    ) -> AuthResult<bool> {
        self.inner
            .delete_organization_role(organization_id, selector)
            .await
    }
}

#[async_trait]
impl<S: AuthSchema> JwkStore for PluginStore<S> {
    async fn list_jwks(&self) -> AuthResult<Vec<Jwk>> {
        self.inner.list_jwks().await
    }
    async fn get_jwk_by_id(&self, id: &str) -> AuthResult<Option<Jwk>> {
        self.inner.get_jwk_by_id(id).await
    }
    async fn create_jwk(&self, data: CreateJwk) -> AuthResult<Jwk> {
        self.inner.create_jwk(data).await
    }
}

#[async_trait]
impl<S: AuthSchema> WalletAddressStore for PluginStore<S> {
    async fn get_wallet_address(
        &self,
        address: &str,
        chain_id: Option<f64>,
    ) -> AuthResult<Option<WalletAddress>> {
        self.inner.get_wallet_address(address, chain_id).await
    }
    async fn create_wallet_address(&self, data: CreateWalletAddress) -> AuthResult<WalletAddress> {
        self.inner.create_wallet_address(data).await
    }
}
