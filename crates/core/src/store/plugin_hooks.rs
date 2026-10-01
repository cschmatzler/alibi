//! Per-auth-instance plugin transforms around the configured store.

use super::*;
use crate::types::*;
use crate::{AuthResult, AuthSchema};
use async_trait::async_trait;
use std::sync::Arc;

pub(crate) type UserCreateTransform =
    Arc<dyn Fn(CreateUser) -> AuthResult<CreateUser> + Send + Sync>;
pub(crate) type UserUpdateTransform =
    Arc<dyn Fn(&str, UpdateUser) -> AuthResult<UpdateUser> + Send + Sync>;

#[derive(Clone, Default)]
pub(crate) struct UserTransforms {
    pub(crate) creates: Vec<UserCreateTransform>,
    pub(crate) updates: Vec<UserUpdateTransform>,
}

pub(crate) struct PluginStore<S: AuthSchema> {
    inner: Arc<dyn AuthStore<S>>,
    transforms: UserTransforms,
    session_fields: crate::field_policy::SessionFields,
    adapter_fields: crate::field_policy::SessionAdapterFields,
}

impl<S: AuthSchema> PluginStore<S> {
    pub(crate) fn new(
        inner: Arc<dyn AuthStore<S>>,
        transforms: UserTransforms,
        session_fields: crate::field_policy::SessionFields,
        adapter_fields: crate::field_policy::SessionAdapterFields,
    ) -> Self {
        Self {
            inner,
            transforms,
            session_fields,
            adapter_fields,
        }
    }
}

fn create_data(mut data: CreateUser, transforms: &[UserCreateTransform]) -> AuthResult<CreateUser> {
    for transform in transforms {
        data = transform(data)?;
    }
    Ok(data)
}
#[async_trait]
impl<S: AuthSchema> UserStore<S> for PluginStore<S> {
    async fn create_user(&self, create_user: CreateUser) -> AuthResult<S::User> {
        let create_user = create_data(create_user, &self.transforms.creates)?;
        self.inner.create_user(create_user).await
    }
    async fn coerce_user_text_number(&self, input: NumericTextInput) -> AuthResult<String> {
        self.inner.coerce_user_text_number(input).await
    }
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<S::User>> {
        self.inner.get_user_by_id(id).await
    }
    async fn list_users_by_ids(&self, ids: &[String]) -> AuthResult<Vec<S::User>> {
        self.inner.list_users_by_ids(ids).await
    }
    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<S::User>> {
        self.inner.get_user_by_email(email).await
    }
    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<S::User>> {
        self.inner.get_user_by_username(username).await
    }
    async fn get_user_by_phone_number(&self, phone_number: &str) -> AuthResult<Option<S::User>> {
        self.inner.get_user_by_phone_number(phone_number).await
    }
    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<S::User> {
        let mut update = update;
        for transform in &self.transforms.updates {
            update = transform(id, update)?;
        }
        self.inner.update_user(id, update).await
    }
    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        self.inner.delete_user(id).await
    }
    async fn list_users(&self, params: ListUsersParams) -> AuthResult<(Vec<S::User>, usize)> {
        self.inner.list_users(params).await
    }
}

#[async_trait]
impl<S: AuthSchema> SessionStore<S> for PluginStore<S> {
    async fn update_session_fields(
        &self,
        token: &str,
        mut fields: crate::field_policy::FieldValues,
    ) -> AuthResult<Option<S::Session>> {
        self.adapter_fields.attach(&mut fields, false);
        self.inner.update_session_fields(token, fields).await
    }
    async fn create_session(&self, mut create_session: CreateSession) -> AuthResult<S::Session> {
        self.session_fields
            .defaults(&mut create_session.additional_fields);
        self.adapter_fields
            .attach(&mut create_session.additional_fields, true);
        self.inner.create_session(create_session).await
    }
    async fn get_session(&self, token: &str) -> AuthResult<Option<S::Session>> {
        self.inner.get_session(token).await
    }
    async fn get_sessions_by_tokens(&self, tokens: &[String]) -> AuthResult<Vec<S::Session>> {
        self.inner.get_sessions_by_tokens(tokens).await
    }
    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<S::Session>> {
        self.inner.get_user_sessions(user_id).await
    }
    async fn refresh_session(
        &self,
        token: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<Option<S::Session>> {
        self.inner.refresh_session(token, expires_at).await
    }
    async fn update_session_expiry(
        &self,
        token: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<()> {
        self.inner.update_session_expiry(token, expires_at).await
    }
    async fn delete_session(&self, token: &str) -> AuthResult<()> {
        self.inner.delete_session(token).await
    }
    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
        self.inner.delete_user_sessions(user_id).await
    }
    async fn delete_expired_sessions(&self) -> AuthResult<usize> {
        self.inner.delete_expired_sessions().await
    }
    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<S::Session> {
        self.inner
            .update_session_active_organization(token, organization_id)
            .await
    }
    async fn update_session_active_team(
        &self,
        token: &str,
        team_id: Option<&str>,
    ) -> AuthResult<S::Session> {
        self.inner.update_session_active_team(token, team_id).await
    }
}

#[async_trait]
impl<S: AuthSchema> AccountStore<S> for PluginStore<S> {
    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<S::Account> {
        self.inner.create_account(create_account).await
    }
    async fn get_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<S::Account>> {
        self.inner.get_account(provider, provider_account_id).await
    }
    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<S::Account>> {
        self.inner.get_user_accounts(user_id).await
    }
    async fn update_account(&self, id: &str, update: UpdateAccount) -> AuthResult<S::Account> {
        self.inner.update_account(id, update).await
    }
    async fn delete_account(&self, id: &str) -> AuthResult<()> {
        self.inner.delete_account(id).await
    }
}

#[async_trait]
impl<S: AuthSchema> VerificationStore<S> for PluginStore<S> {
    async fn create_verification(
        &self,
        verification: CreateVerification,
    ) -> AuthResult<S::Verification> {
        self.inner.create_verification(verification).await
    }
    async fn get_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<S::Verification>> {
        self.inner.get_verification(identifier, value).await
    }
    async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<S::Verification>> {
        self.inner.get_verification_by_value(value).await
    }
    async fn get_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        self.inner.get_verification_by_identifier(identifier).await
    }
    async fn consume_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<S::Verification>> {
        self.inner.consume_verification(identifier, value).await
    }
    async fn get_latest_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        self.inner
            .get_latest_verification_by_identifier(identifier)
            .await
    }
    async fn consume_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        self.inner
            .consume_verification_by_identifier(identifier)
            .await
    }
    async fn delete_verifications_by_identifier(&self, identifier: &str) -> AuthResult<()> {
        self.inner
            .delete_verifications_by_identifier(identifier)
            .await
    }
    async fn compare_and_swap_verification(
        &self,
        id: &str,
        expected_value: &str,
        value: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<bool> {
        self.inner
            .compare_and_swap_verification(id, expected_value, value, expires_at)
            .await
    }
    async fn reserve_verification(&self, verification: CreateVerification) -> AuthResult<bool> {
        self.inner.reserve_verification(verification).await
    }
    async fn delete_verification(&self, id: &str) -> AuthResult<()> {
        self.inner.delete_verification(id).await
    }
    async fn delete_expired_verifications(&self) -> AuthResult<usize> {
        self.inner.delete_expired_verifications().await
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
        _invitation_id: &str,
        _user_id: &str,
        _session_token: &str,
        _team_limits: &[(String, Option<usize>)],
        _membership_limit: Option<usize>,
    ) -> AuthResult<Option<(Invitation, Member)>> {
        self.inner
            .accept_invitation_with_teams(
                _invitation_id,
                _user_id,
                _session_token,
                _team_limits,
                _membership_limit,
            )
            .await
    }
    async fn update_invitation_team_ids(
        &self,
        _id: &str,
        _team_ids: Option<String>,
    ) -> AuthResult<Invitation> {
        self.inner.update_invitation_team_ids(_id, _team_ids).await
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
    ) -> AuthResult<Passkey> {
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
    async fn create_team(&self, _data: CreateTeam) -> AuthResult<Team> {
        self.inner.create_team(_data).await
    }
    async fn get_team(
        &self,
        _organization_id: Option<&str>,
        _team_id: &str,
    ) -> AuthResult<Option<Team>> {
        self.inner.get_team(_organization_id, _team_id).await
    }
    async fn list_teams(&self, _organization_id: &str) -> AuthResult<Vec<Team>> {
        self.inner.list_teams(_organization_id).await
    }
    async fn update_team(
        &self,
        _organization_id: &str,
        _team_id: &str,
        _update: UpdateTeam,
    ) -> AuthResult<Team> {
        self.inner
            .update_team(_organization_id, _team_id, _update)
            .await
    }
    async fn delete_team(&self, _organization_id: &str, _team_id: &str) -> AuthResult<bool> {
        self.inner.delete_team(_organization_id, _team_id).await
    }
    async fn get_team_member(
        &self,
        _team_id: &str,
        _user_id: &str,
    ) -> AuthResult<Option<TeamMember>> {
        self.inner.get_team_member(_team_id, _user_id).await
    }
    async fn add_team_member(
        &self,
        _team_id: &str,
        _user_id: &str,
        _maximum: Option<usize>,
    ) -> AuthResult<AddTeamMemberResult> {
        self.inner
            .add_team_member(_team_id, _user_id, _maximum)
            .await
    }
    async fn remove_team_member(&self, _team_id: &str, _user_id: &str) -> AuthResult<usize> {
        self.inner.remove_team_member(_team_id, _user_id).await
    }
    async fn list_team_members(&self, _team_id: &str) -> AuthResult<Vec<TeamMember>> {
        self.inner.list_team_members(_team_id).await
    }
    async fn list_user_teams(&self, _user_id: &str) -> AuthResult<Vec<Team>> {
        self.inner.list_user_teams(_user_id).await
    }
}

#[async_trait]
impl<S: AuthSchema> OrganizationRoleStore for PluginStore<S> {
    async fn create_organization_role(
        &self,
        _data: CreateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        self.inner.create_organization_role(_data).await
    }
    async fn get_organization_role(
        &self,
        _organization_id: &str,
        _selector: &OrganizationRoleSelector,
    ) -> AuthResult<Option<OrganizationRole>> {
        self.inner
            .get_organization_role(_organization_id, _selector)
            .await
    }
    async fn list_organization_roles(
        &self,
        _organization_id: &str,
    ) -> AuthResult<Vec<OrganizationRole>> {
        self.inner.list_organization_roles(_organization_id).await
    }
    async fn count_organization_roles(&self, _organization_id: &str) -> AuthResult<usize> {
        self.inner.count_organization_roles(_organization_id).await
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
        _organization_id: &str,
        _selector: &OrganizationRoleSelector,
        _update: UpdateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        self.inner
            .update_organization_role(_organization_id, _selector, _update)
            .await
    }
    async fn delete_organization_role(
        &self,
        _organization_id: &str,
        _selector: &OrganizationRoleSelector,
    ) -> AuthResult<bool> {
        self.inner
            .delete_organization_role(_organization_id, _selector)
            .await
    }
}

struct PluginTransaction<'a, S: AuthSchema> {
    inner: &'a dyn AuthTransaction<S>,
    creates: Vec<UserCreateTransform>,
    session_fields: crate::field_policy::SessionFields,
    adapter_fields: crate::field_policy::SessionAdapterFields,
}

#[async_trait]
impl<S: AuthSchema> AuthTransaction<S> for PluginTransaction<'_, S> {
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<S::User>> {
        self.inner.get_user_by_id(id).await
    }
    async fn create_passkey(&self, data: CreatePasskey) -> AuthResult<Passkey> {
        self.inner.create_passkey(data).await
    }
    async fn create_user(&self, data: CreateUser) -> AuthResult<S::User> {
        self.inner
            .create_user(create_data(data, &self.creates)?)
            .await
    }
    async fn create_account(&self, data: CreateAccount) -> AuthResult<S::Account> {
        self.inner.create_account(data).await
    }
    async fn create_session(&self, mut data: CreateSession) -> AuthResult<S::Session> {
        self.session_fields.defaults(&mut data.additional_fields);
        self.adapter_fields
            .attach(&mut data.additional_fields, true);
        self.inner.create_session(data).await
    }
    async fn create_verification(&self, data: CreateVerification) -> AuthResult<S::Verification> {
        self.inner.create_verification(data).await
    }
}

#[async_trait]
impl<S: AuthSchema> TransactionStore<S> for PluginStore<S> {
    async fn transaction_boxed(
        &self,
        work: Box<TransactionWork<S>>,
    ) -> AuthResult<BoxedTransactionValue> {
        let creates = self.transforms.creates.clone();
        let session_fields = self.session_fields.clone();
        let adapter_fields = self.adapter_fields.clone();
        self.inner
            .transaction_boxed(Box::new(move |inner| {
                Box::pin(async move {
                    let transaction = PluginTransaction {
                        inner,
                        creates,
                        session_fields,
                        adapter_fields,
                    };
                    work(&transaction).await
                })
            }))
            .await
    }
}

#[async_trait]
impl<S: AuthSchema> JwkStore for PluginStore<S> {
    async fn list_jwks(&self) -> AuthResult<Vec<Jwk>> {
        self.inner.list_jwks().await
    }
    async fn get_jwk_by_id(&self, _id: &str) -> AuthResult<Option<Jwk>> {
        self.inner.get_jwk_by_id(_id).await
    }
    async fn create_jwk(&self, _data: CreateJwk) -> AuthResult<Jwk> {
        self.inner.create_jwk(_data).await
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
