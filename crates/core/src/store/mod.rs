pub mod cache;

mod org_extensions;

mod jwks;

mod wallets;

use crate::error::{AuthError, AuthResult};
use crate::schema::AuthSchema;
use crate::types::{
    AddTeamMemberResult, CreateJwk, CreateOrganizationRole, CreateTeam, CreateWalletAddress, Jwk,
    OrganizationRole, OrganizationRoleSelector, Team, TeamMember, UpdateOrganizationRole,
    UpdateTeam, WalletAddress,
};
use crate::types::{
    ApiKey, CreateAccount, CreateApiKey, CreateDeviceCode, CreateInvitation, CreateMember,
    CreateOrganization, CreatePasskey, CreateSession, CreateTwoFactor, CreateUser,
    CreateVerification, DeviceCode, Invitation, InvitationStatus, ListUsersParams, Member,
    Organization, Passkey, TwoFactor, UpdateAccount, UpdateApiKey, UpdateDeviceCode,
    UpdateOrganization, UpdatePasskeyAuthentication, UpdateTwoFactor, UpdateUser,
};
use async_trait::async_trait;
#[cfg(feature = "redis-cache")]
pub use cache::RedisAdapter;
pub use cache::{CacheAdapter, MemoryCacheAdapter};
pub use jwks::JwkStore;
pub use org_extensions::{OrganizationRoleStore, TeamStore, team_membership_key};
use std::any::Any;
use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
pub use wallets::WalletAddressStore;

pub(crate) type UserCreateTransform =
    Arc<dyn Fn(CreateUser) -> AuthResult<CreateUser> + Send + Sync>;

pub(crate) type UserUpdateTransform =
    Arc<dyn Fn(&str, UpdateUser) -> AuthResult<UpdateUser> + Send + Sync>;

#[derive(Clone, Default)]
pub(crate) struct UserTransforms {
    pub(crate) creates: Vec<UserCreateTransform>,
    pub(crate) updates: Vec<UserUpdateTransform>,
}

/// Application/plugin adapter hook observing a successfully persisted session.
/// Transactional hooks execute only after commit against the finalized store,
/// including registered user transforms. Hook failures do not roll back commit.
#[async_trait]
pub trait SessionCreatedHook<S: AuthSchema>: Send + Sync {
    async fn after_create(
        &self,
        session: &S::Session,
        database: &dyn AuthStore<S>,
    ) -> AuthResult<()>;
}

pub(crate) struct SessionCreatedCallbacks<S: AuthSchema> {
    pub(crate) callbacks: Vec<Arc<dyn SessionCreatedHook<S>>>,
}
impl<S: AuthSchema> Default for SessionCreatedCallbacks<S> {
    fn default() -> Self {
        Self {
            callbacks: Vec::new(),
        }
    }
}
impl<S: AuthSchema> Clone for SessionCreatedCallbacks<S> {
    fn clone(&self) -> Self {
        Self {
            callbacks: self.callbacks.clone(),
        }
    }
}

pub(crate) struct PluginStore<S: AuthSchema> {
    inner: Arc<dyn AuthStore<S>>,
    transforms: UserTransforms,
    session_callbacks: SessionCreatedCallbacks<S>,
    session_fields: crate::field_policy::SessionFields,
    adapter_fields: crate::field_policy::SessionAdapterFields,
}

impl<S: AuthSchema> PluginStore<S> {
    #[must_use]
    pub(crate) fn new(
        inner: Arc<dyn AuthStore<S>>,
        transforms: UserTransforms,
        session_callbacks: SessionCreatedCallbacks<S>,
        session_fields: crate::field_policy::SessionFields,
        adapter_fields: crate::field_policy::SessionAdapterFields,
    ) -> Self {
        Self {
            inner,
            transforms,
            session_callbacks,
            session_fields,
            adapter_fields,
        }
    }
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
    async fn list_users_by_ids_page(&self, ids: &[String], limit: f64) -> AuthResult<Vec<S::User>> {
        self.inner.list_users_by_ids_page(ids, limit).await
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
        let session = self.inner.create_session(create_session).await?;
        for callback in &self.session_callbacks.callbacks {
            callback.after_create(&session, self).await?;
        }
        Ok(session)
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
    pending_sessions: Arc<std::sync::Mutex<Vec<S::Session>>>,
    session_fields: crate::field_policy::SessionFields,
    adapter_fields: crate::field_policy::SessionAdapterFields,
}

#[async_trait]
impl<S: AuthSchema> AuthTransaction<S> for PluginTransaction<'_, S> {
    async fn get_team(&self, organization_id: &str, team_id: &str) -> AuthResult<Option<Team>> {
        self.inner.get_team(organization_id, team_id).await
    }

    async fn add_team_member(
        &self,
        team_id: &str,
        user_id: &str,
        maximum: Option<usize>,
    ) -> AuthResult<AddTeamMemberResult> {
        self.inner.add_team_member(team_id, user_id, maximum).await
    }

    async fn create_member(&self, member: CreateMember) -> AuthResult<Member> {
        self.inner.create_member(member).await
    }

    async fn update_session_active_team(
        &self,
        token: &str,
        team_id: Option<&str>,
    ) -> AuthResult<S::Session> {
        self.inner.update_session_active_team(token, team_id).await
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

    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<S::User>> {
        self.inner.get_user_by_id(id).await
    }

    async fn create_passkey(&self, data: CreatePasskey) -> AuthResult<Passkey> {
        self.inner.create_passkey(data).await
    }

    async fn create_user(&self, create_user: CreateUser) -> AuthResult<S::User> {
        self.inner
            .create_user(create_data(create_user, &self.creates)?)
            .await
    }

    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<S::Account> {
        self.inner.create_account(create_account).await
    }

    async fn create_session(&self, mut create_session: CreateSession) -> AuthResult<S::Session> {
        self.session_fields
            .defaults(&mut create_session.additional_fields);
        self.adapter_fields
            .attach(&mut create_session.additional_fields, true);
        let session = self.inner.create_session(create_session).await?;
        self.pending_sessions
            .lock()
            .map_err(|_| AuthError::internal("Session callback queue poisoned"))?
            .push(session.clone());
        Ok(session)
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
        let pending_sessions = Arc::new(std::sync::Mutex::new(Vec::new()));
        let pending_in_transaction = Arc::clone(&pending_sessions);
        let session_fields = self.session_fields.clone();
        let adapter_fields = self.adapter_fields.clone();
        let value = self
            .inner
            .transaction_boxed(Box::new(move |inner| {
                Box::pin(async move {
                    let transaction = PluginTransaction {
                        inner,
                        creates,
                        pending_sessions: pending_in_transaction,
                        session_fields,
                        adapter_fields,
                    };
                    work(&transaction).await
                })
            }))
            .await?;
        // The adapter owns commit/rollback. Callbacks observe only committed
        // sessions and run against the ordinary store, never a closed transaction.
        let sessions = std::mem::take(
            &mut *pending_sessions
                .lock()
                .map_err(|_| AuthError::internal("Session callback queue poisoned"))?,
        );
        for session in sessions {
            for callback in &self.session_callbacks.callbacks {
                callback.after_create(&session, self).await?;
            }
        }
        Ok(value)
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

pub type BoxedTransactionValue = Box<dyn Any + Send>;

pub type TransactionFuture<'a> =
    Pin<Box<dyn Future<Output = AuthResult<BoxedTransactionValue>> + Send + 'a>>;

pub type TypedTransactionFuture<'a, T> = Pin<Box<dyn Future<Output = AuthResult<T>> + Send + 'a>>;

pub type TransactionWork<S> =
    dyn for<'tx> FnOnce(&'tx dyn AuthTransaction<S>) -> TransactionFuture<'tx> + Send;

#[async_trait]
pub trait AuthTransaction<S: AuthSchema>: Send + Sync {
    /// Read a team within the authorized organization through this transaction.
    async fn get_team(&self, _organization_id: &str, _team_id: &str) -> AuthResult<Option<Team>> {
        Err(AuthError::NotImplemented(
            "Team lookup in a transaction is not supported by this store".into(),
        ))
    }
    /// Add an idempotent team membership under the same transaction's capacity check.
    async fn add_team_member(
        &self,
        _team_id: &str,
        _user_id: &str,
        _maximum: Option<usize>,
    ) -> AuthResult<AddTeamMemberResult> {
        Err(AuthError::NotImplemented(
            "Team admission in a transaction is not supported by this store".into(),
        ))
    }
    async fn create_member(&self, _member: CreateMember) -> AuthResult<Member> {
        Err(AuthError::NotImplemented(
            "Member creation in a transaction is not supported by this store".into(),
        ))
    }
    /// Update the already authenticated token through the transaction connection.
    async fn update_session_active_team(
        &self,
        _token: &str,
        _team_id: Option<&str>,
    ) -> AuthResult<S::Session> {
        Err(AuthError::NotImplemented(
            "Active team updates in a transaction are not supported by this store".into(),
        ))
    }
    async fn update_session_active_organization(
        &self,
        _token: &str,
        _organization_id: Option<&str>,
    ) -> AuthResult<S::Session> {
        Err(AuthError::NotImplemented(
            "Active organization updates in a transaction are not supported by this store".into(),
        ))
    }
    /// Read an existing registration owner through this transaction's connection.
    async fn get_user_by_id(&self, _id: &str) -> AuthResult<Option<S::User>> {
        Err(AuthError::NotImplemented(
            "User lookup in a transaction is not supported by this store".to_owned(),
        ))
    }
    /// Persist a verified passkey in the same transaction as its new session.
    async fn create_passkey(&self, _passkey: CreatePasskey) -> AuthResult<Passkey> {
        Err(AuthError::NotImplemented(
            "Passkey creation in a transaction is not supported by this store".to_owned(),
        ))
    }
    async fn create_user(&self, create_user: CreateUser) -> AuthResult<S::User>;
    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<S::Account>;
    async fn create_session(&self, create_session: CreateSession) -> AuthResult<S::Session>;
    async fn create_verification(
        &self,
        _verification: CreateVerification,
    ) -> AuthResult<S::Verification> {
        Err(AuthError::NotImplemented(
            "Verification creation in a transaction is not supported by this store".to_owned(),
        ))
    }
}

/// Numeric binding used when a registered user text field accepts a JSON number.
/// The HTTP caller first rounds it to a JavaScript number, preserving negative zero.
#[derive(Clone, Copy, Debug)]
pub enum NumericTextInput {
    Integer(i64),
    Real(f64),
}

#[async_trait]
pub trait UserStore<S: AuthSchema>: Send + Sync {
    async fn create_user(&self, create_user: CreateUser) -> AuthResult<S::User>;
    /// Coerce a numeric binding with the configured adapter's text semantics.
    /// Custom adapters must implement this explicitly when accepting such input.
    async fn coerce_user_text_number(&self, _input: NumericTextInput) -> AuthResult<String> {
        Err(AuthError::NotImplemented(
            "Numeric user-field text coercion is not supported by this store".into(),
        ))
    }
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<S::User>>;
    /// Fetch multiple users by id.
    ///
    /// Implementations may return rows in any order. Callers must remap by id
    /// when response order matters.
    async fn list_users_by_ids(&self, ids: &[String]) -> AuthResult<Vec<S::User>>;
    /// Apply the adapter's raw numeric page to actual matching users. Unsupported
    /// stores fail closed rather than rounding, capping, or delegating to an unpaged read.
    async fn list_users_by_ids_page(
        &self,
        _ids: &[String],
        _limit: f64,
    ) -> AuthResult<Vec<S::User>> {
        Err(AuthError::NotImplemented(
            "Raw numeric user pages are not supported by this store".into(),
        ))
    }
    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<S::User>>;
    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<S::User>>;
    async fn get_user_by_phone_number(&self, _phone_number: &str) -> AuthResult<Option<S::User>> {
        Err(AuthError::internal(
            "phone-number lookup is not supported by this store",
        ))
    }
    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<S::User>;
    async fn delete_user(&self, id: &str) -> AuthResult<()>;
    async fn list_users(&self, params: ListUsersParams) -> AuthResult<(Vec<S::User>, usize)>;
}

#[async_trait]
pub trait SessionStore<S: AuthSchema>: Send + Sync {
    /// Persist already authorized fields for the currently authenticated token.
    async fn update_session_fields(
        &self,
        _token: &str,
        _fields: crate::field_policy::FieldValues,
    ) -> AuthResult<Option<S::Session>> {
        Err(AuthError::internal(
            "the store does not support session field updates",
        ))
    }

    async fn create_session(&self, create_session: CreateSession) -> AuthResult<S::Session>;

    async fn get_session(&self, token: &str) -> AuthResult<Option<S::Session>>;

    /// Fetch matching sessions once each, including expired rows. The bundled
    /// SQLite adapter returns token-index order rather than request order.
    async fn get_sessions_by_tokens(&self, tokens: &[String]) -> AuthResult<Vec<S::Session>> {
        let mut sessions = Vec::new();
        for token in BTreeSet::from_iter(tokens) {
            if let Some(session) = self.get_session(token).await? {
                sessions.push(session);
            }
        }
        Ok(sessions)
    }

    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<S::Session>>;

    async fn update_session_expiry(
        &self,
        token: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<()>;

    /// Refresh the persisted expiry and return the updated snapshot. A session
    /// removed before the update returns `None`, never its old credentials.
    async fn refresh_session(
        &self,
        token: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<Option<S::Session>> {
        match self.update_session_expiry(token, expires_at).await {
            Ok(()) => self.get_session(token).await,
            Err(AuthError::SessionNotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }

    async fn delete_session(&self, token: &str) -> AuthResult<()>;

    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()>;

    async fn delete_expired_sessions(&self) -> AuthResult<usize>;

    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<S::Session>;

    async fn update_session_active_team(
        &self,
        _token: &str,
        _team_id: Option<&str>,
    ) -> AuthResult<S::Session> {
        Err(AuthError::internal(
            "active-team updates are not supported by this store",
        ))
    }
}

#[async_trait]
pub trait AccountStore<S: AuthSchema>: Send + Sync {
    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<S::Account>;
    async fn get_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<S::Account>>;
    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<S::Account>>;
    async fn update_account(&self, id: &str, update: UpdateAccount) -> AuthResult<S::Account>;
    async fn delete_account(&self, id: &str) -> AuthResult<()>;
}

#[async_trait]
pub trait VerificationStore<S: AuthSchema>: Send + Sync {
    async fn create_verification(
        &self,
        verification: CreateVerification,
    ) -> AuthResult<S::Verification>;
    async fn get_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<S::Verification>>;
    async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<S::Verification>>;
    async fn get_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>>;
    async fn consume_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<S::Verification>>;
    /// Fetch the newest generation, including expired records. The caller
    /// decides whether cleanup and a distinct expiry error are required.
    async fn get_latest_verification_by_identifier(
        &self,
        _identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        Err(AuthError::internal(
            "raw verification lookup is not supported by this store",
        ))
    }
    /// Atomically invalidate an identifier and return its newest generation.
    /// Exactly one concurrent caller can receive a row. Expired records are
    /// removed along with every sibling and return `None`.
    async fn consume_verification_by_identifier(
        &self,
        _identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        Err(AuthError::internal(
            "atomic verification consumption is not supported by this store",
        ))
    }
    async fn delete_verifications_by_identifier(&self, _identifier: &str) -> AuthResult<()> {
        Err(AuthError::internal(
            "verification invalidation is not supported by this store",
        ))
    }
    /// Update a generation only when its value still matches the snapshot.
    async fn compare_and_swap_verification(
        &self,
        _id: &str,
        _expected_value: &str,
        _value: &str,
        _expires_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<bool> {
        Err(AuthError::internal(
            "atomic verification updates are not supported by this store",
        ))
    }
    /// Insert a deterministic reservation exactly once. An expired marker
    /// remains reserved until it is cleaned up or explicitly consumed.
    async fn reserve_verification(&self, verification: CreateVerification) -> AuthResult<bool> {
        drop(verification);
        Err(AuthError::internal(
            "verification reservation is not supported by this store",
        ))
    }
    async fn delete_verification(&self, id: &str) -> AuthResult<()>;
    async fn delete_expired_verifications(&self) -> AuthResult<usize>;
}

/// Query parameters for listing organization members.
#[derive(Debug, Clone, Default)]
pub struct ListOrganizationMembersParams {
    /// Organization id whose members should be listed.
    pub organization_id: String,
    /// Maximum number of members to return.
    pub limit: Option<usize>,
    /// Number of matching members to skip before returning rows.
    pub offset: Option<usize>,
    /// Client-visible field name used for sorting.
    pub sort_by: Option<String>,
    /// Sort direction (`asc` or `desc`).
    pub sort_direction: Option<String>,
    /// Client-visible field name used for filtering.
    pub filter_field: Option<String>,
    /// Filter value paired with `filter_field`.
    pub filter_value: Option<String>,
    /// Filter operator (`eq`, `ne`, `contains`, `gt`, `gte`, `lt`, `lte`).
    pub filter_operator: Option<String>,
}

/// Adapter page with JavaScript numeric limits retained through SQL binding.
/// Unlike the legacy usize query, an absent sort does not impose an order.
#[derive(Debug, Clone, Default)]
pub struct MemberPageQuery {
    pub organization_id: String,
    pub limit: Option<f64>,
    pub offset: Option<f64>,
    pub sort_by: Option<String>,
    pub sort_direction: Option<String>,
    pub filter_field: Option<String>,
    pub filter_value: Option<String>,
    pub filter_operator: Option<String>,
}

#[async_trait]
pub trait OrganizationStore: Send + Sync {
    async fn create_organization(&self, org: CreateOrganization) -> AuthResult<Organization>;
    async fn get_organization_by_id(&self, id: &str) -> AuthResult<Option<Organization>>;
    async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<Organization>>;
    /// Fetch multiple organizations by id.
    ///
    /// Implementations may return rows in any order. Callers must remap by id
    /// when response order matters.
    async fn list_organizations_by_ids(&self, ids: &[String]) -> AuthResult<Vec<Organization>>;
    async fn update_organization(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Organization>;
    /// Apply exactly the supplied organization columns as a database patch.
    /// Returns absence separately from database errors. Empty patches are sent
    /// to the adapter rather than converted into timestamp-only updates.
    /// Custom stores serving the default HTTP update route must implement this
    /// bounded operation; the default fails closed with NotImplemented.
    /// Model callbacks belong to `update_organization_if_present` instead.
    async fn patch_organization_if_present(
        &self,
        _id: &str,
        _update: UpdateOrganization,
    ) -> AuthResult<Option<Organization>> {
        Err(AuthError::NotImplemented(
            "Organization patches are not supported by this store".into(),
        ))
    }
    /// Update a matching organization, retaining adapter model hooks.
    /// `None` means no row was updated; other storage failures remain errors.
    /// Custom stores must implement this optional-row operation explicitly.
    async fn update_organization_if_present(
        &self,
        _id: &str,
        _update: UpdateOrganization,
    ) -> AuthResult<Option<Organization>> {
        Err(AuthError::NotImplemented(
            "Optional organization updates are not supported by this store".into(),
        ))
    }
    /// Delete the organization and its members/invitations atomically.
    /// Extension rows (teams, roles, API keys) and sessions are retained, matching
    /// the pinned default adapter. Custom adapters own their constraint policy.
    async fn delete_organization(&self, id: &str) -> AuthResult<()>;
    async fn list_user_organizations(&self, user_id: &str) -> AuthResult<Vec<Organization>>;
}

#[async_trait]
pub trait MemberStore: Send + Sync {
    async fn create_member(&self, member: CreateMember) -> AuthResult<Member>;
    async fn get_member(&self, organization_id: &str, user_id: &str) -> AuthResult<Option<Member>>;
    async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<Member>>;
    async fn update_member_role(&self, member_id: &str, role: &str) -> AuthResult<Member>;
    /// Update a matching member while preserving adapter model hooks.
    /// Absence is `None`; other storage failures remain errors.
    async fn update_member_role_if_present(
        &self,
        _member_id: &str,
        _role: &str,
    ) -> AuthResult<Option<Member>> {
        Err(AuthError::NotImplemented(
            "Optional member role updates are not supported by this store".into(),
        ))
    }
    async fn delete_member(&self, member_id: &str) -> AuthResult<()>;
    /// Delete the authorized original member, then optionally release its team
    /// memberships atomically. The original scope/user remains authoritative if
    /// a lifecycle callback independently changes or removes the stored member.
    /// A missing/ignored member deletion is successful; SQL errors are failures.
    async fn delete_member_with_context(
        &self,
        _member_id: &str,
        _organization_id: &str,
        _user_id: &str,
        _remove_team_members: bool,
    ) -> AuthResult<()> {
        Err(AuthError::NotImplemented(
            "Contextual member deletion is not supported by this store".into(),
        ))
    }
    /// Return the adapter's organization-scoped page without imposing a sort.
    /// Used for the source's paged last-owner guard independently of total count.
    async fn list_organization_members_page(
        &self,
        _organization_id: &str,
        _limit: usize,
    ) -> AuthResult<Vec<Member>> {
        Err(AuthError::NotImplemented(
            "Unsorted member pages are not supported by this store".into(),
        ))
    }
    async fn list_organization_members(&self, org_id: &str) -> AuthResult<Vec<Member>>;
    /// Query organization members with filter, sort, and pagination applied in
    /// the store when possible.
    async fn query_organization_members(
        &self,
        params: &ListOrganizationMembersParams,
    ) -> AuthResult<(Vec<Member>, usize)>;
    /// Apply raw numeric pagination without converting it into the legacy usize API.
    async fn query_organization_members_page(
        &self,
        _params: &MemberPageQuery,
    ) -> AuthResult<(Vec<Member>, usize)> {
        Err(AuthError::NotImplemented(
            "Raw numeric member pages are not supported by this store".into(),
        ))
    }
    async fn count_organization_members(&self, org_id: &str) -> AuthResult<i64>;
    async fn count_organization_owners(&self, org_id: &str) -> AuthResult<i64>;
}

#[async_trait]
pub trait InvitationStore: Send + Sync {
    async fn create_invitation(&self, invitation: CreateInvitation) -> AuthResult<Invitation>;
    async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<Invitation>>;
    async fn get_pending_invitation(
        &self,
        org_id: &str,
        email: &str,
    ) -> AuthResult<Option<Invitation>>;
    async fn update_invitation_status(
        &self,
        id: &str,
        status: InvitationStatus,
    ) -> AuthResult<Invitation>;
    /// Atomically change only an invitation still at the expected status and return
    /// the actual updated row. A mismatch or missing row returns None. This write
    /// commits independently of a later membership transaction.
    async fn update_invitation_status_if_status(
        &self,
        _id: &str,
        _expected: InvitationStatus,
        _status: InvitationStatus,
    ) -> AuthResult<Option<Invitation>> {
        Err(AuthError::NotImplemented(
            "Conditional invitation updates are not supported by this store".into(),
        ))
    }
    async fn list_organization_invitations(&self, org_id: &str) -> AuthResult<Vec<Invitation>>;
    /// Count still-pending, unexpired invitations for an organization.
    async fn count_pending_organization_invitations(&self, org_id: &str) -> AuthResult<i64>;
    async fn list_user_invitations(&self, email: &str) -> AuthResult<Vec<Invitation>>;
    /// Claim a pending invitation and persist memberships/session scope in one transition.
    async fn accept_invitation_with_teams(
        &self,
        _invitation_id: &str,
        _user_id: &str,
        _session_token: &str,
        _team_limits: &[(String, Option<usize>)],
        _membership_limit: Option<usize>,
    ) -> AuthResult<Option<(Invitation, Member)>> {
        Err(AuthError::NotImplemented(
            "Atomic invitation acceptance is not supported by this store".to_owned(),
        ))
    }
    async fn update_invitation_team_ids(
        &self,
        _id: &str,
        _team_ids: Option<String>,
    ) -> AuthResult<Invitation> {
        Err(AuthError::NotImplemented(
            "Invitation team updates are not supported by this store".to_owned(),
        ))
    }
}

#[async_trait]
pub trait TwoFactorStore: Send + Sync {
    async fn create_two_factor(&self, two_factor: CreateTwoFactor) -> AuthResult<TwoFactor>;
    async fn get_two_factor_by_user_id(&self, user_id: &str) -> AuthResult<Option<TwoFactor>>;
    async fn update_two_factor_backup_codes(
        &self,
        user_id: &str,
        backup_codes: &str,
    ) -> AuthResult<TwoFactor>;
    async fn delete_two_factor(&self, user_id: &str) -> AuthResult<()>;
    async fn update_two_factor(
        &self,
        id: &str,
        update: UpdateTwoFactor,
    ) -> AuthResult<Option<TwoFactor>> {
        drop((id, update));
        Err(AuthError::not_implemented(
            "Exact factor updates are not supported by this store",
        ))
    }
    /// Atomically increment the stored counter, returning the winning row.
    /// SQL-backed adapters preserve NULL, matching the pinned Kysely adapter.
    async fn increment_two_factor_failure(&self, _id: &str) -> AuthResult<Option<TwoFactor>> {
        Err(AuthError::not_implemented(
            "Atomic factor failure increments are not supported by this store",
        ))
    }
    async fn set_two_factor_lock_if_count_at_least(
        &self,
        _id: &str,
        _threshold: f64,
        _until: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<Option<TwoFactor>> {
        Err(AuthError::not_implemented(
            "Conditional factor locking is not supported by this store",
        ))
    }
    async fn clear_expired_two_factor_lock(
        &self,
        _id: &str,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<Option<TwoFactor>> {
        Err(AuthError::not_implemented(
            "Conditional factor unlocking is not supported by this store",
        ))
    }
    async fn reset_two_factor_failures(&self, _id: &str) -> AuthResult<()> {
        Err(AuthError::not_implemented(
            "Factor failure reset is not supported by this store",
        ))
    }
    async fn compare_and_swap_two_factor_backup_codes(
        &self,
        _id: &str,
        _expected: &str,
        _replacement: &str,
    ) -> AuthResult<bool> {
        Err(AuthError::not_implemented(
            "Atomic factor backup consumption is not supported by this store",
        ))
    }
}

#[async_trait]
pub trait ApiKeyStore: Send + Sync {
    async fn create_api_key(&self, input: CreateApiKey) -> AuthResult<ApiKey>;
    async fn get_api_key_by_id(&self, id: &str) -> AuthResult<Option<ApiKey>>;
    async fn get_api_key_by_hash(&self, hash: &str) -> AuthResult<Option<ApiKey>>;
    async fn list_api_keys_by_reference(&self, reference_id: &str) -> AuthResult<Vec<ApiKey>>;
    async fn update_api_key(&self, id: &str, update: UpdateApiKey) -> AuthResult<ApiKey>;
    async fn delete_api_key(&self, id: &str) -> AuthResult<()>;
    async fn delete_expired_api_keys(&self) -> AuthResult<usize>;

    /// Atomically consume one use of an API key: decrement remaining
    /// (with refill), increment rate-limit counter, and update timestamps.
    ///
    /// All counter mutations are derived from the locked row inside a
    /// transaction, preventing concurrent requests from corrupting counters.
    /// Read-only checks (enabled, expired, permissions) happen before this
    /// call in the plugin layer.
    ///
    /// `global_rate_limit_enabled`: whether the plugin-level rate limiting
    /// is turned on. Per-key settings are read from the locked row.
    async fn consume_api_key_usage(
        &self,
        id: &str,
        global_rate_limit_enabled: bool,
    ) -> AuthResult<ConsumeApiKeyResult>;

    /// Consume usage from the validated database snapshot with Source write phases.
    /// Quota/refill and rate claims are independently guarded atomic writes;
    /// successful earlier writes survive a later storage failure. Finally touch
    /// `updated_at` and return the current row. This is distinct from the combined
    /// transactional operation above and cannot be supplied by delegating to it.
    async fn consume_api_key_usage_from_snapshot(
        &self,
        _observed: &ApiKey,
        _global_rate_limit_enabled: bool,
    ) -> AuthResult<ConsumeApiKeyResult> {
        Err(AuthError::internal(
            "snapshot-aware API key consumption is unsupported by this store",
        ))
    }
}

/// Outcome of an atomic API key usage consumption.
pub enum ConsumeApiKeyResult {
    /// The key was valid and counters were updated. Contains the updated key.
    Allowed(Box<ApiKey>),
    /// The rate limit was exceeded after consuming the request's usage quota.
    RateLimited {
        /// Milliseconds until the current rate-limit window ends.
        try_again_in: f64,
    },
    /// The quota was exhausted. Non-refillable keys at zero quota are deleted.
    UsageExhausted,
}

#[async_trait]
pub trait PasskeyStore: Send + Sync {
    async fn create_passkey(&self, input: CreatePasskey) -> AuthResult<Passkey>;
    async fn get_passkey_by_id(&self, id: &str) -> AuthResult<Option<Passkey>>;
    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> AuthResult<Option<Passkey>>;
    async fn list_passkeys_by_user(&self, user_id: &str) -> AuthResult<Vec<Passkey>>;
    /// Update the verified credential, returning `None` if application code removed its row.
    /// Storage failures remain errors; an absent row does not invalidate completed verification.
    async fn update_passkey_authentication(
        &self,
        id: &str,
        update: UpdatePasskeyAuthentication,
    ) -> AuthResult<Option<Passkey>>;
    async fn update_passkey_name(&self, id: &str, name: &str) -> AuthResult<Passkey>;
    async fn delete_passkey(&self, id: &str) -> AuthResult<()>;
}

/// Persistence for OAuth device authorization codes.
#[async_trait]
pub trait DeviceCodeStore: Send + Sync {
    /// Persist a newly-issued device code.
    async fn create_device_code(&self, input: CreateDeviceCode) -> AuthResult<DeviceCode>;
    /// Fetch a device code by its opaque device-facing token.
    async fn get_device_code_by_device_code(
        &self,
        device_code: &str,
    ) -> AuthResult<Option<DeviceCode>>;
    /// Fetch a device code by its user-facing verification code.
    async fn get_device_code_by_user_code(&self, user_code: &str)
    -> AuthResult<Option<DeviceCode>>;
    /// Update mutable device-code state such as approval status or poll time.
    async fn update_device_code(
        &self,
        id: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<DeviceCode>;
    /// Update a device code only when it still has the expected status.
    ///
    /// Returns `true` when the compare-and-swap succeeds, or `false` when the
    /// row was already moved to a different state.
    async fn update_device_code_if_status(
        &self,
        id: &str,
        current_status: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<bool>;
    /// Bind a still-pending, still-unclaimed device code to a user.
    ///
    /// Returns `true` when this call performed the claim, and `false` when the
    /// row was already claimed or no longer pending. The status and
    /// unclaimed checks are part of the write so two concurrent verifiers
    /// cannot both claim the same code.
    async fn claim_device_code(&self, id: &str, user_id: &str) -> AuthResult<bool>;
    /// Delete a device code record.
    async fn delete_device_code(&self, id: &str) -> AuthResult<()>;
    /// Delete a device code only when it still has the expected status.
    ///
    /// Returns `true` when a matching row was deleted and `false` otherwise.
    async fn delete_device_code_if_status(&self, id: &str, status: &str) -> AuthResult<bool>;
}

#[async_trait]
pub trait TransactionStore<S: AuthSchema>: Send + Sync {
    async fn transaction_boxed(
        &self,
        work: Box<TransactionWork<S>>,
    ) -> AuthResult<BoxedTransactionValue>;
}

pub trait AuthStore<S: AuthSchema>:
    UserStore<S>
    + SessionStore<S>
    + AccountStore<S>
    + VerificationStore<S>
    + OrganizationStore
    + MemberStore
    + InvitationStore
    + TeamStore
    + OrganizationRoleStore
    + WalletAddressStore
    + TwoFactorStore
    + ApiKeyStore
    + PasskeyStore
    + DeviceCodeStore
    + JwkStore
    + TransactionStore<S>
    + Send
    + Sync
{
}

impl<S, T> AuthStore<S> for T
where
    S: AuthSchema,
    T: UserStore<S>
        + SessionStore<S>
        + AccountStore<S>
        + VerificationStore<S>
        + OrganizationStore
        + MemberStore
        + InvitationStore
        + TeamStore
        + OrganizationRoleStore
        + WalletAddressStore
        + TwoFactorStore
        + ApiKeyStore
        + PasskeyStore
        + DeviceCodeStore
        + JwkStore
        + TransactionStore<S>
        + Send
        + Sync,
{
}

impl std::fmt::Debug for ConsumeApiKeyResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allowed(..) => f.write_str("ConsumeApiKeyResult::Allowed"),
            Self::RateLimited { .. } => f.write_str("ConsumeApiKeyResult::RateLimited"),
            Self::UsageExhausted => f.write_str("ConsumeApiKeyResult::UsageExhausted"),
        }
    }
}

fn create_data(mut data: CreateUser, transforms: &[UserCreateTransform]) -> AuthResult<CreateUser> {
    for transform in transforms {
        data = transform(data)?;
    }
    Ok(data)
}

/// Upstream's deterministic database key for first-writer verification claims.
#[must_use]
pub fn verification_reservation_key(identifier: &str) -> (String, [u8; 32]) {
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let mut hash = Sha256::new();
    hash.update(b"reserve:");
    hash.update(identifier.as_bytes());
    let digest: [u8; 32] = hash.finalize().into();
    (
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest),
        digest,
    )
}

///
/// # Errors
///
/// Propagates transaction or callback errors; also rejects an unexpected transaction result type.
pub async fn transaction<S, T, F>(store: &dyn AuthStore<S>, work: F) -> AuthResult<T>
where
    S: AuthSchema,
    T: Send + 'static,
    F: for<'tx> FnOnce(&'tx dyn AuthTransaction<S>) -> TypedTransactionFuture<'tx, T>
        + Send
        + 'static,
{
    let value = store
        .transaction_boxed(Box::new(move |tx| {
            Box::pin(async move {
                let result: BoxedTransactionValue = Box::new(work(tx).await?);
                Ok(result)
            })
        }))
        .await?;

    value
        .downcast::<T>()
        .map(|boxed| *boxed)
        .map_err(|_error| AuthError::internal("store returned an invalid transaction payload"))
}
