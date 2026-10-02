//! Application-owned adapter that gates only the real bulk deletion.
//! Every other operation delegates unchanged to the bundled SeaORM store.
use super::Application;
use better_auth::__private_core::store::*;
use better_auth::__private_core::types::*;
use better_auth::__private_core::{AuthResult, AuthSchema};
use better_auth_seaorm::SeaOrmStore;

pub(super) struct ControlledStore<S: AuthSchema> {
    pub(super) inner: SeaOrmStore<S>,
    pub(super) application: Application,
    pub(super) profile: &'static str,
}
macro_rules! delegate_store {
    ($trait:ident $(<$schema:ident>)?, { $(async fn $name:ident(&self $(, $argument:ident: $ty:ty)* $(,)?) -> $output:ty;)* }) => {
        #[async_trait::async_trait]
        impl<S: AuthSchema> $trait $(<$schema>)? for ControlledStore<S>
        where SeaOrmStore<S>: $trait $(<$schema>)? {
            $(async fn $name(&self $(, $argument: $ty)*) -> $output {
                self.inner.$name($($argument),*).await
            })*
        }
    };
}
delegate_store!(UserStore<S>, {
    async fn create_user(&self, create_user: CreateUser) -> AuthResult<S::User>;
    async fn coerce_user_text_number(&self, _input: NumericTextInput) -> AuthResult<String>;
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<S::User>>;
    async fn list_users_by_ids(&self, ids: &[String]) -> AuthResult<Vec<S::User>>;
    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<S::User>>;
    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<S::User>>;
    async fn get_user_by_phone_number(&self, phone_number: &str) -> AuthResult<Option<S::User>>;
    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<S::User>;
    async fn delete_user(&self, id: &str) -> AuthResult<()>;
    async fn list_users(&self, params: ListUsersParams) -> AuthResult<(Vec<S::User>, usize)>;
});
delegate_store!(SessionStore<S>, {
    async fn update_session_fields(
        &self,
        _token: &str,
        _fields: better_auth::__private_core::field_policy::FieldValues,
    ) -> AuthResult<Option<S::Session>>;
    async fn create_session(&self, create_session: CreateSession) -> AuthResult<S::Session>;
    async fn get_session(&self, token: &str) -> AuthResult<Option<S::Session>>;
    async fn get_sessions_by_tokens(&self, tokens: &[String]) -> AuthResult<Vec<S::Session>>;
    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<S::Session>>;
    async fn update_session_expiry(
        &self,
        token: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<()>;
    async fn refresh_session(
        &self,
        token: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<Option<S::Session>>;
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
        token: &str,
        team_id: Option<&str>,
    ) -> AuthResult<S::Session>;
});
delegate_store!(AccountStore<S>, {
    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<S::Account>;
    async fn get_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<S::Account>>;
    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<S::Account>>;
    async fn update_account(&self, id: &str, update: UpdateAccount) -> AuthResult<S::Account>;
    async fn delete_account(&self, id: &str) -> AuthResult<()>;
});
delegate_store!(VerificationStore<S>, {
    async fn create_verification_record(
        &self,
        data: better_auth::__private_core::verification::VerificationCreation,
        publication: better_auth::__private_core::verification::VerificationPublication,
    ) -> AuthResult<Option<better_auth::__private_core::verification::VerificationSnapshot>>;
    async fn consume_verification_snapshot(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>>;
    async fn update_verification_by_identifier(
        &self,
        identifier: &str,
        data: UpdateVerification,
    ) -> AuthResult<Option<better_auth::__private_core::verification::VerificationSnapshot>>;
    async fn reserve_verification_record(
        &self,
        logical_identifier: &str,
        data: CreateVerification,
    ) -> AuthResult<Option<S::Verification>>;
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
    async fn get_latest_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>>;
    async fn consume_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>>;
    async fn delete_verifications_by_identifier(&self, identifier: &str) -> AuthResult<()>;
    async fn compare_and_swap_verification(
        &self,
        id: &str,
        expected_value: &str,
        value: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<bool>;
    async fn reserve_verification(&self, verification: CreateVerification) -> AuthResult<bool>;
    async fn delete_verification(&self, id: &str) -> AuthResult<()>;
    async fn delete_expired_verifications(&self) -> AuthResult<usize>;
});
delegate_store!(OrganizationStore, {
    async fn create_organization(&self, org: CreateOrganization) -> AuthResult<Organization>;
    async fn get_organization_by_id(&self, id: &str) -> AuthResult<Option<Organization>>;
    async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<Organization>>;
    async fn list_organizations_by_ids(&self, ids: &[String]) -> AuthResult<Vec<Organization>>;
    async fn update_organization(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Organization>;
    async fn delete_organization(&self, id: &str) -> AuthResult<()>;
    async fn list_user_organizations(&self, user_id: &str) -> AuthResult<Vec<Organization>>;
});
delegate_store!(MemberStore, {
    async fn create_member(&self, member: CreateMember) -> AuthResult<Member>;
    async fn get_member(&self, organization_id: &str, user_id: &str) -> AuthResult<Option<Member>>;
    async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<Member>>;
    async fn update_member_role(&self, member_id: &str, role: &str) -> AuthResult<Member>;
    async fn delete_member(&self, member_id: &str) -> AuthResult<()>;
    async fn list_organization_members(&self, org_id: &str) -> AuthResult<Vec<Member>>;
    async fn query_organization_members(
        &self,
        params: &ListOrganizationMembersParams,
    ) -> AuthResult<(Vec<Member>, usize)>;
    async fn count_organization_members(&self, org_id: &str) -> AuthResult<i64>;
    async fn count_organization_owners(&self, org_id: &str) -> AuthResult<i64>;
});
delegate_store!(InvitationStore, {
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
    async fn list_organization_invitations(&self, org_id: &str) -> AuthResult<Vec<Invitation>>;
    async fn count_pending_organization_invitations(&self, org_id: &str) -> AuthResult<i64>;
    async fn list_user_invitations(&self, email: &str) -> AuthResult<Vec<Invitation>>;
    async fn accept_invitation_with_teams(
        &self,
        _invitation_id: &str,
        _user_id: &str,
        _session_token: &str,
        _team_limits: &[(String, Option<usize>)],
        _membership_limit: Option<usize>,
    ) -> AuthResult<Option<(Invitation, Member)>>;
    async fn update_invitation_team_ids(
        &self,
        _id: &str,
        _team_ids: Option<String>,
    ) -> AuthResult<Invitation>;
});
delegate_store!(TwoFactorStore, {
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
    ) -> AuthResult<Option<TwoFactor>>;
    async fn increment_two_factor_failure(&self, id: &str) -> AuthResult<Option<TwoFactor>>;
    async fn set_two_factor_lock_if_count_at_least(
        &self,
        id: &str,
        threshold: f64,
        until: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<Option<TwoFactor>>;
    async fn clear_expired_two_factor_lock(
        &self,
        id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<Option<TwoFactor>>;
    async fn reset_two_factor_failures(&self, id: &str) -> AuthResult<()>;
    async fn compare_and_swap_two_factor_backup_codes(
        &self,
        id: &str,
        expected: &str,
        replacement: &str,
    ) -> AuthResult<bool>;
});
delegate_store!(PasskeyStore, {
    async fn create_passkey(&self, input: CreatePasskey) -> AuthResult<Passkey>;
    async fn get_passkey_by_id(&self, id: &str) -> AuthResult<Option<Passkey>>;
    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> AuthResult<Option<Passkey>>;
    async fn list_passkeys_by_user(&self, user_id: &str) -> AuthResult<Vec<Passkey>>;
    async fn update_passkey_authentication(
        &self,
        id: &str,
        update: UpdatePasskeyAuthentication,
    ) -> AuthResult<Option<Passkey>>;
    async fn update_passkey_name(&self, id: &str, name: &str) -> AuthResult<Passkey>;
    async fn delete_passkey(&self, id: &str) -> AuthResult<()>;
});
delegate_store!(DeviceCodeStore, {
    async fn create_device_code(&self, input: CreateDeviceCode) -> AuthResult<DeviceCode>;
    async fn get_device_code_by_device_code(
        &self,
        device_code: &str,
    ) -> AuthResult<Option<DeviceCode>>;
    async fn get_device_code_by_user_code(&self, user_code: &str)
    -> AuthResult<Option<DeviceCode>>;
    async fn update_device_code(
        &self,
        id: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<DeviceCode>;
    async fn update_device_code_if_status(
        &self,
        id: &str,
        current_status: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<bool>;
    async fn claim_device_code(&self, id: &str, user_id: &str) -> AuthResult<bool>;
    async fn delete_device_code(&self, id: &str) -> AuthResult<()>;
    async fn delete_device_code_if_status(&self, id: &str, status: &str) -> AuthResult<bool>;
});
delegate_store!(TransactionStore<S>, {
    async fn transaction_boxed(
        &self,
        work: Box<TransactionWork<S>>,
    ) -> AuthResult<BoxedTransactionValue>;
});
delegate_store!(TeamStore, {
    async fn create_team(&self, _data: CreateTeam) -> AuthResult<Team>;
    async fn get_team(
        &self,
        _organization_id: Option<&str>,
        _team_id: &str,
    ) -> AuthResult<Option<Team>>;
    async fn list_teams(&self, _organization_id: &str) -> AuthResult<Vec<Team>>;
    async fn update_team(
        &self,
        _organization_id: &str,
        _team_id: &str,
        _update: UpdateTeam,
    ) -> AuthResult<Team>;
    async fn delete_team(&self, _organization_id: &str, _team_id: &str) -> AuthResult<bool>;
    async fn get_team_member(
        &self,
        _team_id: &str,
        _user_id: &str,
    ) -> AuthResult<Option<TeamMember>>;
    async fn add_team_member(
        &self,
        _team_id: &str,
        _user_id: &str,
        _maximum: Option<usize>,
    ) -> AuthResult<AddTeamMemberResult>;
    async fn remove_team_member(&self, _team_id: &str, _user_id: &str) -> AuthResult<usize>;
    async fn list_team_members(&self, _team_id: &str) -> AuthResult<Vec<TeamMember>>;
    async fn list_user_teams(&self, _user_id: &str) -> AuthResult<Vec<Team>>;
});
delegate_store!(OrganizationRoleStore, {
    async fn create_organization_role(
        &self,
        _data: CreateOrganizationRole,
    ) -> AuthResult<OrganizationRole>;
    async fn get_organization_role(
        &self,
        _organization_id: &str,
        _selector: &OrganizationRoleSelector,
    ) -> AuthResult<Option<OrganizationRole>>;
    async fn list_organization_roles(
        &self,
        _organization_id: &str,
    ) -> AuthResult<Vec<OrganizationRole>>;
    async fn count_organization_roles(&self, _organization_id: &str) -> AuthResult<usize>;
    async fn has_organization_role_members(
        &self,
        _organization_id: &str,
        _role: &str,
    ) -> AuthResult<bool>;
    async fn update_organization_role(
        &self,
        _organization_id: &str,
        _selector: &OrganizationRoleSelector,
        _update: UpdateOrganizationRole,
    ) -> AuthResult<OrganizationRole>;
    async fn delete_organization_role(
        &self,
        _organization_id: &str,
        _selector: &OrganizationRoleSelector,
    ) -> AuthResult<bool>;
});
delegate_store!(JwkStore, {
    async fn list_jwks(&self) -> AuthResult<Vec<Jwk>>;
    async fn get_jwk_by_id(&self, _id: &str) -> AuthResult<Option<Jwk>>;
    async fn create_jwk(&self, _data: CreateJwk) -> AuthResult<Jwk>;
});
delegate_store!(WalletAddressStore, {
    async fn get_wallet_address(
        &self,
        _address: &str,
        _chain_id: Option<f64>,
    ) -> AuthResult<Option<WalletAddress>>;
    async fn create_wallet_address(&self, _data: CreateWalletAddress) -> AuthResult<WalletAddress>;
});
#[async_trait::async_trait]
impl<S: AuthSchema> ApiKeyStore for ControlledStore<S>
where
    SeaOrmStore<S>: ApiKeyStore,
{
    async fn consume_api_key_usage_from_snapshot(
        &self,
        observed: &ApiKey,
        global_rate_limit_enabled: bool,
    ) -> AuthResult<ConsumeApiKeyResult> {
        let serial = self
            .application
            .begin_usage(self.profile, &observed.id)
            .await;
        let result = self
            .inner
            .consume_api_key_usage_from_snapshot(observed, global_rate_limit_enabled)
            .await;
        if let Some(serial) = serial {
            self.application.finish_usage(serial, result.is_ok());
        }
        result
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
        let serial = self.application.begin_delete(self.profile, id).await;
        let result = self.inner.delete_api_key(id).await;
        self.application.finish_delete(serial, result.is_ok());
        result
    }
    async fn delete_expired_api_keys(&self) -> AuthResult<usize> {
        let admission = self.application.begin(self.profile).await;
        let result = self.inner.delete_expired_api_keys().await;
        self.application.finish(admission, result.is_ok());
        result
    }
    async fn consume_api_key_usage(
        &self,
        id: &str,
        global_rate_limit_enabled: bool,
    ) -> AuthResult<ConsumeApiKeyResult> {
        let serial = self.application.begin_usage(self.profile, id).await;
        let result = self
            .inner
            .consume_api_key_usage(id, global_rate_limit_enabled)
            .await;
        if let Some(serial) = serial {
            self.application.finish_usage(serial, result.is_ok());
        }
        result
    }
}
