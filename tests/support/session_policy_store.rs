//! A real store wrapper injecting an explicit application policy at session lookup.
use async_trait::async_trait;
use better_auth_core::store::*;
use better_auth_core::types::*;
use better_auth_core::{AuthError, AuthResult, AuthSchema};
use better_auth_seaorm::SeaOrmStore;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

#[expect(
    unreachable_pub,
    reason = "The private fixture module exposes its store and schema only to the parent integration test"
)]
pub type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

#[expect(
    unreachable_pub,
    reason = "The private fixture module exposes its store and schema only to the parent integration test"
)]
pub struct PolicyStore {
    pub(super) inner: Arc<SeaOrmStore<Schema>>,
    pub(super) reject: Arc<AtomicBool>,
    pub(super) rejected_reads: Arc<AtomicUsize>,
}

// Forward the real persistence operations required by AuthBuilder. Optional
// plugin operations keep their normal unsupported defaults in this fixture.
macro_rules! forwarding {
    ($trait_type:ty {$(fn $method:ident($($arg:ident: $arg_type:ty),*) -> $result:ty;)*}) => {
        #[async_trait]
        impl $trait_type for PolicyStore {
            $(async fn $method(&self, $($arg: $arg_type),*) -> $result {
                self.inner.$method($($arg),*).await
            })*
        }
    };
}
forwarding!(UserStore<Schema> {
    fn create_user(create_user: CreateUser) -> AuthResult<<Schema as AuthSchema>::User>;
    fn get_user_by_id(id: &str) -> AuthResult<Option<<Schema as AuthSchema>::User>>;
    fn list_users_by_ids(ids: &[String]) -> AuthResult<Vec<<Schema as AuthSchema>::User>>;
    fn get_user_by_email(email: &str) -> AuthResult<Option<<Schema as AuthSchema>::User>>;
    fn get_user_by_username(username: &str) -> AuthResult<Option<<Schema as AuthSchema>::User>>;
    fn update_user(id: &str, update: UpdateUser) -> AuthResult<<Schema as AuthSchema>::User>;
    fn delete_user(id: &str) -> AuthResult<()>;
    fn list_users(params: ListUsersParams) -> AuthResult<(Vec<<Schema as AuthSchema>::User>, usize)>;
});

forwarding!(AccountStore<Schema> {
    fn create_account(create_account: CreateAccount) -> AuthResult<<Schema as AuthSchema>::Account>;
    fn get_account(provider: &str, provider_account_id: &str) -> AuthResult<Option<<Schema as AuthSchema>::Account>>;
    fn get_user_accounts(user_id: &str) -> AuthResult<Vec<<Schema as AuthSchema>::Account>>;
    fn update_account(id: &str, update: UpdateAccount) -> AuthResult<<Schema as AuthSchema>::Account>;
    fn delete_account(id: &str) -> AuthResult<()>;
});

forwarding!(VerificationStore<Schema> {
    fn create_verification_record(data: better_auth_core::verification::VerificationCreation, publication: better_auth_core::verification::VerificationPublication) -> AuthResult<Option<better_auth_core::verification::VerificationSnapshot>>;
    fn consume_verification_snapshot(identifier: &str) -> AuthResult<Option<<Schema as AuthSchema>::Verification>>;
    fn update_verification_by_identifier(identifier: &str, data: UpdateVerification) -> AuthResult<Option<better_auth_core::verification::VerificationSnapshot>>;
    fn reserve_verification_record(logical_identifier: &str, data: CreateVerification) -> AuthResult<Option<<Schema as AuthSchema>::Verification>>;
    fn create_verification(verification: CreateVerification) -> AuthResult<<Schema as AuthSchema>::Verification>;
    fn get_latest_verification_by_identifier(identifier: &str) -> AuthResult<Option<<Schema as AuthSchema>::Verification>>;
    fn delete_verifications_by_identifier(identifier: &str) -> AuthResult<()>;
    fn get_verification(identifier: &str, value: &str) -> AuthResult<Option<<Schema as AuthSchema>::Verification>>;
    fn get_verification_by_value(value: &str) -> AuthResult<Option<<Schema as AuthSchema>::Verification>>;
    fn get_verification_by_identifier(identifier: &str) -> AuthResult<Option<<Schema as AuthSchema>::Verification>>;
    fn consume_verification(identifier: &str, value: &str) -> AuthResult<Option<<Schema as AuthSchema>::Verification>>;
    fn delete_verification(id: &str) -> AuthResult<()>;
    fn delete_expired_verifications() -> AuthResult<usize>;
});

forwarding!(OrganizationStore {
    fn create_organization(org: CreateOrganization) -> AuthResult<Organization>;
    fn get_organization_by_id(id: &str) -> AuthResult<Option<Organization>>;
    fn get_organization_by_slug(slug: &str) -> AuthResult<Option<Organization>>;
    fn list_organizations_by_ids(ids: &[String]) -> AuthResult<Vec<Organization>>;
    fn update_organization(id: &str, update: UpdateOrganization) -> AuthResult<Organization>;
    fn delete_organization(id: &str) -> AuthResult<()>;
    fn list_user_organizations(user_id: &str) -> AuthResult<Vec<Organization>>;
});

forwarding!(MemberStore {
    fn create_member(member: CreateMember) -> AuthResult<Member>;
    fn get_member(organization_id: &str, user_id: &str) -> AuthResult<Option<Member>>;
    fn get_member_by_id(id: &str) -> AuthResult<Option<Member>>;
    fn update_member_role(member_id: &str, role: &str) -> AuthResult<Member>;
    fn delete_member(member_id: &str) -> AuthResult<()>;
    fn list_organization_members(org_id: &str) -> AuthResult<Vec<Member>>;
    fn query_organization_members(params: &ListOrganizationMembersParams) -> AuthResult<(Vec<Member>, usize)>;
    fn count_organization_members(org_id: &str) -> AuthResult<i64>;
    fn count_organization_owners(org_id: &str) -> AuthResult<i64>;
});

forwarding!(InvitationStore {
    fn create_invitation(invitation: CreateInvitation) -> AuthResult<Invitation>;
    fn get_invitation_by_id(id: &str) -> AuthResult<Option<Invitation>>;
    fn get_pending_invitation(org_id: &str, email: &str) -> AuthResult<Option<Invitation>>;
    fn update_invitation_status(id: &str, status: InvitationStatus) -> AuthResult<Invitation>;
    fn list_organization_invitations(org_id: &str) -> AuthResult<Vec<Invitation>>;
    fn count_pending_organization_invitations(org_id: &str) -> AuthResult<i64>;
    fn list_user_invitations(email: &str) -> AuthResult<Vec<Invitation>>;
});

forwarding!(TwoFactorStore {
    fn create_two_factor(two_factor: CreateTwoFactor) -> AuthResult<TwoFactor>;
    fn get_two_factor_by_user_id(user_id: &str) -> AuthResult<Option<TwoFactor>>;
    fn update_two_factor_backup_codes(user_id: &str, backup_codes: &str) -> AuthResult<TwoFactor>;
    fn delete_two_factor(user_id: &str) -> AuthResult<()>;
});

forwarding!(ApiKeyStore {
    fn create_api_key(input: CreateApiKey) -> AuthResult<ApiKey>;
    fn get_api_key_by_id(id: &str) -> AuthResult<Option<ApiKey>>;
    fn get_api_key_by_hash(hash: &str) -> AuthResult<Option<ApiKey>>;
    fn list_api_keys_by_reference(reference_id: &str) -> AuthResult<Vec<ApiKey>>;
    fn update_api_key(id: &str, update: UpdateApiKey) -> AuthResult<ApiKey>;
    fn delete_api_key(id: &str) -> AuthResult<()>;
    fn delete_expired_api_keys() -> AuthResult<usize>;
    fn consume_api_key_usage(id: &str, global_rate_limit_enabled: bool) -> AuthResult<ConsumeApiKeyResult>;
});

forwarding!(PasskeyStore {
    fn create_passkey(input: CreatePasskey) -> AuthResult<Passkey>;
    fn get_passkey_by_id(id: &str) -> AuthResult<Option<Passkey>>;
    fn get_passkey_by_credential_id(credential_id: &str) -> AuthResult<Option<Passkey>>;
    fn list_passkeys_by_user(user_id: &str) -> AuthResult<Vec<Passkey>>;
    fn update_passkey_authentication(id: &str, update: UpdatePasskeyAuthentication) -> AuthResult<Option<Passkey>>;
    fn update_passkey_name(id: &str, name: &str) -> AuthResult<Passkey>;
    fn delete_passkey(id: &str) -> AuthResult<()>;
});

forwarding!(DeviceCodeStore {
    fn create_device_code(input: CreateDeviceCode) -> AuthResult<DeviceCode>;
    fn get_device_code_by_device_code(device_code: &str) -> AuthResult<Option<DeviceCode>>;
    fn get_device_code_by_user_code(user_code: &str) -> AuthResult<Option<DeviceCode>>;
    fn update_device_code(id: &str, update: UpdateDeviceCode) -> AuthResult<DeviceCode>;
    fn update_device_code_if_status(id: &str, current_status: &str, update: UpdateDeviceCode) -> AuthResult<bool>;
    fn claim_device_code(id: &str, user_id: &str) -> AuthResult<bool>;
    fn delete_device_code(id: &str) -> AuthResult<()>;
    fn delete_device_code_if_status(id: &str, status: &str) -> AuthResult<bool>;
});

forwarding!(TransactionStore<Schema> {
    fn transaction_boxed(work: Box<TransactionWork<Schema>>) -> AuthResult<BoxedTransactionValue>;
});

#[async_trait]
impl JwkStore for PolicyStore {}

impl TeamStore for PolicyStore {}
#[async_trait]
impl OrganizationRoleStore for PolicyStore {}
impl WalletAddressStore for PolicyStore {}

#[async_trait]
impl SessionStore<Schema> for PolicyStore {
    async fn create_session(
        &self,
        create_session: CreateSession,
    ) -> AuthResult<<Schema as AuthSchema>::Session> {
        self.inner.create_session(create_session).await
    }
    async fn get_session(
        &self,
        token: &str,
    ) -> AuthResult<Option<<Schema as AuthSchema>::Session>> {
        let row = self.inner.get_session(token).await?;
        if row.is_some() && self.reject.load(Ordering::SeqCst) {
            _ = self.rejected_reads.fetch_add(1, Ordering::SeqCst);
            return Err(AuthError::Upstream {
                status: 403,
                code: "FIXTURE_SESSION_POLICY",
                message: "Fixture session policy",
            });
        }
        Ok(row)
    }
    async fn get_user_sessions(
        &self,
        user_id: &str,
    ) -> AuthResult<Vec<<Schema as AuthSchema>::Session>> {
        self.inner.get_user_sessions(user_id).await
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
    ) -> AuthResult<<Schema as AuthSchema>::Session> {
        self.inner
            .update_session_active_organization(token, organization_id)
            .await
    }
}
