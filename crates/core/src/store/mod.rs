use async_trait::async_trait;
use std::any::Any;
use std::future::Future;
use std::pin::Pin;

pub mod cache;
mod org_extensions;
pub use org_extensions::{OrganizationRoleStore, TeamStore, team_membership_key};

use crate::error::{AuthError, AuthResult};
use crate::schema::AuthSchema;
use crate::types::{
    ApiKey, CreateAccount, CreateApiKey, CreateDeviceCode, CreateInvitation, CreateMember,
    CreateOrganization, CreatePasskey, CreateSession, CreateTwoFactor, CreateUser,
    CreateVerification, DeviceCode, Invitation, InvitationStatus, ListUsersParams, Member,
    Organization, Passkey, TwoFactor, UpdateAccount, UpdateApiKey, UpdateDeviceCode,
    UpdateOrganization, UpdatePasskeyAuthentication, UpdateUser,
};

pub use cache::{CacheAdapter, MemoryCacheAdapter};

#[cfg(feature = "redis-cache")]
pub use cache::RedisAdapter;

pub type BoxedTransactionValue = Box<dyn Any + Send>;
pub type TransactionFuture<'a> =
    Pin<Box<dyn Future<Output = AuthResult<BoxedTransactionValue>> + Send + 'a>>;
pub type TypedTransactionFuture<'a, T> = Pin<Box<dyn Future<Output = AuthResult<T>> + Send + 'a>>;
pub type TransactionWork<S> =
    dyn for<'tx> FnOnce(&'tx dyn AuthTransaction<S>) -> TransactionFuture<'tx> + Send;

#[async_trait]
pub trait AuthTransaction<S: AuthSchema>: Send + Sync {
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

#[async_trait]
pub trait UserStore<S: AuthSchema>: Send + Sync {
    async fn create_user(&self, create_user: CreateUser) -> AuthResult<S::User>;
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<S::User>>;
    /// Fetch multiple users by id.
    ///
    /// Implementations may return rows in any order. Callers must remap by id
    /// when response order matters.
    async fn list_users_by_ids(&self, ids: &[String]) -> AuthResult<Vec<S::User>>;
    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<S::User>>;
    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<S::User>>;
    async fn get_user_by_phone_number(&self, phone_number: &str) -> AuthResult<Option<S::User>> {
        let _ = phone_number;
        Err(crate::AuthError::internal(
            "phone-number lookup is not supported by this store",
        ))
    }
    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<S::User>;
    async fn delete_user(&self, id: &str) -> AuthResult<()>;
    async fn list_users(&self, params: ListUsersParams) -> AuthResult<(Vec<S::User>, usize)>;
}

#[async_trait]
pub trait SessionStore<S: AuthSchema>: Send + Sync {
    async fn create_session(&self, create_session: CreateSession) -> AuthResult<S::Session>;
    async fn get_session(&self, token: &str) -> AuthResult<Option<S::Session>>;
    /// Fetch matching sessions once each, including expired rows. The bundled
    /// SQLite adapter returns token-index order rather than request order.
    async fn get_sessions_by_tokens(&self, tokens: &[String]) -> AuthResult<Vec<S::Session>> {
        let mut sessions = Vec::new();
        for token in tokens.iter().collect::<std::collections::BTreeSet<_>>() {
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
            Err(crate::AuthError::SessionNotFound) => Ok(None),
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
        token: &str,
        team_id: Option<&str>,
    ) -> AuthResult<S::Session> {
        let _ = (token, team_id);
        Err(crate::AuthError::internal(
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
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        let _ = identifier;
        Err(crate::AuthError::internal(
            "raw verification lookup is not supported by this store",
        ))
    }
    /// Atomically invalidate an identifier and return its newest generation.
    /// Exactly one concurrent caller can receive a row. Expired records are
    /// removed along with every sibling and return `None`.
    async fn consume_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        let _ = identifier;
        Err(crate::AuthError::internal(
            "atomic verification consumption is not supported by this store",
        ))
    }
    async fn delete_verifications_by_identifier(&self, identifier: &str) -> AuthResult<()> {
        let _ = identifier;
        Err(crate::AuthError::internal(
            "verification invalidation is not supported by this store",
        ))
    }
    /// Update a generation only when its value still matches the snapshot.
    async fn compare_and_swap_verification(
        &self,
        id: &str,
        expected_value: &str,
        value: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<bool> {
        let _ = (id, expected_value, value, expires_at);
        Err(crate::AuthError::internal(
            "atomic verification updates are not supported by this store",
        ))
    }
    /// Insert a deterministic reservation exactly once. An expired marker
    /// remains reserved until it is cleaned up or explicitly consumed.
    async fn reserve_verification(&self, verification: CreateVerification) -> AuthResult<bool> {
        let _ = verification;
        Err(crate::AuthError::internal(
            "verification reservation is not supported by this store",
        ))
    }
    async fn delete_verification(&self, id: &str) -> AuthResult<()>;
    async fn delete_expired_verifications(&self) -> AuthResult<usize>;
}

/// Upstream's deterministic database key for first-writer verification claims.
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
    async fn delete_organization(&self, id: &str) -> AuthResult<()>;
    async fn list_user_organizations(&self, user_id: &str) -> AuthResult<Vec<Organization>>;
}

#[async_trait]
pub trait MemberStore: Send + Sync {
    async fn create_member(&self, member: CreateMember) -> AuthResult<Member>;
    async fn get_member(&self, organization_id: &str, user_id: &str) -> AuthResult<Option<Member>>;
    async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<Member>>;
    async fn update_member_role(&self, member_id: &str, role: &str) -> AuthResult<Member>;
    async fn delete_member(&self, member_id: &str) -> AuthResult<()>;
    async fn list_organization_members(&self, org_id: &str) -> AuthResult<Vec<Member>>;
    /// Query organization members with filter, sort, and pagination applied in
    /// the store when possible.
    async fn query_organization_members(
        &self,
        params: &ListOrganizationMembersParams,
    ) -> AuthResult<(Vec<Member>, usize)>;
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
    async fn update_passkey_authentication(
        &self,
        id: &str,
        update: UpdatePasskeyAuthentication,
    ) -> AuthResult<Passkey>;
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
    + TwoFactorStore
    + ApiKeyStore
    + PasskeyStore
    + DeviceCodeStore
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
        + TwoFactorStore
        + ApiKeyStore
        + PasskeyStore
        + DeviceCodeStore
        + TransactionStore<S>
        + Send
        + Sync,
{
}

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
            Box::pin(async move { Ok(Box::new(work(tx).await?) as BoxedTransactionValue) })
        }))
        .await?;

    value
        .downcast::<T>()
        .map(|boxed| *boxed)
        .map_err(|_| AuthError::internal("store returned an invalid transaction payload"))
}
