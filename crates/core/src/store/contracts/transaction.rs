use crate::AdapterRecord;
use crate::field_policy::FieldValues;
use crate::types::AddTeamMemberResult;
use crate::user_validation::{PreparedUserCreation, UserValidationSource};
use crate::verification::{VerificationCreation, VerificationPublication, VerificationSnapshot};
use crate::{
    AuthError, AuthResult, AuthSchema, AuthStore, CreateAccount, CreateJwk, CreateMember,
    CreatePasskey, CreateSession, CreateUser, CreateVerification, Jwk, Member, Passkey, Team,
};
use async_trait::async_trait;
use std::any::Any;
use std::pin::Pin;
pub type BoxedTransactionValue = Box<dyn Any + Send>;

pub type TransactionFuture<'a> =
    Pin<Box<dyn Future<Output = AuthResult<BoxedTransactionValue>> + Send + 'a>>;

pub type TypedTransactionFuture<'a, T> = Pin<Box<dyn Future<Output = AuthResult<T>> + Send + 'a>>;

pub type TransactionWork<S> =
    dyn for<'tx> FnOnce(&'tx dyn AuthTransaction<S>) -> TransactionFuture<'tx> + Send;

#[async_trait]
pub trait AuthTransaction<S: AuthSchema>: Send + Sync {
    async fn check_scim_user_attributes(
        &self,
        _id: &str,
        _connection: &str,
        _attributes: &crate::store::ScimUserAttributes,
    ) -> AuthResult<()> {
        Err(AuthError::not_implemented(
            "Transactional SCIM User uniqueness checks are unsupported",
        ))
    }

    async fn lock_scim_user(
        &self,
        _id: &str,
        _connection: &str,
        _domain: &str,
        _attributes: Option<&crate::store::ScimUserAttributes>,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<crate::store::ScimUserMutationContext> {
        Err(AuthError::not_implemented(
            "Transactional SCIM User mutation is unsupported",
        ))
    }
    async fn replace_scim_user(
        &self,
        _id: &str,
        _data: crate::store::ReplaceScimUser,
        _roles: bool,
    ) -> AuthResult<(
        crate::store::ScimUserRecord,
        Vec<crate::store::ScimProjectionPreparedUser>,
    )> {
        Err(AuthError::not_implemented(
            "Transactional SCIM User replacement is unsupported",
        ))
    }

    async fn create_scim_user(
        &self,
        _data: crate::store::CreateScimUser,
        _roles: bool,
    ) -> AuthResult<(
        crate::store::ScimUserRecord,
        Vec<crate::store::ScimProjectionPreparedUser>,
    )> {
        Err(AuthError::not_implemented(
            "Transactional SCIM User creation is unsupported",
        ))
    }

    async fn delete_scim_user(
        &self,
        _id: &str,
        _connection: &str,
        _domain: &str,
        _roles: bool,
    ) -> AuthResult<(String, Vec<crate::store::ScimProjectionPreparedUser>)> {
        Err(AuthError::not_implemented(
            "Transactional SCIM User deletion is unsupported",
        ))
    }
    async fn patch_scim_group(
        &self,
        _id: &str,
        _connection: &str,
        _domain: &str,
        _patch: crate::store::ScimGroupPatch,
        _roles: bool,
    ) -> AuthResult<(
        crate::store::ScimGroupRecord,
        Vec<crate::store::ScimProjectionPreparedUser>,
    )> {
        Err(AuthError::not_implemented(
            "Transactional SCIM Group patching is unsupported",
        ))
    }
    async fn replace_scim_group(
        &self,
        _id: &str,
        _data: crate::store::ReplaceScimGroup,
        _roles: bool,
    ) -> AuthResult<(
        crate::store::ScimGroupRecord,
        Vec<crate::store::ScimProjectionPreparedUser>,
    )> {
        Err(AuthError::not_implemented(
            "Transactional SCIM Group replacement is unsupported",
        ))
    }
    async fn delete_scim_group(
        &self,
        _id: &str,
        _connection: &str,
        _domain: &str,
        _roles: bool,
    ) -> AuthResult<Vec<crate::store::ScimProjectionPreparedUser>> {
        Err(AuthError::not_implemented(
            "Transactional SCIM Group deletion is unsupported",
        ))
    }
    async fn create_scim_group(
        &self,
        _data: crate::store::CreateScimGroup,
        _roles: bool,
    ) -> AuthResult<(
        crate::store::ScimGroupRecord,
        Vec<crate::store::ScimProjectionPreparedUser>,
    )> {
        Err(AuthError::not_implemented(
            "Transactional SCIM Groups are unsupported",
        ))
    }
    async fn fence_scim_connection(&self, _id: &str, _key: &str) -> AuthResult<()> {
        Err(AuthError::not_implemented(
            "Transactional SCIM fencing is unsupported",
        ))
    }
    async fn get_scim_connection_binding(
        &self,
        _id: &str,
    ) -> AuthResult<Option<crate::store::ScimConnectionBinding>> {
        Err(AuthError::not_implemented(
            "Transactional SCIM bindings are unsupported",
        ))
    }
    async fn scim_projection_candidates(
        &self,
        _domain: &str,
        _cursor: Option<&str>,
    ) -> AuthResult<Vec<crate::store::ScimProjectionCandidate>> {
        Err(AuthError::not_implemented(
            "Transactional SCIM candidates are unsupported",
        ))
    }
    async fn renew_scim_decommission_lease(
        &self,
        _binding: &crate::store::ScimConnectionBinding,
        _lease: &str,
    ) -> AuthResult<bool> {
        Err(AuthError::not_implemented(
            "Transactional SCIM leases are unsupported",
        ))
    }
    async fn advance_scim_decommission(
        &self,
        _binding: &crate::store::ScimConnectionBinding,
        _lease: &str,
        _cursor: Option<&str>,
        _count: usize,
        _more: bool,
    ) -> AuthResult<Option<crate::store::ScimConnectionBinding>> {
        Err(AuthError::not_implemented(
            "Transactional SCIM checkpoints are unsupported",
        ))
    }
    async fn reconcile_scim_identity(
        &self,
        _user_id: &str,
    ) -> AuthResult<crate::store::ScimIdentityState> {
        Err(AuthError::not_implemented(
            "Transactional SCIM identity is unsupported",
        ))
    }
    async fn delete_user_sessions(&self, _user_id: &str) -> AuthResult<()> {
        Err(AuthError::not_implemented(
            "Transactional session retirement is unsupported",
        ))
    }
    /// Read session deletion candidates on this transaction's connection.
    async fn get_user_sessions(&self, _user_id: &str) -> AuthResult<Vec<S::Session>> {
        Err(AuthError::not_implemented(
            "Transactional session reads are unsupported",
        ))
    }
    async fn list_oauth_tokens_for_session(
        &self,
        _kind: crate::store::OAuthTokenKind,
        _session_id: &str,
    ) -> AuthResult<Vec<crate::store::OAuthToken>> {
        Err(AuthError::not_implemented(
            "Transactional OAuth token reads are unsupported",
        ))
    }
    async fn get_oauth_client(
        &self,
        _client_id: &str,
    ) -> AuthResult<Option<crate::store::OAuthClient>> {
        Err(AuthError::not_implemented(
            "Transactional OAuth client reads are unsupported",
        ))
    }
    /// Attach prepared retirement to the matching queued delete-after event.
    /// A veto or missing row has no event and must not complete the work.
    async fn queue_session_deletion_work(
        &self,
        _session_id: &str,
        _works: Vec<Box<dyn crate::store::SessionDeletionWork<S>>>,
        _context: std::sync::Arc<crate::AuthContext<S>>,
    ) -> AuthResult<()> {
        Err(AuthError::not_implemented(
            "Transactional session retirement queueing is unsupported",
        ))
    }

    async fn prepare_scim_projection(
        &self,
        _domain: &str,
        _ids: &[String],
        _roles: bool,
    ) -> AuthResult<Vec<crate::store::ScimProjectionPreparedUser>> {
        Err(AuthError::not_implemented(
            "Transactional SCIM projection is unsupported",
        ))
    }
    async fn create_scim_projection_grant(
        &self,
        _data: crate::store::CreateScimProjectionGrant,
    ) -> AuthResult<()> {
        Err(AuthError::not_implemented(
            "Transactional SCIM grants are unsupported",
        ))
    }
    async fn remove_scim_projection_grants(
        &self,
        _domain: &str,
        _user_id: &str,
        _ids: &[String],
    ) -> AuthResult<()> {
        Err(AuthError::not_implemented(
            "Transactional SCIM grants are unsupported",
        ))
    }

    async fn get_user_by_email(&self, _email: &str) -> AuthResult<Option<S::User>> {
        Err(AuthError::NotImplemented(
            "Transactional user lookup is unsupported".into(),
        ))
    }
    async fn get_account(
        &self,
        _provider: &str,
        _account_id: &str,
    ) -> AuthResult<Option<S::Account>> {
        Err(AuthError::NotImplemented(
            "Transactional account lookup is unsupported".into(),
        ))
    }
    async fn update_user(&self, _id: &str, _update: crate::UpdateUser) -> AuthResult<S::User> {
        Err(AuthError::NotImplemented(
            "Transactional user updates are unsupported".into(),
        ))
    }
    async fn update_account(
        &self,
        _id: &str,
        _update: crate::UpdateAccount,
    ) -> AuthResult<S::Account> {
        Err(AuthError::NotImplemented(
            "Transactional account updates are unsupported".into(),
        ))
    }
    async fn get_user_by_email_record(
        &self,
        email: &str,
    ) -> AuthResult<Option<AdapterRecord<S::User>>> {
        self.get_user_by_email(email)
            .await?
            .map(AdapterRecord::physical)
            .transpose()
    }
    async fn get_account_record(
        &self,
        provider: &str,
        account_id: &str,
    ) -> AuthResult<Option<AdapterRecord<S::Account>>> {
        self.get_account(provider, account_id)
            .await?
            .map(AdapterRecord::physical)
            .transpose()
    }
    async fn update_user_record(
        &self,
        id: &str,
        update: crate::UpdateUser,
    ) -> AuthResult<AdapterRecord<S::User>> {
        AdapterRecord::physical(self.update_user(id, update).await?)
    }
    async fn update_account_record(
        &self,
        id: &str,
        update: crate::UpdateAccount,
    ) -> AuthResult<AdapterRecord<S::Account>> {
        AdapterRecord::physical(self.update_account(id, update).await?)
    }

    /// Lock and read a persisted enterprise provider on this transaction's connection.
    async fn lock_sso_provider(
        &self,
        _id: &str,
        _provider_id: &str,
    ) -> AuthResult<Option<crate::store::SsoProvider>> {
        Err(AuthError::NotImplemented(
            "Transactional SSO provider locking is unsupported".into(),
        ))
    }
    /// Apply a prepared provider update, including linked-account boundary protection.
    async fn update_sso_provider(
        &self,
        _update: crate::store::SsoProviderUpdate,
    ) -> AuthResult<Option<crate::store::SsoProvider>> {
        Err(AuthError::NotImplemented(
            "Transactional SSO provider updates are unsupported".into(),
        ))
    }
    /// Retire a provider and its identity namespace in this transaction.
    async fn delete_sso_provider_and_accounts(
        &self,
        _id: &str,
        _provider_id: &str,
    ) -> AuthResult<bool> {
        Err(AuthError::NotImplemented(
            "Transactional SSO provider deletion is unsupported".into(),
        ))
    }

    /// Read the provider verification column using the adapter's physical scalar
    /// rules. This is retained output, not authorization input; typed models
    /// continue to supply the canonical boolean accessor.
    async fn provider_verification_output(
        &self,
        _id: &str,
    ) -> AuthResult<Option<serde_json::Value>> {
        Ok(None)
    }

    /// Stage a session using the actual transaction-local model and creation hooks.
    async fn prepare_secondary_session_creation(
        &self,
        _input: CreateSession,
        _persist: bool,
    ) -> AuthResult<S::Session> {
        Err(AuthError::NotImplemented(
            "Transactional secondary session creation is unsupported".into(),
        ))
    }

    /// Stage an update against a trusted cached model using this transaction's hooks.
    async fn prepare_secondary_session_update(
        &self,
        _session: S::Session,
        _expires_at: Option<chrono::DateTime<chrono::Utc>>,
        _fields: FieldValues,
    ) -> AuthResult<Option<(S::Session, FieldValues)>> {
        Err(AuthError::NotImplemented(
            "Transactional secondary session updates are unsupported".into(),
        ))
    }
    /// Persist a staged update on the current connection; after hooks belong to commit.
    async fn complete_secondary_session_update(
        &self,
        _session: S::Session,
        _expires_at: Option<chrono::DateTime<chrono::Utc>>,
        _fields: FieldValues,
        _persist: bool,
    ) -> AuthResult<Option<S::Session>> {
        Err(AuthError::NotImplemented(
            "Transactional secondary session updates are unsupported".into(),
        ))
    }

    /// Read the managed signing keyring on this transaction's connection.
    async fn list_jwks(&self) -> AuthResult<Vec<Jwk>> {
        Err(AuthError::config(
            "Transactional JWKS reads are unsupported by this store",
        ))
    }
    /// Find a managed signing key on this transaction's connection.
    async fn get_jwk_by_id(&self, _id: &str) -> AuthResult<Option<Jwk>> {
        Err(AuthError::config(
            "Transactional JWKS reads are unsupported by this store",
        ))
    }
    /// Persist a newly generated managed signing key in this transaction.
    async fn create_jwk(&self, _data: CreateJwk) -> AuthResult<Jwk> {
        Err(AuthError::config(
            "Transactional JWKS writes are unsupported by this store",
        ))
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn create_user_record(
        &self,
        create_user: CreateUser,
    ) -> AuthResult<AdapterRecord<S::User>> {
        AdapterRecord::physical(self.create_user(create_user).await?)
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn create_user_with_source_record(
        &self,
        create_user: CreateUser,
        source: UserValidationSource,
    ) -> AuthResult<AdapterRecord<S::User>> {
        AdapterRecord::physical(self.create_user_with_source(create_user, source).await?)
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn create_user_prepared_record(
        &self,
        prepared: PreparedUserCreation,
    ) -> AuthResult<AdapterRecord<S::User>> {
        AdapterRecord::physical(self.create_user_prepared(prepared).await?)
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn get_user_by_id_record(&self, id: &str) -> AuthResult<Option<AdapterRecord<S::User>>> {
        self.get_user_by_id(id)
            .await?
            .map(AdapterRecord::physical)
            .transpose()
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn create_account_record(
        &self,
        create_account: CreateAccount,
    ) -> AuthResult<AdapterRecord<S::Account>> {
        AdapterRecord::physical(self.create_account(create_account).await?)
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn create_session_record(
        &self,
        create_session: CreateSession,
    ) -> AuthResult<AdapterRecord<S::Session>> {
        AdapterRecord::physical(self.create_session(create_session).await?)
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn update_session_active_organization_record(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<AdapterRecord<S::Session>> {
        AdapterRecord::physical(
            self.update_session_active_organization(token, organization_id)
                .await?,
        )
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn update_session_active_team_record(
        &self,
        token: &str,
        team_id: Option<&str>,
    ) -> AuthResult<AdapterRecord<S::Session>> {
        AdapterRecord::physical(self.update_session_active_team(token, team_id).await?)
    }

    /// Create through before hooks, optional physical persistence, secondary
    /// publication, then after hooks. Unsupported adapters must fail closed.
    async fn create_verification_record(
        &self,
        _data: VerificationCreation,
        _publication: VerificationPublication,
    ) -> AuthResult<Option<VerificationSnapshot>> {
        Err(AuthError::NotImplemented(
            "Verification publication phases are not supported by this store".into(),
        ))
    }
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
        _maximum: Option<f64>,
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
    /// Create with endpoint-owned identity provenance. The finalized instance
    /// applies its policy before adapter hooks. Raw adapters retain ordinary creation.
    async fn create_user_with_source(
        &self,
        create_user: CreateUser,
        _source: UserValidationSource,
    ) -> AuthResult<S::User> {
        self.create_user(create_user).await
    }
    /// Persist an admitted candidate without a second email normalization.
    /// Custom adapters serving validation-enabled instances must implement this.
    async fn create_user_prepared(&self, _prepared: PreparedUserCreation) -> AuthResult<S::User> {
        Err(AuthError::NotImplemented(
            "Prepared user creation is not supported by this transaction".into(),
        ))
    }
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
    /// Spend the newest generation for `identifier` on this transaction's
    /// connection, as [`VerificationStore::consume_verification_snapshot`]
    /// does: the row is locked, deleted with its siblings, and returned even
    /// when expired. Delete after-hooks run once the transaction commits.
    ///
    /// [`VerificationStore::consume_verification_snapshot`]: crate::store::VerificationStore::consume_verification_snapshot
    async fn consume_verification_snapshot(
        &self,
        _identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        Err(AuthError::NotImplemented(
            "Verification consumption in a transaction is not supported by this store".to_owned(),
        ))
    }
}

/// How to handle callback errors after the database has committed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AfterCommitErrorPolicy {
    Propagate,
    Report,
}
#[async_trait]
pub trait TransactionStore<S: AuthSchema>: Send + Sync {
    async fn transaction_boxed(
        &self,
        work: Box<TransactionWork<S>>,
    ) -> AuthResult<BoxedTransactionValue>;
    async fn transaction_boxed_with_policy(
        &self,
        work: Box<TransactionWork<S>>,
        policy: AfterCommitErrorPolicy,
    ) -> AuthResult<BoxedTransactionValue> {
        if policy == AfterCommitErrorPolicy::Propagate {
            self.transaction_boxed(work).await
        } else {
            Err(AuthError::NotImplemented(
                "Reporting committed transaction hook failures is unsupported".into(),
            ))
        }
    }
    /// Run `work` holding the database write lock from its first statement
    /// (SQLite `BEGIN IMMEDIATE`), so a read-then-write gate cannot deadlock
    /// concurrent writers. PostgreSQL row locks need no different start.
    async fn write_transaction_boxed(
        &self,
        work: Box<TransactionWork<S>>,
    ) -> AuthResult<BoxedTransactionValue> {
        self.transaction_boxed(work).await
    }
}

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
    transaction_with_policy(store, AfterCommitErrorPolicy::Propagate, work).await
}
/// Run typed work in a [`TransactionStore::write_transaction_boxed`] transaction.
///
/// # Errors
/// Propagates transaction errors and rejects an unexpected result type.
pub async fn write_transaction<S, T, F>(store: &dyn AuthStore<S>, work: F) -> AuthResult<T>
where
    S: AuthSchema,
    T: Send + 'static,
    F: for<'tx> FnOnce(&'tx dyn AuthTransaction<S>) -> TypedTransactionFuture<'tx, T>
        + Send
        + 'static,
{
    let value = store
        .write_transaction_boxed(Box::new(move |tx| {
            Box::pin(async move {
                let result: BoxedTransactionValue = Box::new(work(tx).await?);
                Ok(result)
            })
        }))
        .await?;
    value
        .downcast::<T>()
        .map(|boxed| *boxed)
        .map_err(|_| AuthError::internal("store returned an invalid transaction payload"))
}

/// Run typed work while selecting the treatment of errors after commit.
///
/// # Errors
/// Propagates transaction errors and rejects an unexpected result type.
pub async fn transaction_with_policy<S, T, F>(
    store: &dyn AuthStore<S>,
    policy: AfterCommitErrorPolicy,
    work: F,
) -> AuthResult<T>
where
    S: AuthSchema,
    T: Send + 'static,
    F: for<'tx> FnOnce(&'tx dyn AuthTransaction<S>) -> TypedTransactionFuture<'tx, T>
        + Send
        + 'static,
{
    let value = store
        .transaction_boxed_with_policy(
            Box::new(move |tx| {
                Box::pin(async move {
                    let result: BoxedTransactionValue = Box::new(work(tx).await?);
                    Ok(result)
                })
            }),
            policy,
        )
        .await?;

    value
        .downcast::<T>()
        .map(|boxed| *boxed)
        .map_err(|_| AuthError::internal("store returned an invalid transaction payload"))
}
