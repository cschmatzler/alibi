use super::*;
pub type BoxedTransactionValue = Box<dyn Any + Send>;

pub type TransactionFuture<'a> =
    Pin<Box<dyn Future<Output = AuthResult<BoxedTransactionValue>> + Send + 'a>>;

pub type TypedTransactionFuture<'a, T> = Pin<Box<dyn Future<Output = AuthResult<T>> + Send + 'a>>;

pub type TransactionWork<S> =
    dyn for<'tx> FnOnce(&'tx dyn AuthTransaction<S>) -> TransactionFuture<'tx> + Send;

#[async_trait]
pub trait AuthTransaction<S: AuthSchema>: Send + Sync {
    /// The adapter's own transaction handle, for application statements that
    /// must commit or roll back with this transaction: `SqlxTransaction` for
    /// SQLx and `sea_orm::DatabaseTransaction` for SeaORM. Stores without a
    /// database transaction return `None`.
    fn native_transaction(&self) -> Option<&(dyn Any + Send + Sync)> {
        None
    }
    /// Access team operations on this transaction's connection (for default-team factories).
    fn team_store(&self) -> AuthResult<&dyn super::super::TeamStore>;
    /// Serialize organization admissions until this transaction commits or rolls back.
    async fn lock_organization(&self, organization_id: &str) -> AuthResult<()>;
    async fn count_organization_members(&self, organization_id: &str) -> AuthResult<i64>;
    async fn count_pending_invitations(&self, organization_id: &str) -> AuthResult<i64>;
    async fn create_organization(&self, data: CreateOrganization) -> AuthResult<Organization>;
    async fn create_invitation_with_options(
        &self,
        data: CreateInvitation,
        options: super::InvitationCreateOptions,
    ) -> AuthResult<Invitation>;
    async fn create_team(&self, data: CreateTeam) -> AuthResult<Team>;

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
        _fields: crate::field_policy::FieldValues,
    ) -> AuthResult<Option<(S::Session, crate::field_policy::FieldValues)>> {
        Err(AuthError::NotImplemented(
            "Transactional secondary session updates are unsupported".into(),
        ))
    }
    /// Persist a staged update on the current connection; after hooks belong to commit.
    async fn complete_secondary_session_update(
        &self,
        _session: S::Session,
        _expires_at: Option<chrono::DateTime<chrono::Utc>>,
        _fields: crate::field_policy::FieldValues,
        _persist: bool,
    ) -> AuthResult<Option<S::Session>> {
        Err(AuthError::NotImplemented(
            "Transactional secondary session updates are unsupported".into(),
        ))
    }

    /// Read the managed signing keyring on this transaction's connection.
    async fn list_jwks(&self) -> AuthResult<Vec<Jwk>> {
        Err(crate::AuthError::config(
            "Transactional JWKS reads are unsupported by this store",
        ))
    }
    /// Find a managed signing key on this transaction's connection.
    async fn get_jwk_by_id(&self, _id: &str) -> AuthResult<Option<Jwk>> {
        Err(crate::AuthError::config(
            "Transactional JWKS reads are unsupported by this store",
        ))
    }
    /// Persist a newly generated managed signing key in this transaction.
    async fn create_jwk(&self, _data: CreateJwk) -> AuthResult<Jwk> {
        Err(crate::AuthError::config(
            "Transactional JWKS writes are unsupported by this store",
        ))
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn create_user_record(
        &self,
        create_user: CreateUser,
    ) -> AuthResult<crate::AdapterRecord<S::User>> {
        crate::AdapterRecord::physical(self.create_user(create_user).await?)
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn create_user_with_source_record(
        &self,
        create_user: CreateUser,
        source: UserValidationSource,
    ) -> AuthResult<crate::AdapterRecord<S::User>> {
        crate::AdapterRecord::physical(self.create_user_with_source(create_user, source).await?)
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn create_user_prepared_record(
        &self,
        prepared: PreparedUserCreation,
    ) -> AuthResult<crate::AdapterRecord<S::User>> {
        crate::AdapterRecord::physical(self.create_user_prepared(prepared).await?)
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn get_user_by_id_record(
        &self,
        id: &str,
    ) -> AuthResult<Option<crate::AdapterRecord<S::User>>> {
        self.get_user_by_id(id)
            .await?
            .map(crate::AdapterRecord::physical)
            .transpose()
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn create_account_record(
        &self,
        create_account: CreateAccount,
    ) -> AuthResult<crate::AdapterRecord<S::Account>> {
        crate::AdapterRecord::physical(self.create_account(create_account).await?)
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn create_session_record(
        &self,
        create_session: CreateSession,
    ) -> AuthResult<crate::AdapterRecord<S::Session>> {
        crate::AdapterRecord::physical(self.create_session(create_session).await?)
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn update_session_active_organization_record(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<crate::AdapterRecord<S::Session>> {
        crate::AdapterRecord::physical(
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
    ) -> AuthResult<crate::AdapterRecord<S::Session>> {
        crate::AdapterRecord::physical(self.update_session_active_team(token, team_id).await?)
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
    async fn update_member_role(&self, member_id: &str, role: &str) -> AuthResult<Member>;
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
}

#[async_trait]
pub trait TransactionStore<S: AuthSchema>: Send + Sync {
    async fn transaction_boxed(
        &self,
        work: Box<TransactionWork<S>>,
    ) -> AuthResult<BoxedTransactionValue>;
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
