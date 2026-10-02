//! SeaORM-backed persistence implementation for built-in auth tables.

mod account_key_multiplicity;
mod accounts;
mod api_key_numbers;
mod api_key_usage_phases;
mod api_keys;
mod bundled_schema;
mod device_code_user_reference;
mod device_codes;
pub mod entities;
mod identity_fields;
mod invitations;
mod jwks;
mod member_pair_multiplicity;
mod members;
mod migrator;
mod nullable_organization_metadata;
mod nullable_user_flags;
mod numeric_page;
mod organization_extensions;
mod organization_reference;
mod organization_roles;
mod organizations;
mod passkeys;
mod sessions;
mod siwe_wallets;
mod sqlite_number;
mod teams;
mod two_factor;
mod two_factor_user_reference;
mod two_factor_verification_policy;
mod user_reference;
mod users;
mod verifications;
mod wallets;

#[doc(hidden)]
pub mod __private_test_support {
    pub mod bundled_schema {
        pub use super::super::bundled_schema::BundledSchema;
    }

    pub mod migrator {
        pub use super::super::migrator::{AuthMigrator, run_migrations};
    }
}

use crate::hooks::{SeaOrmHookContext, SeaOrmHooks, current_request_hook_context};
use crate::schema::{
    AuthSchema, SeaOrmAccountModel, SeaOrmSessionModel, SeaOrmUserModel, SeaOrmVerificationModel,
};
use async_trait::async_trait;
use better_auth_core::config::AuthConfig;
use better_auth_core::error::{AuthError, AuthResult, DatabaseError};
use better_auth_core::store::{
    AuthTransaction, BoxedTransactionValue, TransactionStore, TransactionWork,
};
use chrono::{DateTime, Utc};
use sea_orm::{DatabaseConnection, DatabaseTransaction, DbErr, SqlErr, TransactionTrait};
use std::marker::PhantomData;
use std::sync::Arc;

#[derive(Clone)]
pub struct SeaOrmStore<S: AuthSchema> {
    config: Arc<AuthConfig>,
    db: DatabaseConnection,
    hooks: Vec<Arc<dyn SeaOrmHooks<S>>>,
    _schema: PhantomData<S>,
}

impl<S: AuthSchema> std::fmt::Debug for SeaOrmStore<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeaOrmStore").finish_non_exhaustive()
    }
}

impl<S: AuthSchema> SeaOrmStore<S> {
    #[must_use]
    pub fn new(config: impl Into<Arc<AuthConfig>>, db: DatabaseConnection) -> Self {
        Self {
            config: config.into(),
            db,
            hooks: Vec::new(),
            _schema: PhantomData,
        }
    }

    #[must_use]
    pub fn with_hooks(mut self, hooks: Vec<Arc<dyn SeaOrmHooks<S>>>) -> Self {
        self.hooks = hooks;
        self
    }

    #[must_use]
    pub fn hook<H: SeaOrmHooks<S> + 'static>(mut self, hook: H) -> Self {
        self.hooks.push(Arc::new(hook));
        self
    }

    #[must_use]
    pub const fn connection(&self) -> &DatabaseConnection {
        &self.db
    }

    #[must_use]
    pub const fn config(&self) -> &Arc<AuthConfig> {
        &self.config
    }

    pub(crate) fn hooks(&self) -> &[Arc<dyn SeaOrmHooks<S>>] {
        &self.hooks
    }

    pub(crate) fn hook_context<'a>(
        &'a self,
        tx: Option<&'a DatabaseTransaction>,
    ) -> SeaOrmHookContext<'a> {
        SeaOrmHookContext {
            config: self.config.as_ref(),
            db: &self.db,
            tx,
            request: current_request_hook_context(),
        }
    }

    ///
    /// # Errors
    ///
    /// Returns an error if the database connection check fails.
    pub async fn test_connection(&self) -> Result<(), DbErr> {
        self.db.ping().await
    }
}

struct SeaOrmTransaction<'a, S: AuthSchema> {
    store: &'a SeaOrmStore<S>,
    tx: &'a DatabaseTransaction,
    pending_after: tokio::sync::Mutex<Vec<AfterCreate<S>>>,
}

enum AfterCreate<S: AuthSchema> {
    User(S::User),
    Account(S::Account),
    Session(S::Session),
    SessionUpdated(S::Session),
    SessionUpdateMissing(String),
    Verification(S::Verification),
    VerificationRecord(better_auth_core::verification::VerificationSnapshot),
}

#[async_trait]
impl<S> AuthTransaction<S> for SeaOrmTransaction<'_, S>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
    S::Account: SeaOrmAccountModel,
    S::Session: SeaOrmSessionModel,
    S::Verification: SeaOrmVerificationModel,
{
    async fn list_jwks(&self) -> AuthResult<Vec<better_auth_core::types::Jwk>> {
        self.store.list_jwks_with_connection(self.tx).await
    }
    async fn get_jwk_by_id(&self, id: &str) -> AuthResult<Option<better_auth_core::types::Jwk>> {
        self.store.get_jwk_with_connection(self.tx, id).await
    }
    async fn create_jwk(
        &self,
        data: better_auth_core::types::CreateJwk,
    ) -> AuthResult<better_auth_core::types::Jwk> {
        self.store.create_jwk_with_connection(self.tx, data).await
    }

    async fn get_team(
        &self,
        organization_id: &str,
        team_id: &str,
    ) -> AuthResult<Option<better_auth_core::types::Team>> {
        self.store
            .get_team_with_connection(self.tx, Some(organization_id), team_id)
            .await
    }
    async fn add_team_member(
        &self,
        team_id: &str,
        user_id: &str,
        maximum: Option<usize>,
    ) -> AuthResult<better_auth_core::types::AddTeamMemberResult> {
        self.store
            .add_team_member_in_tx(self.tx, team_id, user_id, maximum)
            .await
    }
    async fn create_member(
        &self,
        member: better_auth_core::CreateMember,
    ) -> AuthResult<better_auth_core::types::Member> {
        self.store
            .create_member_with_connection(self.tx, member)
            .await
    }
    async fn update_session_active_team(
        &self,
        token: &str,
        team_id: Option<&str>,
    ) -> AuthResult<S::Session> {
        self.store
            .update_session_scope_with_connection(
                self.tx,
                token,
                sessions::SessionScope::Team(team_id),
            )
            .await
    }
    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<S::Session> {
        self.store
            .update_session_scope_with_connection(
                self.tx,
                token,
                sessions::SessionScope::Organization(organization_id),
            )
            .await
    }
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<S::User>> {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        let id = S::User::parse_id(id)?;
        <S::User as SeaOrmUserModel>::Entity::find()
            .filter(S::User::id_column().eq(id))
            .one(self.tx)
            .await
            .map_err(map_db_err)
    }
    async fn create_passkey(
        &self,
        data: better_auth_core::CreatePasskey,
    ) -> AuthResult<better_auth_core::Passkey> {
        self.store
            .create_passkey_with_connection(self.tx, data)
            .await
    }
    async fn create_user(&self, create_user: better_auth_core::CreateUser) -> AuthResult<S::User> {
        let user = self.store.create_user_in_tx(self.tx, create_user).await?;
        self.pending_after
            .lock()
            .await
            .push(AfterCreate::User(user.clone()));
        Ok(user)
    }

    async fn create_user_prepared(
        &self,
        prepared: better_auth_core::user_validation::PreparedUserCreation,
    ) -> AuthResult<S::User> {
        let user = self
            .store
            .create_user_prepared_in_tx(self.tx, prepared)
            .await?;
        self.pending_after
            .lock()
            .await
            .push(AfterCreate::User(user.clone()));
        Ok(user)
    }

    async fn create_account(
        &self,
        create_account: better_auth_core::CreateAccount,
    ) -> AuthResult<S::Account> {
        let account = self
            .store
            .create_account_in_tx(self.tx, create_account)
            .await?;
        self.pending_after
            .lock()
            .await
            .push(AfterCreate::Account(account.clone()));
        Ok(account)
    }

    async fn prepare_secondary_session_update(
        &self,
        session: S::Session,
        expires_at: Option<DateTime<Utc>>,
        fields: better_auth_core::field_policy::FieldValues,
    ) -> AuthResult<Option<(S::Session, better_auth_core::field_policy::FieldValues)>> {
        self.store
            .prepare_secondary_update_with_connection(
                self.tx,
                Some(self.tx),
                session,
                expires_at,
                fields,
            )
            .await
    }
    async fn complete_secondary_session_update(
        &self,
        session: S::Session,
        expires_at: Option<DateTime<Utc>>,
        fields: better_auth_core::field_policy::FieldValues,
        persist: bool,
    ) -> AuthResult<Option<S::Session>> {
        use better_auth_core::AuthSession;
        let token = session.token().to_owned();
        let result = self
            .store
            .complete_secondary_update_with_connection(
                self.tx,
                Some(self.tx),
                session,
                expires_at,
                fields,
                persist,
            )
            .await?;
        let event = result.as_ref().map_or_else(
            || AfterCreate::SessionUpdateMissing(token),
            |model| AfterCreate::SessionUpdated(model.clone()),
        );
        self.pending_after.lock().await.push(event);
        Ok(result)
    }
    async fn prepare_secondary_session_creation(
        &self,
        input: better_auth_core::CreateSession,
        persist: bool,
    ) -> AuthResult<S::Session> {
        let session = self
            .store
            .prepare_secondary_session_in_tx(self.tx, input, persist)
            .await?;
        self.pending_after
            .lock()
            .await
            .push(AfterCreate::Session(session.clone()));
        Ok(session)
    }
    async fn create_session(
        &self,
        create_session: better_auth_core::CreateSession,
    ) -> AuthResult<S::Session> {
        let session = self
            .store
            .create_session_in_tx(self.tx, create_session)
            .await?;
        self.pending_after
            .lock()
            .await
            .push(AfterCreate::Session(session.clone()));
        Ok(session)
    }
    async fn create_verification_record(
        &self,
        data: better_auth_core::verification::VerificationCreation,
        publication: better_auth_core::verification::VerificationPublication,
    ) -> AuthResult<Option<better_auth_core::verification::VerificationSnapshot>> {
        let snapshot = self
            .store
            .create_verification_record_with_connection(self.tx, Some(self.tx), data, publication)
            .await?;
        if let Some(snapshot) = &snapshot {
            self.pending_after
                .lock()
                .await
                .push(AfterCreate::VerificationRecord(snapshot.clone()));
        }
        Ok(snapshot)
    }

    async fn create_verification(
        &self,
        verification: better_auth_core::CreateVerification,
    ) -> AuthResult<S::Verification> {
        let verification = self
            .store
            .create_verification_in_tx(self.tx, verification)
            .await?;
        self.pending_after
            .lock()
            .await
            .push(AfterCreate::Verification(verification.clone()));
        Ok(verification)
    }
}

#[async_trait]
impl<S> TransactionStore<S> for SeaOrmStore<S>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
    S::Account: SeaOrmAccountModel,
    S::Session: SeaOrmSessionModel,
    S::Verification: SeaOrmVerificationModel,
{
    async fn transaction_boxed(
        &self,
        work: Box<TransactionWork<S>>,
    ) -> AuthResult<BoxedTransactionValue> {
        let tx = self.db.begin().await.map_err(map_db_err)?;
        let tx_store = SeaOrmTransaction {
            store: self,
            tx: &tx,
            pending_after: tokio::sync::Mutex::new(Vec::new()),
        };
        let outcome = work(&tx_store).await;
        let pending_after = tx_store.pending_after.into_inner();
        match outcome {
            Ok(value) => {
                tx.commit().await.map_err(map_db_err)?;
                // The pinned adapter defers after callbacks until commit and
                // drops them on rollback. Preserve each created snapshot and
                // its operation order, including interleaved model writes.
                let hook_context = self.hook_context(None);
                for created in pending_after {
                    for hook in self.hooks() {
                        match &created {
                            AfterCreate::User(user) => {
                                hook.after_create_user(user, &hook_context).await?;
                            }
                            AfterCreate::Account(account) => {
                                hook.after_create_account(account, &hook_context).await?;
                            }
                            AfterCreate::Session(session) => {
                                hook.after_create_session(session, &hook_context).await?;
                            }
                            AfterCreate::SessionUpdated(session) => {
                                hook.after_update_session(session, &hook_context).await?;
                            }
                            AfterCreate::SessionUpdateMissing(token) => {
                                hook.after_update_session_missing(token, &hook_context)
                                    .await?;
                            }
                            AfterCreate::VerificationRecord(snapshot) => {
                                hook.after_create_verification_record(snapshot, &hook_context)
                                    .await?;
                            }
                            AfterCreate::Verification(verification) => {
                                hook.after_create_verification(verification, &hook_context)
                                    .await?;
                            }
                        }
                    }
                }
                Ok(value)
            }
            Err(err) => {
                tx.rollback().await.map_err(map_db_err)?;
                Err(err)
            }
        }
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "Result::map_err transfers ownership to this error-boundary adapter"
)]
pub(crate) fn map_db_err(err: DbErr) -> AuthError {
    match err.sql_err() {
        Some(
            SqlErr::UniqueConstraintViolation(message)
            | SqlErr::ForeignKeyConstraintViolation(message),
        ) => AuthError::Database(DatabaseError::Constraint(message)),
        Some(_) | None => AuthError::Database(DatabaseError::Query(err.to_string())),
    }
}

pub(crate) fn cancelled_by_hook(operation: &str) -> AuthError {
    AuthError::forbidden(format!("{operation} cancelled by database hook"))
}

fn parse_rfc3339(value: &str, field: &str) -> Result<DateTime<Utc>, AuthError> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_error| AuthError::bad_request(format!("Invalid RFC 3339 timestamp for {field}")))
}

fn parse_optional_rfc3339(
    value: Option<&str>,
    field: &str,
) -> Result<Option<DateTime<Utc>>, AuthError> {
    value.map(|inner| parse_rfc3339(inner, field)).transpose()
}

/// Match the pinned SQLite adapter's decimal formatting of finite REAL values.
pub(crate) fn sqlite_real_text(input: f64) -> String {
    sqlite_number::real_text(input)
}

// LCOV_EXCL_START
#[cfg(test)]
mod account_multiplicity_tests {
    //! Installed OAuth account rows keep row identities without choosing ambiguous owners.
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Persistence assertions propagate setup failures"
    )]
    use super::{SeaOrmStore, bundled_schema::BundledSchema, migrator::AuthMigrator};
    use better_auth_core::store::{AccountStore, UserStore};
    use better_auth_core::{AuthConfig, CreateAccount, CreateUser};
    use sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement};
    use sea_orm_migration::MigratorTrait;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    const UPGRADE: &str = "m20261001_000016_account_key_multiplicity";
    fn account(user_id: &str) -> CreateAccount {
        CreateAccount {
            additional_fields: Default::default(),
            user_id: user_id.to_owned(),
            provider_id: "gitlab".into(),
            account_id: "shared-provider-identity".into(),
            access_token: Some("retained-access".into()),
            refresh_token: Some("retained-refresh".into()),
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: Some("read_user".into()),
            password: None,
        }
    }
    async fn scalar(db: &DatabaseConnection, sql: &str) -> Result<String, sea_orm::DbErr> {
        db.query_one_raw(Statement::from_string(DbBackend::Sqlite, sql))
            .await?
            .ok_or_else(|| sea_orm::DbErr::Custom("missing snapshot".into()))?
            .try_get("", "value")
    }
    #[tokio::test]
    async fn installed_account_upgrade_preserves_rows_and_app_schema_then_rejects_ambiguous_identity()
    -> TestResult {
        let db = Database::connect("sqlite::memory:").await?;
        let prior = AuthMigrator::migrations()
            .iter()
            .take_while(|migration| migration.name() != UPGRADE)
            .count();
        AuthMigrator::up(&db, Some(u32::try_from(prior)?)).await?;
        let store = SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("installed-account-multiplicity-secret"),
            db.clone(),
        );
        let owner = store
            .create_user(CreateUser::new().with_email("owner@account-multiplicity.test"))
            .await?;
        let foreign = store
            .create_user(CreateUser::new().with_email("foreign@account-multiplicity.test"))
            .await?;
        let original = store.create_account(account(&owner.id)).await?;
        assert!(store.create_account(account(&owner.id)).await.is_err());
        for sql in [
            "ALTER TABLE accounts ADD COLUMN app_note TEXT NOT NULL DEFAULT 'kept,bytes' CHECK(app_note <> 'blocked')",
            "CREATE INDEX app_account_note ON accounts(app_note)",
            "CREATE TABLE app_account_audit(id TEXT)",
            "CREATE TRIGGER app_account_changes AFTER UPDATE ON accounts BEGIN INSERT INTO app_account_audit VALUES(NEW.id); END",
            "CREATE VIEW app_accounts AS SELECT id,app_note FROM accounts",
        ] {
            let _result = db.execute_unprepared(sql).await?;
        }
        let rows = "SELECT json_group_array(json_object('rowid',rowid,'id',id,'owner',user_id,'provider',provider_id,'account',account_id,'access',access_token,'created',created_at,'note',app_note)) AS value FROM (SELECT rowid,* FROM accounts ORDER BY rowid)";
        let schema = "SELECT json_group_array(json_object('type',type,'name',name,'sql',sql)) AS value FROM (SELECT type,name,sql FROM sqlite_schema WHERE (tbl_name='accounts' OR name='app_accounts') AND name NOT IN ('idx_accounts_provider_account','idx_accounts_provider_account_lookup') ORDER BY type,name)";
        let before = (scalar(&db, rows).await?, scalar(&db, schema).await?);
        AuthMigrator::up(&db, None).await?;
        assert_eq!(
            (scalar(&db, rows).await?, scalar(&db, schema).await?),
            before
        );
        let same_owner = store.create_account(account(&owner.id)).await?;
        assert_ne!(same_owner.id, original.id);
        assert!(
            store
                .get_account("gitlab", "shared-provider-identity")
                .await
                .is_err(),
            "same-owner multiplicity must not silently choose a row"
        );
        store.delete_account(&same_owner.id).await?;
        assert_eq!(
            serde_json::to_value(
                store
                    .get_account("gitlab", "shared-provider-identity")
                    .await?
            )?,
            serde_json::to_value(Some(original.clone()))?
        );
        let other_owner = store.create_account(account(&foreign.id)).await?;
        assert!(
            store
                .get_account("gitlab", "shared-provider-identity")
                .await
                .is_err(),
            "foreign-owner multiplicity must fail closed"
        );
        assert_eq!(store.get_user_accounts(&owner.id).await?.len(), 1);
        assert_eq!(store.get_user_accounts(&foreign.id).await?.len(), 1);
        store.delete_account(&other_owner.id).await?;
        assert_eq!(
            serde_json::to_value(store.get_user_accounts(&owner.id).await?)?,
            serde_json::to_value(vec![original])?
        );
        assert!(
            db.execute_unprepared("UPDATE accounts SET app_note='blocked'")
                .await
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn account_upgrade_refuses_incoming_provider_key_foreign_keys_without_writes()
    -> TestResult {
        let db = Database::connect("sqlite::memory:").await?;
        let prior = AuthMigrator::migrations()
            .iter()
            .take_while(|migration| migration.name() != UPGRADE)
            .count();
        AuthMigrator::up(&db, Some(u32::try_from(prior)?)).await?;
        let store = SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("dependent-account-migration-secret"),
            db.clone(),
        );
        let owner = store
            .create_user(CreateUser::new().with_email("owner@account-fk.test"))
            .await?;
        let original = store.create_account(account(&owner.id)).await?;
        let _result=db.execute_unprepared("CREATE TABLE \"app \"\"key\"\" refs\"(provider TEXT,account TEXT,note TEXT,FOREIGN KEY(provider,account) REFERENCES accounts(provider_id,account_id)); INSERT INTO \"app \"\"key\"\" refs\" VALUES('gitlab','shared-provider-identity','kept,bytes')").await?;
        let snapshot = "SELECT json_group_array(json_object('name',name,'sql',sql)) AS value FROM (SELECT name,sql FROM sqlite_schema ORDER BY name)";
        let before = scalar(&db, snapshot).await?;
        assert!(matches!(
            AuthMigrator::up(&db, None).await,
            Err(sea_orm::DbErr::Migration(_))
        ));
        assert_eq!(scalar(&db, snapshot).await?, before);
        assert!(
            db.query_all_raw(Statement::from_string(
                DbBackend::Sqlite,
                "PRAGMA foreign_key_check"
            ))
            .await?
            .is_empty()
        );
        assert_eq!(
            serde_json::to_value(store.get_user_accounts(&owner.id).await?)?,
            serde_json::to_value(vec![original])?
        );
        assert!(store.create_account(account(&owner.id)).await.is_err());
        let _result=db.execute_unprepared("CREATE TABLE app_account_ids(account_id TEXT REFERENCES accounts(id),note TEXT); INSERT INTO app_account_ids SELECT a.id,r.note FROM accounts a JOIN \"app \"\"key\"\" refs\" r ON a.provider_id=r.provider AND a.account_id=r.account; DROP TABLE \"app \"\"key\"\" refs\"").await?;
        let app = "SELECT json_group_array(json_object('id',account_id,'note',note)) AS value FROM app_account_ids";
        let app_before = scalar(&db, app).await?;
        AuthMigrator::up(&db, None).await?;
        let duplicate = store.create_account(account(&owner.id)).await?;
        assert_eq!(scalar(&db, app).await?, app_before);
        assert!(
            db.query_all_raw(Statement::from_string(
                DbBackend::Sqlite,
                "PRAGMA foreign_key_check"
            ))
            .await?
            .is_empty()
        );
        store.delete_account(&duplicate.id).await?;
        Ok(())
    }

    #[tokio::test]
    async fn account_rollback_refuses_duplicates_then_restores_uniqueness_without_row_loss()
    -> TestResult {
        let db = Database::connect("sqlite::memory:").await?;
        AuthMigrator::up(&db, None).await?;
        let store = SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("account-rollback-secret"),
            db.clone(),
        );
        let owner = store
            .create_user(CreateUser::new().with_email("owner@account-rollback.test"))
            .await?;
        let original = store.create_account(account(&owner.id)).await?;
        let duplicate = store.create_account(account(&owner.id)).await?;
        let rows = "SELECT json_group_array(json_object('id',id,'owner',user_id,'provider',provider_id,'account',account_id,'token',access_token)) AS value FROM (SELECT * FROM accounts ORDER BY rowid)";
        let before = scalar(&db, rows).await?;
        assert!(AuthMigrator::down(&db, Some(1)).await.is_err());
        assert_eq!(scalar(&db, rows).await?, before);
        store.delete_account(&duplicate.id).await?;
        let retained = scalar(&db, rows).await?;
        AuthMigrator::down(&db, Some(1)).await?;
        assert_eq!(scalar(&db, rows).await?, retained);
        assert!(store.create_account(account(&owner.id)).await.is_err());
        AuthMigrator::up(&db, None).await?;
        assert_eq!(scalar(&db, rows).await?, retained);
        let restored = store.create_account(account(&owner.id)).await?;
        assert_ne!(restored.id, original.id);
        Ok(())
    }

    #[tokio::test]
    async fn independent_connections_admit_duplicate_account_rows_without_selecting_an_owner()
    -> TestResult {
        let path = std::env::temp_dir().join(format!(
            "account-multiplicity-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let first_db = Database::connect(&url).await?;
        AuthMigrator::up(&first_db, None).await?;
        let config = AuthConfig::new("independent-account-admission-secret");
        let first = SeaOrmStore::<BundledSchema>::new(config.clone(), first_db.clone());
        let second_db = Database::connect(&url).await?;
        let second = SeaOrmStore::<BundledSchema>::new(config, second_db.clone());
        let owner = first
            .create_user(CreateUser::new().with_email("concurrent@account-pair.test"))
            .await?;
        let foreign = first
            .create_user(CreateUser::new().with_email("foreign@account-pair.test"))
            .await?;
        let mut peer_input = account(&foreign.id);
        peer_input.account_id = "independent-foreign-identity".into();
        let peer = first.create_account(peer_input).await?;
        let (left, right) = tokio::join!(
            first.create_account(account(&owner.id)),
            second.create_account(account(&owner.id))
        );
        let left = left?;
        let right = right?;
        assert_ne!(left.id, right.id);
        let rows = first.get_user_accounts(&owner.id).await?;
        assert_eq!(rows.len(), 2);
        for expected in [left, right] {
            assert_eq!(
                serde_json::to_value(
                    second
                        .get_user_accounts(&owner.id)
                        .await?
                        .into_iter()
                        .find(|row| row.id == expected.id)
                )?,
                serde_json::to_value(Some(expected))?
            );
        }
        assert!(matches!(
            second
                .get_account("gitlab", "shared-provider-identity")
                .await,
            Err(better_auth_core::AuthError::Database(
                better_auth_core::DatabaseError::AmbiguousAccount { .. }
            ))
        ));
        assert_eq!(
            serde_json::to_value(first.get_user_accounts(&foreign.id).await?)?,
            serde_json::to_value(vec![peer])?
        );
        first_db.close().await?;
        second_db.close().await?;
        std::fs::remove_file(path)?;
        Ok(())
    }
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
#[cfg(test)]
mod invitation_staging_tests {
    //! Conditional invitation claims remain separate from membership transactions.
    #![expect(
        clippy::panic_in_result_fn,
        reason = "public storage tests assert persisted invariants and propagate setup failures"
    )]
    use super::{SeaOrmStore, bundled_schema::BundledSchema, migrator::run_migrations};
    use better_auth_core::entity::{AuthSession, AuthUser};
    use better_auth_core::field_policy::FieldValues;
    use better_auth_core::store::{
        InvitationStore, MemberStore, OrganizationStore, SessionStore, TeamStore, UserStore,
        transaction,
    };
    use better_auth_core::{
        AuthConfig, AuthError, AuthResult, CreateInvitation, CreateMember, CreateOrganization,
        CreateSession, CreateTeam, CreateUser, InvitationStatus,
    };
    use chrono::{Duration, Utc};
    use sea_orm::{ConnectOptions, ConnectionTrait, Database, DbBackend, Statement};
    use std::sync::Arc;
    use tokio::sync::Barrier;

    type TestResult = Result<(), Box<dyn std::error::Error>>;
    async fn store() -> Result<SeaOrmStore<BundledSchema>, Box<dyn std::error::Error>> {
        let db = Database::connect("sqlite::memory:").await?;
        run_migrations(&db).await?;
        Ok(SeaOrmStore::new(
            AuthConfig::new("invitation-stage-real-storage-local-secret"),
            db,
        ))
    }
    async fn seed(
        store: &SeaOrmStore<BundledSchema>,
    ) -> AuthResult<(String, String, String, String, String)> {
        let user = store
            .create_user(CreateUser::new().with_email("actual@invitation-stage.test"))
            .await?;
        let org = store
            .create_organization(CreateOrganization::new("Actual", "actual-stage"))
            .await?;
        let foreign = store
            .create_organization(CreateOrganization::new("Foreign", "foreign-stage"))
            .await?;
        let team = store
            .create_team(CreateTeam {
                name: "Actual team".into(),
                organization_id: org.id.clone(),
                updated_at: None,
            })
            .await?;
        let session = store
            .create_session(CreateSession {
                user_id: user.id().into_owned(),
                token: None,
                expires_at: Utc::now() + Duration::hours(1),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
                active_team_id: None,
                additional_fields: FieldValues::default(),
            })
            .await?;
        let mut input = CreateInvitation::new(
            &org.id,
            "actual@invitation-stage.test",
            "member",
            user.id(),
            Utc::now() + Duration::hours(1),
        );
        input.team_id = Some(team.id.clone());
        let invitation = store.create_invitation(input).await?;
        Ok((
            user.id().into_owned(),
            org.id,
            foreign.id,
            team.id,
            format!("{}!{}", invitation.id, session.token()),
        ))
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn staged_claim_survives_real_transaction_abort_and_reset_veto_then_retry_commits()
    -> TestResult {
        let store = store().await?;
        let (user, org, foreign, team, handles) = seed(&store).await?;
        let (invitation, token) = handles.split_once('!').ok_or("missing setup handles")?;
        let before = store
            .get_session(token)
            .await?
            .ok_or("missing initial session")?;
        let claimed = store
            .update_invitation_status_if_status(
                invitation,
                InvitationStatus::Pending,
                InvitationStatus::Accepted,
            )
            .await?
            .ok_or("claim failed")?;
        assert_eq!(claimed.status, InvitationStatus::Accepted);
        _ = store.connection().execute_raw(Statement::from_string(DbBackend::Sqlite,"CREATE TRIGGER stage_member_veto BEFORE INSERT ON member BEGIN SELECT RAISE(ABORT,'actual staged member veto'); END".to_owned())).await?;
        let (tx_user, tx_org, tx_foreign, tx_team, tx_token) = (
            user.clone(),
            org.clone(),
            foreign.clone(),
            team.clone(),
            token.to_owned(),
        );
        let result: AuthResult<()> = transaction(&store, move |tx| {
            Box::pin(async move {
                assert!(tx.get_team(&tx_foreign, &tx_team).await?.is_none());
                assert_eq!(
                    tx.get_team(&tx_org, &tx_team)
                        .await?
                        .ok_or_else(|| AuthError::internal("missing actual team"))?
                        .id,
                    tx_team
                );
                drop(tx.add_team_member(&tx_team, &tx_user, Some(1)).await?);
                drop(
                    tx.update_session_active_team(&tx_token, Some(&tx_team))
                        .await?,
                );
                drop(
                    tx.create_member(CreateMember {
                        organization_id: tx_org,
                        user_id: tx_user,
                        role: "member".into(),
                    })
                    .await?,
                );
                Ok(())
            })
        })
        .await;
        assert!(matches!(result, Err(AuthError::Database(_))));
        assert!(store.get_member(&org, &user).await?.is_none());
        assert!(store.get_team_member(&team, &user).await?.is_none());
        let after = store
            .get_session(token)
            .await?
            .ok_or("session missing after rollback")?;
        assert_eq!(
            serde_json::to_value(&after)?,
            serde_json::to_value(&before)?
        );
        assert_eq!(
            store
                .get_invitation_by_id(invitation)
                .await?
                .ok_or("missing accepted row")?
                .status,
            InvitationStatus::Accepted
        );
        _ = store.connection().execute_raw(Statement::from_string(DbBackend::Sqlite,"CREATE TRIGGER stage_reset_veto BEFORE UPDATE OF status ON invitation WHEN OLD.status='accepted' AND NEW.status='pending' BEGIN SELECT RAISE(ABORT,'actual conditional reset veto'); END".to_owned())).await?;
        assert!(matches!(
            store
                .update_invitation_status_if_status(
                    invitation,
                    InvitationStatus::Accepted,
                    InvitationStatus::Pending
                )
                .await,
            Err(AuthError::Database(_))
        ));
        assert_eq!(
            store
                .get_invitation_by_id(invitation)
                .await?
                .ok_or("missing row after reset veto")?
                .status,
            InvitationStatus::Accepted
        );
        for trigger in ["stage_reset_veto", "stage_member_veto"] {
            _ = store
                .connection()
                .execute_raw(Statement::from_string(
                    DbBackend::Sqlite,
                    format!("DROP TRIGGER {trigger}"),
                ))
                .await?;
        }
        assert!(
            store
                .update_invitation_status_if_status(
                    invitation,
                    InvitationStatus::Accepted,
                    InvitationStatus::Pending
                )
                .await?
                .is_some()
        );
        assert!(
            store
                .update_invitation_status_if_status(
                    invitation,
                    InvitationStatus::Accepted,
                    InvitationStatus::Rejected
                )
                .await?
                .is_none()
        );
        assert_eq!(
            store
                .get_invitation_by_id(invitation)
                .await?
                .ok_or("missing conditional no-op row")?
                .status,
            InvitationStatus::Pending
        );
        drop(
            store
                .update_invitation_status_if_status(
                    invitation,
                    InvitationStatus::Pending,
                    InvitationStatus::Accepted,
                )
                .await?
                .ok_or("retry claim failed")?,
        );
        let (tx_user_2, tx_org_2, tx_team_2, tx_token_2) =
            (user.clone(), org.clone(), team.clone(), token.to_owned());
        let created = transaction(&store, move |tx| {
            Box::pin(async move {
                drop(tx.add_team_member(&tx_team_2, &tx_user_2, Some(1)).await?);
                drop(
                    tx.update_session_active_team(&tx_token_2, Some(&tx_team_2))
                        .await?,
                );
                let member = tx
                    .create_member(CreateMember {
                        organization_id: tx_org_2.clone(),
                        user_id: tx_user_2,
                        role: "member".into(),
                    })
                    .await?;
                drop(
                    tx.update_session_active_organization(&tx_token_2, Some(&tx_org_2))
                        .await?,
                );
                Ok(member)
            })
        })
        .await?;
        assert_eq!(created.user_id, user);
        assert_eq!(created.organization_id, org);
        assert!(store.get_team_member(&team, &user).await?.is_some());
        let final_session = store
            .get_session(token)
            .await?
            .ok_or("missing selected session")?;
        assert_eq!(final_session.token(), before.token());
        assert_eq!(final_session.active_team_id(), Some(team.as_str()));
        assert_eq!(final_session.active_organization_id(), Some(org.as_str()));
        assert!(store.get_member(&foreign, &user).await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn independent_connections_have_one_exact_invitation_claim_winner() -> TestResult {
        let path = std::env::temp_dir().join(format!(
            "invitation-stage-cas-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        let url = format!("sqlite:{}?mode=rwc", path.display());
        let mut options = ConnectOptions::new(url.clone());
        _ = options.max_connections(1);
        let db = Database::connect(options).await?;
        run_migrations(&db).await?;
        let first = Arc::new(SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("invitation-stage-independent-secret"),
            db.clone(),
        ));
        let (_, _, _, _, handles) = seed(&first).await?;
        let (id, _) = handles.split_once('!').ok_or("missing handles")?;
        let before = first
            .get_invitation_by_id(id)
            .await?
            .ok_or("missing initial invitation")?;
        let other = Database::connect(url).await?;
        let second = Arc::new(SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("invitation-stage-independent-secret"),
            other.clone(),
        ));
        let barrier = Arc::new(Barrier::new(2));
        let mut tasks = tokio::task::JoinSet::new();
        for store in [Arc::clone(&first), second] {
            let id = id.to_owned();
            let barrier = Arc::clone(&barrier);
            drop(tasks.spawn(async move {
                _ = barrier.wait().await;
                store
                    .update_invitation_status_if_status(
                        &id,
                        InvitationStatus::Pending,
                        InvitationStatus::Accepted,
                    )
                    .await
            }));
        }
        let mut winners = 0;
        while let Some(result) = tasks.join_next().await {
            if let Some(row) = result?? {
                assert_eq!(row.id, id);
                assert_eq!(row.status, InvitationStatus::Accepted);
                winners += 1;
            }
        }
        assert_eq!(winners, 1);
        let mut expected = before;
        expected.status = InvitationStatus::Accepted;
        assert_eq!(
            serde_json::to_value(
                first
                    .get_invitation_by_id(id)
                    .await?
                    .ok_or("missing final row")?
            )?,
            serde_json::to_value(expected)?
        );
        assert!(
            first
                .update_invitation_status_if_status(
                    "missing",
                    InvitationStatus::Pending,
                    InvitationStatus::Accepted
                )
                .await?
                .is_none()
        );
        drop(first);
        db.close().await?;
        other.close().await?;
        std::fs::remove_file(path)?;
        Ok(())
    }
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
#[cfg(test)]
mod member_multiplicity_tests {
    //! Installed member identities and physical membership pages remain authoritative.
    #![expect(
        clippy::panic_in_result_fn,
        reason = "native persistence tests assert invariants while propagating setup failures"
    )]
    use super::{SeaOrmStore, bundled_schema::BundledSchema, migrator::AuthMigrator};
    use better_auth_core::store::{MemberStore, OrganizationStore, TeamStore, UserStore};
    use better_auth_core::{AuthConfig, CreateMember, CreateOrganization, CreateTeam, CreateUser};
    use sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement};
    use sea_orm_migration::{MigratorTrait, SchemaManager};

    type TestResult = Result<(), Box<dyn std::error::Error>>;
    const UPGRADE: &str = "m20261001_000015_member_pair_multiplicity";

    async fn scalar(db: &DatabaseConnection, sql: &str) -> Result<String, sea_orm::DbErr> {
        db.query_one_raw(Statement::from_string(DbBackend::Sqlite, sql))
            .await?
            .ok_or_else(|| sea_orm::DbErr::Custom("missing snapshot".into()))?
            .try_get("", "value")
    }

    #[tokio::test]
    async fn installed_member_upgrade_preserves_rows_and_application_schema_then_allows_duplicates()
    -> TestResult {
        let db = Database::connect("sqlite::memory:").await?;
        let prior = AuthMigrator::migrations()
            .iter()
            .take_while(|migration| migration.name() != UPGRADE)
            .count();
        AuthMigrator::up(&db, Some(u32::try_from(prior)?)).await?;
        let store = SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("installed-member-multiplicity-secret"),
            db.clone(),
        );
        let user = store
            .create_user(CreateUser::new().with_email("installed@member-pair.test"))
            .await?;
        let foreign = store
            .create_user(CreateUser::new().with_email("foreign@member-pair.test"))
            .await?;
        let org = store
            .create_organization(CreateOrganization::new("Installed", "installed-pair"))
            .await?;
        let other = store
            .create_organization(CreateOrganization::new("Foreign", "foreign-pair"))
            .await?;
        let original = store
            .create_member(CreateMember::new(&org.id, &user.id, "owner"))
            .await?;
        let peer = store
            .create_member(CreateMember::new(&other.id, &foreign.id, "member"))
            .await?;
        assert!(
            store
                .create_member(CreateMember::new(&org.id, &user.id, "admin"))
                .await
                .is_err(),
            "the actual installed pair constraint must exist before upgrade"
        );
        for sql in [
            "ALTER TABLE member ADD COLUMN app_note TEXT NOT NULL DEFAULT 'kept,bytes' CHECK(app_note <> 'blocked')",
            "CREATE INDEX app_member_note ON member(app_note) WHERE app_note IS NOT NULL",
            "CREATE TABLE app_member_audit(id TEXT)",
            "CREATE TRIGGER app_member_changes AFTER UPDATE ON member BEGIN INSERT INTO app_member_audit VALUES(NEW.id); END",
            "CREATE VIEW app_members AS SELECT id,app_note FROM member",
        ] {
            let _ignored_execute_unprepared = db.execute_unprepared(sql).await?;
        }
        let row_sql = "SELECT json_group_array(json_object('rowid',rowid,'id',id,'org',organization_id,'user',user_id,'role',role,'created',created_at,'note',app_note)) AS value FROM (SELECT rowid,* FROM member ORDER BY rowid)";
        let schema_sql = "SELECT json_group_array(json_object('type',type,'name',name,'sql',sql)) AS value FROM (SELECT type,name,sql FROM sqlite_schema WHERE (tbl_name='member' OR name='app_members') AND name <> 'idx_member_org_user_unique' ORDER BY type,name)";
        let before = (scalar(&db, row_sql).await?, scalar(&db, schema_sql).await?);
        AuthMigrator::up(&db, None).await?;
        assert_eq!(
            (scalar(&db, row_sql).await?, scalar(&db, schema_sql).await?),
            before,
            "index removal must preserve physical IDs, rowids, date/text bytes and unrelated schema"
        );
        assert_eq!(
            serde_json::to_value(store.get_member_by_id(&original.id).await?)?,
            serde_json::to_value(Some(original.clone()))?
        );
        assert_eq!(
            serde_json::to_value(store.get_member_by_id(&peer.id).await?)?,
            serde_json::to_value(Some(peer.clone()))?
        );
        let second = store
            .create_member(CreateMember::new(&org.id, &user.id, "admin"))
            .await?;
        assert_ne!(second.id, original.id);
        assert_eq!(store.count_organization_members(&org.id).await?, 2);
        assert_eq!(
            serde_json::to_value(store.get_member(&org.id, &user.id).await?)?,
            serde_json::to_value(Some(original.clone()))?
        );
        let changed = store.update_member_role(&second.id, "member").await?;
        assert_eq!(changed.id, second.id);
        assert_eq!(
            serde_json::to_value(store.get_member_by_id(&original.id).await?)?,
            serde_json::to_value(Some(original))?
        );
        assert_eq!(
            scalar(
                &db,
                "SELECT json_group_array(id) AS value FROM app_member_audit"
            )
            .await?,
            serde_json::to_string(&vec![second.id.clone()])?
        );
        assert!(
            db.execute_unprepared("UPDATE member SET app_note='blocked'")
                .await
                .is_err()
        );
        let before_repeat=(scalar(&db,row_sql).await?,scalar(&db,schema_sql).await?,scalar(&db,"SELECT json_group_array(version) AS value FROM (SELECT version FROM better_auth_migrations ORDER BY version)").await?);
        AuthMigrator::up(&db, None).await?;
        let migration = AuthMigrator::migrations()
            .into_iter()
            .find(|migration| migration.name() == UPGRADE)
            .ok_or("member pair migration missing")?;
        // Exercise the absence guard itself, independently of the migration ledger.
        migration.up(&SchemaManager::new(&db)).await?;
        migration.up(&SchemaManager::new(&db)).await?;
        assert_eq!((scalar(&db,row_sql).await?,scalar(&db,schema_sql).await?,scalar(&db,"SELECT json_group_array(version) AS value FROM (SELECT version FROM better_auth_migrations ORDER BY version)").await?),before_repeat);
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn organization_list_pages_physical_members_before_joining_and_keeps_full_peer_rows()
    -> TestResult {
        let db = Database::connect("sqlite::memory:").await?;
        AuthMigrator::up(&db, None).await?;
        // A published SQLite installation already has this unconstrained shape.
        // It isolates consumer behavior from whether the upgrade itself ran.
        let _ignored_execute_unprepared_2 = db
            .execute_unprepared("DROP INDEX IF EXISTS idx_member_org_user_unique")
            .await?;
        let config = AuthConfig::new("physical-member-page-secret");
        let store = SeaOrmStore::<BundledSchema>::new(config.clone(), db.clone());
        let user = store
            .create_user(CreateUser::new().with_email("target@member-page.test"))
            .await?;
        let foreign = store
            .create_user(CreateUser::new().with_email("foreign@member-page.test"))
            .await?;
        let old = store
            .create_organization(CreateOrganization::new("Old", "older-member-page"))
            .await?;
        let new = store
            .create_organization(CreateOrganization::new("New", "newer-member-page"))
            .await?;
        let other = store
            .create_organization(CreateOrganization::new("Other", "foreign-member-page"))
            .await?;
        for (id, date) in [
            (&old.id, "2020-01-01 00:00:00+00:00"),
            (&new.id, "2021-01-01 00:00:00+00:00"),
        ] {
            let _ignored_into = db
                .execute_raw(Statement::from_sql_and_values(
                    DbBackend::Sqlite,
                    "UPDATE organization SET created_at=? WHERE id=?",
                    [date.into(), id.clone().into()],
                ))
                .await?;
        }
        let old = store
            .get_organization_by_id(&old.id)
            .await?
            .ok_or("older organization missing")?;
        let new = store
            .get_organization_by_id(&new.id)
            .await?
            .ok_or("newer organization missing")?;
        let first = store
            .create_member(CreateMember::new(&new.id, &user.id, "member"))
            .await?;
        let second = store
            .create_member(CreateMember::new(&old.id, &user.id, "owner"))
            .await?;
        let duplicate = store
            .create_member(CreateMember::new(&new.id, &user.id, "admin"))
            .await?;
        let peer = store
            .create_member(CreateMember::new(&other.id, &foreign.id, "owner"))
            .await?;
        let foreign_before = serde_json::to_value((&peer, &other, &foreign))?;
        for (limit, expected) in [
            (100, vec![new.clone(), old.clone(), new.clone()]),
            (2, vec![new.clone(), old.clone()]),
            (1, vec![new.clone()]),
            (0, vec![]),
        ] {
            let mut configured = config.clone();
            configured.advanced.database.default_find_many_limit = limit;
            let paged = SeaOrmStore::<BundledSchema>::new(configured, db.clone());
            assert_eq!(
                serde_json::to_value(paged.list_user_organizations(&user.id).await?)?,
                serde_json::to_value(expected)?,
                "membership page {limit} must retain multiplicity, full output and admission order"
            );
        }
        assert_eq!(
            serde_json::to_value(store.get_member(&new.id, &user.id).await?)?,
            serde_json::to_value(Some(first.clone()))?,
            "first physical member stays authoritative; duplicate role is not unioned"
        );
        let team = store
            .create_team(CreateTeam {
                name: "Owned team".into(),
                organization_id: new.id.clone(),
                updated_at: None,
            })
            .await?;
        let peer_team = store
            .create_team(CreateTeam {
                name: "Foreign team".into(),
                organization_id: other.id.clone(),
                updated_at: None,
            })
            .await?;
        drop(store.add_team_member(&team.id, &user.id, None).await?);
        drop(store.add_team_member(&team.id, &foreign.id, None).await?);
        drop(store.add_team_member(&peer_team.id, &user.id, None).await?);
        let foreign_team_before = store.get_team(Some(&other.id), &peer_team.id).await?;
        let foreign_link_before = store.get_team_member(&peer_team.id, &user.id).await?;
        store
            .delete_member_with_context(&duplicate.id, &new.id, &user.id, true)
            .await?;
        assert_eq!(
            serde_json::to_value(store.get_member_by_id(&first.id).await?)?,
            serde_json::to_value(Some(first))?
        );
        assert_eq!(
            serde_json::to_value(store.get_member_by_id(&second.id).await?)?,
            serde_json::to_value(Some(second))?
        );
        assert!(store.get_member_by_id(&duplicate.id).await?.is_none());
        assert!(store.get_team_member(&team.id, &user.id).await?.is_none());
        assert!(
            store
                .get_team_member(&team.id, &foreign.id)
                .await?
                .is_some()
        );
        assert_eq!(
            store
                .get_team(Some(&new.id), &team.id)
                .await?
                .map(|team| team.member_count),
            Some(1)
        );
        assert_eq!(
            serde_json::to_value(store.get_team(Some(&other.id), &peer_team.id).await?)?,
            serde_json::to_value(foreign_team_before)?
        );
        assert_eq!(
            serde_json::to_value(store.get_team_member(&peer_team.id, &user.id).await?)?,
            serde_json::to_value(foreign_link_before)?
        );
        assert_eq!(
            serde_json::to_value((
                store
                    .get_member_by_id(&peer.id)
                    .await?
                    .ok_or("peer missing")?,
                store
                    .get_organization_by_id(&other.id)
                    .await?
                    .ok_or("peer organization missing")?,
                store
                    .get_user_by_id(&foreign.id)
                    .await?
                    .ok_or("foreign user missing")?
            ))?,
            foreign_before
        );
        Ok(())
    }

    #[tokio::test]
    async fn independent_connections_admit_distinct_member_ids_for_the_same_pair() -> TestResult {
        let path = std::env::temp_dir().join(format!(
            "member-multiplicity-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let first_db = Database::connect(&url).await?;
        AuthMigrator::up(&first_db, None).await?;
        let config = AuthConfig::new("independent-member-admission-secret");
        let first = SeaOrmStore::<BundledSchema>::new(config.clone(), first_db.clone());
        let second_db = Database::connect(&url).await?;
        let second = SeaOrmStore::<BundledSchema>::new(config, second_db.clone());
        let user = first
            .create_user(CreateUser::new().with_email("concurrent@member-pair.test"))
            .await?;
        let foreign = first
            .create_user(CreateUser::new().with_email("foreign@member-race.test"))
            .await?;
        let org = first
            .create_organization(CreateOrganization::new("Concurrent", "concurrent-pair"))
            .await?;
        let other = first
            .create_organization(CreateOrganization::new("Foreign", "foreign-race-pair"))
            .await?;
        let peer = first
            .create_member(CreateMember::new(&other.id, &foreign.id, "owner"))
            .await?;
        let results = tokio::join!(
            first.create_member(CreateMember::new(&org.id, &user.id, "member")),
            second.create_member(CreateMember::new(&org.id, &user.id, "admin")),
        );
        let a = results.0?;
        let b = results.1?;
        assert_ne!(a.id, b.id);
        assert_eq!(first.count_organization_members(&org.id).await?, 2);
        let rows = first.list_organization_members(&org.id).await?;
        assert_eq!(rows.len(), 2);
        for row in &rows {
            assert_eq!(row.user_id, user.id);
            assert_eq!(row.organization_id, org.id);
        }
        assert_eq!(
            serde_json::to_value(second.get_member_by_id(&a.id).await?)?,
            serde_json::to_value(Some(a))?
        );
        assert_eq!(
            serde_json::to_value(first.get_member_by_id(&b.id).await?)?,
            serde_json::to_value(Some(b))?
        );
        assert_eq!(
            serde_json::to_value(second.get_member_by_id(&peer.id).await?)?,
            serde_json::to_value(Some(peer))?
        );
        first_db.close().await?;
        second_db.close().await?;
        std::fs::remove_file(path)?;
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn installed_pair_upgrade_preserves_dependent_foreign_key_then_retries_after_app_id_migration()
    -> TestResult {
        let db = Database::connect("sqlite::memory:").await?;
        let prior = AuthMigrator::migrations()
            .iter()
            .take_while(|migration| migration.name() != UPGRADE)
            .count();
        AuthMigrator::up(&db, Some(u32::try_from(prior)?)).await?;
        let store = SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("dependent-member-pair-upgrade-secret"),
            db.clone(),
        );
        let user = store
            .create_user(CreateUser::new().with_email("pair-owner@app-ref.test"))
            .await?;
        let foreign = store
            .create_user(CreateUser::new().with_email("pair-peer@app-ref.test"))
            .await?;
        let org = store
            .create_organization(CreateOrganization::new("Owned", "dependent-pair-owned"))
            .await?;
        let other = store
            .create_organization(CreateOrganization::new("Foreign", "dependent-pair-foreign"))
            .await?;
        let member = store
            .create_member(CreateMember::new(&org.id, &user.id, "owner"))
            .await?;
        let peer = store
            .create_member(CreateMember::new(&other.id, &foreign.id, "member"))
            .await?;
        let _ignored_execute_unprepared_3 = db.execute_unprepared("CREATE TABLE \"app \"\"pair\"\" refs\"(org TEXT NOT NULL,user TEXT NOT NULL,note TEXT NOT NULL,FOREIGN KEY(org,user) REFERENCES member(organization_id,user_id))").await?;
        for (organization_id, user_id, note) in [
            (&org.id, &user.id, "owned,bytes"),
            (&other.id, &foreign.id, "peer'bytes"),
        ] {
            let _ignored_into_2 = db
                .execute_raw(Statement::from_sql_and_values(
                    DbBackend::Sqlite,
                    "INSERT INTO \"app \"\"pair\"\" refs\" VALUES(?,?,?)",
                    [
                        organization_id.clone().into(),
                        user_id.clone().into(),
                        note.into(),
                    ],
                ))
                .await?;
        }
        let schema_sql = "SELECT json_group_array(json_object('type',type,'name',name,'table',tbl_name,'sql',sql)) AS value FROM (SELECT * FROM sqlite_schema ORDER BY type,name)";
        let members_sql = "SELECT json_group_array(json_object('rowid',rowid,'id',id,'org',organization_id,'user',user_id,'role',role,'created',created_at)) AS value FROM (SELECT rowid,* FROM member ORDER BY rowid)";
        let app_sql = "SELECT json_group_array(json_object('rowid',rowid,'org',org,'user',user,'note',note)) AS value FROM (SELECT rowid,* FROM \"app \"\"pair\"\" refs\" ORDER BY rowid)";
        let ledger_sql = "SELECT json_group_array(json_object('version',version,'applied',applied_at)) AS value FROM (SELECT * FROM better_auth_migrations ORDER BY version)";
        let before = (
            scalar(&db, schema_sql).await?,
            scalar(&db, members_sql).await?,
            scalar(&db, app_sql).await?,
            scalar(&db, ledger_sql).await?,
        );
        let owners_before = serde_json::to_value((&user, &foreign, &org, &other, &member, &peer))?;
        assert!(
            db.query_all_raw(Statement::from_string(
                DbBackend::Sqlite,
                "PRAGMA foreign_key_check"
            ))
            .await?
            .is_empty()
        );
        let upgrade = AuthMigrator::up(&db, None).await;
        // On the former production this checks the actual broken constraint, rather
        // than failing only because a migration unexpectedly returned success.
        let integrity = db
            .query_all_raw(Statement::from_string(
                DbBackend::Sqlite,
                "PRAGMA foreign_key_check",
            ))
            .await;
        let deletion = store.delete_member(&member.id).await;
        assert!(
            deletion.is_err(),
            "the actual referenced member must stay protected"
        );
        assert!(
            integrity.is_ok(),
            "upgrade invalidated the actual application foreign key: {integrity:?}; member delete: {deletion:?}"
        );
        assert!(integrity?.is_empty());
        assert!(
            matches!(upgrade, Err(sea_orm::DbErr::Migration(_))),
            "a dependent application foreign key must stop the upgrade with its explicit migration error: {upgrade:?}"
        );
        assert_eq!(
            (
                scalar(&db, schema_sql).await?,
                scalar(&db, members_sql).await?,
                scalar(&db, app_sql).await?,
                scalar(&db, ledger_sql).await?
            ),
            before
        );
        assert_eq!(
            serde_json::to_value((
                store
                    .get_user_by_id(&user.id)
                    .await?
                    .ok_or("owner missing")?,
                store
                    .get_user_by_id(&foreign.id)
                    .await?
                    .ok_or("peer user missing")?,
                store
                    .get_organization_by_id(&org.id)
                    .await?
                    .ok_or("owned organization missing")?,
                store
                    .get_organization_by_id(&other.id)
                    .await?
                    .ok_or("peer organization missing")?,
                store
                    .get_member_by_id(&member.id)
                    .await?
                    .ok_or("owned member missing")?,
                store
                    .get_member_by_id(&peer.id)
                    .await?
                    .ok_or("peer member missing")?
            ))?,
            owners_before
        );
        assert!(
            store
                .create_member(CreateMember::new(&org.id, &user.id, "admin"))
                .await
                .is_err()
        );
        // Only the application changes its reference contract, preserving both
        // actual rows and their byte payloads while moving to the member's identity.
        let _ignored_execute_unprepared_4 = db.execute_unprepared("CREATE TABLE app_member_ids(member_id TEXT NOT NULL REFERENCES member(id),note TEXT NOT NULL); INSERT INTO app_member_ids SELECT m.id,a.note FROM \"app \"\"pair\"\" refs\" a JOIN member m ON m.organization_id=a.org AND m.user_id=a.user; DROP TABLE \"app \"\"pair\"\" refs\"").await?;
        let app_ids_sql = "SELECT json_group_array(json_object('member',member_id,'note',note)) AS value FROM (SELECT * FROM app_member_ids ORDER BY rowid)";
        let migrated_app = scalar(&db, app_ids_sql).await?;
        AuthMigrator::up(&db, None).await?;
        assert_eq!(scalar(&db, app_ids_sql).await?, migrated_app);
        assert_eq!(scalar(&db, members_sql).await?, before.1);
        assert!(
            db.query_all_raw(Statement::from_string(
                DbBackend::Sqlite,
                "PRAGMA foreign_key_check"
            ))
            .await?
            .is_empty()
        );
        let duplicate = store
            .create_member(CreateMember::new(&org.id, &user.id, "admin"))
            .await?;
        assert_ne!(duplicate.id, member.id);
        assert_eq!(store.count_organization_members(&org.id).await?, 2);
        assert_eq!(
            serde_json::to_value(store.get_member_by_id(&peer.id).await?)?,
            serde_json::to_value(Some(peer))?
        );
        assert_eq!(scalar(&db, app_ids_sql).await?, migrated_app);
        Ok(())
    }
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
#[cfg(test)]
mod member_removal_tests {
    //! Captured member deletion preserves phase ordering, rollback and adapter pages.
    use super::{
        SeaOrmStore,
        bundled_schema::BundledSchema,
        entities::{member, team, team_member},
        migrator::run_migrations,
    };
    use better_auth_core::store::{MemberStore, OrganizationStore, TeamStore, UserStore};
    use better_auth_core::{AuthConfig, CreateMember, CreateOrganization, CreateTeam, CreateUser};
    use sea_orm::{ConnectionTrait, Database, DbBackend, EntityTrait, QueryOrder, Statement};

    type TestResult = Result<(), Box<dyn std::error::Error>>;
    async fn rows(
        db: &sea_orm::DatabaseConnection,
    ) -> Result<
        (
            Vec<member::Model>,
            Vec<team::Model>,
            Vec<team_member::Model>,
        ),
        sea_orm::DbErr,
    > {
        Ok((
            member::Entity::find()
                .order_by_asc(member::Column::Id)
                .all(db)
                .await?,
            team::Entity::find()
                .order_by_asc(team::Column::Id)
                .all(db)
                .await?,
            team_member::Entity::find()
                .order_by_asc(team_member::Column::Id)
                .all(db)
                .await?,
        ))
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn captured_member_deletion_orders_writes_and_distinguishes_veto_ignore_and_absence()
    -> TestResult {
        let db = Database::connect("sqlite::memory:").await?;
        run_migrations(&db).await?;
        let store = SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("captured-member-deletion-public-store-secret"),
            db.clone(),
        );
        let owner = store
            .create_user(CreateUser::new().with_email("target@member-delete.fixture.test"))
            .await?;
        let foreign = store
            .create_user(CreateUser::new().with_email("foreign@member-delete.fixture.test"))
            .await?;
        let organization = store
            .create_organization(CreateOrganization::new("Own", "own"))
            .await?;
        let other = store
            .create_organization(CreateOrganization::new("Other", "other"))
            .await?;
        let member = store
            .create_member(CreateMember {
                organization_id: organization.id.clone(),
                user_id: owner.id.clone(),
                role: "victim".into(),
            })
            .await?;
        let unrelated = store
            .create_member(CreateMember {
                organization_id: other.id.clone(),
                user_id: foreign.id.clone(),
                role: "foreign".into(),
            })
            .await?;
        let own_team = store
            .create_team(CreateTeam {
                name: "Own team".into(),
                organization_id: organization.id.clone(),
                updated_at: None,
            })
            .await?;
        let other_team = store
            .create_team(CreateTeam {
                name: "Other team".into(),
                organization_id: other.id.clone(),
                updated_at: None,
            })
            .await?;
        drop(store.add_team_member(&own_team.id, &owner.id, None).await?);
        drop(
            store
                .add_team_member(&own_team.id, &foreign.id, None)
                .await?,
        );
        drop(
            store
                .add_team_member(&other_team.id, &owner.id, None)
                .await?,
        );
        let before = rows(&db).await?;
        let _ignored_execute_unprepared=db.execute_unprepared("CREATE TRIGGER member_veto BEFORE DELETE ON member WHEN OLD.role='victim' BEGIN SELECT RAISE(ABORT,'member deletion veto'); END").await?;
        let member_error = store
            .delete_member_with_context(&member.id, &organization.id, &owner.id, true)
            .await
            .err()
            .ok_or_else(|| std::io::Error::other("real member SQL veto must fail"))?;
        assert!(member_error.to_string().contains("member deletion veto"));
        assert_eq!(
            rows(&db).await?,
            before,
            "member veto must preserve all member/team rows"
        );
        let _ignored_execute_unprepared_2 =
            db.execute_unprepared("DROP TRIGGER member_veto").await?;
        let _ignored_execute_unprepared_3=db.execute_unprepared("CREATE TRIGGER team_veto BEFORE DELETE ON team_member WHEN OLD.user_id=(SELECT id FROM users WHERE email='target@member-delete.fixture.test') BEGIN SELECT RAISE(ABORT,'team deletion veto'); END").await?;
        let team_error = store
            .delete_member_with_context(&member.id, &organization.id, &owner.id, true)
            .await
            .err()
            .ok_or_else(|| std::io::Error::other("real later team SQL veto must fail"))?;
        assert!(team_error.to_string().contains("team deletion veto"));
        assert_eq!(
            rows(&db).await?,
            before,
            "later team veto must roll back the member deletion"
        );
        let _ignored_execute_unprepared_4 = db.execute_unprepared("DROP TRIGGER team_veto").await?;
        let _ignored_execute_unprepared_5=db.execute_unprepared("CREATE TRIGGER ignored_member BEFORE DELETE ON member WHEN OLD.role='victim' BEGIN SELECT RAISE(IGNORE); END").await?;
        store
            .delete_member_with_context(&member.id, &organization.id, &owner.id, true)
            .await?;
        assert_eq!(
            serde_json::to_value(store.get_member_by_id(&member.id).await?)?,
            serde_json::to_value(Some(member.clone()))?,
            "ignored deletion is successful with member retained"
        );
        assert!(
            store
                .get_team_member(&own_team.id, &owner.id)
                .await?
                .is_none()
        );
        assert!(
            store
                .get_team_member(&own_team.id, &foreign.id)
                .await?
                .is_some()
        );
        assert_eq!(
            store
                .get_team(Some(&organization.id), &own_team.id)
                .await?
                .map(|team| team.member_count),
            Some(1)
        );
        let _ignored_execute_unprepared_6 =
            db.execute_unprepared("DROP TRIGGER ignored_member").await?;
        drop(store.add_team_member(&own_team.id, &owner.id, None).await?);
        let _ignored_execute_unprepared_7=db.execute_unprepared("CREATE TRIGGER phase_guard BEFORE DELETE ON team_member WHEN EXISTS(SELECT 1 FROM member WHERE user_id=OLD.user_id AND role='victim') BEGIN SELECT RAISE(ABORT,'member must be deleted first'); END").await?;
        store
            .delete_member_with_context(&member.id, &organization.id, &owner.id, true)
            .await?;
        assert!(store.get_member_by_id(&member.id).await?.is_none());
        assert!(
            store
                .get_team_member(&own_team.id, &owner.id)
                .await?
                .is_none()
        );
        let _ignored_execute_unprepared_8 =
            db.execute_unprepared("DROP TRIGGER phase_guard").await?;
        drop(store.add_team_member(&own_team.id, &owner.id, None).await?);
        store
            .delete_member_with_context(&member.id, &organization.id, &owner.id, true)
            .await?;
        assert!(
            store
                .get_team_member(&own_team.id, &owner.id)
                .await?
                .is_none(),
            "captured cleanup still runs after genuine row absence"
        );
        assert_eq!(
            serde_json::to_value(store.get_member_by_id(&unrelated.id).await?)?,
            serde_json::to_value(Some(unrelated))?
        );
        assert_eq!(store.get_user_by_id(&owner.id).await?, Some(owner.clone()));
        assert_eq!(store.get_user_by_id(&foreign.id).await?, Some(foreign));
        assert_eq!(
            serde_json::to_value(store.get_organization_by_id(&organization.id).await?)?,
            serde_json::to_value(Some(organization.clone()))?
        );
        assert_eq!(
            serde_json::to_value(store.get_organization_by_id(&other.id).await?)?,
            serde_json::to_value(Some(other.clone()))?
        );
        let final_rows = rows(&db).await?;
        assert_eq!(
            final_rows.0,
            before
                .0
                .into_iter()
                .filter(|row| row.id != member.id)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            final_rows.2,
            before
                .2
                .into_iter()
                .filter(|row| !(row.team_id == own_team.id && row.user_id == owner.id))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            final_rows.1,
            before
                .1
                .into_iter()
                .map(|mut row| {
                    if row.id == own_team.id {
                        row.member_count -= 1;
                    }
                    row
                })
                .collect::<Vec<_>>()
        );
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn contextual_deletion_uses_original_scope_and_unsorted_configured_pages() -> TestResult {
        let db = Database::connect("sqlite::memory:").await?;
        run_migrations(&db).await?;
        let mut config = AuthConfig::new("member-deletion-pages-public-store-secret");
        config.advanced.database.default_find_many_limit = 1;
        let store = SeaOrmStore::<BundledSchema>::new(config, db.clone());
        let user = store
            .create_user(CreateUser::new().with_email("page-target@member-delete.fixture.test"))
            .await?;
        let other_user = store
            .create_user(CreateUser::new().with_email("page-other@member-delete.fixture.test"))
            .await?;
        let org = store
            .create_organization(CreateOrganization::new("Page", "page"))
            .await?;
        let other = store
            .create_organization(CreateOrganization::new("Other page", "other-page"))
            .await?;
        let first = store
            .create_member(CreateMember {
                organization_id: org.id.clone(),
                user_id: user.id.clone(),
                role: "owner".into(),
            })
            .await?;
        let second = store
            .create_member(CreateMember {
                organization_id: org.id.clone(),
                user_id: other_user.id.clone(),
                role: "owner".into(),
            })
            .await?;
        let _ignored_into = db
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "UPDATE member SET created_at=? WHERE id=?",
                ["2030-01-01T00:00:00Z".into(), first.id.clone().into()],
            ))
            .await?;
        let _ignored_into_2 = db
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "UPDATE member SET created_at=? WHERE id=?",
                ["2000-01-01T00:00:00Z".into(), second.id.clone().into()],
            ))
            .await?;
        assert_eq!(
            store
                .list_organization_members_page(&org.id, 1)
                .await?
                .into_iter()
                .map(|row| row.id)
                .collect::<Vec<_>>(),
            vec![first.id.clone()],
            "adapter page follows physical insertion rather than timestamp ordering"
        );
        assert_eq!(
            store
                .list_organization_members(&org.id)
                .await?
                .into_iter()
                .map(|row| row.id)
                .collect::<Vec<_>>(),
            vec![second.id.clone(), first.id.clone()],
            "existing sorted API stays unchanged"
        );
        let mut teams = Vec::new();
        for name in ["First physical", "Second physical"] {
            let team = store
                .create_team(CreateTeam {
                    name: name.into(),
                    organization_id: org.id.clone(),
                    updated_at: None,
                })
                .await?;
            drop(store.add_team_member(&team.id, &user.id, None).await?);
            teams.push(team);
        }
        let [first_team, second_team] = teams.as_slice() else {
            return Err(
                std::io::Error::other("two actual team creations must return their rows").into(),
            );
        };
        let before = rows(&db).await?;
        let _ignored_into_3 = db
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "UPDATE member SET organization_id=?, user_id=? WHERE id=?",
                [
                    other.id.clone().into(),
                    other_user.id.clone().into(),
                    first.id.clone().into(),
                ],
            ))
            .await?;
        store
            .delete_member_with_context(&first.id, &org.id, &user.id, false)
            .await?;
        let after_disabled = rows(&db).await?;
        assert_eq!(after_disabled.1, before.1);
        assert_eq!(
            after_disabled.2, before.2,
            "disabled teams retain their real legacy memberships"
        );
        store
            .delete_member_with_context(&first.id, &org.id, &user.id, true)
            .await?;
        assert!(
            store
                .get_team_member(&first_team.id, &user.id)
                .await?
                .is_none()
        );
        assert!(
            store
                .get_team_member(&second_team.id, &user.id)
                .await?
                .is_some(),
            "teams outside the actual configured page remain"
        );
        let final_rows = rows(&db).await?;
        assert_eq!(
            final_rows.1,
            before
                .1
                .into_iter()
                .map(|mut row| {
                    if row.id == first_team.id {
                        row.member_count -= 1;
                    }
                    row
                })
                .collect::<Vec<_>>()
        );
        assert_eq!(
            final_rows.2,
            before
                .2
                .into_iter()
                .filter(|row| row.team_id != first_team.id)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            store
                .get_member_by_id(&second.id)
                .await?
                .map(|row| row.role),
            Some("owner".into())
        );
        assert_eq!(store.get_user_by_id(&user.id).await?, Some(user));
        assert_eq!(
            store.get_user_by_id(&other_user.id).await?,
            Some(other_user)
        );
        assert_eq!(
            serde_json::to_value(store.get_organization_by_id(&org.id).await?)?,
            serde_json::to_value(Some(org))?
        );
        assert_eq!(
            serde_json::to_value(store.get_organization_by_id(&other.id).await?)?,
            serde_json::to_value(Some(other))?
        );
        Ok(())
    }
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
#[cfg(test)]
mod member_role_tests {
    //! Public optional member updates distinguish genuine absence and SQL failures.
    use super::{SeaOrmStore, bundled_schema::BundledSchema, migrator::run_migrations};
    use better_auth_core::store::{MemberStore, OrganizationStore, UserStore};
    use better_auth_core::{AuthConfig, CreateMember, CreateOrganization, CreateUser};
    use sea_orm::{ConnectionTrait, Database};

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn optional_member_role_updates_distinguish_missing_rows_from_write_errors()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect("sqlite::memory:").await?;
        run_migrations(&database).await?;
        let store = SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("optional-member-role-public-store-secret"),
            database.clone(),
        );
        let organization = store
            .create_organization(CreateOrganization::new("Roles", "roles"))
            .await?;
        let mut members = Vec::new();
        for name in ["target", "foreign"] {
            let user = store
                .create_user(CreateUser::new().with_email(format!("{name}@role.fixture.test")))
                .await?;
            members.push(
                store
                    .create_member(CreateMember {
                        organization_id: organization.id.clone(),
                        user_id: user.id,
                        role: name.into(),
                    })
                    .await?,
            );
        }
        let target = (members)
            .first()
            .expect("fixture contains the requested index");
        let foreign = (members)
            .get(1)
            .expect("fixture contains the requested index");
        let updated = store
            .update_member_role_if_present(&target.id, "admin")
            .await?
            .ok_or_else(|| {
                std::io::Error::other("existing member update must return its actual row")
            })?;
        assert_eq!(updated.role, "admin");
        assert_eq!(updated.id, target.id);
        assert_eq!(updated.user_id, target.user_id);
        assert_eq!(updated.organization_id, target.organization_id);
        assert_eq!(updated.created_at, target.created_at);
        assert_eq!(
            serde_json::to_value(store.get_member_by_id(&target.id).await?)?,
            serde_json::to_value(Some(&updated))?
        );
        let _ignored_execute_unprepared=database.execute_unprepared("CREATE TRIGGER veto_optional_member BEFORE UPDATE OF role ON member WHEN OLD.role='admin' BEGIN SELECT RAISE(ABORT,'optional member storage veto'); END").await?;
        assert!(
            store
                .update_member_role_if_present(&target.id, "must-not-persist")
                .await
                .is_err(),
            "storage veto is not missing-row success"
        );
        assert_eq!(
            serde_json::to_value(store.get_member_by_id(&target.id).await?)?,
            serde_json::to_value(Some(&updated))?
        );
        let _ignored_execute_unprepared_2 = database
            .execute_unprepared("DROP TRIGGER veto_optional_member")
            .await?;
        let _ignored_execute_unprepared_3=database.execute_unprepared("CREATE TRIGGER ignore_optional_member BEFORE UPDATE OF role ON member WHEN OLD.role='admin' BEGIN SELECT RAISE(IGNORE); END").await?;
        assert!(
            store
                .update_member_role_if_present(&target.id, "ignored")
                .await?
                .is_none(),
            "actual zero-row update is absence"
        );
        assert_eq!(
            serde_json::to_value(store.get_member_by_id(&target.id).await?)?,
            serde_json::to_value(Some(&updated))?
        );
        store.delete_member(&target.id).await?;
        assert!(
            store
                .update_member_role_if_present(&target.id, "deleted")
                .await?
                .is_none()
        );
        assert!(
            store
                .update_member_role(&target.id, "deleted")
                .await
                .is_err(),
            "original operation preserves missing-row error"
        );
        assert_eq!(
            serde_json::to_value(store.get_member_by_id(&foreign.id).await?)?,
            serde_json::to_value(Some(foreign))?
        );
        assert_eq!(
            serde_json::to_value(store.get_organization_by_id(&organization.id).await?)?,
            serde_json::to_value(Some(&organization))?
        );
        Ok(())
    }
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
#[cfg(test)]
mod nullable_organization_tests {
    use super::{SeaOrmStore, bundled_schema::BundledSchema, migrator::run_migrations};
    use better_auth_core::{
        AuthConfig, CreateOrganization, UpdateOrganization, store::OrganizationStore,
    };
    use sea_orm::{ConnectionTrait, Database, DatabaseConnection, Statement};
    use serde_json::{Value, json};

    async fn raw_metadata(
        database: &DatabaseConnection,
        id: &str,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let row = database
            .query_one_raw(Statement::from_sql_and_values(
                database.get_database_backend(),
                "SELECT metadata FROM organization WHERE id = ?",
                [id.into()],
            ))
            .await?
            .ok_or_else(|| std::io::Error::other("organization disappeared"))?;
        Ok(row.try_get("", "metadata")?)
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn public_store_distinguishes_omitted_and_literal_null_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect("sqlite::memory:").await?;
        run_migrations(&database).await?;
        let store = SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("nullable-organization-metadata-public-store-secret"),
            database.clone(),
        );
        let absent = store
            .create_organization(CreateOrganization::new("Absent", "absent"))
            .await?;
        assert_eq!(absent.metadata, None);
        assert_eq!(raw_metadata(&database, &absent.id).await?, None);
        let literal = store
            .create_organization(
                CreateOrganization::new("Literal", "literal").with_metadata(Value::Null),
            )
            .await?;
        assert_eq!(literal.metadata, Some(Value::Null));
        assert_eq!(
            raw_metadata(&database, &literal.id).await?,
            Some("null".into())
        );
        for organization in [&absent, &literal] {
            let renamed = store
                .update_organization(
                    &organization.id,
                    UpdateOrganization {
                        name: Some("Renamed".into()),
                        ..Default::default()
                    },
                )
                .await?;
            assert_eq!(renamed.metadata, organization.metadata);
            assert_eq!(renamed.slug, organization.slug);
            assert_eq!(renamed.created_at, organization.created_at);
        }
        for value in [
            json!({}),
            json!({"guard": [null, true, "kept"]}),
            Value::Null,
        ] {
            let updated = store
                .update_organization(
                    &absent.id,
                    UpdateOrganization {
                        metadata: Some(value.clone()),
                        ..Default::default()
                    },
                )
                .await?;
            assert_eq!(updated.metadata, Some(value.clone()));
            assert_eq!(
                raw_metadata(&database, &absent.id).await?,
                Some(better_auth_core::utils::json::to_string(&value)?)
            );
            let read = store
                .get_organization_by_id(&absent.id)
                .await?
                .ok_or_else(|| std::io::Error::other("organization disappeared"))?;
            assert_eq!(read.metadata, Some(value));
        }
        assert_eq!(
            store
                .get_organization_by_slug("literal")
                .await?
                .map(|row| row.metadata),
            Some(Some(Value::Null))
        );
        let rows = store
            .list_organizations_by_ids(&[absent.id, literal.id])
            .await?;
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| row.metadata == Some(Value::Null)));
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn installed_organization_upgrade_preserves_bytes_custom_schema_and_references()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect("sqlite::memory:").await?;
        for sql in [
            "CREATE TABLE organization (id TEXT PRIMARY KEY, name TEXT NOT NULL, slug TEXT NOT NULL UNIQUE, logo TEXT, metadata JSON CONSTRAINT metadata_required NOT NULL ON CONFLICT FAIL CONSTRAINT metadata_default DEFAULT ('{}') CHECK(json_valid(metadata)), created_at TEXT NOT NULL, updated_at TEXT NOT NULL, \"app,notes\" TEXT NOT NULL DEFAULT 'kept,bytes', display_label TEXT GENERATED ALWAYS AS (name || ', generated') VIRTUAL)",
            "INSERT INTO organization (rowid,id,name,slug,metadata,created_at,updated_at) VALUES (97,'legacy-literal','Legacy','legacy','null','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z'),(103,'legacy-object','Object','object','{ \"guard\" : [null,true] }','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
            "CREATE TABLE custom_organization_links (id TEXT PRIMARY KEY, organization_id TEXT REFERENCES organization(id) ON DELETE CASCADE)",
            "INSERT INTO custom_organization_links VALUES ('kept-link','legacy-literal')",
            "CREATE UNIQUE INDEX idx_organization_app ON organization(\"app,notes\",slug) WHERE metadata IS NOT NULL",
            "CREATE VIEW visible_organizations AS SELECT id,metadata,display_label FROM organization",
            "CREATE TABLE organization_events (id TEXT, name TEXT)",
            "CREATE TRIGGER organization_name_event AFTER UPDATE OF name ON organization BEGIN INSERT INTO organization_events VALUES (NEW.id,NEW.name); END",
        ] {
            let _ignored_execute_unprepared = database.execute_unprepared(sql).await?;
        }
        run_migrations(&database).await?;
        let store = SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("nullable-organization-metadata-installed-store-secret"),
            database.clone(),
        );
        assert_eq!(
            raw_metadata(&database, "legacy-literal").await?,
            Some("null".into())
        );
        assert_eq!(
            raw_metadata(&database, "legacy-object").await?,
            Some("{ \"guard\" : [null,true] }".into())
        );
        let retained = database
        .query_one_raw(Statement::from_string(
            database.get_database_backend(),
            "SELECT rowid, \"app,notes\",display_label FROM organization WHERE id='legacy-literal'",
        ))
        .await?
        .ok_or_else(|| std::io::Error::other("lost legacy row"))?;
        assert_eq!(retained.try_get::<i64>("", "rowid")?, 97);
        assert_eq!(retained.try_get::<String>("", "app,notes")?, "kept,bytes");
        assert_eq!(
            retained.try_get::<String>("", "display_label")?,
            "Legacy, generated"
        );
        let ddl = database
            .query_one_raw(Statement::from_string(
                database.get_database_backend(),
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name='organization'",
            ))
            .await?
            .ok_or_else(|| std::io::Error::other("lost organization schema"))?
            .try_get::<String>("", "sql")?;
        assert!(
            ddl.contains("CONSTRAINT metadata_default DEFAULT ('{}') CHECK(json_valid(metadata))")
        );
        assert!(!ddl.contains("metadata_required"));
        let new = store
            .create_organization(CreateOrganization::new("New Absent", "new-absent"))
            .await?;
        assert_eq!(new.metadata, None);
        assert_eq!(raw_metadata(&database, &new.id).await?, None);
        let literal = store
            .get_organization_by_id("legacy-literal")
            .await?
            .ok_or_else(|| std::io::Error::other("lost legacy model"))?;
        assert_eq!(literal.metadata, Some(Value::Null));
        let updated = store
            .update_organization(
                "legacy-literal",
                UpdateOrganization {
                    name: Some("Changed".into()),
                    ..Default::default()
                },
            )
            .await?;
        assert_eq!(updated.metadata, Some(Value::Null));
        let view = database
        .query_one_raw(Statement::from_string(
            database.get_database_backend(),
            "SELECT metadata, display_label FROM visible_organizations WHERE id='legacy-literal'",
        ))
        .await?
        .ok_or_else(|| std::io::Error::other("lost dependent view"))?;
        assert_eq!(view.try_get::<String>("", "metadata")?, "null");
        assert_eq!(
            view.try_get::<String>("", "display_label")?,
            "Changed, generated"
        );
        let event = database
            .query_one_raw(Statement::from_string(
                database.get_database_backend(),
                "SELECT id,name FROM organization_events",
            ))
            .await?
            .ok_or_else(|| std::io::Error::other("lost update trigger"))?;
        assert_eq!(event.try_get::<String>("", "id")?, "legacy-literal");
        assert_eq!(event.try_get::<String>("", "name")?, "Changed");
        let index = database
            .query_one_raw(Statement::from_string(
                database.get_database_backend(),
                "SELECT sql FROM sqlite_schema WHERE name='idx_organization_app'",
            ))
            .await?
            .ok_or_else(|| std::io::Error::other("lost index"))?;
        assert!(
            index
                .try_get::<String>("", "sql")?
                .contains("WHERE metadata IS NOT NULL")
        );
        assert!(
            database
                .execute_unprepared(
                    "INSERT INTO custom_organization_links VALUES ('denied','missing')"
                )
                .await
                .is_err()
        );
        store.delete_organization("legacy-literal").await?;
        assert!(
            database
                .query_one_raw(Statement::from_string(
                    database.get_database_backend(),
                    "SELECT id FROM custom_organization_links WHERE id='kept-link'"
                ))
                .await?
                .is_none()
        );
        assert_eq!(
            raw_metadata(&database, "legacy-object").await?,
            Some("{ \"guard\" : [null,true] }".into())
        );
        run_migrations(&database).await?;
        assert_eq!(raw_metadata(&database, &new.id).await?, None);
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn invalid_installed_reference_rolls_back_metadata_upgrade_and_restores_settings()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect("sqlite::memory:").await?;
        // Establish the prior schema and migration ledger before installing a
        // legacy constrained organization table with an already-invalid child.
        run_migrations(&database).await?;
        for sql in [
            "DROP TABLE organization",
            "CREATE TABLE organization (id TEXT PRIMARY KEY, metadata JSON NOT NULL, app TEXT)",
            "INSERT INTO organization VALUES ('kept','null','retained')",
            "CREATE TABLE custom_organization_links (id TEXT PRIMARY KEY, organization_id TEXT REFERENCES organization(id))",
            "PRAGMA foreign_keys=OFF",
            "INSERT INTO custom_organization_links VALUES ('invalid','missing')",
            "PRAGMA foreign_keys=ON",
            "DELETE FROM better_auth_migrations WHERE version='m20260930_000013_nullable_organization_metadata'",
        ] {
            let _ignored_execute_unprepared_2 = database.execute_unprepared(sql).await?;
        }
        let error = run_migrations(&database).await.err().ok_or_else(|| {
            std::io::Error::other("invalid foreign key did not reject the actual table rebuild")
        })?;
        assert!(error.to_string().contains("foreign-key"));
        let row = database
            .query_one_raw(Statement::from_string(
                database.get_database_backend(),
                "SELECT metadata,app FROM organization WHERE id='kept'",
            ))
            .await?
            .ok_or_else(|| std::io::Error::other("rollback lost row"))?;
        assert_eq!(row.try_get::<String>("", "metadata")?, "null");
        assert_eq!(row.try_get::<String>("", "app")?, "retained");
        assert!(
            database
                .execute_unprepared("INSERT INTO organization VALUES ('null-rejected',NULL,'no')")
                .await
                .is_err()
        );
        assert!(
            database
                .execute_unprepared(
                    "INSERT INTO custom_organization_links VALUES ('still-denied','missing')"
                )
                .await
                .is_err()
        );
        for (pragma, expected) in [
            ("PRAGMA foreign_keys", 1_i64),
            ("PRAGMA legacy_alter_table", 0),
        ] {
            let row_2 = database
                .query_one_raw(Statement::from_string(
                    database.get_database_backend(),
                    pragma,
                ))
                .await?
                .ok_or_else(|| std::io::Error::other("missing setting"))?;
            assert_eq!(row_2.try_get_by_index::<i64>(0)?, expected);
        }
        assert!(
            database
                .query_one_raw(Statement::from_string(
                    database.get_database_backend(),
                    "SELECT name FROM sqlite_schema WHERE name='organization__nullable_metadata'"
                ))
                .await?
                .is_none()
        );
        assert!(database.query_one_raw(Statement::from_string(database.get_database_backend(),"SELECT version FROM better_auth_migrations WHERE version='m20260930_000013_nullable_organization_metadata'")).await?.is_none());
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn optional_organization_update_distinguishes_absence_from_database_write_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect("sqlite::memory:").await?;
        run_migrations(&database).await?;
        let store = SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("optional-organization-update-public-store-secret"),
            database.clone(),
        );
        let target = store
            .create_organization(CreateOrganization::new("Original", "optional-target"))
            .await?;
        let foreign = store
            .create_organization(
                CreateOrganization::new("Unrelated", "optional-foreign")
                    .with_metadata(json!({"private":"retained"})),
            )
            .await?;
        let updated = store
            .update_organization_if_present(
                &target.id,
                UpdateOrganization {
                    name: Some("Updated".into()),
                    ..Default::default()
                },
            )
            .await?
            .ok_or_else(|| std::io::Error::other("existing update must return its actual row"))?;
        assert_eq!(updated.name, "Updated");
        assert_eq!(updated.id, target.id);
        assert_eq!(updated.created_at, target.created_at);
        assert_eq!(updated.logo, target.logo);
        assert_eq!(updated.metadata, target.metadata);
        assert_eq!(
            serde_json::to_value(store.get_organization_by_id(&target.id).await?)?,
            serde_json::to_value(Some(&updated))?
        );
        let _ignored_execute_unprepared_3 = database.execute_unprepared("CREATE TRIGGER veto_optional_organization BEFORE UPDATE ON organization WHEN OLD.slug='optional-target' BEGIN SELECT RAISE(ABORT,'optional organization storage veto'); END").await?;
        let veto = store
            .update_organization_if_present(
                &target.id,
                UpdateOrganization {
                    name: Some("Must Not Persist".into()),
                    ..Default::default()
                },
            )
            .await;
        assert!(veto.is_err(), "database veto is not a missing-row success");
        assert_eq!(
            serde_json::to_value(store.get_organization_by_id(&target.id).await?)?,
            serde_json::to_value(Some(&updated))?
        );
        let _ignored_execute_unprepared_4 = database
            .execute_unprepared("DROP TRIGGER veto_optional_organization")
            .await?;
        let _ignored_execute_unprepared_5 = database.execute_unprepared("CREATE TRIGGER ignore_optional_organization BEFORE UPDATE ON organization WHEN OLD.slug='optional-target' BEGIN SELECT RAISE(IGNORE); END").await?;
        assert!(
            store
                .update_organization_if_present(
                    &target.id,
                    UpdateOrganization {
                        name: Some("Ignored By Adapter".into()),
                        ..Default::default()
                    }
                )
                .await?
                .is_none(),
            "a real zero-row UPDATE is absence, not a database failure"
        );
        assert_eq!(
            serde_json::to_value(store.get_organization_by_id(&target.id).await?)?,
            serde_json::to_value(Some(&updated))?
        );
        store.delete_organization(&target.id).await?;
        assert!(
            store
                .update_organization_if_present(
                    &target.id,
                    UpdateOrganization {
                        name: Some("Deleted".into()),
                        ..Default::default()
                    }
                )
                .await?
                .is_none()
        );
        assert!(
            store
                .update_organization(&target.id, UpdateOrganization::default())
                .await
                .is_err(),
            "original public update retains its missing-row error contract"
        );
        assert_eq!(
            serde_json::to_value(store.get_organization_by_id(&foreign.id).await?)?,
            serde_json::to_value(Some(&foreign))?
        );
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Public store contract assertions propagate database setup errors"
    )]
    async fn organization_database_patch_retains_unrequested_native_columns()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect("sqlite::memory:").await?;
        run_migrations(&database).await?;
        let store = SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("organization-database-patch-native-store-secret"),
            database,
        );
        let original = store
            .create_organization(
                CreateOrganization::new("Original", "database-patch")
                    .with_logo("https://example.test/original.png")
                    .with_metadata(json!({"nested":[true,null]})),
            )
            .await?;
        let updated = store
            .patch_organization_if_present(
                &original.id,
                UpdateOrganization {
                    name: Some("Updated".into()),
                    logo: Some(None),
                    ..Default::default()
                },
            )
            .await?
            .ok_or_else(|| std::io::Error::other("patch must return its matching row"))?;
        assert_eq!(updated.name, "Updated");
        assert_eq!(updated.logo, None);
        assert_eq!(updated.metadata, original.metadata);
        assert_eq!(updated.created_at, original.created_at);
        assert_eq!(updated.updated_at, original.updated_at);
        assert!(
            matches!(
                store
                    .patch_organization_if_present(&original.id, UpdateOrganization::default())
                    .await,
                Err(better_auth_core::AuthError::Database(_))
            ),
            "an actual empty prepared UPDATE remains a database error"
        );
        assert_eq!(
            serde_json::to_value(store.get_organization_by_id(&original.id).await?)?,
            serde_json::to_value(Some(&updated))?
        );
        store.delete_organization(&original.id).await?;
        assert!(
            store
                .patch_organization_if_present(
                    &original.id,
                    UpdateOrganization {
                        name: Some("Gone".into()),
                        ..Default::default()
                    }
                )
                .await?
                .is_none()
        );
        Ok(())
    }
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
#[cfg(test)]
mod nullable_user_tests {
    use super::{SeaOrmStore, bundled_schema::BundledSchema, migrator::run_migrations};
    use better_auth_core::{
        AuthConfig, CreateAccount, CreateSession, CreateUser, UpdateUser,
        entity::AuthUser,
        store::{AccountStore, SessionStore, UserStore},
    };
    use chrono::{Duration, Utc};
    use sea_orm::{ConnectOptions, ConnectionTrait, Database, Statement};
    use sea_orm_migration::{MigrationTrait, MigratorTrait, SchemaManager};

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    async fn disabled_plugin_creation_preserves_sql_null() -> Result<(), Box<dyn std::error::Error>>
    {
        let database = Database::connect("sqlite::memory:").await?;
        run_migrations(&database).await?;
        let store = SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("nullable-plugin-fields-local-test-secret-32"),
            database,
        );
        let user = store
            .create_user(CreateUser::new().with_email("disabled-plugin@example.com"))
            .await?;
        assert!(!user.two_factor_enabled());
        assert!(!user.banned());
        assert_eq!(user.two_factor_enabled_value(), None);
        assert_eq!(user.banned_value(), None);
        let row = store
            .connection()
            .query_one_raw(Statement::from_sql_and_values(
                store.connection().get_database_backend(),
                "SELECT two_factor_enabled, banned FROM users WHERE id = ?",
                vec![user.id.into()],
            ))
            .await?
            .ok_or_else(|| std::io::Error::other("created user disappeared"))?;
        assert_eq!(row.try_get::<Option<bool>>("", "two_factor_enabled")?, None);
        assert_eq!(row.try_get::<Option<bool>>("", "banned")?, None);
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    async fn explicit_flags_persist_without_initializing_unrelated_updates()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect("sqlite::memory:").await?;
        run_migrations(&database).await?;
        let store = SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("nullable-plugin-flags-explicit-local-secret-32"),
            database,
        );
        let unset = store
            .create_user(CreateUser::new().with_email("unset-fields@example.com"))
            .await?;
        let renamed = store
            .update_user(
                &unset.id,
                UpdateUser {
                    name: Some("Unrelated update".to_owned()),
                    ..Default::default()
                },
            )
            .await?;
        assert_eq!(renamed.two_factor_enabled_value(), None);
        assert_eq!(renamed.banned_value(), None);
        let configured = store
            .create_user(CreateUser {
                email: Some("explicit-fields@example.com".to_owned()),
                two_factor_enabled: Some(true),
                banned: Some(true),
                ..Default::default()
            })
            .await?;
        let persisted = store
            .get_user_by_id(&configured.id)
            .await?
            .ok_or_else(|| std::io::Error::other("created configured user disappeared"))?;
        assert!(persisted.two_factor_enabled());
        assert!(persisted.banned());
        assert_eq!(persisted.two_factor_enabled_value(), Some(true));
        assert_eq!(persisted.banned_value(), Some(true));
        let disabled = store
            .update_user(
                &configured.id,
                UpdateUser {
                    two_factor_enabled: Some(false),
                    banned: Some(false),
                    ..Default::default()
                },
            )
            .await?;
        assert_eq!(disabled.two_factor_enabled_value(), Some(false));
        assert_eq!(disabled.banned_value(), Some(false));
        let initialized = store
            .update_user(
                &unset.id,
                UpdateUser {
                    two_factor_enabled: Some(false),
                    banned: Some(false),
                    ..Default::default()
                },
            )
            .await?;
        assert_eq!(initialized.two_factor_enabled_value(), Some(false));
        assert_eq!(initialized.banned_value(), Some(false));
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn upgrades_populated_users_preserving_custom_schema_and_foreign_keys()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect("sqlite::memory:").await?;
        // An installed user table predating nullable fields, extended by its
        // application. The migration must retain the entire table definition.
        let _ignored_execute_unprepared = database.execute_unprepared(
        "CREATE TABLE users (
            id TEXT NOT NULL PRIMARY KEY,
            name TEXT, email TEXT UNIQUE, email_verified BOOLEAN NOT NULL DEFAULT FALSE,
            image TEXT, username TEXT UNIQUE, display_username TEXT,
            two_factor_enabled BOOLEAN CONSTRAINT two_factor_required NOT NULL DEFAULT (FALSE) CHECK(two_factor_enabled IN (0, 1)),
            role TEXT, banned BOOLEAN NOT NULL CONSTRAINT banned_default DEFAULT FALSE,
            ban_reason TEXT, ban_expires TEXT, metadata JSON NOT NULL,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            \"profile,notes\" TEXT NOT NULL DEFAULT 'retained,custom',
            display_label TEXT GENERATED ALWAYS AS (coalesce(name, 'unknown, user')) VIRTUAL
        )",
    ).await?;
        super::migrator::AuthMigrator::up(&database, Some(5)).await?;
        let store = SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("nullable-plugin-upgrade-local-test-secret-32"),
            database.clone(),
        );
        let existing = store
            .create_user(CreateUser {
                id: Some("existing-upgrade-user".to_owned()),
                email: Some("existing-upgrade@example.com".to_owned()),
                name: Some("Existing user".to_owned()),
                two_factor_enabled: Some(true),
                banned: Some(false),
                ..Default::default()
            })
            .await?;
        let opposite = store
            .create_user(CreateUser {
                id: Some("opposite-upgrade-user".to_owned()),
                email: Some("opposite-upgrade@example.com".to_owned()),
                two_factor_enabled: Some(false),
                banned: Some(true),
                ..Default::default()
            })
            .await?;
        let session = store
            .create_session(CreateSession {
                additional_fields: better_auth_core::field_policy::FieldValues::default(),
                token: None,
                user_id: existing.id.clone(),
                expires_at: Utc::now() + Duration::hours(1),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
                active_team_id: None,
            })
            .await?;
        let account = store
            .create_account(CreateAccount {
                additional_fields: Default::default(),
                account_id: existing.id.clone(),
                provider_id: "credential".to_owned(),
                user_id: existing.id.clone(),
                password: Some("local-test-password-hash".to_owned()),
                access_token: None,
                refresh_token: None,
                id_token: None,
                access_token_expires_at: None,
                refresh_token_expires_at: None,
                scope: None,
            })
            .await?;
        let _ignored_execute_unprepared_2 = database.execute_unprepared(
        "CREATE TABLE custom_user_links (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE)",
    ).await?;
        let _ignored_execute_unprepared_3 = database
            .execute_unprepared(
                "INSERT INTO custom_user_links VALUES ('retained-link', 'existing-upgrade-user')",
            )
            .await?;
        let _ignored_execute_unprepared_4 = database
        .execute_unprepared(
            "CREATE UNIQUE INDEX idx_users_custom_email ON users(lower(email)) WHERE banned = 0",
        )
        .await?;
        let _ignored_execute_unprepared_5 = database
            .execute_unprepared(
                "CREATE TABLE custom_user_events (user_id TEXT, observed_name TEXT)",
            )
            .await?;
        let _ignored_execute_unprepared_6 = database.execute_unprepared(
        "CREATE TRIGGER custom_user_updated AFTER UPDATE OF name ON users BEGIN INSERT INTO custom_user_events VALUES (new.id, new.name); END",
    ).await?;
        let _ignored_execute_unprepared_7 = database
            .execute_unprepared(
                "CREATE VIEW visible_users AS SELECT id, banned, display_label FROM users",
            )
            .await?;
        run_migrations(&database).await?;
        run_migrations(&database).await?;
        let retained = store
            .get_user_by_id(&existing.id)
            .await?
            .ok_or_else(|| std::io::Error::other("upgrade lost existing user"))?;
        assert_eq!(retained.two_factor_enabled_value(), Some(true));
        assert_eq!(retained.banned_value(), Some(false));
        let other = store
            .get_user_by_id(&opposite.id)
            .await?
            .ok_or_else(|| std::io::Error::other("upgrade lost opposite user"))?;
        assert_eq!(other.two_factor_enabled_value(), Some(false));
        assert_eq!(other.banned_value(), Some(true));
        assert_eq!(
            store.get_session(&session.token).await?.map(|row| row.id),
            Some(session.id.clone())
        );
        assert_eq!(
            store
                .get_account("credential", &existing.id)
                .await?
                .map(|row| row.id),
            Some(account.id.clone())
        );
        let fields = database
        .query_one_raw(Statement::from_string(
            database.get_database_backend(),
            "SELECT \"profile,notes\", display_label FROM users WHERE id = 'existing-upgrade-user'"
                .to_owned(),
        ))
        .await?
        .ok_or_else(|| std::io::Error::other("missing retained custom fields"))?;
        assert_eq!(
            fields.try_get::<String>("", "profile,notes")?,
            "retained,custom"
        );
        assert_eq!(
            fields.try_get::<String>("", "display_label")?,
            "Existing user"
        );
        let visible = database.query_one_raw(Statement::from_string(
        database.get_database_backend(),
        "SELECT id, banned, display_label FROM visible_users WHERE id = 'existing-upgrade-user'".to_owned(),
    )).await?.ok_or_else(|| std::io::Error::other("upgrade lost dependent view"))?;
        assert_eq!(visible.try_get::<String>("", "id")?, existing.id);
        assert!(!visible.try_get::<bool>("", "banned")?);
        let null_user = store
            .create_user(CreateUser::new().with_email("new-null-user@example.com"))
            .await?;
        assert_eq!(null_user.two_factor_enabled_value(), None);
        assert_eq!(null_user.banned_value(), None);
        drop(
            store
                .update_user(
                    &existing.id,
                    UpdateUser {
                        name: Some("Trigger still works".to_owned()),
                        ..Default::default()
                    },
                )
                .await?,
        );
        let event = database
            .query_one_raw(Statement::from_string(
                database.get_database_backend(),
                "SELECT user_id, observed_name FROM custom_user_events".to_owned(),
            ))
            .await?
            .ok_or_else(|| std::io::Error::other("upgrade lost custom trigger"))?;
        assert_eq!(event.try_get::<String>("", "user_id")?, existing.id);
        assert_eq!(
            event.try_get::<String>("", "observed_name")?,
            "Trigger still works"
        );
        let unique_index = database
            .query_one_raw(Statement::from_string(
                database.get_database_backend(),
                "SELECT sql FROM sqlite_schema WHERE name = 'idx_users_custom_email'".to_owned(),
            ))
            .await?
            .ok_or_else(|| std::io::Error::other("upgrade lost custom index"))?;
        assert!(
            unique_index
                .try_get::<String>("", "sql")?
                .contains("WHERE banned = 0")
        );
        assert!(
            database
                .execute_unprepared(
                    "INSERT INTO custom_user_links VALUES ('invalid-link', 'missing-user')"
                )
                .await
                .is_err()
        );
        store.delete_user(&existing.id).await?;
        assert!(store.get_session(&session.token).await?.is_none());
        assert!(
            store
                .get_account("credential", &existing.id)
                .await?
                .is_none()
        );
        assert!(
            database
                .query_one_raw(Statement::from_string(
                    database.get_database_backend(),
                    "SELECT id FROM custom_user_links WHERE id = 'retained-link'".to_owned(),
                ))
                .await?
                .is_none()
        );
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    async fn rejected_rebuild_rolls_back_and_restores_foreign_key_enforcement()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect("sqlite::memory:").await?;
        for sql in [
            "CREATE TABLE users (id TEXT PRIMARY KEY, two_factor_enabled BOOLEAN NOT NULL DEFAULT FALSE, banned BOOLEAN NOT NULL DEFAULT FALSE, profile TEXT)",
            "INSERT INTO users VALUES ('retained', 1, 0, 'custom preserved')",
            "CREATE TABLE custom_user_links (id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id))",
            "PRAGMA foreign_keys = OFF",
            "INSERT INTO custom_user_links VALUES ('preexisting-invalid-link', 'missing-user')",
            "PRAGMA foreign_keys = ON",
        ] {
            let _ignored_execute_unprepared_8 = database.execute_unprepared(sql).await?;
        }
        let error = super::nullable_user_flags::NullableUserPluginFlags
            .up(&SchemaManager::new(&database))
            .await
            .expect_err("the existing invalid relationship must stop this rebuild");
        assert!(
            error
                .to_string()
                .contains("invalid foreign-key relationships")
        );
        let row = database
            .query_one_raw(Statement::from_string(
                database.get_database_backend(),
                "SELECT two_factor_enabled, banned, profile FROM users WHERE id = 'retained'"
                    .to_owned(),
            ))
            .await?
            .ok_or_else(|| std::io::Error::other("rollback lost the user"))?;
        assert!(row.try_get::<bool>("", "two_factor_enabled")?);
        assert!(!row.try_get::<bool>("", "banned")?);
        assert_eq!(row.try_get::<String>("", "profile")?, "custom preserved");
        assert!(
            database
                .execute_unprepared(
                    "INSERT INTO custom_user_links VALUES ('new-invalid-link', 'missing-user')"
                )
                .await
                .is_err()
        );
        let flags = database
            .query_all_raw(Statement::from_string(
                database.get_database_backend(),
                "PRAGMA table_info(users)".to_owned(),
            ))
            .await?;
        for row_3 in flags.iter().filter(|row_2| {
            row_2
                .try_get::<String>("", "name")
                .is_ok_and(|name| name == "two_factor_enabled" || name == "banned")
        }) {
            assert_eq!(row_3.try_get::<i64>("", "notnull")?, 1);
            assert!(row_3.try_get::<Option<String>>("", "dflt_value")?.is_some());
        }
        assert!(
            !SchemaManager::new(&database)
                .has_table("users__nullable_plugin_flags")
                .await?
        );
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    async fn canceled_rebuild_preserves_rows_and_does_not_reuse_a_connection_with_foreign_keys_disabled()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::{
            Arc, Condvar, Mutex,
            atomic::{AtomicBool, Ordering},
        };
        let directory = std::env::temp_dir().join(format!(
            "better-auth-nullable-cancel-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&directory)?;
        let outcome = async {
        let enabled = Arc::new(AtomicBool::new(false));
        let (started, observed) = tokio::sync::oneshot::channel();
        let started = Arc::new(Mutex::new(Some(started)));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let mut options = ConnectOptions::new(format!("sqlite://{}?mode=rwc", directory.join("auth.sqlite").display()));
        let _ignored_cmp = options.max_connections(1).map_sqlx_sqlite_opts({
            let enabled = Arc::clone(&enabled);
            let started = Arc::clone(&started);
            let release = Arc::clone(&release);
            move |options_2| {
                let enabled = Arc::clone(&enabled);
                let started = Arc::clone(&started);
                let release = Arc::clone(&release);
                options_2.collation("nullable_copy_observer", move |left, right| {
                    if enabled.swap(false, Ordering::SeqCst) {
                        let sender = started.lock().unwrap().take();
                        if let Some(sender) = sender {
                            let _ignored_send = sender.send(());
                        }
                        let (lock, condition) = &*release;
                        let mut released = lock.lock().unwrap();
                        while !*released {
                            released = condition.wait(released).unwrap();
                        }
 drop(released);

                    }
                    left.cmp(right)
                })
            }
        });
        let database = Database::connect(options).await?;
        for sql in [
            "CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT COLLATE nullable_copy_observer UNIQUE, two_factor_enabled BOOLEAN NOT NULL DEFAULT FALSE, banned BOOLEAN NOT NULL DEFAULT FALSE, profile TEXT)",
            "INSERT INTO users VALUES ('first', 'first@example.com', 1, 0, 'first preserved')",
            "INSERT INTO users VALUES ('second', 'second@example.com', 0, 1, 'second preserved')",
            "CREATE TABLE custom_user_links (id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id))",
            "INSERT INTO custom_user_links VALUES ('retained-link', 'first')",
        ] {
            let _ignored_execute_unprepared_9 = database.execute_unprepared(sql).await?;
        }
        enabled.store(true, Ordering::SeqCst);
        let work = {
            let database = database.clone();
            tokio::spawn(async move {
                super::nullable_user_flags::NullableUserPluginFlags.up(&SchemaManager::new(&database)).await
            })
        };
        // The database's real collation runs while copying the second row:
        // the rebuild is inside its transaction and foreign keys are off.
        tokio::time::timeout(std::time::Duration::from_secs(5), observed).await??;
        work.abort();
        assert!(work.await.unwrap_err().is_cancelled());
        {
            let (lock, condition) = &*release;
            *lock.lock().unwrap() = true;
            condition.notify_all();
        }
        let rows = tokio::time::timeout(std::time::Duration::from_secs(10), database.query_all_raw(Statement::from_string(
            database.get_database_backend(),
            "SELECT id, profile, two_factor_enabled, banned FROM users ORDER BY id".to_owned(),
        ))).await??;
        assert_eq!(rows.len(), 2);
        assert_eq!((*(rows).first().expect("fixture contains the requested index")).try_get::<String>("", "profile")?, "first preserved");
        assert_eq!((*(rows).get(1).expect("fixture contains the requested index")).try_get::<String>("", "profile")?, "second preserved");
        assert!((*(rows).first().expect("fixture contains the requested index")).try_get::<bool>("", "two_factor_enabled")?);
        assert!((*(rows).get(1).expect("fixture contains the requested index")).try_get::<bool>("", "banned")?);
        assert!(database.execute_unprepared(
            "INSERT INTO custom_user_links VALUES ('new-invalid-link', 'missing-user')"
        ).await.is_err());
        assert!(database.execute_unprepared(
            "INSERT INTO users (id, email, two_factor_enabled, banned) VALUES ('invalid-null-user', 'invalid-null@example.com', NULL, NULL)"
        ).await.is_err());
        assert!(!SchemaManager::new(&database).has_table("users__nullable_plugin_flags").await?);
        database.close().await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    }.await;
        std::fs::remove_dir_all(&directory)?;
        outcome
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    async fn nullable_upgrade_preserves_numeric_id_sequence_and_hidden_row_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        for (id_type, extra_key, retained_rowid, auto_increment) in [
            ("INTEGER PRIMARY KEY AUTOINCREMENT", "", 10, true),
            ("TEXT PRIMARY KEY", "", 40, false),
            ("INTEGER PRIMARY KEY DESC", "", 40, false),
            ("INTEGER", ", PRIMARY KEY(id, tenant)", 40, false),
        ] {
            let database = Database::connect("sqlite::memory:").await?;
            let _ignored_execute_unprepared_10 = database.execute_unprepared(&format!(
            "CREATE TABLE users (id {id_type}, tenant TEXT NOT NULL DEFAULT 'local', two_factor_enabled BOOLEAN NOT NULL DEFAULT FALSE, banned BOOLEAN NOT NULL DEFAULT FALSE{extra_key})"
        )).await?;
            for sql in [
                format!("INSERT INTO users (rowid, id) VALUES ({retained_rowid}, 10)"),
                format!(
                    "INSERT INTO users (rowid, id) VALUES ({}, 20)",
                    if auto_increment { 20 } else { 80 }
                ),
                "DELETE FROM users WHERE id = 20".to_owned(),
            ] {
                let _ignored_execute_unprepared_11 = database.execute_unprepared(&sql).await?;
            }
            super::nullable_user_flags::NullableUserPluginFlags
                .up(&SchemaManager::new(&database))
                .await?;
            let retained = database
                .query_one_raw(Statement::from_string(
                    database.get_database_backend(),
                    "SELECT rowid AS retained_row FROM users WHERE id = 10".to_owned(),
                ))
                .await?
                .ok_or_else(|| std::io::Error::other("upgrade lost ID"))?;
            assert_eq!(
                retained.try_get::<i64>("", "retained_row")?,
                retained_rowid,
                "{id_type}"
            );
            if auto_increment {
                let _ignored_execute_unprepared_12 = database
                    .execute_unprepared(
                        "INSERT INTO users (two_factor_enabled, banned) VALUES (NULL, NULL)",
                    )
                    .await?;
                let generated = database
                    .query_one_raw(Statement::from_string(
                        database.get_database_backend(),
                        "SELECT id FROM users WHERE id != 10".to_owned(),
                    ))
                    .await?
                    .ok_or_else(|| std::io::Error::other("numeric ID was not generated"))?;
                assert_eq!(generated.try_get::<i64>("", "id")?, 21);
            }
        }
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    async fn installed_without_rowid_tables_and_unary_defaults_preserve_custom_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect("sqlite::memory:").await?;
        for sql in [
            "CREATE TABLE users(id TEXT PRIMARY KEY, two_factor_enabled BOOLEAN NOT /* retained */ NULL DEFAULT+0, banned BOOLEAN NOT NULL DEFAULT-0, \"profile,notes\" TEXT DEFAULT 'value,retained') WITHOUT ROWID",
            "INSERT INTO users(id) VALUES('old')",
        ] {
            let _ignored_execute_unprepared_13 = database.execute_unprepared(sql).await?;
        }
        super::nullable_user_flags::NullableUserPluginFlags
            .up(&SchemaManager::new(&database))
            .await?;
        let _ignored_execute_unprepared_14 = database
            .execute_unprepared("INSERT INTO users(id) VALUES('new')")
            .await?;
        let rows = database
            .query_all_raw(Statement::from_string(
                database.get_database_backend(),
                "SELECT id, two_factor_enabled, banned, \"profile,notes\" FROM users ORDER BY id"
                    .to_owned(),
            ))
            .await?;
        let new = rows
            .first()
            .ok_or_else(|| std::io::Error::other("missing new user"))?;
        assert_eq!(new.try_get::<String>("", "id")?, "new");
        assert_eq!(new.try_get::<Option<bool>>("", "two_factor_enabled")?, None);
        assert_eq!(new.try_get::<Option<bool>>("", "banned")?, None);
        assert_eq!(
            new.try_get::<String>("", "profile,notes")?,
            "value,retained"
        );
        let old = rows
            .get(1)
            .ok_or_else(|| std::io::Error::other("missing old user"))?;
        assert_eq!(old.try_get::<String>("", "id")?, "old");
        assert_eq!(
            old.try_get::<Option<bool>>("", "two_factor_enabled")?,
            Some(false)
        );
        assert_eq!(old.try_get::<Option<bool>>("", "banned")?, Some(false));
        assert!(
            database
                .query_one_raw(Statement::from_string(
                    database.get_database_backend(),
                    "SELECT rowid FROM users".to_owned()
                ))
                .await
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    async fn upgrades_named_not_null_conflict_rules_without_dropping_checks()
    -> Result<(), Box<dyn std::error::Error>> {
        for conflict in ["ABORT", "FAIL", "IGNORE", "REPLACE", "ROLLBACK"] {
            let database = Database::connect("sqlite::memory:").await?;
            let _ignored_execute_unprepared_15 = database.execute_unprepared(&format!(
            "CREATE TABLE users(id TEXT PRIMARY KEY, two_factor_enabled BOOLEAN NOT NULL ON CONFLICT {conflict} DEFAULT FALSE, banned BOOLEAN CONSTRAINT ban_required NOT NULL ON CONFLICT {conflict} DEFAULT FALSE CHECK(banned IN (0,1)))"
        )).await?;
            let _ignored_execute_unprepared_16 = database
                .execute_unprepared("INSERT INTO users(id) VALUES('old')")
                .await?;
            super::nullable_user_flags::NullableUserPluginFlags
                .up(&SchemaManager::new(&database))
                .await?;
            let _ignored_execute_unprepared_17 = database
                .execute_unprepared("INSERT INTO users(id) VALUES('new')")
                .await?;
            let rows = database
                .query_all_raw(Statement::from_string(
                    database.get_database_backend(),
                    "SELECT id, two_factor_enabled, banned FROM users ORDER BY id".to_owned(),
                ))
                .await?;
            let new = rows
                .first()
                .ok_or_else(|| std::io::Error::other("missing new user"))?;
            assert_eq!(new.try_get::<Option<bool>>("", "two_factor_enabled")?, None);
            assert_eq!(new.try_get::<Option<bool>>("", "banned")?, None);
            let old = rows
                .get(1)
                .ok_or_else(|| std::io::Error::other("missing old user"))?;
            assert_eq!(
                old.try_get::<Option<bool>>("", "two_factor_enabled")?,
                Some(false)
            );
            assert_eq!(old.try_get::<Option<bool>>("", "banned")?, Some(false));
            assert!(
                database
                    .execute_unprepared("UPDATE users SET banned = 2 WHERE id = 'new'")
                    .await
                    .is_err()
            );
        }
        Ok(())
    }
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
#[cfg(test)]
mod numeric_page_tests {
    //! Public adapter pages preserve numeric binding and physical rows independently
    //! of HTTP query parsing or organization authorization.
    #![expect(
        clippy::panic_in_result_fn,
        reason = "native public storage proof propagates setup failures"
    )]
    use super::{SeaOrmStore, bundled_schema::BundledSchema, migrator::run_migrations};
    use better_auth_core::store::{MemberPageQuery, MemberStore, OrganizationStore, UserStore};
    use better_auth_core::{AuthConfig, AuthError, CreateMember, CreateOrganization, CreateUser};
    use sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement};
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    async fn snapshot(db: &DatabaseConnection) -> Result<String, sea_orm::DbErr> {
        db.query_one_raw(Statement::from_string(DbBackend::Sqlite,
        "SELECT json_object('members',(SELECT json_group_array(json_object('rowid',rowid,'id',id,'org',organization_id,'user',user_id,'role',role,'created',created_at)) FROM (SELECT rowid,* FROM member ORDER BY rowid)),'users',(SELECT json_group_array(json_object('id',id,'email',email,'created',created_at,'updated',updated_at)) FROM (SELECT * FROM users ORDER BY rowid)),'organizations',(SELECT json_group_array(json_object('id',id,'name',name,'created',created_at)) FROM (SELECT * FROM organization ORDER BY rowid))) AS snapshot"))
        .await?.ok_or_else(|| sea_orm::DbErr::Custom("missing snapshot".into()))?.try_get("", "snapshot")
    }
    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn public_numeric_pages_bind_raw_limits_and_keep_insertion_order_filtered_count_and_full_state()
    -> TestResult {
        let db = Database::connect("sqlite::memory:").await?;
        run_migrations(&db).await?;
        let store = SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("raw-member-page-secret"),
            db.clone(),
        );
        let owner = store
            .create_user(CreateUser::new().with_email("owner@numeric-page.test"))
            .await?;
        let target = store
            .create_user(CreateUser::new().with_email("target@numeric-page.test"))
            .await?;
        let foreign = store
            .create_user(CreateUser::new().with_email("foreign@numeric-page.test"))
            .await?;
        let own = store
            .create_organization(CreateOrganization::new("Owned", "numeric-owned"))
            .await?;
        let other = store
            .create_organization(CreateOrganization::new("Other", "numeric-other"))
            .await?;
        let first = store
            .create_member(CreateMember::new(&own.id, &owner.id, "owner"))
            .await?;
        let second = store
            .create_member(CreateMember::new(&own.id, &target.id, "member"))
            .await?;
        let peer = store
            .create_member(CreateMember::new(&other.id, &foreign.id, "owner"))
            .await?;
        // Contradict timestamp order with insertion order so an implicit legacy
        // createdAt sort cannot accidentally satisfy the actual page contract.
        for (id, date) in [
            (&first.id, "2021-01-01 00:00:00+00:00"),
            (&second.id, "2020-01-01 00:00:00+00:00"),
        ] {
            _ = db
                .execute_raw(Statement::from_sql_and_values(
                    DbBackend::Sqlite,
                    "UPDATE member SET created_at=? WHERE id=?",
                    [date.into(), id.clone().into()],
                ))
                .await?;
        }
        let first = store
            .get_member_by_id(&first.id)
            .await?
            .ok_or("first missing")?;
        let second = store
            .get_member_by_id(&second.id)
            .await?
            .ok_or("second missing")?;
        let before = snapshot(&db).await?;
        for (limit, offset, expected) in [
            (1.0, 0.0, vec![first.clone()]),
            (1.0, 1.0, vec![second.clone()]),
            (-1.0, 0.0, vec![first.clone(), second.clone()]),
            (-0.0, 0.0, vec![]),
        ] {
            let (rows, total) = store
                .query_organization_members_page(&MemberPageQuery {
                    organization_id: own.id.clone(),
                    limit: Some(limit),
                    offset: Some(offset),
                    ..Default::default()
                })
                .await?;
            assert_eq!(total, 2);
            assert_eq!(serde_json::to_value(rows)?, serde_json::to_value(expected)?);
        }
        let (filtered, total) = store
            .query_organization_members_page(&MemberPageQuery {
                organization_id: own.id.clone(),
                limit: Some(1.0),
                filter_field: Some("role".into()),
                filter_value: Some("member".into()),
                filter_operator: Some("eq".into()),
                ..Default::default()
            })
            .await?;
        assert_eq!(total, 1);
        assert_eq!(
            serde_json::to_value(filtered)?,
            serde_json::to_value(vec![second])?
        );
        for (limit, offset) in [
            (1.5, 0.0),
            (f64::INFINITY, 0.0),
            (f64::NEG_INFINITY, 0.0),
            (f64::NAN, 0.0),
            (1.0, 0.5),
        ] {
            assert!(
                matches!(
                    store
                        .query_organization_members_page(&MemberPageQuery {
                            organization_id: own.id.clone(),
                            limit: Some(limit),
                            offset: Some(offset),
                            ..Default::default()
                        })
                        .await,
                    Err(AuthError::Database(_))
                ),
                "SQLite must validate actual raw binding, not round/cap it"
            );
        }
        let ids = vec![target.id.clone(), owner.id.clone()];
        let returned = store.list_users_by_ids_page(&ids, -1.0).await?;
        assert_eq!(returned.len(), 2);
        assert!(returned.iter().all(|user| ids.contains(&user.id)));
        assert_eq!(store.list_users_by_ids_page(&ids, -0.0).await?.len(), 0);
        assert_eq!(store.list_users_by_ids_page(&ids, 1.0).await?.len(), 1);
        for limit in [1.5, f64::INFINITY, f64::NAN] {
            assert!(matches!(
                store.list_users_by_ids_page(&ids, limit).await,
                Err(AuthError::Database(_))
            ));
        }
        assert_eq!(
            serde_json::to_value(store.get_member_by_id(&peer.id).await?)?,
            serde_json::to_value(Some(peer))?
        );
        assert_eq!(
            snapshot(&db).await?,
            before,
            "all read pages and genuine SQL failures preserve owner/foreign physical records and date bytes"
        );
        Ok(())
    }
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
#[cfg(test)]
mod organization_deletion_tests {
    //! Public deletion storage semantics and its independent transaction boundary.
    use super::{SeaOrmStore, bundled_schema::BundledSchema, migrator::run_migrations};
    use better_auth_core::store::{
        ApiKeyStore, InvitationStore, MemberStore, OrganizationRoleStore, OrganizationStore,
        TeamStore, UserStore,
    };
    use better_auth_core::types::CreateOrganizationRole;
    use better_auth_core::{
        AuthConfig, CreateApiKey, CreateInvitation, CreateMember, CreateOrganization, CreateTeam,
        CreateUser,
    };
    use chrono::{Duration, Utc};
    use sea_orm::{ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, Statement};
    use std::collections::BTreeMap;

    async fn physical(
        database: &DatabaseConnection,
    ) -> Result<BTreeMap<String, String>, sea_orm::DbErr> {
        let mut values = BTreeMap::new();
        for table in [
            "users",
            "organization",
            "member",
            "invitation",
            "team",
            "team_member",
            "organization_role",
            "api_keys",
        ] {
            let columns = database
                .query_all_raw(Statement::from_string(
                    DatabaseBackend::Sqlite,
                    format!("PRAGMA table_xinfo(\"{table}\")"),
                ))
                .await?;
            let fields = columns
                .iter()
                .map(|row| row.try_get::<String>("", "name"))
                .collect::<Result<Vec<_>, _>>()?;
            let object = fields
                .iter()
                .map(|name| {
                    format!(
                        "'{}',\"{}\"",
                        name.replace('\'', "''"),
                        name.replace('\"', "\"\"")
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            let query = format!(
                "SELECT json_group_array(json_object({object})) AS snapshot FROM (SELECT * FROM \"{table}\" ORDER BY rowid)"
            );
            let row = database
                .query_one_raw(Statement::from_string(DatabaseBackend::Sqlite, query))
                .await?
                .ok_or_else(|| sea_orm::DbErr::Custom("snapshot missing".into()))?;
            drop(values.insert(table.to_owned(), row.try_get("", "snapshot")?));
        }
        Ok(values)
    }
    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn public_organization_delete_retains_extensions_and_rolls_back_all_scoped_writes()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect("sqlite::memory:").await?;
        run_migrations(&database).await?;
        let store = SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("organization-delete-store-local-proof-secret"),
            database.clone(),
        );
        let mut records = Vec::new();
        for slug in ["target", "unrelated"] {
            let user = store
                .create_user(CreateUser::new().with_email(format!("{slug}@deletion.fixture.test")))
                .await?;
            let org = store
                .create_organization(CreateOrganization::new(slug, slug))
                .await?;
            let member = store
                .create_member(CreateMember {
                    organization_id: org.id.clone(),
                    user_id: user.id.clone(),
                    role: "owner".into(),
                })
                .await?;
            let invitation = store
                .create_invitation(CreateInvitation::new(
                    &org.id,
                    format!("invited-{slug}@deletion.fixture.test"),
                    "member",
                    &user.id,
                    Utc::now() + Duration::days(1),
                ))
                .await?;
            let team = store
                .create_team(CreateTeam {
                    name: slug.into(),
                    organization_id: org.id.clone(),
                    updated_at: None,
                })
                .await?;
            drop(store.add_team_member(&team.id, &user.id, None).await?);
            drop(
                store
                    .create_organization_role(CreateOrganizationRole {
                        organization_id: org.id.clone(),
                        role: "retained".into(),
                        permission: better_auth_core::OrganizationPermissions::default(),
                    })
                    .await?,
            );
            drop(
                store
                    .create_api_key(CreateApiKey {
                        reference_id: org.id.clone(),
                        config_id: "organization".into(),
                        name: Some(slug.into()),
                        prefix: None,
                        key_hash: format!("{slug}-local-key-hash"),
                        start: None,
                        expires_at: None,
                        remaining: None,
                        rate_limit_enabled: false,
                        rate_limit_time_window: None,
                        rate_limit_max: None,
                        refill_interval: None,
                        refill_amount: None,
                        permissions: None,
                        metadata: None,
                        enabled: true,
                    })
                    .await?,
            );
            records.push((org, member, invitation));
        }
        let before = physical(&database).await?;
        let _ignored_execute_unprepared = database.execute_unprepared("CREATE TRIGGER app_refuse_organization_delete BEFORE DELETE ON organization WHEN OLD.slug='target' BEGIN SELECT RAISE(ABORT,'application deletion denied'); END").await?;
        assert!(
            store
                .delete_organization(
                    &(records)
                        .first()
                        .expect("fixture contains the requested index")
                        .0
                        .id
                )
                .await
                .is_err()
        );
        assert_eq!(
            physical(&database).await?,
            before,
            "a failed final organization write must roll back members/invitations and retain every key/extension row"
        );
        let _ignored_execute_unprepared_2 = database
            .execute_unprepared("DROP TRIGGER app_refuse_organization_delete")
            .await?;
        store
            .delete_organization(
                &(records)
                    .first()
                    .expect("fixture contains the requested index")
                    .0
                    .id,
            )
            .await?;
        assert!(
            store
                .get_organization_by_id(
                    &(records)
                        .first()
                        .expect("fixture contains the requested index")
                        .0
                        .id
                )
                .await?
                .is_none()
        );
        assert!(
            store
                .get_member_by_id(
                    &(records)
                        .first()
                        .expect("fixture contains the requested index")
                        .1
                        .id
                )
                .await?
                .is_none()
        );
        assert!(
            store
                .get_invitation_by_id(
                    &(records)
                        .first()
                        .expect("fixture contains the requested index")
                        .2
                        .id
                )
                .await?
                .is_none()
        );
        assert_eq!(
            store
                .get_organization_by_id(
                    &(records)
                        .get(1)
                        .expect("fixture contains the requested index")
                        .0
                        .id
                )
                .await?
                .as_ref()
                .map(|org| &org.slug),
            Some(
                &(records)
                    .get(1)
                    .expect("fixture contains the requested index")
                    .0
                    .slug
            )
        );
        assert!(
            store
                .get_member_by_id(
                    &(records)
                        .get(1)
                        .expect("fixture contains the requested index")
                        .1
                        .id
                )
                .await?
                .is_some()
        );
        assert!(
            store
                .get_invitation_by_id(
                    &(records)
                        .get(1)
                        .expect("fixture contains the requested index")
                        .2
                        .id
                )
                .await?
                .is_some()
        );
        let after = physical(&database).await?;
        for table in [
            "users",
            "team",
            "team_member",
            "organization_role",
            "api_keys",
        ] {
            assert_eq!(
                (*(after)
                    .get(table)
                    .expect("fixture contains the requested index")),
                (*(before)
                    .get(table)
                    .expect("fixture contains the requested index")),
                "retained {table} rows must preserve all physical fields"
            );
        }
        store.delete_organization("missing-organization").await?;
        assert_eq!(
            physical(&database).await?,
            after,
            "missing organization deletion is a scoped no-op"
        );
        Ok(())
    }
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
#[cfg(test)]
mod organization_reference_tests {
    //! Installed two-table migration: byte preservation and atomic rollback.
    use super::{SeaOrmStore, bundled_schema::BundledSchema, migrator::AuthMigrator};
    use better_auth_core::store::OrganizationStore;
    use better_auth_core::{AuthConfig, CreateOrganization};
    use sea_orm::{ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, Statement};
    use sea_orm_migration::MigratorTrait;

    async fn snapshot(
        database: &DatabaseConnection,
    ) -> Result<Vec<(String, String)>, sea_orm::DbErr> {
        let mut rows = Vec::new();
        for (name, query) in [
            (
                "schema",
                "SELECT json_group_array(json_object('type',type,'name',name,'table',tbl_name,'sql',sql)) AS value FROM (SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE tbl_name IN ('team','organization_role','team_link','app_org_scope') OR name='app_teams' ORDER BY type,name)",
            ),
            (
                "teams",
                "SELECT json_group_array(json_object('rowid',rowid,'id',id,'org',organization_id,'name',name,'count',member_count,'created',created_at,'updated',updated_at,'note',app_note,'label',app_label)) AS value FROM (SELECT rowid,* FROM team ORDER BY rowid)",
            ),
            (
                "roles",
                "SELECT json_group_array(json_object('rowid',rowid,'id',id,'org',organization_id,'role',role,'permission',permission,'created',created_at,'updated',updated_at,'note',app_note)) AS value FROM (SELECT rowid,* FROM organization_role ORDER BY rowid)",
            ),
            (
                "application_scopes",
                "SELECT json_group_array(json_object('rowid',rowid,'id',id)) AS value FROM (SELECT rowid,* FROM app_org_scope ORDER BY rowid)",
            ),
            (
                "application_links",
                "SELECT json_group_array(json_object('rowid',rowid,'team',team_id)) AS value FROM (SELECT rowid,* FROM team_link ORDER BY rowid)",
            ),
            (
                "application_audit",
                "SELECT json_group_array(json_object('rowid',rowid,'id',id)) AS value FROM (SELECT rowid,* FROM app_team_audit ORDER BY rowid)",
            ),
            (
                "ledger",
                "SELECT json_group_array(json_object('version',version,'applied',applied_at)) AS value FROM (SELECT * FROM better_auth_migrations ORDER BY version)",
            ),
        ] {
            let row = database
                .query_one_raw(Statement::from_string(DatabaseBackend::Sqlite, query))
                .await?
                .ok_or_else(|| sea_orm::DbErr::Custom("missing snapshot".into()))?;
            rows.push((name.into(), row.try_get("", "value")?));
        }
        Ok(rows)
    }
    async fn installed_at(
        url: &str,
    ) -> Result<(DatabaseConnection, String), Box<dyn std::error::Error>> {
        let mut options = sea_orm::ConnectOptions::new(url);
        let _configured = options.max_connections(1);
        let database = Database::connect(options).await?;
        AuthMigrator::up(&database, None).await?;
        let store = SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("org-reference-upgrade-local-secret-at-least32"),
            database.clone(),
        );
        let org = store
            .create_organization(CreateOrganization::new("Existing", "existing"))
            .await?;
        for sql in [
            "DELETE FROM better_auth_migrations WHERE version='m20261001_000014_detach_organization_references'",
            "DROP TABLE team_member",
            "DROP TABLE team",
            "DROP TABLE organization_role",
            "CREATE TABLE app_org_scope(id TEXT PRIMARY KEY)",
            "CREATE TABLE team(id TEXT PRIMARY KEY NOT NULL,name TEXT NOT NULL,organization_id TEXT NOT NULL,member_count BIGINT NOT NULL DEFAULT 0,created_at TEXT NOT NULL,updated_at TEXT,app_note TEXT DEFAULT 'has,comma' CHECK(app_note <> 'blocked'),app_label TEXT GENERATED ALWAYS AS (name || ':' || app_note) VIRTUAL,CONSTRAINT fk_team_organization FOREIGN KEY(organization_id) REFERENCES organization(id) ON DELETE CASCADE,CONSTRAINT app_team_scope FOREIGN KEY(organization_id) REFERENCES app_org_scope(id))",
            "CREATE TABLE organization_role(id TEXT PRIMARY KEY NOT NULL,organization_id TEXT NOT NULL,role TEXT NOT NULL,permission TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT,app_note TEXT DEFAULT 'retained' CHECK(app_note <> 'forbidden'),CONSTRAINT fk_organization_role_organization FOREIGN KEY(organization_id) REFERENCES organization(id) ON DELETE CASCADE,CONSTRAINT app_role_scope FOREIGN KEY(organization_id) REFERENCES app_org_scope(id))",
            "CREATE INDEX app_team_note ON team(app_note) WHERE app_note IS NOT NULL",
            "CREATE INDEX app_role_note ON organization_role(app_note)",
            "CREATE TABLE app_team_audit(id TEXT)",
            "CREATE TRIGGER app_team_changes AFTER UPDATE ON team BEGIN INSERT INTO app_team_audit VALUES(NEW.id); END",
            "CREATE TABLE team_link(team_id TEXT REFERENCES team(id))",
            "CREATE VIEW app_teams AS SELECT id,app_note,app_label FROM team",
        ] {
            let _ignored_execute_unprepared = database.execute_unprepared(sql).await?;
        }
        let _ignored_into = database
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "INSERT INTO app_org_scope VALUES (?)",
                vec![org.id.clone().into()],
            ))
            .await?;
        let _ignored_into_2 = database.execute_raw(Statement::from_sql_and_values(DatabaseBackend::Sqlite,"INSERT INTO team(rowid,id,name,organization_id,member_count,created_at,app_note) VALUES(97,'installed-team','Existing Team',?,1,'2026-01-02 03:04:05.125','kept,bytes')",vec![org.id.clone().into()])).await?;
        let _ignored_into_3 = database.execute_raw(Statement::from_sql_and_values(DatabaseBackend::Sqlite,"INSERT INTO organization_role(rowid,id,organization_id,role,permission,created_at,app_note) VALUES(103,'installed-role',?,'retained-role','{ \"team\" : [\"create\"] }','2026-01-02 03:04:05.125','role-bytes')",vec![org.id.clone().into()])).await?;
        let _ignored_execute_unprepared_2 = database
            .execute_unprepared("INSERT INTO team_link VALUES('installed-team')")
            .await?;
        Ok((database, org.id))
    }
    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn installed_organization_references_preserve_rows_and_unrelated_constraints()
    -> Result<(), Box<dyn std::error::Error>> {
        let (database, organization_id) = installed_at("sqlite::memory:").await?;
        let before = snapshot(&database).await?;
        AuthMigrator::up(&database, None).await?;
        AuthMigrator::up(&database, None).await?;
        let after = snapshot(&database).await?;
        assert_eq!(
            (*(before)
                .get(1)
                .expect("fixture contains the requested index")),
            (*(after)
                .get(1)
                .expect("fixture contains the requested index"))
        );
        assert_eq!(
            (*(before)
                .get(2)
                .expect("fixture contains the requested index")),
            (*(after)
                .get(2)
                .expect("fixture contains the requested index"))
        );
        for table in ["team", "organization_role"] {
            let rows = database
                .query_all_raw(Statement::from_string(
                    DatabaseBackend::Sqlite,
                    format!("PRAGMA foreign_key_list('{table}')"),
                ))
                .await?;
            assert_eq!(rows.len(), 1);
            assert_eq!(
                (*(rows)
                    .first()
                    .expect("fixture contains the requested index"))
                .try_get::<String>("", "table")?,
                "app_org_scope"
            );
        }
        let row = database
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT app_label FROM app_teams WHERE id='installed-team'",
            ))
            .await?
            .ok_or_else(|| std::io::Error::other("view disappeared"))?;
        assert_eq!(
            row.try_get::<String>("", "app_label")?,
            "Existing Team:kept,bytes"
        );
        assert!(
            database
                .execute_unprepared("UPDATE team SET app_note='blocked' WHERE id='installed-team'")
                .await
                .is_err()
        );
        let _ignored_execute_unprepared_3 = database
            .execute_unprepared("UPDATE team SET app_note='changed' WHERE id='installed-team'")
            .await?;
        let trigger = database
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT id FROM app_team_audit",
            ))
            .await?
            .ok_or_else(|| std::io::Error::other("trigger disappeared"))?;
        assert_eq!(trigger.try_get::<String>("", "id")?, "installed-team");
        assert!(
            database
                .execute_unprepared("INSERT INTO team_link VALUES('missing-team')")
                .await
                .is_err()
        );
        let store = SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("org-reference-upgrade-local-secret-at-least32"),
            database.clone(),
        );
        store.delete_organization(&organization_id).await?;
        assert!(
            store
                .get_organization_by_id(&organization_id)
                .await?
                .is_none()
        );
        for table in ["team", "organization_role"] {
            let row_2 = database
                .query_one_raw(Statement::from_string(
                    DatabaseBackend::Sqlite,
                    format!("SELECT COUNT(*) AS count FROM {table}"),
                ))
                .await?
                .ok_or_else(|| std::io::Error::other("count disappeared"))?;
            assert_eq!(row_2.try_get::<i64>("", "count")?, 1);
        }
        Ok(())
    }
    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn second_organization_reference_failure_rolls_back_first_table_and_settings()
    -> Result<(), Box<dyn std::error::Error>> {
        let (database, _) = installed_at("sqlite::memory:").await?;
        for sql in [
            "PRAGMA ignore_check_constraints=ON",
            "UPDATE organization_role SET app_note='forbidden' WHERE id='installed-role'",
            "PRAGMA ignore_check_constraints=OFF",
        ] {
            let _ignored_execute_unprepared_4 = database.execute_unprepared(sql).await?;
        }
        let before = snapshot(&database).await?;
        let failure = AuthMigrator::up(&database, None)
            .await
            .expect_err("the second table copy must reject its legacy check-violating row");
        assert!(failure.to_string().contains("CHECK constraint failed"));
        assert_eq!(
            snapshot(&database).await?,
            before,
            "both recreated tables, exact bytes and migration ledger must roll back"
        );
        for (pragma, expected) in [
            ("foreign_keys", 1_i64),
            ("legacy_alter_table", 0),
            ("ignore_check_constraints", 0),
        ] {
            let row = database
                .query_one_raw(Statement::from_string(
                    DatabaseBackend::Sqlite,
                    format!("PRAGMA {pragma}"),
                ))
                .await?
                .ok_or_else(|| std::io::Error::other("pragma disappeared"))?;
            assert_eq!(row.try_get::<i64>("", pragma)?, expected);
        }
        let temporary = database
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) AS count FROM sqlite_schema WHERE name LIKE '%__user_reference'",
            ))
            .await?
            .ok_or_else(|| std::io::Error::other("schema count disappeared"))?;
        assert_eq!(temporary.try_get::<i64>("", "count")?, 0);
        assert!(
            database
                .execute_unprepared("INSERT INTO team_link VALUES('another-missing')")
                .await
                .is_err()
        );
        let _ignored_execute_unprepared_5 = database
            .execute_unprepared(
                "UPDATE organization_role SET app_note='repaired' WHERE id='installed-role'",
            )
            .await?;
        AuthMigrator::up(&database, None).await?;
        Ok(())
    }

    // A real application-owned driver delegates the installed migration, then pauses
    // before SeaORM owns the ledger insert. No production timing hook is needed.
    struct PausedMigration(std::sync::Arc<tokio::sync::Notify>);
    impl sea_orm_migration::MigrationName for PausedMigration {
        fn name(&self) -> &str {
            "m20261001_000014_detach_organization_references"
        }
    }
    #[async_trait::async_trait]
    impl sea_orm_migration::MigrationTrait for PausedMigration {
        fn use_transaction(&self) -> Option<bool> {
            Some(false)
        }
        #[expect(
            elided_lifetimes_in_paths,
            reason = "SeaORM MigrationTrait requires the manager lifetime to remain late-bound"
        )]
        async fn up(
            &self,
            manager: &sea_orm_migration::SchemaManager,
        ) -> Result<(), sea_orm::DbErr> {
            sea_orm_migration::MigrationTrait::up(
                &super::organization_reference::DetachOrganizationReferences,
                manager,
            )
            .await?;
            self.0.notify_one();
            std::future::pending().await
        }
    }
    struct PausedDriver(std::sync::Arc<tokio::sync::Notify>);
    #[async_trait::async_trait]
    impl sea_orm_migration::MigratorTraitSelf for PausedDriver {
        fn migrations(&self) -> Vec<Box<dyn sea_orm_migration::MigrationTrait>> {
            <AuthMigrator as MigratorTrait>::migrations()
                .into_iter()
                .map(|migration| {
                    if migration.name() == "m20261001_000014_detach_organization_references" {
                        Box::new(PausedMigration(self.0.clone()))
                            as Box<dyn sea_orm_migration::MigrationTrait>
                    } else {
                        migration
                    }
                })
                .collect()
        }
        fn migration_table_name(&self) -> sea_orm::DynIden {
            <AuthMigrator as MigratorTrait>::migration_table_name()
        }
    }
    fn require(condition: bool, message: &str) -> Result<(), Box<dyn std::error::Error>> {
        if condition {
            Ok(())
        } else {
            Err(std::io::Error::other(message).into())
        }
    }
    struct DatabaseFile(std::path::PathBuf);
    impl Drop for DatabaseFile {
        fn drop(&mut self) {
            let _removed = std::fs::remove_file(&self.0);
        }
    }

    #[tokio::test]
    async fn committed_rebuild_recovers_after_real_ledger_veto_and_driver_cancellation()
    -> Result<(), Box<dyn std::error::Error>> {
        for cancel in [false, true] {
            let file = DatabaseFile(std::env::temp_dir().join(format!(
                "better-auth-ledger-{}.sqlite",
                uuid::Uuid::new_v4()
            )));
            let url = format!("sqlite://{}?mode=rwc", file.0.display());
            let (database, _) = installed_at(&url).await?;
            let before = snapshot(&database).await?;
            if cancel {
                let committed = std::sync::Arc::new(tokio::sync::Notify::new());
                let driver = PausedDriver(committed.clone());
                let worker_database = database.clone();
                let worker = tokio::spawn(async move {
                    sea_orm_migration::MigratorTraitSelf::up(&driver, &worker_database, None).await
                });
                tokio::time::timeout(std::time::Duration::from_secs(10), committed.notified())
                    .await?;
                worker.abort();
                require(
                    worker.await.is_err_and(|error| error.is_cancelled()),
                    "driver did not cancel after committed rebuild",
                )?;
            } else {
                let _created = database.execute_unprepared("CREATE TRIGGER veto_auth_ledger BEFORE INSERT ON better_auth_migrations WHEN NEW.version='m20261001_000014_detach_organization_references' BEGIN SELECT RAISE(ABORT,'application ledger veto'); END").await?;
                let failure = AuthMigrator::up(&database, None).await;
                require(
                    failure
                        .is_err_and(|error| error.to_string().contains("application ledger veto")),
                    "ledger SQL veto did not reach the actual migration driver",
                )?;
            }
            // Reopen independently: observing the writer alone cannot prove commit.
            let observer = Database::connect(&url).await?;
            let completed = snapshot(&observer).await?;
            require(
                before
                    .iter()
                    .filter(|(name, _)| name != "schema")
                    .eq(completed.iter().filter(|(name, _)| name != "schema")),
                "rebuild changed installed row bytes or recorded an uncompleted ledger entry",
            )?;
            require(
                before != completed,
                "failure happened before the schema rebuild committed",
            )?;
            for query in [
                "PRAGMA foreign_key_list('team')",
                "PRAGMA foreign_key_list('organization_role')",
            ] {
                let keys = observer
                    .query_all_raw(Statement::from_string(DatabaseBackend::Sqlite, query))
                    .await?;
                require(
                    keys.len() == 1
                        && keys.first().is_some_and(|key| {
                            key.try_get::<String>("", "table")
                                .is_ok_and(|name| name == "app_org_scope")
                        }),
                    "completed rebuild failed to preserve the independent application foreign key",
                )?;
            }
            for (query, name, expected) in [
                ("PRAGMA foreign_keys", "foreign_keys", 1_i64),
                ("PRAGMA legacy_alter_table", "legacy_alter_table", 0),
            ] {
                let row = database
                    .query_one_raw(Statement::from_string(DatabaseBackend::Sqlite, query))
                    .await?
                    .ok_or_else(|| std::io::Error::other("missing connection setting"))?;
                require(
                    row.try_get::<i64>("", name)? == expected,
                    "committed helper returned an altered connection setting",
                )?;
            }
            require(
                database
                    .execute_unprepared(
                        "INSERT INTO team_link VALUES('missing-after-ledger-failure')",
                    )
                    .await
                    .is_err(),
                "foreign-key enforcement was lost",
            )?;
            if !cancel {
                let _dropped = database
                    .execute_unprepared("DROP TRIGGER veto_auth_ledger")
                    .await?;
            }
            AuthMigrator::up(&database, None).await?;
            let retried = snapshot(&observer).await?;
            require(
                completed
                    .iter()
                    .filter(|(name, _)| name != "ledger")
                    .eq(retried.iter().filter(|(name, _)| name != "ledger")),
                "retry rebuilt an already completed schema or changed application rows",
            )?;
            AuthMigrator::up(&database, None).await?;
            require(
                snapshot(&observer).await? == retried,
                "second retry changed rows, schema or ledger",
            )?;
            let ledger = observer.query_one_raw(Statement::from_string(DatabaseBackend::Sqlite, "SELECT COUNT(*) AS count FROM better_auth_migrations WHERE version='m20261001_000014_detach_organization_references'")).await?.ok_or_else(|| std::io::Error::other("missing migration ledger"))?;
            require(
                ledger.try_get::<i64>("", "count")? == 1,
                "completed retry did not record exactly one migration",
            )?;
            let _updated = database
                .execute_unprepared(
                    "UPDATE team SET app_note='changed-after-retry' WHERE id='installed-team'",
                )
                .await?;
            let trigger = observer
                .query_one_raw(Statement::from_string(
                    DatabaseBackend::Sqlite,
                    "SELECT id FROM app_team_audit",
                ))
                .await?
                .ok_or_else(|| std::io::Error::other("installed trigger disappeared"))?;
            require(
                trigger.try_get::<String>("", "id")? == "installed-team",
                "installed trigger no longer observes application updates",
            )?;
            require(
                database
                    .execute_unprepared(
                        "UPDATE team SET app_note='blocked' WHERE id='installed-team'",
                    )
                    .await
                    .is_err(),
                "installed CHECK constraint disappeared",
            )?;
            observer.close().await?;
            database.close().await?;
        }
        Ok(())
    }
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
#[cfg(test)]
mod two_factor_policy_tests {
    use super::{SeaOrmStore, bundled_schema::BundledSchema, migrator::run_migrations};
    use better_auth_core::store::TwoFactorStore;
    use better_auth_core::{AuthConfig, CreateTwoFactor, UpdateTwoFactor};
    use chrono::{Duration, Utc};
    use sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseBackend, Statement};
    use std::sync::Arc;
    use tokio::{sync::Barrier, task::JoinSet};

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn installed_factor_policy_upgrade_retains_rows_custom_schema_and_is_idempotent()
    -> Result<(), Box<dyn std::error::Error>> {
        let db = Database::connect("sqlite::memory:").await?;
        let _ignored_execute_unprepared = db.execute_unprepared(
        "CREATE TABLE two_factor (id TEXT PRIMARY KEY, secret TEXT NOT NULL, backup_codes TEXT NOT NULL, user_id TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, custom TEXT DEFAULT 'kept');
         CREATE INDEX installed_factor_owner ON two_factor(user_id);
         CREATE TABLE factor_audit (value TEXT);
         CREATE TRIGGER installed_factor_trigger AFTER INSERT ON two_factor BEGIN INSERT INTO factor_audit VALUES(NEW.id); END;
         INSERT INTO two_factor(rowid,id,secret,backup_codes,user_id,created_at,updated_at) VALUES(41,'installed','secret-bytes','backup-bytes','owner','2025-01-02T03:04:05Z','2025-01-02T03:04:05Z')"
    ).await?;
        run_migrations(&db).await?;
        run_migrations(&db).await?;
        let row = db.query_one_raw(Statement::from_string(DatabaseBackend::Sqlite,
        "SELECT rowid,id,secret,backup_codes,user_id,created_at,updated_at,custom,verified,failed_verification_count,locked_until FROM two_factor WHERE id='installed'".to_owned())).await?.unwrap();
        assert_eq!(row.try_get::<i64>("", "rowid")?, 41);
        for (column, expected) in [
            ("id", "installed"),
            ("secret", "secret-bytes"),
            ("backup_codes", "backup-bytes"),
            ("user_id", "owner"),
            ("created_at", "2025-01-02T03:04:05Z"),
            ("updated_at", "2025-01-02T03:04:05Z"),
            ("custom", "kept"),
        ] {
            assert_eq!(row.try_get::<String>("", column)?, expected);
        }
        assert!(row.try_get::<bool>("", "verified")?);
        assert_eq!(row.try_get::<i64>("", "failed_verification_count")?, 0);
        assert_eq!(row.try_get::<Option<String>>("", "locked_until")?, None);
        let _ignored_execute_unprepared_2 = db.execute_unprepared("INSERT INTO two_factor(id,secret,backup_codes,user_id,created_at,updated_at,verified,failed_verification_count) VALUES('nullable','s','b','nullable-owner','2025-01-02T03:04:05Z','2025-01-02T03:04:05Z',NULL,NULL)").await?;
        let _ignored_execute_unprepared_3 = db.execute_unprepared("INSERT INTO two_factor(id,secret,backup_codes,user_id,created_at,updated_at) VALUES('defaults','s','b','default-owner','2025-01-02T03:04:05Z','2025-01-02T03:04:05Z')").await?;
        let audit = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) AS n FROM factor_audit".to_owned(),
            ))
            .await?
            .unwrap();
        assert_eq!(audit.try_get::<i64>("", "n")?, 3);
        let index = db
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT name FROM sqlite_schema WHERE type='index' AND name='installed_factor_owner'"
                .to_owned(),
        ))
        .await?;
        assert!(index.is_some());
        let store = SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("installed-factor-secret-at-least-32-characters"),
            db.clone(),
        );
        let legacy = store.get_two_factor_by_user_id("owner").await?.unwrap();
        assert_eq!(legacy.verified, Some(true));
        assert_eq!(legacy.failed_verification_count, Some(0.0));
        let nullable = store
            .get_two_factor_by_user_id("nullable-owner")
            .await?
            .unwrap();
        assert_eq!(nullable.verified, None);
        assert_eq!(nullable.failed_verification_count, None);
        let incremented_null = store
            .increment_two_factor_failure(&nullable.id)
            .await?
            .unwrap();
        assert_eq!(incremented_null.failed_verification_count, None);
        assert!(
            store
                .set_two_factor_lock_if_count_at_least(&nullable.id, 0.0, Utc::now())
                .await?
                .is_none()
        );
        let _ignored_execute_unprepared_4 = db
            .execute_unprepared(
                "UPDATE two_factor SET failed_verification_count=0.25 WHERE id='defaults'",
            )
            .await?;
        let fraction = store
            .get_two_factor_by_user_id("default-owner")
            .await?
            .unwrap();
        assert_eq!(fraction.failed_verification_count, Some(0.25));
        db.close().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn independent_factor_connections_increment_nullable_numbers_and_conditionally_reset_or_consume()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = std::env::temp_dir().join(format!(
            "better-auth-factor-policy-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&directory)?;
        let outcome = async {
        let url = format!("sqlite://{}?mode=rwc", directory.join("auth.sqlite").display());
        let mut first_options = ConnectOptions::new(url.clone());
        let _ignored_min_connections = first_options.max_connections(1).min_connections(1);
        let db = Database::connect(first_options).await?;
        run_migrations(&db).await?;
        // The factor table's preexisting FK requires an owner on this branch.
        let _ignored_execute_unprepared_5 = db.execute_unprepared("INSERT INTO users(id,name,email,email_verified,metadata,created_at,updated_at) VALUES('owner','Owner','owner@fixture.test',0,'{}','2025-01-02T03:04:05Z','2025-01-02T03:04:05Z')").await?;
        let config = AuthConfig::new("factor-policy-secret-at-least-32-characters");
        let store = SeaOrmStore::<BundledSchema>::new(config.clone(), db.clone());
        let factor = store.create_two_factor(CreateTwoFactor { user_id:"owner".into(),secret:"secret".into(),backup_codes:"old-backup".into(),..Default::default() }).await?;
        assert_eq!(factor.failed_verification_count, Some(0.0));
        let _ignored_execute_unprepared_6 = db.execute_unprepared("DROP INDEX idx_two_factor_user_id").await?;
        // Installed/custom schemas can contain multiple generations for one owner.
        let sibling = store.create_two_factor(CreateTwoFactor { user_id:"owner".into(),secret:"other-secret".into(),backup_codes:"other-backup".into(),..Default::default() }).await?;
        let mut connections = Vec::new();
        for _ in 0..8 {
            let mut options = ConnectOptions::new(url.clone());
            let _ignored_min_connections_2 = options.max_connections(1).min_connections(1);
            connections.push(Database::connect(options).await?);
        }
        let result = async {
            let barrier = Arc::new(Barrier::new(8));
            let mut tasks = JoinSet::new();
            for connection in &connections {
                let worker = SeaOrmStore::<BundledSchema>::new(config.clone(), connection.clone());
                let barrier = Arc::clone(&barrier); let id = factor.id.clone();
                drop(tasks.spawn(async move { let _ignored_wait = barrier.wait().await; worker.increment_two_factor_failure(&id).await }));
            }
            let mut counts = Vec::new();
            while let Some(row) = tasks.join_next().await { counts.push(row??.unwrap().failed_verification_count.unwrap()); }
            counts.sort_by(f64::total_cmp);
            assert_eq!(counts, (1..=8).map(f64::from).collect::<Vec<_>>());
            let physical = db.query_one_raw(Statement::from_sql_and_values(DatabaseBackend::Sqlite,
                "SELECT typeof(failed_verification_count) AS affinity FROM two_factor WHERE id=?", [factor.id.clone().into()])).await?.unwrap();
            assert_eq!(physical.try_get::<String>("", "affinity")?, "integer");
            let now = Utc::now(); let future = now + Duration::minutes(15);
            assert!(store.set_two_factor_lock_if_count_at_least(&factor.id,8.5,future).await?.is_none());
            assert!(store.set_two_factor_lock_if_count_at_least(&factor.id,7.5,future).await?.is_some());
            assert!(store.clear_expired_two_factor_lock(&factor.id,now).await?.is_none());
            let barrier_2 = Arc::new(Barrier::new(8));
            let mut unlocks = JoinSet::new();
            for connection in &connections {
                let worker = SeaOrmStore::<BundledSchema>::new(config.clone(), connection.clone());
                let barrier_2_3 = Arc::clone(&barrier_2); let id = factor.id.clone();
                drop(unlocks.spawn(async move { let _ignored_wait_2 = barrier_2_3.wait().await; worker.clear_expired_two_factor_lock(&id, future).await }));
            }
            let mut winners = Vec::new();
            while let Some(row) = unlocks.join_next().await { if let Some(row) = row?? { winners.push(row); } }
            assert_eq!(winners.len(), 1);
            let unlocked = winners.pop().unwrap();
            assert_eq!(unlocked.failed_verification_count,Some(0.0)); assert_eq!(unlocked.locked_until,None);
            // A stale failure cannot set a lock after a concurrent success reset.
            assert!(store.set_two_factor_lock_if_count_at_least(&factor.id,1.0,future).await?.is_none());
            let _ignored_into = db.execute_raw(Statement::from_sql_and_values(DatabaseBackend::Sqlite,
                "UPDATE two_factor SET failed_verification_count=0.5 WHERE id=?", [factor.id.clone().into()])).await?;
            let incremented = store.increment_two_factor_failure(&factor.id).await?.unwrap();
            assert_eq!(incremented.failed_verification_count,Some(1.5));
            let updated = store.update_two_factor(&factor.id,UpdateTwoFactor {secret:Some("rotated".into()),verified:Some(false),..Default::default()}).await?.unwrap();
            assert_eq!(updated.failed_verification_count,Some(1.5)); assert_eq!(updated.verified,Some(false));
            assert_eq!(updated.created_at,factor.created_at); assert_eq!(updated.updated_at,factor.updated_at);
            let barrier_3 = Arc::new(Barrier::new(8)); let mut swaps = JoinSet::new();
            for (index,connection) in connections.iter().enumerate() {
                let worker = SeaOrmStore::<BundledSchema>::new(config.clone(),connection.clone()); let id=factor.id.clone(); let barrier_4=Arc::clone(&barrier_3);
                drop(swaps.spawn(async move { let _ignored_wait_3 = barrier_4.wait().await; worker.compare_and_swap_two_factor_backup_codes(&id,"old-backup",&format!("winner-{index}")).await }));
            }
            let mut winners_2=0; while let Some(row)=swaps.join_next().await { if row?? { winners_2+=1; } } assert_eq!(winners_2,1);
            store.reset_two_factor_failures(&factor.id).await?;
            let reset = store.update_two_factor(&factor.id,UpdateTwoFactor::default()).await?.unwrap();
            assert_eq!(reset.failed_verification_count,Some(0.0)); assert_eq!(reset.locked_until,None);
            assert_eq!(reset.secret,"rotated"); assert!(reset.backup_codes.starts_with("winner-"));
            let untouched = store.update_two_factor(&sibling.id,UpdateTwoFactor::default()).await?.unwrap();
            assert_eq!(serde_json::to_value(untouched)?,serde_json::to_value(sibling)?);
            assert!(store.increment_two_factor_failure("missing").await?.is_none());
            Ok::<_,Box<dyn std::error::Error>>(())
        }.await;
        for connection in connections { connection.close().await?; }
        db.close().await?;
        result
    }.await;
        std::fs::remove_dir_all(directory)?;
        outcome
    }
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
#[cfg(test)]
mod wallet_tests {
    use super::SeaOrmStore;
    use super::bundled_schema::BundledSchema;
    use super::entities::wallet_address;
    use super::migrator::run_migrations;
    use better_auth_core::store::{UserStore, WalletAddressStore};
    use better_auth_core::{AuthConfig, AuthError, CreateUser, CreateWalletAddress};
    use sea_orm::{ConnectionTrait, Database, EntityTrait, PaginatorTrait, Statement};

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    async fn wallet_owner_lookup_and_user_deletion_keep_state_atomic()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect("sqlite::memory:").await?;
        run_migrations(&database).await?;
        let store = SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("wallet-owner-native-at-least-32-characters"),
            database.clone(),
        );
        let owner = store
            .create_user(CreateUser::new().with_email("wallet-owner@fixture.test"))
            .await?;
        let other = store
            .create_user(CreateUser::new().with_email("wallet-other@fixture.test"))
            .await?;
        let address = "0x52908400098527886E0F7030069857D2E4169EE7";
        let first = store
            .create_wallet_address(CreateWalletAddress {
                user_id: owner.id.clone(),
                address: address.to_owned(),
                chain_id: 100.0,
                is_primary: true,
            })
            .await?;
        let second = store
            .create_wallet_address(CreateWalletAddress::new(&other.id, address, 1.0))
            .await?;
        let third = store
            .create_wallet_address(CreateWalletAddress::new(
                &owner.id,
                "0xde709f2102306220921060314715629080e2fb77",
                1e21,
            ))
            .await?;
        assert_eq!(
            store.get_wallet_address(address, None).await?,
            Some(first.clone())
        );
        assert_eq!(
            store.get_wallet_address(address, Some(1.0)).await?,
            Some(second.clone())
        );
        assert_eq!(
            store.get_wallet_address(&third.address, Some(1e21)).await?,
            Some(third.clone())
        );
        assert!(matches!(
            store
                .create_wallet_address(CreateWalletAddress::new("missing-owner", address, 2.0))
                .await,
            Err(AuthError::UserNotFound)
        ));
        assert_eq!(wallet_address::Entity::find().count(&database).await?, 3);
        let _ignored_to_owned = database.execute_raw(Statement::from_string(database.get_database_backend(),
        "CREATE TRIGGER wallet_user_delete_abort BEFORE DELETE ON users BEGIN SELECT RAISE(ABORT,'wallet deletion veto'); END".to_owned())).await?;
        assert!(store.delete_user(&owner.id).await.is_err());
        assert!(store.get_user_by_id(&owner.id).await?.is_some());
        assert_eq!(
            store.get_wallet_address(address, Some(100.0)).await?,
            Some(first)
        );
        assert_eq!(
            store.get_wallet_address(&third.address, Some(1e21)).await?,
            Some(third)
        );
        assert_eq!(
            store.get_wallet_address(address, Some(1.0)).await?,
            Some(second.clone())
        );
        let _ignored_to_owned_2 = database
            .execute_raw(Statement::from_string(
                database.get_database_backend(),
                "DROP TRIGGER wallet_user_delete_abort".to_owned(),
            ))
            .await?;
        store.delete_user(&owner.id).await?;
        assert!(store.get_user_by_id(&owner.id).await?.is_none());
        assert!(
            store
                .get_wallet_address(address, Some(100.0))
                .await?
                .is_none()
        );
        assert!(
            store
                .get_wallet_address("0xde709f2102306220921060314715629080e2fb77", None)
                .await?
                .is_none()
        );
        assert_eq!(store.get_wallet_address(address, None).await?, Some(second));
        assert!(store.get_user_by_id(&other.id).await?.is_some());
        assert_eq!(wallet_address::Entity::find().count(&database).await?, 1);
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    async fn wallet_upgrade_preserves_installed_identity_and_defaults_primary_to_false()
    -> Result<(), Box<dyn std::error::Error>> {
        use sea_orm_migration::{MigrationTrait, MigratorTrait};
        struct InstalledSchema;
        #[async_trait::async_trait]
        impl MigratorTrait for InstalledSchema {
            fn migrations() -> Vec<Box<dyn MigrationTrait>> {
                let mut migrations = super::migrator::AuthMigrator::migrations();
                drop(migrations.pop());
                migrations
            }
            fn migration_table_name() -> sea_orm::DynIden {
                use sea_orm::sea_query::IntoIden;
                "better_auth_migrations".into_iden()
            }
        }
        let database = Database::connect("sqlite::memory:").await?;
        InstalledSchema::up(&database, None).await?;
        let store = SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("wallet-upgrade-native-at-least-32-characters"),
            database.clone(),
        );
        let owner = store
            .create_user(CreateUser::new().with_email("wallet-upgrade@fixture.test"))
            .await?;
        run_migrations(&database).await?;
        let _ignored_execute_unprepared = database.execute_unprepared(&format!("INSERT INTO wallet_address (id,user_id,address,chain_id,created_at) VALUES ('upgraded-wallet','{}','0x52908400098527886E0F7030069857D2E4169EE7',1,'2026-09-30 00:00:00+00:00')",owner.id)).await?;
        let wallet = store
            .get_wallet_address("0x52908400098527886E0F7030069857D2E4169EE7", Some(1.0))
            .await?
            .ok_or("wallet missing after upgrade")?;
        assert_eq!(wallet.user_id, owner.id);
        assert!(!wallet.is_primary);
        assert_eq!(store.get_user_by_id(&owner.id).await?, Some(owner));
        run_migrations(&database).await?;
        assert_eq!(wallet_address::Entity::find().count(&database).await?, 1);
        Ok(())
    }
}
// LCOV_EXCL_STOP
