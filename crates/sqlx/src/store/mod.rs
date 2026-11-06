//! `SQLx`-backed persistence implementation for built-in auth tables.

mod accounts;
mod api_key_usage_phases;
mod api_keys;
mod bundled_schema;
mod device_codes;
pub mod entities;
mod invitations;
mod jwks;
mod members;
pub(crate) mod migrator;
mod oauth_clients;
mod organization_roles;
mod organizations;
mod passkeys;
mod sessions;
mod teams;
mod two_factor;
#[cfg(all(test, feature = "sqlite"))]
mod user_native_tests;
mod users;
mod verifications;
mod wallets;

#[doc(hidden)]
pub mod __private_test_support {
    pub mod bundled_schema {
        pub use super::super::bundled_schema::BundledSchema;
    }

    pub mod migrator {
        pub use super::super::migrator::run_migrations;
    }
}

use crate::OrganizationModels;
use crate::hooks::{DatabaseHooks, SqlxBackend, SqlxHookContext, current_request_hook_context};
use crate::pool::{Engine, Exec, SqlxPool, SqlxTransaction};
use crate::schema::{
    AuthSchema, SqlxAccountModel, SqlxSessionModel, SqlxUserModel, SqlxVerificationModel,
};
use crate::sql::Sql;
use alibi_core::config::AuthConfig;
use alibi_core::error::AuthResult;
use alibi_core::field_policy::FieldValues;
use alibi_core::store::SchemaMigrator;
use alibi_core::store::adapter::{AfterHook, AfterHookQueue};
use alibi_core::store::{
    AuthTransaction, BoxedTransactionValue, TransactionStore, TransactionWork,
};
use alibi_core::types::{AddTeamMemberResult, CreateJwk, Jwk, Member, Team};
use alibi_core::user_validation::PreparedUserCreation;
use alibi_core::verification::{
    VerificationCreation, VerificationPublication, VerificationSnapshot,
};
use alibi_core::{
    CreateAccount, CreateMember, CreatePasskey, CreateSession, CreateUser, CreateVerification,
    Passkey,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::marker::PhantomData;
use std::sync::Arc;

#[derive(Clone)]
pub struct SqlxStore<S: AuthSchema> {
    config: Arc<AuthConfig>,
    pool: SqlxPool,
    hooks: Vec<Arc<dyn DatabaseHooks<S, SqlxBackend>>>,
    organization_models: OrganizationModels,
    _schema: PhantomData<S>,
}

impl<S: AuthSchema> std::fmt::Debug for SqlxStore<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqlxStore").finish_non_exhaustive()
    }
}

impl<S: AuthSchema> SqlxStore<S> {
    #[must_use]
    pub fn new(config: impl Into<Arc<AuthConfig>>, pool: impl Into<SqlxPool>) -> Self {
        Self {
            config: config.into(),
            pool: pool.into(),
            hooks: Vec::new(),
            organization_models: crate::OrganizationModels::default(),
            _schema: PhantomData,
        }
    }

    /// Bind the organization plugin to application-owned tables.
    #[must_use]
    pub fn with_organization_models(mut self, models: OrganizationModels) -> Self {
        self.organization_models = models;
        self
    }

    #[must_use]
    pub fn with_hooks(mut self, hooks: Vec<Arc<dyn DatabaseHooks<S, SqlxBackend>>>) -> Self {
        self.hooks = hooks;
        self
    }

    #[must_use]
    pub fn hook<H: DatabaseHooks<S, SqlxBackend> + 'static>(mut self, hook: H) -> Self {
        self.hooks.push(Arc::new(hook));
        self
    }

    #[must_use]
    pub const fn pool(&self) -> &SqlxPool {
        &self.pool
    }

    #[must_use]
    pub const fn config(&self) -> &Arc<AuthConfig> {
        &self.config
    }

    pub(crate) fn hooks(&self) -> &[Arc<dyn DatabaseHooks<S, SqlxBackend>>] {
        &self.hooks
    }

    pub(crate) async fn generated_id(
        &self,
        exec: Exec<'_>,
        model: &str,
        table: &str,
        column: &str,
    ) -> AuthResult<Option<String>> {
        let policy = &self.config.advanced.database;
        if !policy.serial_ids() {
            return policy.generated_id(model);
        }
        let [ddl, allocate] = alibi_core::config::serial_id_statements(
            table,
            column,
            exec.engine() == Engine::Postgres,
        );
        _ = exec.execute(Sql::with(exec.engine(), &ddl)).await?;
        let value = exec
            .fetch_scalar::<i64>(Sql::with(exec.engine(), &allocate))
            .await?
            .ok_or_else(|| alibi_core::AuthError::internal("ID allocation returned no value"))?;
        Ok(Some(value.to_string()))
    }

    async fn begin(&self, immediate: bool) -> AuthResult<SqlxTransaction> {
        let mut transaction = self.pool.begin(immediate).await?;
        transaction.config = Some(self.config.clone());
        Ok(transaction)
    }

    pub(crate) fn exec(&self) -> Exec<'_> {
        Exec::pool(&self.pool).with_config(self.config.as_ref())
    }

    pub(crate) fn hook_context<'a>(
        &'a self,
        tx: Option<&'a SqlxTransaction>,
    ) -> SqlxHookContext<'a> {
        SqlxHookContext {
            config: self.config.as_ref(),
            db: &self.pool,
            tx,
            request: current_request_hook_context(),
        }
    }

    pub(crate) fn find_many_limit(&self) -> i64 {
        // Mirrors the unsigned page binding of the reference adapter.
        i64::try_from(self.config.advanced.database.default_find_many_limit).unwrap_or(i64::MAX)
    }

    /// Run work on a fresh transaction, committing on success. On failure the
    /// transaction is dropped, which rolls it back, and the work's error returns.
    pub(crate) async fn in_transaction<T>(
        &self,
        immediate: bool,
        work: impl AsyncFnOnce(&SqlxTransaction) -> AuthResult<T>,
    ) -> AuthResult<T> {
        let transaction = self.begin(immediate).await?;
        let value = work(&transaction).await?;
        transaction.commit().await?;
        Ok(value)
    }
}

/// Installs the bundled auth schema in `better_auth_migrations`, the ledger
/// the `SeaORM` adapter also records.
#[async_trait]
impl<S: AuthSchema> SchemaMigrator for SqlxStore<S> {
    async fn migrate(&self) -> AuthResult<()> {
        migrator::run_migrations_scoped(&self.pool, &self.config).await?;
        if self.config.advanced.database.serial_ids() {
            let [ddl, _] = alibi_core::config::serial_id_statements("", "", false);
            let exec = self.exec();
            _ = exec.execute(Sql::with(exec.engine(), &ddl)).await?;
        }
        if let Some(mapping) = &self.config.advanced.database.two_factor {
            let commands = mapping.migration_statements()?;
            self.in_transaction(false, async move |tx| {
                let exec = Exec::tx(tx);
                if migrator::has_table(exec, "twoFactor").await? {
                    for command in commands {
                        _ = exec.execute(Sql::with(exec.engine(), &command)).await?;
                    }
                }
                Ok(())
            })
            .await?;
        }
        if let Some(mapping) = &self.config.advanced.database.sso_provider {
            let commands = mapping.migration_statements()?;
            self.in_transaction(false, async move |tx| {
                let exec = Exec::tx(tx);
                if migrator::has_table(exec, "ssoProvider").await? {
                    for command in commands {
                        _ = exec.execute(Sql::with(exec.engine(), &command)).await?;
                    }
                }
                Ok(())
            })
            .await?;
        }

        let storage = &self.config.advanced.database;
        alibi_core::store::validate_sso_fields(storage)?;
        if !storage.sso_provider_fields.0.is_empty() {
            let table = storage
                .sso_provider
                .as_ref()
                .map_or("ssoProvider", |mapping| mapping.table_name.as_str());
            self.in_transaction(false, async move |tx| {
                let exec = Exec::tx(tx);
                for (name, field) in &storage.sso_provider_fields.0 {
                    let column = alibi_core::store::sso_field_column(name, field);
                    if !migrator::has_column(exec, table, column).await? {
                        let definition = alibi_core::store::sso_field_definition(
                            name,
                            field,
                            exec.engine() == crate::pool::Engine::Postgres,
                        )?;
                        let mut ddl = Sql::with(exec.engine(), "ALTER TABLE ");
                        ddl.ident(table);
                        ddl.push(" ADD COLUMN ");
                        ddl.push(&definition);
                        _ = exec.execute(ddl).await?;
                    }
                }
                Ok(())
            })
            .await?;
        }

        Ok(())
    }
}

struct SqlxStoreTransaction<'a, S: AuthSchema> {
    store: &'a SqlxStore<S>,
    tx: &'a SqlxTransaction,
    pending_after: AfterHookQueue<S>,
}

#[async_trait]
impl<S> AuthTransaction<S> for SqlxStoreTransaction<'_, S>
where
    S: AuthSchema,
    S::User: SqlxUserModel,
    S::Account: SqlxAccountModel,
    S::Session: SqlxSessionModel,
    S::Verification: SqlxVerificationModel,
{
    async fn get_scim_connection_binding(
        &self,
        id: &str,
    ) -> AuthResult<Option<alibi_core::store::ScimConnectionBinding>> {
        self.store
            .get_scim_connection_binding_with_exec(Exec::tx(self.tx), id)
            .await
    }
    async fn scim_projection_candidates(
        &self,
        domain: &str,
        cursor: Option<&str>,
    ) -> AuthResult<Vec<alibi_core::store::ScimProjectionCandidate>> {
        self.store
            .scim_projection_candidates_with_exec(Exec::tx(self.tx), domain, cursor)
            .await
    }
    async fn renew_scim_decommission_lease(
        &self,
        binding: &alibi_core::store::ScimConnectionBinding,
        lease: &str,
    ) -> AuthResult<bool> {
        self.store
            .renew_scim_decommission_lease_with_exec(Exec::tx(self.tx), binding, lease)
            .await
    }
    async fn advance_scim_decommission(
        &self,
        binding: &alibi_core::store::ScimConnectionBinding,
        lease: &str,
        cursor: Option<&str>,
        count: usize,
        more: bool,
    ) -> AuthResult<Option<alibi_core::store::ScimConnectionBinding>> {
        self.store
            .advance_scim_decommission_with_exec(
                Exec::tx(self.tx),
                binding,
                lease,
                cursor,
                count,
                more,
            )
            .await
    }
    async fn reconcile_scim_identity(
        &self,
        user_id: &str,
    ) -> AuthResult<alibi_core::store::ScimIdentityState> {
        self.store
            .reconcile_scim_identity_with_exec(Exec::tx(self.tx), user_id)
            .await
    }
    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
        use crate::model::SqlxModel;
        let sessions = self.get_user_sessions(user_id).await?;
        let context = self.store.hook_context(Some(self.tx));
        for session in &sessions {
            for hook in self.store.hooks() {
                if hook
                    .before_delete_session(session, &context)
                    .await?
                    .is_cancelled()
                {
                    return Ok(());
                }
            }
        }
        let exec = Exec::tx(self.tx);
        let table = <S::Session as SqlxModel>::TABLE;
        let id = <S::Session as SqlxSessionModel>::parse_user_id(user_id)?;
        let mut sql = Sql::with(exec.engine(), "DELETE FROM ");
        sql.ident(table);
        sql.push(" WHERE ");
        sql.compare_model::<S::Session>(table, S::Session::user_id_column(), " = ", id);
        _ = exec.execute(sql).await?;
        for session in sessions {
            self.pending_after
                .push(AfterHook::SessionDeleted(session))
                .await;
        }
        Ok(())
    }
    async fn queue_session_revocation(
        &self,
        session_ids: &[String],
        revocation: Arc<dyn alibi_core::store::SessionRevocation>,
    ) -> AuthResult<()> {
        self.pending_after
            .attach_session_revocation(session_ids, revocation)
            .await;
        Ok(())
    }
    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<S::Session>> {
        use crate::model::SqlxModel;
        let exec = Exec::tx(self.tx);
        let table = <S::Session as SqlxModel>::TABLE;
        let mut sql = crate::model::select_model::<S::Session>(exec);
        sql.push(" WHERE ");
        sql.compare_model::<S::Session>(
            table,
            S::Session::user_id_column(),
            " = ",
            S::Session::parse_user_id(user_id)?,
        );
        sql.push(" LIMIT ");
        sql.bind(self.store.find_many_limit());
        exec.fetch_all::<S::Session>(sql).await
    }
    async fn list_oauth_tokens_for_session(
        &self,
        kind: alibi_core::store::OAuthTokenKind,
        session_id: &str,
    ) -> AuthResult<Vec<alibi_core::store::OAuthToken>> {
        self.store
            .session_oauth_tokens(Exec::tx(self.tx), kind, session_id)
            .await
    }
    async fn get_oauth_client(
        &self,
        client_id: &str,
    ) -> AuthResult<Option<alibi_core::store::OAuthClient>> {
        self.store
            .oauth_client_with_exec(Exec::tx(self.tx), client_id)
            .await
    }
    async fn queue_session_deletion_work(
        &self,
        session_id: &str,
        works: Vec<Box<dyn alibi_core::store::SessionDeletionWork<S>>>,
        context: Arc<alibi_core::AuthContext<S>>,
    ) -> AuthResult<()> {
        self.pending_after
            .attach_session_retirement(session_id, works, context)
            .await;
        Ok(())
    }
    async fn check_scim_user_attributes(
        &self,
        id: &str,
        connection: &str,
        attributes: &alibi_core::store::ScimUserAttributes,
    ) -> AuthResult<()> {
        self.store
            .assert_scim_user_keys_with_exec(
                Exec::tx(self.tx),
                connection,
                &attributes.user_name_key,
                attributes.external_id_key.as_deref(),
                None,
                Some(id),
            )
            .await
    }
    async fn lock_scim_user(
        &self,
        id: &str,
        connection: &str,
        domain: &str,
        attributes: Option<&alibi_core::store::ScimUserAttributes>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<alibi_core::store::ScimUserMutationContext> {
        self.store
            .lock_scim_user_with_exec(Exec::tx(self.tx), id, connection, domain, attributes, now)
            .await
    }
    async fn replace_scim_user(
        &self,
        id: &str,
        data: alibi_core::store::ReplaceScimUser,
        roles: bool,
    ) -> AuthResult<(
        alibi_core::store::ScimUserRecord,
        Vec<alibi_core::store::ScimProjectionPreparedUser>,
    )> {
        self.store
            .replace_scim_user_with_exec(Exec::tx(self.tx), id, data, roles)
            .await
    }
    async fn create_scim_user(
        &self,
        data: alibi_core::store::CreateScimUser,
        roles: bool,
    ) -> AuthResult<(
        alibi_core::store::ScimUserRecord,
        Vec<alibi_core::store::ScimProjectionPreparedUser>,
    )> {
        self.store
            .create_scim_user_with_exec(Exec::tx(self.tx), data, roles)
            .await
    }
    async fn delete_scim_user(
        &self,
        id: &str,
        connection: &str,
        domain: &str,
        roles: bool,
    ) -> AuthResult<(String, Vec<alibi_core::store::ScimProjectionPreparedUser>)> {
        self.store
            .delete_scim_user_with_exec(Exec::tx(self.tx), id, connection, domain, roles)
            .await
    }
    async fn patch_scim_group(
        &self,
        id: &str,
        connection: &str,
        domain: &str,
        patch: alibi_core::store::ScimGroupPatch,
        roles: bool,
    ) -> AuthResult<(
        alibi_core::store::ScimGroupRecord,
        Vec<alibi_core::store::ScimProjectionPreparedUser>,
    )> {
        self.store
            .patch_scim_group_with_exec(Exec::tx(self.tx), id, connection, domain, patch, roles)
            .await
    }
    async fn replace_scim_group(
        &self,
        id: &str,
        data: alibi_core::store::ReplaceScimGroup,
        roles: bool,
    ) -> AuthResult<(
        alibi_core::store::ScimGroupRecord,
        Vec<alibi_core::store::ScimProjectionPreparedUser>,
    )> {
        self.store
            .replace_scim_group_with_exec(Exec::tx(self.tx), id, data, roles)
            .await
    }
    async fn delete_scim_group(
        &self,
        id: &str,
        connection: &str,
        domain: &str,
        roles: bool,
    ) -> AuthResult<Vec<alibi_core::store::ScimProjectionPreparedUser>> {
        self.store
            .delete_scim_group_with_exec(Exec::tx(self.tx), id, connection, domain, roles)
            .await
    }
    async fn create_scim_group(
        &self,
        data: alibi_core::store::CreateScimGroup,
        roles: bool,
    ) -> AuthResult<(
        alibi_core::store::ScimGroupRecord,
        Vec<alibi_core::store::ScimProjectionPreparedUser>,
    )> {
        self.store
            .create_scim_group_with_exec(Exec::tx(self.tx), data, roles)
            .await
    }
    async fn fence_scim_connection(&self, id: &str, key: &str) -> AuthResult<()> {
        self.store
            .fence_scim_connection_with_exec(Exec::tx(self.tx), id, key)
            .await
    }
    async fn prepare_scim_projection(
        &self,
        domain: &str,
        ids: &[String],
        roles: bool,
    ) -> AuthResult<Vec<alibi_core::store::ScimProjectionPreparedUser>> {
        self.store
            .prepare_scim_projection_with_exec(Exec::tx(self.tx), domain, ids, roles)
            .await
    }
    async fn create_scim_projection_grant(
        &self,
        data: alibi_core::store::CreateScimProjectionGrant,
    ) -> AuthResult<()> {
        self.store
            .create_scim_projection_grant_with_exec(Exec::tx(self.tx), data)
            .await
    }
    async fn remove_scim_projection_grants(
        &self,
        domain: &str,
        user_id: &str,
        ids: &[String],
    ) -> AuthResult<()> {
        self.store
            .remove_scim_projection_grants_with_exec(Exec::tx(self.tx), domain, user_id, ids)
            .await
    }
    async fn get_user_by_email(
        &self,
        email: &alibi_core::utils::json::JsString,
    ) -> AuthResult<Option<S::User>> {
        self.store
            .get_user_by_email_with_connection(Exec::tx(self.tx), email)
            .await
    }
    async fn get_account(
        &self,
        provider: &str,
        account_id: &alibi_core::utils::json::JsString,
    ) -> AuthResult<Option<S::Account>> {
        self.store
            .get_account_with_connection(Exec::tx(self.tx), provider, account_id)
            .await
    }
    async fn update_user(&self, id: &str, update: alibi_core::UpdateUser) -> AuthResult<S::User> {
        let user = self
            .store
            .update_user_with_connection(Exec::tx(self.tx), Some(self.tx), id, update)
            .await?;
        self.pending_after
            .push(AfterHook::UserUpdated(user.clone()))
            .await;
        Ok(user)
    }
    async fn update_account(
        &self,
        id: &str,
        update: alibi_core::UpdateAccount,
    ) -> AuthResult<S::Account> {
        let account = self
            .store
            .update_account_with_connection(Exec::tx(self.tx), Some(self.tx), id, update)
            .await?;
        self.pending_after
            .push(AfterHook::AccountUpdated(account.clone()))
            .await;
        Ok(account)
    }
    async fn lock_sso_provider(
        &self,
        id: &str,
        provider_id: &str,
    ) -> AuthResult<Option<alibi_core::store::SsoProvider>> {
        self.store
            .lock_sso_provider_with(Exec::tx(self.tx), id, provider_id)
            .await
    }
    async fn update_sso_provider(
        &self,
        update: alibi_core::store::SsoProviderUpdate,
    ) -> AuthResult<Option<alibi_core::store::SsoProvider>> {
        self.store
            .update_sso_provider_with(Exec::tx(self.tx), update)
            .await
    }
    async fn delete_sso_provider_and_accounts(
        &self,
        id: &str,
        provider_id: &str,
    ) -> AuthResult<bool> {
        self.store
            .delete_sso_provider_with(Exec::tx(self.tx), id, provider_id)
            .await
    }
    async fn list_jwks(&self) -> AuthResult<Vec<Jwk>> {
        self.store.list_jwks_with(Exec::tx(self.tx)).await
    }
    async fn get_jwk_by_id(&self, id: &str) -> AuthResult<Option<Jwk>> {
        self.store.get_jwk_with(Exec::tx(self.tx), id).await
    }
    async fn create_jwk(&self, data: CreateJwk) -> AuthResult<Jwk> {
        self.store.create_jwk_with(Exec::tx(self.tx), data).await
    }

    async fn get_team(&self, organization_id: &str, team_id: &str) -> AuthResult<Option<Team>> {
        self.store
            .get_team_with_connection(Exec::tx(self.tx), Some(organization_id), team_id)
            .await
    }
    async fn add_team_member(
        &self,
        team_id: &str,
        user_id: &str,
        maximum: Option<f64>,
    ) -> AuthResult<AddTeamMemberResult> {
        self.store
            .add_team_member_in_tx(self.tx, team_id, user_id, maximum)
            .await
    }
    async fn create_member(&self, member: CreateMember) -> AuthResult<Member> {
        self.store
            .create_member_with_connection(Exec::tx(self.tx), member)
            .await
    }
    async fn update_session_active_team(
        &self,
        token: &str,
        team_id: Option<&str>,
    ) -> AuthResult<S::Session> {
        self.store
            .update_session_scope_with_connection(
                Exec::tx(self.tx),
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
                Exec::tx(self.tx),
                token,
                sessions::SessionScope::Organization(organization_id),
            )
            .await
    }
    async fn native_user_output(
        &self,
        id: &str,
    ) -> AuthResult<std::collections::BTreeMap<String, serde_json::Value>> {
        users::native_user_output::<S::User>(Exec::tx(self.tx), id).await
    }

    async fn provider_verification_output(
        &self,
        id: &str,
    ) -> AuthResult<Option<serde_json::Value>> {
        users::provider_verification_output::<S::User>(Exec::tx(self.tx), id).await
    }
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<S::User>> {
        users::find_user_by_id::<S::User>(Exec::tx(self.tx), id, users::Lock::None).await
    }
    async fn get_user_by_username_value(
        &self,
        username: &alibi_core::utils::json::JsValue,
    ) -> AuthResult<Option<S::User>> {
        self.store
            .get_user_by_username_value_with_connection(Exec::tx(self.tx), username)
            .await
    }
    async fn create_passkey(&self, data: CreatePasskey) -> AuthResult<Passkey> {
        self.store
            .create_passkey_with_connection(Exec::tx(self.tx), data)
            .await
    }
    async fn create_user(&self, create_user: CreateUser) -> AuthResult<S::User> {
        let user = self.store.create_user_in_tx(self.tx, create_user).await?;
        self.pending_after
            .push(AfterHook::UserCreated(user.clone()))
            .await;
        Ok(user)
    }

    async fn create_user_prepared(&self, prepared: PreparedUserCreation) -> AuthResult<S::User> {
        let user = self
            .store
            .create_user_prepared_in_tx(self.tx, prepared)
            .await?;
        self.pending_after
            .push(AfterHook::UserCreated(user.clone()))
            .await;
        Ok(user)
    }

    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<S::Account> {
        let account = self
            .store
            .create_account_in_tx(self.tx, create_account)
            .await?;
        self.pending_after
            .push(AfterHook::AccountCreated(account.clone()))
            .await;
        Ok(account)
    }

    async fn prepare_secondary_session_update(
        &self,
        session: S::Session,
        expires_at: Option<DateTime<Utc>>,
        fields: FieldValues,
    ) -> AuthResult<Option<(S::Session, FieldValues)>> {
        self.store
            .prepare_secondary_update_with_connection(
                Exec::tx(self.tx),
                Some(self.tx),
                session,
                expires_at,
                fields,
            )
            .await
    }
    async fn complete_secondary_session_update(
        &self,
        token: &str,
        session: S::Session,
        expires_at: Option<DateTime<Utc>>,
        fields: FieldValues,
        persist: bool,
    ) -> AuthResult<Option<S::Session>> {
        let result = self
            .store
            .complete_secondary_update_with_connection(
                Exec::tx(self.tx),
                Some(self.tx),
                token,
                session,
                expires_at,
                fields,
                persist,
            )
            .await?;
        let event = result.as_ref().map_or_else(
            || AfterHook::SessionUpdateMissing(token.to_owned()),
            |model| AfterHook::SessionUpdated(model.clone()),
        );
        self.pending_after.push(event).await;
        Ok(result)
    }
    async fn queue_session_publication(
        &self,
        session_id: &str,
        publication: Arc<dyn alibi_core::session::SessionPublication>,
    ) -> AuthResult<()> {
        self.pending_after
            .attach_session_publication(session_id, publication)
            .await
    }

    async fn prepare_secondary_session_creation(
        &self,
        input: CreateSession,
        persist: bool,
    ) -> AuthResult<S::Session> {
        let session = self
            .store
            .prepare_secondary_session_in_tx(self.tx, input, persist)
            .await?;
        self.pending_after
            .push(AfterHook::SessionCreated(session.clone()))
            .await;
        Ok(session)
    }
    async fn create_session(&self, create_session: CreateSession) -> AuthResult<S::Session> {
        let session = self
            .store
            .create_session_in_tx(self.tx, create_session)
            .await?;
        self.pending_after
            .push(AfterHook::SessionCreated(session.clone()))
            .await;
        Ok(session)
    }
    async fn create_verification_record(
        &self,
        data: VerificationCreation,
        publication: VerificationPublication,
    ) -> AuthResult<Option<VerificationSnapshot>> {
        let snapshot = self
            .store
            .create_verification_record_with_connection(
                Exec::tx(self.tx),
                Some(self.tx),
                data,
                publication,
            )
            .await?;
        if let Some(snapshot) = &snapshot {
            self.pending_after
                .push(AfterHook::VerificationRecordCreated(snapshot.clone()))
                .await;
        }
        Ok(snapshot)
    }

    async fn create_verification(
        &self,
        verification: CreateVerification,
    ) -> AuthResult<S::Verification> {
        let verification = self
            .store
            .create_verification_in_tx(self.tx, verification)
            .await?;
        self.pending_after
            .push(AfterHook::VerificationCreated(verification.clone()))
            .await;
        Ok(verification)
    }
    async fn consume_verification_snapshot(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        let consumed = self
            .store
            .consume_generation_in(self.tx, identifier, None)
            .await?;
        if let Some(verification) = &consumed {
            self.pending_after
                .push(AfterHook::VerificationDeleted(verification.clone()))
                .await;
        }
        Ok(consumed)
    }
}

#[async_trait]
impl<S> TransactionStore<S> for SqlxStore<S>
where
    S: AuthSchema,
    S::User: SqlxUserModel,
    S::Account: SqlxAccountModel,
    S::Session: SqlxSessionModel,
    S::Verification: SqlxVerificationModel,
{
    async fn transaction_boxed(
        &self,
        work: Box<TransactionWork<S>>,
    ) -> AuthResult<BoxedTransactionValue> {
        self.transaction_boxed_with_policy(
            work,
            alibi_core::store::AfterCommitErrorPolicy::Propagate,
        )
        .await
    }
    async fn transaction_boxed_with_policy(
        &self,
        work: Box<TransactionWork<S>>,
        policy: alibi_core::store::AfterCommitErrorPolicy,
    ) -> AuthResult<BoxedTransactionValue> {
        self.run_transaction(work, policy, false).await
    }
    async fn write_transaction_boxed(
        &self,
        work: Box<TransactionWork<S>>,
    ) -> AuthResult<BoxedTransactionValue> {
        self.run_transaction(
            work,
            alibi_core::store::AfterCommitErrorPolicy::Propagate,
            true,
        )
        .await
    }
}

impl<S> SqlxStore<S>
where
    S: AuthSchema,
    S::User: SqlxUserModel,
    S::Session: SqlxSessionModel,
    S::Account: SqlxAccountModel,
    S::Verification: SqlxVerificationModel,
{
    async fn run_transaction(
        &self,
        work: Box<TransactionWork<S>>,
        policy: alibi_core::store::AfterCommitErrorPolicy,
        immediate: bool,
    ) -> AuthResult<BoxedTransactionValue> {
        let tx = self.begin(immediate).await?;
        let tx_store = SqlxStoreTransaction {
            store: self,
            tx: &tx,
            pending_after: AfterHookQueue::new(),
        };
        let outcome = work(&tx_store).await;
        let pending_after = tx_store.pending_after;
        match outcome {
            Ok(value) => {
                tx.commit().await?;
                // After hooks run only once the auth writes are durable, in
                // operation order; rollback drops them.
                pending_after
                    .run_with_policy(self.hooks(), &self.hook_context(None), policy)
                    .await?;
                Ok(value)
            }
            Err(err) => {
                tx.rollback().await?;
                Err(err)
            }
        }
    }
}

/// `FOR UPDATE` on PostgreSQL; SQLite relies on its `BEGIN IMMEDIATE` writer lock.
pub(crate) fn lock_exclusive(sql: &mut Sql) {
    if sql.engine() == Engine::Postgres {
        sql.push(" FOR UPDATE");
    }
}

/// `FOR SHARE` on PostgreSQL; SQLite relies on its `BEGIN IMMEDIATE` writer lock.
pub(crate) fn lock_shared(sql: &mut Sql) {
    if sql.engine() == Engine::Postgres {
        sql.push(" FOR SHARE");
    }
}

/// Bind raw numeric `LIMIT`/`OFFSET` values; the database validates them.
pub(crate) fn bind_page(sql: &mut crate::sql::Sql, limit: Option<f64>, offset: Option<f64>) {
    for (clause, number) in [(" LIMIT ", limit), (" OFFSET ", offset)] {
        if let Some(number) = number {
            sql.push(clause);
            if sql.engine() == Engine::Postgres {
                // node-postgres sends Number parameters as text. Binding float8
                // instead lets PostgreSQL round fractional pages to bigint.
                sql.bind(ryu_js::Buffer::new().format(number).to_owned());
                sql.push("::bigint");
            } else {
                sql.bind(number);
            }
        }
    }
}

mod sso;

mod scim;
mod scim_decommission;
mod scim_groups;
mod scim_projection;
mod scim_user_create;
mod scim_user_replace;
mod scim_users;

#[cfg(all(test, feature = "sqlite"))]
mod session_publication_tests {
    use super::*;

    #[derive(crate::AuthEntity, Clone, Debug, serde::Serialize, sqlx::FromRow)]
    #[auth(role = "session", table = "mapped_session", secondary_storage)]
    struct MappedClockSession {
        id: String,
        user_id: String,
        token: String,
        expires_at: chrono::NaiveDateTime,
        #[sqlx(rename = "database_creation_clock")]
        created_at: chrono::NaiveDateTime,
        updated_at: chrono::NaiveDateTime,
        ip_address: Option<String>,
        user_agent: Option<String>,
        impersonated_by: Option<String>,
        active_organization_id: Option<String>,
        custom_label: String,
    }

    #[test]
    fn creation_codec_corrects_mapped_naive_clock_without_mutating_model_or_custom_fields() {
        let clock = chrono::DateTime::from_timestamp_millis(1_800_000_000_789).unwrap();
        let rounded = chrono::DateTime::from_timestamp_millis(1_800_000_000_000).unwrap();
        let session = MappedClockSession {
            id: "session".into(),
            user_id: "owner".into(),
            token: "credential".into(),
            expires_at: (clock + chrono::Duration::hours(1)).naive_utc(),
            created_at: rounded.naive_utc(),
            updated_at: rounded.naive_utc(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            custom_label: "retained".into(),
        };
        let snapshot = session.secondary_snapshot_for_creation(clock).unwrap();
        assert_eq!(snapshot["custom_label"], "retained");
        assert!(snapshot.get("database_creation_clock").is_none());
        let restored = MappedClockSession::from_secondary_snapshot(snapshot).unwrap();
        assert_eq!(restored.created_at(), clock);
        assert_eq!(restored.updated_at(), rounded);
        assert_eq!(session.created_at(), rounded);
        let ordinary =
            MappedClockSession::from_secondary_snapshot(session.secondary_snapshot().unwrap())
                .unwrap();
        assert_eq!(ordinary.created_at(), rounded);
    }

    #[derive(crate::AuthEntity, Clone, Debug, serde::Serialize, sqlx::FromRow)]
    #[auth(role = "session", table = "projected_session", secondary_storage)]
    struct ProjectedSession {
        id: String,
        user_id: String,
        token: String,
        expires_at: chrono::DateTime<chrono::Utc>,
        #[sqlx(rename = "renamed_clock_column")]
        created_at: chrono::DateTime<chrono::Utc>,
        updated_at: chrono::DateTime<chrono::Utc>,
        ip_address: Option<String>,
        user_agent: Option<String>,
        #[sqlx(rename = "renamed_label_column")]
        custom_label: Option<String>,
    }

    #[test]
    fn session_native_output_codec_maps_logical_fields_without_mutating_storage_authority() {
        let clock = chrono::DateTime::from_timestamp_millis(1_800_000_000_789).unwrap();
        let rounded = chrono::DateTime::from_timestamp_millis(1_800_000_000_000).unwrap();
        let session = ProjectedSession {
            id: "session".into(),
            user_id: "owner".into(),
            token: "credential".into(),
            expires_at: clock + chrono::Duration::hours(1),
            created_at: rounded,
            updated_at: rounded,
            ip_address: Some("stored-ip".into()),
            user_agent: Some("stored-agent".into()),
            custom_label: Some("stored-label".into()),
        };
        let mut native = alibi_core::AdapterOutput::default();
        native.insert("customLabel".into(), Some(serde_json::Value::Null));
        native.insert("ipAddress".into(), None);
        native.insert(
            "unknownTrustedObject".into(),
            Some(serde_json::json!({"nested":[true,null]})),
        );
        native.insert(
            "createdAt".into(),
            Some(serde_json::json!("2001-01-01T00:00:00.000Z")),
        );
        let snapshot = session
            .secondary_snapshot_with_native_output(&native)
            .unwrap();
        assert_eq!(snapshot["custom_label"], serde_json::Value::Null);
        assert!(snapshot.get("ip_address").is_none());
        assert_eq!(
            snapshot["unknownTrustedObject"],
            serde_json::json!({"nested":[true,null]})
        );
        assert!(snapshot.get("renamed_label_column").is_none());
        assert!(snapshot.get("renamed_clock_column").is_none());
        let creation = session
            .secondary_snapshot_for_creation_with_native_output(clock, &native)
            .unwrap();
        assert_eq!(creation["created_at"], serde_json::to_value(clock).unwrap());
        assert_eq!(snapshot["created_at"], "2001-01-01T00:00:00.000Z");
        let output = ProjectedSession::output_from_secondary_snapshot(snapshot.clone()).unwrap();
        assert_eq!(output.values()["customLabel"], serde_json::Value::Null);
        assert!(output.field_is_undefined("ipAddress"));
        assert_eq!(
            output.values()["unknownTrustedObject"],
            serde_json::json!({"nested":[true,null]})
        );
        assert!(!output.values().contains_key("custom_label"));
        assert!(!output.values().contains_key("renamed_label_column"));
        let decoded = ProjectedSession::from_secondary_snapshot(snapshot.clone()).unwrap();
        assert_eq!(decoded.custom_label, None);
        assert_eq!(decoded.ip_address, None);

        assert_eq!(session.created_at(), rounded);
        assert_eq!(session.custom_label.as_deref(), Some("stored-label"));
        native.insert("customLabel".into(), None);
        assert!(
            session
                .secondary_snapshot_with_native_output(&native)
                .unwrap()
                .get("custom_label")
                .is_none()
        );

        let naive = MappedClockSession {
            id: "session".into(),
            user_id: "owner".into(),
            token: "credential".into(),
            expires_at: (clock + chrono::Duration::hours(1)).naive_utc(),
            created_at: rounded.naive_utc(),
            updated_at: rounded.naive_utc(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            custom_label: "retained".into(),
        };
        let snapshot = naive
            .secondary_snapshot_for_creation_with_native_output(clock, &native)
            .unwrap();
        assert_eq!(
            snapshot["created_at"],
            serde_json::to_value(clock.naive_utc()).unwrap()
        );
        assert!(snapshot.get("database_creation_clock").is_none());
        assert_eq!(naive.created_at(), rounded);
    }

    use alibi_core::store::{SessionStore, UserStore, write_transaction};
    use alibi_core::{AuthError, AuthSession};
    use std::sync::Mutex;

    type Schema = bundled_schema::BundledSchema;

    struct Publication {
        store: Arc<SqlxStore<Schema>>,
        token: String,
        events: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl alibi_core::session::SessionPublication for Publication {
        async fn publish(&self) {
            assert!(self.store.get_session(&self.token).await.unwrap().is_some());
            self.events.lock().unwrap().push("mirror".into());
        }
    }

    struct Hooks {
        events: Arc<Mutex<Vec<String>>>,
        fail_commit: bool,
    }

    #[async_trait]
    impl DatabaseHooks<Schema, SqlxBackend> for Hooks {
        async fn before_create_session(
            &self,
            input: &mut CreateSession,
            ctx: &SqlxHookContext<'_>,
        ) -> AuthResult<crate::hooks::HookControl> {
            if self.fail_commit && input.token.as_deref() == Some("replacement") {
                use crate::hooks::SqlxHookContextExt;
                let mut connection = ctx.connection().await?;
                let db = connection.sqlite().unwrap();
                _ = sqlx::raw_sql(sqlx::AssertSqlSafe(
                    "CREATE TABLE commit_failure (id TEXT REFERENCES user(id) DEFERRABLE INITIALLY DEFERRED); INSERT INTO commit_failure VALUES ('missing-user')".to_owned()
                )).execute(db).await.unwrap();
            }
            Ok(crate::hooks::HookControl::Continue)
        }

        async fn after_create_session(
            &self,
            session: &<Schema as alibi_core::AuthSchema>::Session,
            ctx: &SqlxHookContext<'_>,
        ) -> AuthResult<()> {
            assert!(ctx.tx.is_none());
            self.events.lock().unwrap().push(session.token().to_owned());
            Ok(())
        }
    }

    fn input(user_id: &str, token: &str) -> CreateSession {
        CreateSession {
            user_id: user_id.to_owned(),
            token: Some(token.to_owned()),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
            additional_fields: Default::default(),
        }
    }

    #[tokio::test]
    async fn secondary_update_persists_by_lookup_token_not_cached_token() {
        let pool = SqlxPool::connect("sqlite::memory:").await.unwrap();
        migrator::run_migrations(&pool).await.unwrap();
        let store = SqlxStore::<Schema>::new(AuthConfig::default(), pool);
        let user = store
            .create_user(CreateUser::new().with_email("lookup@example.com"))
            .await
            .unwrap();
        let original = store
            .create_session(input(&user.id, "lookup-token"))
            .await
            .unwrap();
        for transactional in [false, true] {
            let mut cached = original.clone();
            cached.token = "unrelated-cached-token".into();
            let expiry = Utc::now() + chrono::Duration::hours(2);
            let updated = if transactional {
                write_transaction(&store, move |tx| {
                    Box::pin(async move {
                        let (staged, fields) = tx
                            .prepare_secondary_session_update(
                                cached,
                                Some(expiry),
                                Default::default(),
                            )
                            .await?
                            .unwrap();
                        tx.complete_secondary_session_update(
                            "lookup-token",
                            staged,
                            Some(expiry),
                            fields,
                            true,
                        )
                        .await
                    })
                })
                .await
                .unwrap()
                .unwrap()
            } else {
                let (staged, fields) = store
                    .prepare_secondary_session_update(cached, Some(expiry), Default::default())
                    .await
                    .unwrap()
                    .unwrap();
                store
                    .complete_secondary_session_update(
                        "lookup-token",
                        staged,
                        Some(expiry),
                        fields,
                        true,
                    )
                    .await
                    .unwrap()
                    .unwrap()
            };
            assert_eq!(updated.token(), "lookup-token");
            assert_eq!(updated.expires_at(), expiry);
            assert_eq!(
                store
                    .get_session("lookup-token")
                    .await
                    .unwrap()
                    .unwrap()
                    .expires_at(),
                expiry
            );
            assert!(
                store
                    .get_session("unrelated-cached-token")
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[tokio::test]
    async fn publication_is_committed_before_matching_create_hook_only() {
        for outcome in ["commit", "rollback", "commit-failure"] {
            let pool = SqlxPool::connect("sqlite::memory:").await.unwrap();
            migrator::run_migrations(&pool).await.unwrap();
            let events = Arc::new(Mutex::new(Vec::new()));
            let store = Arc::new(
                SqlxStore::<Schema>::new(AuthConfig::new("test-secret-min-32-chars-1234567"), pool)
                    .hook(Hooks {
                        events: events.clone(),
                        fail_commit: outcome == "commit-failure",
                    }),
            );
            let user = store
                .create_user(CreateUser::new().with_email("mirror@example.com"))
                .await
                .unwrap();
            let user_id = user.id;
            let publication = Arc::new(Publication {
                store: store.clone(),
                token: "replacement".into(),
                events: events.clone(),
            });
            let result = write_transaction(store.as_ref(), move |tx| {
                Box::pin(async move {
                    _ = tx.create_session(input(&user_id, "preceding")).await?;
                    let replacement = tx
                        .prepare_secondary_session_creation(input(&user_id, "replacement"), true)
                        .await?;
                    tx.queue_session_publication(replacement.id().as_ref(), publication)
                        .await?;
                    if outcome == "rollback" {
                        return Err(AuthError::internal("rollback"));
                    }
                    Ok(())
                })
            })
            .await;
            if outcome == "commit" {
                result.unwrap();
                assert_eq!(
                    *events.lock().unwrap(),
                    ["preceding", "mirror", "replacement"]
                );
            } else {
                assert!(result.is_err(), "{outcome}");
                assert!(events.lock().unwrap().is_empty(), "{outcome}");
                assert!(store.get_session("preceding").await.unwrap().is_none());
                assert!(store.get_session("replacement").await.unwrap().is_none());
            }
        }
    }
}
