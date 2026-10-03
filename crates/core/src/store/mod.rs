pub mod adapter;
pub mod cache;
pub mod stateless;

mod database_hooks;
mod migrations;
mod org_extensions;
mod secondary_sessions;

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
use crate::user_validation::{PreparedUserCreation, UserValidationSource, prepare_creation};
use crate::verification::{VerificationCreation, VerificationPublication, VerificationSnapshot};
use async_trait::async_trait;
#[cfg(feature = "redis-cache")]
pub use cache::RedisAdapter;
pub use cache::{CacheAdapter, MemoryCacheAdapter};
pub use database_hooks::{DatabaseHookContext, DatabaseHooks, HookBackend, HookControl};
pub use jwks::JwkStore;
pub use migrations::SchemaMigrator;
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
    pub(crate) adapter_defaults: UserCreationDefaults,
    pub(crate) updates: Vec<UserUpdateTransform>,
}

/// Registered model defaults applied by an adapter after its creation hooks.
/// Keeping this phase separate preserves a validation candidate's absent fields.
#[derive(Clone, Default)]
pub struct UserCreationDefaults(pub(crate) Vec<UserCreateTransform>);
impl UserCreationDefaults {
    pub fn apply(self, data: CreateUser) -> AuthResult<CreateUser> {
        create_data(data, &self.0)
    }
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

/// A persisted adapter result after declared output transforms. Hidden fields
/// remain present; public response filtering has not run on this record.
pub enum AdapterEvent<S: AuthSchema> {
    UserCreated(crate::AdapterRecord<S::User>),
    UserUpdated(crate::AdapterRecord<S::User>),
    SessionCreated(crate::AdapterRecord<S::Session>),
    SessionUpdated(crate::AdapterRecord<S::Session>),
    AccountCreated(crate::AdapterRecord<S::Account>),
    AccountUpdated(crate::AdapterRecord<S::Account>),
}

/// Record-aware application adapter after observer. Output errors prevent this
/// observer; transaction observers run only after commit. Observer errors do not
/// roll back committed writes. Typed physical storage hooks remain separate.
#[async_trait]
pub trait AdapterAfterHook<S: AuthSchema>: Send + Sync {
    async fn after_write(
        &self,
        event: &AdapterEvent<S>,
        database: &dyn AuthStore<S>,
    ) -> AuthResult<()>;
}

pub(crate) struct AdapterCallbacks<S: AuthSchema>(pub(crate) Vec<Arc<dyn AdapterAfterHook<S>>>);

impl<S: AuthSchema> Default for AdapterCallbacks<S> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<S: AuthSchema> Clone for AdapterCallbacks<S> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

pub(crate) struct PluginStore<S: AuthSchema> {
    ephemeral_sessions: Arc<std::sync::Mutex<indexmap::IndexMap<String, S::Session>>>,
    inner: Arc<dyn AuthStore<S>>,
    config: Arc<crate::AuthConfig>,
    transforms: UserTransforms,
    session_callbacks: SessionCreatedCallbacks<S>,
    session_fields: crate::field_policy::SessionFields,
    adapter_fields: crate::field_policy::SessionAdapterFields,
    projection_context: Arc<crate::AuthContext<S>>,
}

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

impl<S: AuthSchema> PluginStore<S> {
    #[must_use]
    pub(crate) fn new(
        inner: Arc<dyn AuthStore<S>>,
        config: Arc<crate::AuthConfig>,
        transforms: UserTransforms,
        session_callbacks: SessionCreatedCallbacks<S>,
        session_fields: crate::field_policy::SessionFields,
        adapter_fields: crate::field_policy::SessionAdapterFields,
        projection_context: crate::AuthContext<S>,
    ) -> Self {
        Self {
            ephemeral_sessions: Arc::new(std::sync::Mutex::new(indexmap::IndexMap::new())),
            inner,
            config,
            transforms,
            session_callbacks,
            session_fields,
            adapter_fields,
            projection_context: Arc::new(projection_context),
        }
    }

    fn field_policies(&self) -> crate::field_policy::AdapterFieldPolicies {
        self.projection_context
            .extensions
            .get::<crate::field_policy::AdapterFieldPolicies>()
            .map(|fields| (*fields).clone())
            .unwrap_or_else(|| crate::field_policy::AdapterFieldPolicies {
                user: crate::field_policy::SessionAdapterFields(Arc::new(
                    self.config.user.additional_fields.clone(),
                )),
                account: crate::field_policy::SessionAdapterFields(Arc::new(
                    self.config.account.additional_fields.clone(),
                )),
            })
    }

    async fn user_record(&self, user: S::User) -> AuthResult<crate::AdapterRecord<S::User>> {
        use crate::AuthUser;
        let verification = self.inner.provider_verification_output(&user.id()).await?;
        let mut record = self.projection_context.user_adapter_record(user).await?;
        if let Some(value) = verification {
            record.retain_provider_verification(value);
        }
        Ok(record)
    }

    async fn session_record(
        &self,
        session: S::Session,
    ) -> AuthResult<crate::AdapterRecord<S::Session>> {
        use crate::AuthSession;
        let absent = self.secondary_absent_fields(session.token()).await?;
        let mut public = serde_json::to_value(crate::SessionView::from(&session))?;
        let mut physical =
            serde_json::to_value(self.projection_context.trusted_session_view(&session))?;
        let mut additional = session.additional_fields();
        for name in absent {
            if let Some(object) = public.as_object_mut() {
                drop(object.remove(&name));
            }
            if let Some(object) = physical.as_object_mut() {
                drop(object.remove(&name));
            }
            drop(additional.remove(&name));
        }
        let output = self
            .adapter_fields
            .record_output(public, additional, physical)
            .await?;
        Ok(crate::AdapterRecord::with_output(session, output))
    }

    async fn session_records(
        &self,
        models: Vec<S::Session>,
    ) -> AuthResult<Vec<crate::AdapterRecord<S::Session>>> {
        if models.is_empty() {
            return Ok(Vec::new());
        }
        let mut records = vec![None; models.len()];
        let store = self.clone();
        let endpoint = crate::endpoint::current_endpoint_call_context();
        let request = crate::hooks::current_request_hook_context();
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        // Like Promise.all, reject the aggregate immediately but keep every
        // launched row projection alive. Retain its actual request context.
        drop(tokio::spawn(async move {
            let project = async {
                drop(
                    futures_util::future::join_all(models.into_iter().enumerate().map(
                        |(index, model)| {
                            let sender = &sender;
                            let store = &store;
                            async move {
                                let result = store.session_record(model).await;
                                let _ignored_closed_receiver = sender.send((index, result));
                            }
                        },
                    ))
                    .await,
                );
            };
            if let Some(endpoint) = endpoint {
                crate::endpoint::with_endpoint_call_context(
                    endpoint,
                    crate::hooks::with_optional_request_hook_context(request, project),
                )
                .await;
            } else {
                crate::hooks::with_optional_request_hook_context(request, project).await;
            }
        }));
        for _ in 0..records.len() {
            let (index, record) = receiver
                .recv()
                .await
                .ok_or_else(|| AuthError::internal("Session collection projection stopped"))?;
            let slot = records
                .get_mut(index)
                .ok_or_else(|| AuthError::internal("Invalid session projection row"))?;
            *slot = Some(record?);
        }
        Ok(records.into_iter().flatten().collect())
    }

    async fn account_record(
        &self,
        account: S::Account,
    ) -> AuthResult<crate::AdapterRecord<S::Account>> {
        use crate::AuthAccount;
        let serde_json::Value::Object(mut canonical) =
            serde_json::to_value(crate::AccountView::from(&account))?
        else {
            return Err(AuthError::internal("Account output must be an object"));
        };
        drop(canonical.insert(
            "password".into(),
            account.password().map_or(serde_json::Value::Null, |value| {
                serde_json::Value::String(value.into())
            }),
        ));
        let output = self
            .field_policies()
            .account
            .record_output(
                serde_json::Value::Object(canonical.clone()),
                account.additional_fields(),
                serde_json::Value::Object(canonical),
            )
            .await?;
        Ok(crate::AdapterRecord::with_output(account, output))
    }

    async fn observe(&self, event: AdapterEvent<S>) -> AuthResult<()> {
        if let Some(callbacks) = self
            .projection_context
            .extensions
            .get::<AdapterCallbacks<S>>()
        {
            for callback in &callbacks.0 {
                callback.after_write(&event, self).await?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl<S: AuthSchema> UserStore<S> for PluginStore<S> {
    async fn provider_verification_output(
        &self,
        id: &str,
    ) -> AuthResult<Option<serde_json::Value>> {
        self.inner.provider_verification_output(id).await
    }

    async fn create_user_record(
        &self,
        create_user: CreateUser,
    ) -> AuthResult<crate::AdapterRecord<S::User>> {
        let record = self
            .user_record(self.create_user(create_user).await?)
            .await?;
        self.observe(AdapterEvent::UserCreated(record.clone()))
            .await?;
        Ok(record)
    }

    async fn create_user_with_source_record(
        &self,
        create_user: CreateUser,
        source: UserValidationSource,
    ) -> AuthResult<crate::AdapterRecord<S::User>> {
        let record = self
            .user_record(self.create_user_with_source(create_user, source).await?)
            .await?;
        self.observe(AdapterEvent::UserCreated(record.clone()))
            .await?;
        Ok(record)
    }

    async fn create_user_prepared_record(
        &self,
        prepared: PreparedUserCreation,
    ) -> AuthResult<crate::AdapterRecord<S::User>> {
        let record = self
            .user_record(self.create_user_prepared(prepared).await?)
            .await?;
        self.observe(AdapterEvent::UserCreated(record.clone()))
            .await?;
        Ok(record)
    }

    async fn get_user_by_id_record(
        &self,
        id: &str,
    ) -> AuthResult<Option<crate::AdapterRecord<S::User>>> {
        let Some(model) = self.get_user_by_id(id).await? else {
            return Ok(None);
        };
        let record = self.user_record(model).await?;
        Ok(Some(record))
    }

    async fn get_user_by_email_record(
        &self,
        email: &str,
    ) -> AuthResult<Option<crate::AdapterRecord<S::User>>> {
        let Some(model) = self.get_user_by_email(email).await? else {
            return Ok(None);
        };
        let record = self.user_record(model).await?;
        Ok(Some(record))
    }

    async fn get_user_by_username_record(
        &self,
        username: &str,
    ) -> AuthResult<Option<crate::AdapterRecord<S::User>>> {
        let Some(model) = self.get_user_by_username(username).await? else {
            return Ok(None);
        };
        let record = self.user_record(model).await?;
        Ok(Some(record))
    }

    async fn get_user_by_phone_number_record(
        &self,
        phone_number: &str,
    ) -> AuthResult<Option<crate::AdapterRecord<S::User>>> {
        let Some(model) = self.get_user_by_phone_number(phone_number).await? else {
            return Ok(None);
        };
        let record = self.user_record(model).await?;
        Ok(Some(record))
    }

    async fn list_users_by_ids_record(
        &self,
        ids: &[String],
    ) -> AuthResult<Vec<crate::AdapterRecord<S::User>>> {
        let mut records = Vec::new();
        for model in self.list_users_by_ids(ids).await? {
            records.push(self.user_record(model).await?);
        }
        Ok(records)
    }

    async fn list_users_by_ids_page_record(
        &self,
        ids: &[String],
        limit: f64,
    ) -> AuthResult<Vec<crate::AdapterRecord<S::User>>> {
        let mut records = Vec::new();
        for model in self.list_users_by_ids_page(ids, limit).await? {
            records.push(self.user_record(model).await?);
        }
        Ok(records)
    }

    async fn update_user_record(
        &self,
        id: &str,
        update: UpdateUser,
    ) -> AuthResult<crate::AdapterRecord<S::User>> {
        let record = self
            .user_record(self.update_user(id, update).await?)
            .await?;
        self.observe(AdapterEvent::UserUpdated(record.clone()))
            .await?;
        Ok(record)
    }

    async fn list_users_record(
        &self,
        params: ListUsersParams,
    ) -> AuthResult<(Vec<crate::AdapterRecord<S::User>>, usize)> {
        let (models, count) = self.list_users(params).await?;
        let mut records = Vec::new();
        for model in models {
            records.push(self.user_record(model).await?);
        }
        Ok((records, count))
    }

    async fn create_user(&self, mut create_user: CreateUser) -> AuthResult<S::User> {
        self.field_policies()
            .user
            .attach(&mut create_user.additional_fields, true);
        if self.config.user_validation.is_some() {
            let prepared = prepare_creation(&self.config, create_user, None).await?;
            return self.create_user_prepared(prepared).await;
        }
        let create_user = create_data(create_user, &self.transforms.creates)?;
        self.inner.create_user(create_user).await
    }
    async fn create_user_with_source(
        &self,
        create_user: CreateUser,
        source: UserValidationSource,
    ) -> AuthResult<S::User> {
        if self.config.user_validation.is_none() {
            return self.create_user(create_user).await;
        }
        let prepared = prepare_creation(&self.config, create_user, Some(source)).await?;
        self.create_user_prepared(prepared).await
    }
    async fn create_user_prepared(&self, prepared: PreparedUserCreation) -> AuthResult<S::User> {
        let mut data = create_data(prepared.into_data(), &self.transforms.creates)?;
        self.field_policies()
            .user
            .attach(&mut data.additional_fields, true);
        self.inner
            .create_user_prepared(
                PreparedUserCreation::from_data(data)
                    .with_defaults(self.transforms.adapter_defaults.clone()),
            )
            .await
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
        self.field_policies()
            .user
            .attach(&mut update.additional_fields, false);
        for transform in &self.transforms.updates {
            update = transform(id, update)?;
        }
        let user = self.inner.update_user(id, update).await?;
        if self.refresh_cached_user(&user).await.is_err() {
            tracing::error!("Failed to refresh committed user sessions in secondary storage");
        }
        Ok(user)
    }
    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        let tokens = self.cached_user_tokens(id).await?;
        self.inner.delete_user(id).await?;
        self.remove_cached_user_sessions(id, tokens).await?;
        Ok(())
    }
    async fn list_users(&self, params: ListUsersParams) -> AuthResult<(Vec<S::User>, usize)> {
        self.inner.list_users(params).await
    }
}

#[async_trait]
impl<S: AuthSchema> SessionStore<S> for PluginStore<S> {
    async fn get_session_user_record(
        &self,
        token: &str,
    ) -> AuthResult<Option<crate::AdapterRecord<S::User>>> {
        let Some(user) = self.get_session_user(token).await? else {
            return Ok(None);
        };
        Ok(Some(self.user_record(user).await?))
    }
    async fn create_session_record(
        &self,
        create_session: CreateSession,
    ) -> AuthResult<crate::AdapterRecord<S::Session>> {
        let record = self
            .session_record(self.create_session(create_session).await?)
            .await?;
        self.observe(AdapterEvent::SessionCreated(record.clone()))
            .await?;
        Ok(record)
    }

    async fn get_session_record(
        &self,
        token: &str,
    ) -> AuthResult<Option<crate::AdapterRecord<S::Session>>> {
        let Some(model) = self.get_session(token).await? else {
            return Ok(None);
        };
        let record = self.session_record(model).await?;
        Ok(Some(record))
    }

    async fn get_sessions_by_tokens_record(
        &self,
        tokens: &[String],
    ) -> AuthResult<Vec<crate::AdapterRecord<S::Session>>> {
        let mut records = Vec::new();
        for model in self.get_sessions_by_tokens(tokens).await? {
            records.push(self.session_record(model).await?);
        }
        Ok(records)
    }

    async fn get_user_sessions_record(
        &self,
        user_id: &str,
    ) -> AuthResult<Vec<crate::AdapterRecord<S::Session>>> {
        self.session_records(self.get_user_sessions(user_id).await?)
            .await
    }

    async fn get_active_user_sessions_record(
        &self,
        user_id: &str,
    ) -> AuthResult<Vec<crate::AdapterRecord<S::Session>>> {
        use crate::AuthSession;
        let now = chrono::Utc::now();
        let models = self
            .get_user_sessions(user_id)
            .await?
            .into_iter()
            .filter(|session| session.expires_at() > now && session.active())
            .collect();
        self.session_records(models).await
    }

    async fn refresh_session_record(
        &self,
        token: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<Option<crate::AdapterRecord<S::Session>>> {
        let Some(model) = self.refresh_session(token, expires_at).await? else {
            return Ok(None);
        };
        let record = self.session_record(model).await?;
        self.observe(AdapterEvent::SessionUpdated(record.clone()))
            .await?;
        Ok(Some(record))
    }

    async fn update_session_fields_record(
        &self,
        token: &str,
        fields: crate::field_policy::FieldValues,
    ) -> AuthResult<Option<crate::AdapterRecord<S::Session>>> {
        let Some(model) = self.update_session_fields(token, fields).await? else {
            return Ok(None);
        };
        let record = self.session_record(model).await?;
        self.observe(AdapterEvent::SessionUpdated(record.clone()))
            .await?;
        Ok(Some(record))
    }

    async fn update_session_active_organization_record(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<crate::AdapterRecord<S::Session>> {
        let record = self
            .session_record(
                self.update_session_active_organization(token, organization_id)
                    .await?,
            )
            .await?;
        self.observe(AdapterEvent::SessionUpdated(record.clone()))
            .await?;
        Ok(record)
    }

    async fn update_session_active_team_record(
        &self,
        token: &str,
        team_id: Option<&str>,
    ) -> AuthResult<crate::AdapterRecord<S::Session>> {
        let record = self
            .session_record(self.update_session_active_team(token, team_id).await?)
            .await?;
        self.observe(AdapterEvent::SessionUpdated(record.clone()))
            .await?;
        Ok(record)
    }

    async fn update_session_fields(
        &self,
        token: &str,
        mut fields: crate::field_policy::FieldValues,
    ) -> AuthResult<Option<S::Session>> {
        self.adapter_fields.attach(&mut fields, false);
        if self.config.session.stateless {
            return self.update_ephemeral_session(token, None, fields).await;
        }
        if self.secondary().is_some() {
            return self.update_secondary_session(token, None, fields).await;
        }
        self.inner.update_session_fields(token, fields).await
    }
    async fn create_session(&self, mut create_session: CreateSession) -> AuthResult<S::Session> {
        self.session_fields
            .defaults(&mut create_session.additional_fields);
        self.adapter_fields
            .attach(&mut create_session.additional_fields, true);
        let session = if self.config.session.stateless {
            self.inner
                .prepare_secondary_session_creation(create_session, false)
                .await?
        } else if self.secondary().is_some() {
            self.inner
                .prepare_secondary_session_creation(create_session, self.session_uses_database())
                .await?
        } else {
            self.inner.create_session(create_session).await?
        };
        self.remember_ephemeral_session(&session)?;
        self.mirror_created_session(&session).await?;
        if self.secondary().is_some() || self.config.session.stateless {
            self.inner
                .complete_secondary_session_creation(&session)
                .await?;
        }
        for callback in &self.session_callbacks.callbacks {
            callback.after_create(&session, self).await?;
        }
        Ok(session)
    }
    async fn get_session(&self, token: &str) -> AuthResult<Option<S::Session>> {
        if self.config.session.stateless {
            return Ok(self
                .ephemeral_sessions
                .lock()
                .map_err(|_| AuthError::internal("Ephemeral session state poisoned"))?
                .get(token)
                .cloned());
        }
        if self.secondary().is_some() {
            if let Some((session, _)) = self.cached_session(token).await? {
                return Ok(Some(session));
            }
            if !self.config.session.store_in_database || self.config.session.preserve_in_database {
                return Ok(None);
            }
            // An absent cache entry allows combined-mode fallback; malformed
            // present data never silently acquires database authority.
            if let Some(cache) = self.secondary()
                && cache.get(token).await?.is_some()
            {
                return Ok(None);
            }
        }
        self.inner.get_session(token).await
    }
    async fn get_session_user(&self, token: &str) -> AuthResult<Option<S::User>> {
        Ok(self.cached_session(token).await?.map(|(_, user)| user))
    }
    async fn get_sessions_by_tokens(&self, tokens: &[String]) -> AuthResult<Vec<S::Session>> {
        if self.config.session.stateless {
            let sessions = self
                .ephemeral_sessions
                .lock()
                .map_err(|_| AuthError::internal("Ephemeral session state poisoned"))?;
            return Ok(sessions
                .values()
                .filter(|session| {
                    tokens
                        .iter()
                        .any(|token| token == crate::AuthSession::token(*session))
                })
                .cloned()
                .collect());
        }
        if self.secondary().is_some() {
            let mut sessions = Vec::new();
            for token in tokens {
                if let Some((session, _)) = self.cached_session(token).await? {
                    sessions.push(session);
                }
            }
            return Ok(sessions);
        }
        self.inner.get_sessions_by_tokens(tokens).await
    }
    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<S::Session>> {
        if self.config.session.stateless {
            return Ok(self
                .ephemeral_sessions
                .lock()
                .map_err(|_| AuthError::internal("Ephemeral session state poisoned"))?
                .values()
                .filter(|session| crate::AuthSession::user_id(*session).as_ref() == user_id)
                .cloned()
                .collect());
        }
        if self.secondary().is_some() {
            return self.cached_user_sessions(user_id).await;
        }
        self.inner.get_user_sessions(user_id).await
    }
    async fn refresh_session(
        &self,
        token: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<Option<S::Session>> {
        self.refresh_session_with_fields(
            token,
            expires_at,
            crate::field_policy::FieldValues::default(),
        )
        .await
    }
    async fn refresh_session_with_fields(
        &self,
        token: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
        mut fields: crate::field_policy::FieldValues,
    ) -> AuthResult<Option<S::Session>> {
        self.adapter_fields.attach(&mut fields, false);
        if self.config.session.stateless {
            return self
                .update_ephemeral_session(token, Some(expires_at), fields)
                .await;
        }
        if self.secondary().is_some() {
            return self
                .update_secondary_session(token, Some(expires_at), fields)
                .await;
        }
        self.inner
            .refresh_session_with_fields(token, expires_at, fields)
            .await
    }
    async fn update_session_expiry(
        &self,
        token: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<()> {
        self.refresh_session(token, expires_at)
            .await?
            .map(|_| ())
            .ok_or(AuthError::SessionNotFound)
    }
    async fn delete_session(&self, token: &str) -> AuthResult<()> {
        if self.config.session.stateless {
            drop(
                self.ephemeral_sessions
                    .lock()
                    .map_err(|_| AuthError::internal("Ephemeral session state poisoned"))?
                    .shift_remove(token),
            );
            return Ok(());
        }
        self.remove_cached_session(token).await?;
        if !self.session_uses_database() {
            return Ok(());
        }
        if self.secondary().is_some() && self.config.session.preserve_in_database {
            return self.inner.end_session_preserving(token).await;
        }
        self.inner.delete_session(token).await
    }
    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
        if self.config.session.stateless {
            self.ephemeral_sessions
                .lock()
                .map_err(|_| AuthError::internal("Ephemeral session state poisoned"))?
                .retain(|_, session| crate::AuthSession::user_id(session).as_ref() != user_id);
            return Ok(());
        }
        drop(self.get_user_sessions_record(user_id).await);
        let tokens = self.cached_user_tokens(user_id).await?;
        if self.session_uses_database() {
            if self.secondary().is_some() && self.config.session.preserve_in_database {
                self.inner.end_user_sessions_preserving(user_id).await?;
            } else {
                self.inner.delete_user_sessions(user_id).await?;
            }
        }
        self.remove_cached_user_sessions(user_id, tokens).await
    }
    async fn delete_expired_sessions(&self) -> AuthResult<usize> {
        if self.config.session.stateless {
            let mut sessions = self
                .ephemeral_sessions
                .lock()
                .map_err(|_| AuthError::internal("Ephemeral session state poisoned"))?;
            let before = sessions.len();
            sessions
                .retain(|_, session| crate::AuthSession::expires_at(session) >= chrono::Utc::now());
            return Ok(before - sessions.len());
        }
        if self.secondary().is_some()
            && (!self.config.session.store_in_database || self.config.session.preserve_in_database)
        {
            // Secondary TTLs own liveness; preserved SQL rows are audit history.
            return Ok(0);
        }
        self.inner.delete_expired_sessions().await
    }
    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<S::Session> {
        if self.config.session.stateless || self.secondary().is_some() {
            let mut fields = crate::field_policy::FieldValues::new();
            drop(fields.insert(
                "activeOrganizationId".into(),
                organization_id.map_or(crate::utils::json::JsValue::Null, |value| {
                    crate::utils::json::JsValue::String(value.to_owned())
                }),
            ));
            let updated = if self.config.session.stateless {
                self.update_ephemeral_session(token, None, fields).await?
            } else {
                self.update_secondary_session(token, None, fields).await?
            };
            return updated.ok_or(AuthError::SessionNotFound);
        }
        self.inner
            .update_session_active_organization(token, organization_id)
            .await
    }
    async fn update_session_active_team(
        &self,
        token: &str,
        team_id: Option<&str>,
    ) -> AuthResult<S::Session> {
        if self.config.session.stateless || self.secondary().is_some() {
            let mut fields = crate::field_policy::FieldValues::new();
            drop(fields.insert(
                "activeTeamId".into(),
                team_id.map_or(crate::utils::json::JsValue::Null, |value| {
                    crate::utils::json::JsValue::String(value.to_owned())
                }),
            ));
            let updated = if self.config.session.stateless {
                self.update_ephemeral_session(token, None, fields).await?
            } else {
                self.update_secondary_session(token, None, fields).await?
            };
            return updated.ok_or(AuthError::SessionNotFound);
        }
        self.inner.update_session_active_team(token, team_id).await
    }
}

#[async_trait]
impl<S: AuthSchema> AccountStore<S> for PluginStore<S> {
    async fn provider_token_text(&self, value: &serde_json::Value) -> AuthResult<Option<String>> {
        self.inner.provider_token_text(value).await
    }

    async fn create_account_record(
        &self,
        create_account: CreateAccount,
    ) -> AuthResult<crate::AdapterRecord<S::Account>> {
        let record = self
            .account_record(self.create_account(create_account).await?)
            .await?;
        self.observe(AdapterEvent::AccountCreated(record.clone()))
            .await?;
        Ok(record)
    }

    async fn get_account_record(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<crate::AdapterRecord<S::Account>>> {
        let Some(model) = self.get_account(provider, provider_account_id).await? else {
            return Ok(None);
        };
        let record = self.account_record(model).await?;
        Ok(Some(record))
    }

    async fn get_credential_account_record(
        &self,
        user_id: &str,
    ) -> AuthResult<Option<crate::AdapterRecord<S::Account>>> {
        use crate::AuthAccount;
        let model = self
            .get_user_accounts(user_id)
            .await?
            .into_iter()
            .find(|account| {
                account.provider_id() == "credential" && account.account_id() == user_id
            });
        match model {
            Some(model) => self.account_record(model).await.map(Some),
            None => Ok(None),
        }
    }

    async fn get_user_accounts_record(
        &self,
        user_id: &str,
    ) -> AuthResult<Vec<crate::AdapterRecord<S::Account>>> {
        let mut records = Vec::new();
        for model in self.get_user_accounts(user_id).await? {
            records.push(self.account_record(model).await?);
        }
        Ok(records)
    }

    async fn update_account_record(
        &self,
        id: &str,
        update: UpdateAccount,
    ) -> AuthResult<crate::AdapterRecord<S::Account>> {
        let record = self
            .account_record(self.update_account(id, update).await?)
            .await?;
        self.observe(AdapterEvent::AccountUpdated(record.clone()))
            .await?;
        Ok(record)
    }

    async fn create_account(&self, mut create_account: CreateAccount) -> AuthResult<S::Account> {
        self.field_policies()
            .account
            .attach(&mut create_account.additional_fields, true);
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
    async fn update_account(&self, id: &str, mut update: UpdateAccount) -> AuthResult<S::Account> {
        self.field_policies()
            .account
            .attach(&mut update.additional_fields, false);
        self.inner.update_account(id, update).await
    }
    async fn delete_account(&self, id: &str) -> AuthResult<()> {
        self.inner.delete_account(id).await
    }
}

#[async_trait]
impl<S: AuthSchema> VerificationStore<S> for PluginStore<S> {
    async fn create_verification_record(
        &self,
        data: VerificationCreation,
        publication: VerificationPublication,
    ) -> AuthResult<Option<VerificationSnapshot>> {
        self.inner
            .create_verification_record(data, publication)
            .await
    }
    async fn consume_verification_snapshot(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        self.inner.consume_verification_snapshot(identifier).await
    }
    async fn update_verification_by_identifier(
        &self,
        identifier: &str,
        data: crate::UpdateVerification,
    ) -> AuthResult<Option<VerificationSnapshot>> {
        self.inner
            .update_verification_by_identifier(identifier, data)
            .await
    }
    async fn reserve_verification_record(
        &self,
        logical_identifier: &str,
        data: CreateVerification,
    ) -> AuthResult<Option<S::Verification>> {
        self.inner
            .reserve_verification_record(logical_identifier, data)
            .await
    }
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
        _invitation_id: &str,
        _user_id: &str,
        _session_token: &str,
        _team_limits: &[(String, Option<f64>)],
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
        _maximum: Option<f64>,
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
    config: Arc<crate::AuthConfig>,
    creates: Vec<UserCreateTransform>,
    adapter_defaults: UserCreationDefaults,
    pending_sessions: Arc<std::sync::Mutex<Vec<S::Session>>>,
    session_fields: crate::field_policy::SessionFields,
    adapter_fields: crate::field_policy::SessionAdapterFields,
    record_store: PluginStore<S>,
    pending_records: Arc<std::sync::Mutex<Vec<AdapterEvent<S>>>>,
}

impl<S: AuthSchema> PluginTransaction<'_, S> {
    fn observe(&self, event: AdapterEvent<S>) -> AuthResult<()> {
        self.pending_records
            .lock()
            .map_err(|_| AuthError::internal("Adapter callback queue poisoned"))?
            .push(event);
        Ok(())
    }
    async fn update_secondary_scope(
        &self,
        token: &str,
        mut fields: crate::field_policy::FieldValues,
    ) -> AuthResult<S::Session> {
        self.adapter_fields.attach(&mut fields, false);
        let (session, user) = self
            .record_store
            .cached_session(token)
            .await?
            .ok_or(AuthError::SessionNotFound)?;
        let (updated, fields) = self
            .inner
            .prepare_secondary_session_update(session, None, fields)
            .await?
            .ok_or(AuthError::SessionNotFound)?;
        self.record_store
            .mirror_session_fields(&updated, &user, Some(&fields))
            .await?;
        self.inner
            .complete_secondary_session_update(
                updated,
                None,
                fields,
                self.record_store.session_uses_database(),
            )
            .await?
            .ok_or(AuthError::SessionNotFound)
    }
}

impl<S: AuthSchema> PluginTransaction<'_, S> {
    async fn transaction_user_record(
        &self,
        user: S::User,
    ) -> AuthResult<crate::AdapterRecord<S::User>> {
        use crate::AuthUser;
        let verification = self.inner.provider_verification_output(&user.id()).await?;
        let mut record = self
            .record_store
            .projection_context
            .user_adapter_record(user)
            .await?;
        if let Some(value) = verification {
            record.retain_provider_verification(value);
        }
        Ok(record)
    }
}

#[async_trait]
impl<S: AuthSchema> AuthTransaction<S> for PluginTransaction<'_, S> {
    async fn provider_verification_output(
        &self,
        id: &str,
    ) -> AuthResult<Option<serde_json::Value>> {
        self.inner.provider_verification_output(id).await
    }

    async fn list_jwks(&self) -> AuthResult<Vec<Jwk>> {
        self.inner.list_jwks().await
    }
    async fn get_jwk_by_id(&self, id: &str) -> AuthResult<Option<Jwk>> {
        self.inner.get_jwk_by_id(id).await
    }
    async fn create_jwk(&self, data: CreateJwk) -> AuthResult<Jwk> {
        self.inner.create_jwk(data).await
    }

    async fn create_user_record(
        &self,
        create_user: CreateUser,
    ) -> AuthResult<crate::AdapterRecord<S::User>> {
        let model = self.create_user(create_user).await?;
        let record = self.transaction_user_record(model).await?;
        self.observe(AdapterEvent::UserCreated(record.clone()))?;
        Ok(record)
    }

    async fn create_user_with_source_record(
        &self,
        create_user: CreateUser,
        source: UserValidationSource,
    ) -> AuthResult<crate::AdapterRecord<S::User>> {
        let model = self.create_user_with_source(create_user, source).await?;
        let record = self.transaction_user_record(model).await?;
        self.observe(AdapterEvent::UserCreated(record.clone()))?;
        Ok(record)
    }

    async fn create_user_prepared_record(
        &self,
        prepared: PreparedUserCreation,
    ) -> AuthResult<crate::AdapterRecord<S::User>> {
        let model = self.create_user_prepared(prepared).await?;
        let record = self.transaction_user_record(model).await?;
        self.observe(AdapterEvent::UserCreated(record.clone()))?;
        Ok(record)
    }

    async fn get_user_by_id_record(
        &self,
        id: &str,
    ) -> AuthResult<Option<crate::AdapterRecord<S::User>>> {
        let Some(model) = self.get_user_by_id(id).await? else {
            return Ok(None);
        };
        let record = self.transaction_user_record(model).await?;
        Ok(Some(record))
    }

    async fn create_account_record(
        &self,
        create_account: CreateAccount,
    ) -> AuthResult<crate::AdapterRecord<S::Account>> {
        let model = self.create_account(create_account).await?;
        let record = self.record_store.account_record(model).await?;
        self.observe(AdapterEvent::AccountCreated(record.clone()))?;
        Ok(record)
    }

    async fn create_session_record(
        &self,
        create_session: CreateSession,
    ) -> AuthResult<crate::AdapterRecord<S::Session>> {
        let model = self.create_session(create_session).await?;
        let record = self.record_store.session_record(model).await?;
        self.observe(AdapterEvent::SessionCreated(record.clone()))?;
        Ok(record)
    }

    async fn update_session_active_organization_record(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<crate::AdapterRecord<S::Session>> {
        let model = self
            .update_session_active_organization(token, organization_id)
            .await?;
        let record = self.record_store.session_record(model).await?;
        self.observe(AdapterEvent::SessionUpdated(record.clone()))?;
        Ok(record)
    }

    async fn update_session_active_team_record(
        &self,
        token: &str,
        team_id: Option<&str>,
    ) -> AuthResult<crate::AdapterRecord<S::Session>> {
        let model = self.update_session_active_team(token, team_id).await?;
        let record = self.record_store.session_record(model).await?;
        self.observe(AdapterEvent::SessionUpdated(record.clone()))?;
        Ok(record)
    }

    async fn get_team(&self, organization_id: &str, team_id: &str) -> AuthResult<Option<Team>> {
        self.inner.get_team(organization_id, team_id).await
    }

    async fn add_team_member(
        &self,
        team_id: &str,
        user_id: &str,
        maximum: Option<f64>,
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
        if self.config.session.stateless {
            let mut fields = crate::field_policy::FieldValues::new();
            drop(fields.insert(
                "activeTeamId".into(),
                team_id.map_or(crate::utils::json::JsValue::Null, |value| {
                    crate::utils::json::JsValue::String(value.to_owned())
                }),
            ));
            return self.record_store.update_ephemeral_session(token, None, fields)
                .await?.ok_or(AuthError::SessionNotFound);
        }
        if self.record_store.secondary().is_some()
            && (!self.record_store.session_uses_database()
                || self.record_store.cached_session(token).await?.is_some())
        {
            let mut fields = crate::field_policy::FieldValues::new();
            drop(fields.insert(
                "activeTeamId".into(),
                team_id.map_or(crate::utils::json::JsValue::Null, |value| {
                    crate::utils::json::JsValue::String(value.to_owned())
                }),
            ));
            return self.update_secondary_scope(token, fields).await;
        }
        self.inner.update_session_active_team(token, team_id).await
    }

    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<S::Session> {
        if self.config.session.stateless {
            let mut fields = crate::field_policy::FieldValues::new();
            drop(fields.insert(
                "activeOrganizationId".into(),
                organization_id.map_or(crate::utils::json::JsValue::Null, |value| {
                    crate::utils::json::JsValue::String(value.to_owned())
                }),
            ));
            return self.record_store.update_ephemeral_session(token, None, fields)
                .await?.ok_or(AuthError::SessionNotFound);
        }
        if self.record_store.secondary().is_some()
            && (!self.record_store.session_uses_database()
                || self.record_store.cached_session(token).await?.is_some())
        {
            let mut fields = crate::field_policy::FieldValues::new();
            drop(fields.insert(
                "activeOrganizationId".into(),
                organization_id.map_or(crate::utils::json::JsValue::Null, |value| {
                    crate::utils::json::JsValue::String(value.to_owned())
                }),
            ));
            return self.update_secondary_scope(token, fields).await;
        }
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

    async fn create_user(&self, mut create_user: CreateUser) -> AuthResult<S::User> {
        self.record_store
            .field_policies()
            .user
            .attach(&mut create_user.additional_fields, true);
        if self.config.user_validation.is_some() {
            let prepared = prepare_creation(&self.config, create_user, None).await?;
            return self.create_user_prepared(prepared).await;
        }
        self.inner
            .create_user(create_data(create_user, &self.creates)?)
            .await
    }
    async fn create_user_with_source(
        &self,
        create_user: CreateUser,
        source: UserValidationSource,
    ) -> AuthResult<S::User> {
        if self.config.user_validation.is_none() {
            return self.create_user(create_user).await;
        }
        let prepared = prepare_creation(&self.config, create_user, Some(source)).await?;
        self.create_user_prepared(prepared).await
    }
    async fn create_user_prepared(&self, prepared: PreparedUserCreation) -> AuthResult<S::User> {
        let mut data = create_data(prepared.into_data(), &self.creates)?;
        self.record_store
            .field_policies()
            .user
            .attach(&mut data.additional_fields, true);
        self.inner
            .create_user_prepared(
                PreparedUserCreation::from_data(data).with_defaults(self.adapter_defaults.clone()),
            )
            .await
    }

    async fn create_account(&self, mut create_account: CreateAccount) -> AuthResult<S::Account> {
        self.record_store
            .field_policies()
            .account
            .attach(&mut create_account.additional_fields, true);
        self.inner.create_account(create_account).await
    }

    async fn create_session(&self, mut create_session: CreateSession) -> AuthResult<S::Session> {
        self.session_fields
            .defaults(&mut create_session.additional_fields);
        self.adapter_fields
            .attach(&mut create_session.additional_fields, true);
        let session = if self.config.session.stateless {
            self.inner
                .prepare_secondary_session_creation(create_session, false)
                .await?
        } else if self.record_store.secondary().is_some() {
            let model = self
                .inner
                .prepare_secondary_session_creation(
                    create_session,
                    self.record_store.session_uses_database(),
                )
                .await?;
            use crate::AuthSession;
            let user = self
                .inner
                .get_user_by_id(model.user_id().as_ref())
                .await?
                .ok_or_else(|| AuthError::internal("Secondary session owner not found"))?;
            self.record_store.mirror_session(&model, &user).await?;
            model
        } else {
            self.inner.create_session(create_session).await?
        };
        self.pending_sessions
            .lock()
            .map_err(|_| AuthError::internal("Session callback queue poisoned"))?
            .push(session.clone());
        Ok(session)
    }

    async fn create_verification_record(
        &self,
        data: VerificationCreation,
        publication: VerificationPublication,
    ) -> AuthResult<Option<VerificationSnapshot>> {
        self.inner
            .create_verification_record(data, publication)
            .await
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
        let adapter_defaults = self.transforms.adapter_defaults.clone();
        let config = Arc::clone(&self.config);
        let pending_sessions = Arc::new(std::sync::Mutex::new(Vec::new()));
        let pending_in_transaction = Arc::clone(&pending_sessions);
        let session_fields = self.session_fields.clone();
        let adapter_fields = self.adapter_fields.clone();
        let record_store = self.clone();
        let pending_records = Arc::new(std::sync::Mutex::new(Vec::new()));
        let records_in_transaction = Arc::clone(&pending_records);
        let value = self
            .inner
            .transaction_boxed(Box::new(move |inner| {
                Box::pin(async move {
                    let transaction = PluginTransaction {
                        inner,
                        config,
                        creates,
                        adapter_defaults,
                        pending_sessions: pending_in_transaction,
                        session_fields,
                        adapter_fields,
                        record_store,
                        pending_records: records_in_transaction,
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
            self.remember_ephemeral_session(&session)?;
            for callback in &self.session_callbacks.callbacks {
                callback.after_create(&session, self).await?;
            }
        }
        let records = std::mem::take(
            &mut *pending_records
                .lock()
                .map_err(|_| AuthError::internal("Adapter callback queue poisoned"))?,
        );
        for record in records {
            self.observe(record).await?;
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

/// Numeric binding used when a registered user text field accepts a JSON number.
/// The HTTP caller first rounds it to a JavaScript number, preserving negative zero.
#[derive(Clone, Copy, Debug)]
pub enum NumericTextInput {
    Integer(i64),
    Real(f64),
}

#[async_trait]
pub trait UserStore<S: AuthSchema>: Send + Sync {
    /// Read the provider verification column using the adapter's physical scalar
    /// rules. This is retained output, not authorization input; typed models
    /// continue to supply the canonical boolean accessor.
    async fn provider_verification_output(
        &self,
        _id: &str,
    ) -> AuthResult<Option<serde_json::Value>> {
        Ok(None)
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
    async fn get_user_by_email_record(
        &self,
        email: &str,
    ) -> AuthResult<Option<crate::AdapterRecord<S::User>>> {
        self.get_user_by_email(email)
            .await?
            .map(crate::AdapterRecord::physical)
            .transpose()
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn get_user_by_username_record(
        &self,
        username: &str,
    ) -> AuthResult<Option<crate::AdapterRecord<S::User>>> {
        self.get_user_by_username(username)
            .await?
            .map(crate::AdapterRecord::physical)
            .transpose()
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn get_user_by_phone_number_record(
        &self,
        phone_number: &str,
    ) -> AuthResult<Option<crate::AdapterRecord<S::User>>> {
        self.get_user_by_phone_number(phone_number)
            .await?
            .map(crate::AdapterRecord::physical)
            .transpose()
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn list_users_by_ids_record(
        &self,
        ids: &[String],
    ) -> AuthResult<Vec<crate::AdapterRecord<S::User>>> {
        self.list_users_by_ids(ids)
            .await?
            .into_iter()
            .map(crate::AdapterRecord::physical)
            .collect()
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn list_users_by_ids_page_record(
        &self,
        ids: &[String],
        limit: f64,
    ) -> AuthResult<Vec<crate::AdapterRecord<S::User>>> {
        self.list_users_by_ids_page(ids, limit)
            .await?
            .into_iter()
            .map(crate::AdapterRecord::physical)
            .collect()
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn update_user_record(
        &self,
        id: &str,
        update: UpdateUser,
    ) -> AuthResult<crate::AdapterRecord<S::User>> {
        crate::AdapterRecord::physical(self.update_user(id, update).await?)
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn list_users_record(
        &self,
        params: ListUsersParams,
    ) -> AuthResult<(Vec<crate::AdapterRecord<S::User>>, usize)> {
        let (models, count) = self.list_users(params).await?;
        Ok((
            models
                .into_iter()
                .map(crate::AdapterRecord::physical)
                .collect::<AuthResult<Vec<_>>>()?,
            count,
        ))
    }

    async fn create_user(&self, create_user: CreateUser) -> AuthResult<S::User>;
    /// Create with endpoint-owned identity provenance, retaining the finalized
    /// instance's validation and database-hook ordering.
    async fn create_user_with_source(
        &self,
        create_user: CreateUser,
        _source: UserValidationSource,
    ) -> AuthResult<S::User> {
        self.create_user(create_user).await
    }
    /// Persist a normalized, admitted candidate without normalizing trusted
    /// callback mutations again. Unsupported custom adapters fail closed.
    async fn create_user_prepared(&self, _prepared: PreparedUserCreation) -> AuthResult<S::User> {
        Err(AuthError::NotImplemented(
            "Prepared user creation is not supported by this store".into(),
        ))
    }
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
    /// Stage a secondary session through creation hooks and optional physical persistence.
    /// The caller publishes the cache before completing its after hooks.
    async fn prepare_secondary_session_creation(
        &self,
        _input: CreateSession,
        _persist: bool,
    ) -> AuthResult<S::Session> {
        Err(AuthError::NotImplemented(
            "Secondary session creation is unsupported".into(),
        ))
    }
    /// Complete creation hooks after the actual secondary writes succeed.
    async fn complete_secondary_session_creation(&self, _session: &S::Session) -> AuthResult<()> {
        Err(AuthError::NotImplemented(
            "Secondary session creation is unsupported".into(),
        ))
    }
    /// Bind a trusted secondary update once, retaining hook-mutated fields for physical publication.
    async fn prepare_secondary_session_update(
        &self,
        _session: S::Session,
        _expires_at: Option<chrono::DateTime<chrono::Utc>>,
        _fields: crate::field_policy::FieldValues,
    ) -> AuthResult<Option<(S::Session, crate::field_policy::FieldValues)>> {
        Err(AuthError::NotImplemented(
            "Secondary session updates are unsupported".into(),
        ))
    }
    /// Publish the staged physical update and run after hooks exactly once.
    async fn complete_secondary_session_update(
        &self,
        _session: S::Session,
        _expires_at: Option<chrono::DateTime<chrono::Utc>>,
        _fields: crate::field_policy::FieldValues,
        _persist: bool,
    ) -> AuthResult<Option<S::Session>> {
        Err(AuthError::NotImplemented(
            "Secondary session updates are unsupported".into(),
        ))
    }
    /// End a still-live physical session without deleting its audit row.
    async fn end_session_preserving(&self, _token: &str) -> AuthResult<()> {
        Err(AuthError::NotImplemented(
            "Preserving ended session rows is unsupported".into(),
        ))
    }
    /// End all live session rows for one owner while retaining audit history.
    async fn end_user_sessions_preserving(&self, _user_id: &str) -> AuthResult<()> {
        Err(AuthError::NotImplemented(
            "Preserving ended session rows is unsupported".into(),
        ))
    }
    /// A typed user snapshot belonging to an authenticated session. The default
    /// signals that the caller must use its physical user store.
    async fn get_session_user(&self, _token: &str) -> AuthResult<Option<S::User>> {
        Ok(None)
    }

    /// Retain declared adapter output for a secondary-backed session owner.
    async fn get_session_user_record(
        &self,
        token: &str,
    ) -> AuthResult<Option<crate::AdapterRecord<S::User>>> {
        self.get_session_user(token)
            .await?
            .map(crate::AdapterRecord::physical)
            .transpose()
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
    async fn get_session_record(
        &self,
        token: &str,
    ) -> AuthResult<Option<crate::AdapterRecord<S::Session>>> {
        self.get_session(token)
            .await?
            .map(crate::AdapterRecord::physical)
            .transpose()
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn get_sessions_by_tokens_record(
        &self,
        tokens: &[String],
    ) -> AuthResult<Vec<crate::AdapterRecord<S::Session>>> {
        self.get_sessions_by_tokens(tokens)
            .await?
            .into_iter()
            .map(crate::AdapterRecord::physical)
            .collect()
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn get_user_sessions_record(
        &self,
        user_id: &str,
    ) -> AuthResult<Vec<crate::AdapterRecord<S::Session>>> {
        self.get_user_sessions(user_id)
            .await?
            .into_iter()
            .map(crate::AdapterRecord::physical)
            .collect()
    }

    /// Return active physical sessions after declared output transforms. Expiry
    /// selection runs before application callbacks, without trusting output fields.
    async fn get_active_user_sessions_record(
        &self,
        user_id: &str,
    ) -> AuthResult<Vec<crate::AdapterRecord<S::Session>>> {
        use crate::AuthSession;
        let now = chrono::Utc::now();
        self.get_user_sessions(user_id)
            .await?
            .into_iter()
            .filter(|session| session.expires_at() > now && session.active())
            .map(crate::AdapterRecord::physical)
            .collect()
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn refresh_session_record(
        &self,
        token: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<Option<crate::AdapterRecord<S::Session>>> {
        self.refresh_session(token, expires_at)
            .await?
            .map(crate::AdapterRecord::physical)
            .transpose()
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn update_session_fields_record(
        &self,
        token: &str,
        fields: crate::field_policy::FieldValues,
    ) -> AuthResult<Option<crate::AdapterRecord<S::Session>>> {
        self.update_session_fields(token, fields)
            .await?
            .map(crate::AdapterRecord::physical)
            .transpose()
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

    /// Refresh expiry and configured fields in one physical update. Adapters
    /// supporting additional values must override this operation so their actual
    /// before hooks precede binding and their after hooks see the final row.
    /// The fallback preserves plain refresh and fails closed on additional writes.
    async fn refresh_session_with_fields(
        &self,
        token: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
        mut fields: crate::field_policy::FieldValues,
    ) -> AuthResult<Option<S::Session>> {
        fields.apply_adapter_transforms_async().await?;
        if !fields.is_empty() {
            return Err(AuthError::NotImplemented(
                "The store does not support refresh field updates".into(),
            ));
        }
        self.refresh_session(token, expires_at).await
    }

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
    /// Apply the physical token TEXT column's scalar affinity before persistence.
    /// SQL adapters override this for their own boolean/numeric representation.
    async fn provider_token_text(&self, value: &serde_json::Value) -> AuthResult<Option<String>> {
        if value.is_null() {
            return Ok(None);
        }
        if value.is_object() || value.is_array() {
            return Err(AuthError::internal(
                "Unsupported provider token SQL parameter",
            ));
        }
        crate::utils::json::JsValue::from(value.clone())
            .coerce_string()
            .map(Some)
            .map_err(AuthError::internal)
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
    async fn get_account_record(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<crate::AdapterRecord<S::Account>>> {
        self.get_account(provider, provider_account_id)
            .await?
            .map(crate::AdapterRecord::physical)
            .transpose()
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    /// Retain the selected physical credential result. Initialization applies
    /// output policy only to that selected row, never unrelated linked accounts.
    async fn get_credential_account_record(
        &self,
        user_id: &str,
    ) -> AuthResult<Option<crate::AdapterRecord<S::Account>>> {
        use crate::AuthAccount;
        self.get_user_accounts(user_id)
            .await?
            .into_iter()
            .find(|account| {
                account.provider_id() == "credential" && account.account_id() == user_id
            })
            .map(crate::AdapterRecord::physical)
            .transpose()
    }

    async fn get_user_accounts_record(
        &self,
        user_id: &str,
    ) -> AuthResult<Vec<crate::AdapterRecord<S::Account>>> {
        self.get_user_accounts(user_id)
            .await?
            .into_iter()
            .map(crate::AdapterRecord::physical)
            .collect()
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn update_account_record(
        &self,
        id: &str,
        update: UpdateAccount,
    ) -> AuthResult<crate::AdapterRecord<S::Account>> {
        crate::AdapterRecord::physical(self.update_account(id, update).await?)
    }

    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<S::Account>;
    /// Resolve a global provider identity only when exactly one physical row matches.
    /// Duplicate rows (including duplicates owned by one user) must return
    /// `DatabaseError::AmbiguousAccount`; choosing a row would make ownership arbitrary.
    async fn get_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<S::Account>>;
    /// Return all scoped physical rows in the adapter's native order. Do not
    /// select or collapse duplicate provider identities, or sort by mutable dates.
    async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<S::Account>>;
    async fn update_account(&self, id: &str, update: UpdateAccount) -> AuthResult<S::Account>;
    async fn delete_account(&self, id: &str) -> AuthResult<()>;
}

#[async_trait]
pub trait VerificationStore<S: AuthSchema>: Send + Sync {
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
    /// Atomically remove the newest generation and all siblings, returning the
    /// actual winning snapshot even when expired. This keeps legacy fallback
    /// from resurrecting an older logical generation.
    async fn consume_verification_snapshot(
        &self,
        _identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        Err(AuthError::NotImplemented(
            "Raw atomic verification consumption is not supported by this store".into(),
        ))
    }
    /// Update every physical match, with one actual adapter result snapshot.
    async fn update_verification_by_identifier(
        &self,
        _identifier: &str,
        _data: crate::UpdateVerification,
    ) -> AuthResult<Option<VerificationSnapshot>> {
        Err(AuthError::NotImplemented(
            "Verification identifier updates are not supported by this store".into(),
        ))
    }
    /// Reserve by the original logical identifier while storing its configured
    /// transformed identifier. Return the actual newly inserted model only.
    async fn reserve_verification_record(
        &self,
        _logical_identifier: &str,
        _data: CreateVerification,
    ) -> AuthResult<Option<S::Verification>> {
        Err(AuthError::NotImplemented(
            "Configured verification reservation is not supported by this store".into(),
        ))
    }
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

/// Trusted persisted-field overrides returned by an invitation creation hook.
/// They are separate from the stable default CreateInvitation constructor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InvitationCreateOptions {
    pub id: Option<String>,
    pub status: Option<InvitationStatus>,
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[async_trait]
pub trait InvitationStore: Send + Sync {
    async fn create_invitation_with_options(
        &self,
        invitation: CreateInvitation,
        options: InvitationCreateOptions,
    ) -> AuthResult<Invitation> {
        if options == InvitationCreateOptions::default() {
            self.create_invitation(invitation).await
        } else {
            Err(AuthError::NotImplemented(
                "Invitation creation overrides are not supported by this store".into(),
            ))
        }
    }

    /// Actual adapter page of pending rows, before expiry filtering.
    async fn pending_invitation_page(
        &self,
        _org_id: &str,
        _email: Option<&str>,
    ) -> AuthResult<Vec<Invitation>> {
        Err(AuthError::NotImplemented(
            "Pending invitation pages are not supported by this store".into(),
        ))
    }
    /// Update expiry independently; reissue retains every other invitation field.
    async fn update_invitation_expiry(
        &self,
        _id: &str,
        _expires_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<Invitation> {
        Err(AuthError::NotImplemented(
            "Invitation expiry updates are not supported by this store".into(),
        ))
    }

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
        _team_limits: &[(String, Option<f64>)],
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
