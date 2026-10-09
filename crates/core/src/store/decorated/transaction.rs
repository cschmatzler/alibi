use crate::store::{
    AdapterEvent, BoxedTransactionValue, PluginStore, TransactionStore, TransactionWork,
    UserCreateTransform, UserCreationDefaults, create_data,
};
use crate::types::AddTeamMemberResult;
use crate::user_validation::{PreparedUserCreation, UserValidationSource, prepare_creation};
use crate::verification::{VerificationCreation, VerificationPublication, VerificationSnapshot};
use crate::{
    AuthError, AuthResult, AuthSchema, AuthSession, AuthTransaction, CreateAccount, CreateJwk,
    CreateMember, CreatePasskey, CreateSession, CreateUser, CreateVerification, Jwk, Member,
    Passkey, Team,
};
use async_trait::async_trait;
use std::sync::Arc;
pub(in crate::store) struct PluginTransaction<'a, S: AuthSchema> {
    pub(in crate::store) inner: &'a dyn AuthTransaction<S>,
    pub(in crate::store) config: Arc<crate::AuthConfig>,
    pub(in crate::store) creates: Vec<UserCreateTransform>,
    pub(in crate::store) adapter_defaults: UserCreationDefaults,
    pub(in crate::store) pending_sessions: Arc<std::sync::Mutex<Vec<S::Session>>>,
    pub(in crate::store) pending_scopes:
        Arc<std::sync::Mutex<std::collections::HashMap<String, S::Session>>>,
    pub(in crate::store) session_fields: crate::field_policy::SessionFields,
    pub(in crate::store) adapter_fields: crate::field_policy::SessionAdapterFields,
    pub(in crate::store) record_store: PluginStore<S>,
    pub(in crate::store) pending_records: Arc<std::sync::Mutex<Vec<AdapterEvent<S>>>>,
}

impl<S: AuthSchema> PluginTransaction<'_, S> {
    pub(in crate::store) fn observe(&self, event: AdapterEvent<S>) -> AuthResult<()> {
        self.pending_records
            .lock()
            .map_err(|_| AuthError::internal("Adapter callback queue poisoned"))?
            .push(event);
        Ok(())
    }
    pub(in crate::store) async fn update_ephemeral_scope(
        &self,
        token: &str,
        mut fields: crate::field_policy::FieldValues,
    ) -> AuthResult<S::Session> {
        self.adapter_fields.attach(&mut fields, false);
        let staged = self
            .pending_scopes
            .lock()
            .map_err(|_| AuthError::internal("Ephemeral scope queue poisoned"))?
            .get(token)
            .cloned();
        let session = match staged {
            Some(session) => session,
            None => self
                .record_store
                .ephemeral_sessions
                .lock()
                .map_err(|_| AuthError::internal("Ephemeral session state poisoned"))?
                .get(token)
                .cloned()
                .ok_or(AuthError::SessionNotFound)?,
        };
        let (updated, fields) = self
            .inner
            .prepare_secondary_session_update(session, None, fields)
            .await?
            .ok_or(AuthError::SessionNotFound)?;
        let updated = self
            .inner
            .complete_secondary_session_update(updated, None, fields, false)
            .await?
            .ok_or(AuthError::SessionNotFound)?;
        _ = self
            .pending_scopes
            .lock()
            .map_err(|_| AuthError::internal("Ephemeral scope queue poisoned"))?
            .insert(token.to_owned(), updated.clone());
        Ok(updated)
    }
    pub(in crate::store) async fn update_secondary_scope(
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
    pub(in crate::store) async fn transaction_user_record(
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
            _ = fields.insert(
                "activeTeamId".into(),
                team_id.map_or(crate::utils::json::JsValue::Null, |value| {
                    crate::utils::json::JsValue::String(value.to_owned())
                }),
            );
            return self.update_ephemeral_scope(token, fields).await;
        }
        if self.record_store.secondary().is_some()
            && (!self.record_store.session_uses_database()
                || self.record_store.cached_session(token).await?.is_some())
        {
            let mut fields = crate::field_policy::FieldValues::new();
            _ = fields.insert(
                "activeTeamId".into(),
                team_id.map_or(crate::utils::json::JsValue::Null, |value| {
                    crate::utils::json::JsValue::String(value.to_owned())
                }),
            );
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
            _ = fields.insert(
                "activeOrganizationId".into(),
                organization_id.map_or(crate::utils::json::JsValue::Null, |value| {
                    crate::utils::json::JsValue::String(value.to_owned())
                }),
            );
            return self.update_ephemeral_scope(token, fields).await;
        }
        if self.record_store.secondary().is_some()
            && (!self.record_store.session_uses_database()
                || self.record_store.cached_session(token).await?.is_some())
        {
            let mut fields = crate::field_policy::FieldValues::new();
            _ = fields.insert(
                "activeOrganizationId".into(),
                organization_id.map_or(crate::utils::json::JsValue::Null, |value| {
                    crate::utils::json::JsValue::String(value.to_owned())
                }),
            );
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
        let pending_scopes = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let scopes_in_transaction = Arc::clone(&pending_scopes);
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
                        pending_scopes: scopes_in_transaction,
                        session_fields,
                        adapter_fields,
                        record_store,
                        pending_records: records_in_transaction,
                    };
                    work(&transaction).await
                })
            }))
            .await?;
        // Publish scope updates only after adapter success. Concurrent logout wins.
        {
            let scopes = std::mem::take(
                &mut *pending_scopes
                    .lock()
                    .map_err(|_| AuthError::internal("Ephemeral scope queue poisoned"))?,
            );
            let mut sessions = self
                .ephemeral_sessions
                .lock()
                .map_err(|_| AuthError::internal("Ephemeral session state poisoned"))?;
            for (token, session) in scopes {
                if let Some(destination) = sessions.get_mut(&token) {
                    *destination = session;
                }
            }
        }
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
