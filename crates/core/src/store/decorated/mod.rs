use crate::AdapterRecord;
use crate::store::{
    AdapterAfterHook, AdapterEvent, SessionCreatedHook, UserCreateTransform, UserCreationDefaults,
};
use crate::{AuthAccount, AuthSession, AuthUser};
use crate::{AuthError, AuthResult, AuthSchema, AuthStore, UpdateUser};
use std::sync::Arc;
mod account;
mod extensions;
mod session;
mod transaction;
mod user;
mod verification;

pub(crate) type UserUpdateTransform =
    Arc<dyn Fn(&str, UpdateUser) -> AuthResult<UpdateUser> + Send + Sync>;

#[derive(Clone, Default)]
pub(crate) struct UserTransforms {
    pub(crate) creates: Vec<UserCreateTransform>,
    pub(crate) adapter_defaults: UserCreationDefaults,
    pub(crate) updates: Vec<UserUpdateTransform>,
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
    pub(in crate::store) ephemeral_sessions:
        Arc<std::sync::Mutex<indexmap::IndexMap<String, S::Session>>>,
    pub(in crate::store) inner: Arc<dyn AuthStore<S>>,
    pub(in crate::store) config: Arc<crate::AuthConfig>,
    pub(in crate::store) transforms: UserTransforms,
    pub(in crate::store) session_callbacks: SessionCreatedCallbacks<S>,
    pub(in crate::store) session_fields: crate::field_policy::SessionFields,
    pub(in crate::store) adapter_fields: crate::field_policy::SessionAdapterFields,
    pub(in crate::store) projection_context: Arc<crate::AuthContext<S>>,
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

    pub(in crate::store) fn ephemeral(
        &self,
    ) -> AuthResult<std::sync::MutexGuard<'_, indexmap::IndexMap<String, S::Session>>> {
        self.ephemeral_sessions
            .lock()
            .map_err(|_| AuthError::internal("Ephemeral session state poisoned"))
    }

    pub(in crate::store) fn field_policies(&self) -> crate::field_policy::AdapterFieldPolicies {
        self.projection_context
            .extensions
            .get::<crate::field_policy::AdapterFieldPolicies>()
            .map_or_else(
                || crate::field_policy::AdapterFieldPolicies {
                    user: crate::field_policy::SessionAdapterFields(Arc::new(
                        self.config.user.additional_fields.clone(),
                    )),
                    account: crate::field_policy::SessionAdapterFields(Arc::new(
                        self.config.account.additional_fields.clone(),
                    )),
                },
                |fields| (*fields).clone(),
            )
    }

    pub(in crate::store) async fn user_record(
        &self,
        user: S::User,
    ) -> AuthResult<AdapterRecord<S::User>> {
        let verification = self.inner.provider_verification_output(&user.id()).await?;
        let mut record = self.projection_context.user_adapter_record(user).await?;
        if let Some(value) = verification {
            record.retain_provider_verification(value);
        }
        Ok(record)
    }

    pub(in crate::store) async fn optional_user_record(
        &self,
        user: Option<S::User>,
    ) -> AuthResult<Option<AdapterRecord<S::User>>> {
        match user {
            Some(user) => self.user_record(user).await.map(Some),
            None => Ok(None),
        }
    }

    pub(in crate::store) async fn user_records(
        &self,
        users: Vec<S::User>,
    ) -> AuthResult<Vec<AdapterRecord<S::User>>> {
        let mut records = Vec::with_capacity(users.len());
        for user in users {
            records.push(self.user_record(user).await?);
        }
        Ok(records)
    }

    pub(in crate::store) async fn optional_account_record(
        &self,
        account: Option<S::Account>,
    ) -> AuthResult<Option<AdapterRecord<S::Account>>> {
        match account {
            Some(account) => self.account_record(account).await.map(Some),
            None => Ok(None),
        }
    }

    pub(in crate::store) async fn session_record(
        &self,
        session: S::Session,
    ) -> AuthResult<AdapterRecord<S::Session>> {
        let absent = self.secondary_absent_fields(session.token()).await?;
        let mut public = serde_json::to_value(crate::SessionView::from(&session))?;
        let mut physical =
            serde_json::to_value(self.projection_context.trusted_session_view(&session))?;
        let mut additional = session.additional_fields();
        for name in absent {
            if let Some(object) = public.as_object_mut() {
                _ = object.remove(&name);
            }
            if let Some(object) = physical.as_object_mut() {
                _ = object.remove(&name);
            }
            _ = additional.remove(&name);
        }
        let output = self
            .adapter_fields
            .record_output(public, additional, physical)
            .await?;
        Ok(AdapterRecord::with_output(session, output))
    }

    pub(in crate::store) async fn session_records(
        &self,
        models: Vec<S::Session>,
    ) -> AuthResult<Vec<AdapterRecord<S::Session>>> {
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
        _ = tokio::spawn(async move {
            let project = async {
                _ = futures_util::future::join_all(models.into_iter().enumerate().map(
                    |(index, model)| {
                        let sender = &sender;
                        let store = &store;
                        async move {
                            let result = store.session_record(model).await;
                            _ = sender.send((index, result));
                        }
                    },
                ))
                .await;
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
        });
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

    pub(in crate::store) async fn account_record(
        &self,
        account: S::Account,
    ) -> AuthResult<AdapterRecord<S::Account>> {
        let serde_json::Value::Object(mut canonical) =
            serde_json::to_value(crate::AccountView::from(&account))?
        else {
            return Err(AuthError::internal("Account output must be an object"));
        };
        _ = canonical.insert(
            "password".into(),
            account.password().map_or(serde_json::Value::Null, |value| {
                serde_json::Value::String(value.into())
            }),
        );
        let output = self
            .field_policies()
            .account
            .record_output(
                serde_json::Value::Object(canonical.clone()),
                account.additional_fields(),
                serde_json::Value::Object(canonical),
            )
            .await?;
        Ok(AdapterRecord::with_output(account, output))
    }

    pub(in crate::store) async fn observe(&self, event: AdapterEvent<S>) -> AuthResult<()> {
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
