use crate::field_policy::FieldValues;
use crate::store::{AdapterEvent, PluginStore, SessionRevocation, SessionStore};
use crate::{AdapterOutput, AdapterRecord};
use crate::{AuthError, AuthResult, AuthSchema, AuthSession, CreateSession};
use async_trait::async_trait;
use chrono::SubsecRound;

struct CacheRevocation<'a, S: AuthSchema> {
    store: &'a PluginStore<S>,
    user_id: &'a str,
    tokens: Vec<String>,
}

#[async_trait]
impl<S: AuthSchema> crate::store::SessionRevocation for CacheRevocation<'_, S> {
    async fn revoke(&self) -> AuthResult<()> {
        self.store
            .cached_user_revocation(self.user_id, self.tokens.clone())
            .await?
            .revoke()
            .await
    }
}
#[async_trait]
impl<S: AuthSchema> SessionStore<S> for PluginStore<S> {
    async fn get_session_user_record(
        &self,
        token: &str,
    ) -> AuthResult<Option<AdapterRecord<S::User>>> {
        if !self.config.session.stateless && self.secondary().is_some() {
            let Some((_, user)) = self.cached_session_record(token).await? else {
                return Ok(None);
            };
            let crate::utils::json::JsValue::Object(values) = crate::utils::json::to_js_value(
                &self.projection_context.trusted_user_view(&user)?,
            )?
            else {
                return Err(AuthError::internal("User output must be an object"));
            };
            let mut output = user.raw_snapshot().clone();
            output.extend(AdapterOutput::from_js_values(values));
            for field in ["createdAt", "updatedAt"] {
                output.insert(
                    field.into(),
                    Some(revive_cached_user_date(
                        user.raw_snapshot().values().get(field),
                    )),
                );
            }
            return Ok(Some(self.projection_context.filter_user_record(
                AdapterRecord::with_output(user.into_stored(), output),
            )));
        }
        let Some(user) = self.get_session_user(token).await? else {
            return Ok(None);
        };
        Ok(Some(self.user_record(user).await?))
    }
    async fn create_session_record(
        &self,
        create_session: CreateSession,
    ) -> AuthResult<AdapterRecord<S::Session>> {
        let record = self.create_projected_session(create_session).await?;
        self.observe(AdapterEvent::SessionCreated(record.clone()))
            .await?;
        Ok(record)
    }

    async fn get_session_record(
        &self,
        token: &str,
    ) -> AuthResult<Option<AdapterRecord<S::Session>>> {
        if !self.config.session.stateless
            && let Some(cache) = self.secondary()
        {
            if let Some((session, _)) = self.cached_session_record(token).await? {
                let mut output = self.secondary_session_output(token).await?;
                for (name, date) in [
                    ("expiresAt", session.expires_at()),
                    ("createdAt", session.created_at()),
                    ("updatedAt", session.updated_at()),
                ] {
                    output.insert(
                        name.into(),
                        Some(crate::utils::json::JsValue::String(
                            crate::utils::datetime::json_date_millis(date.timestamp_millis())
                                .into(),
                        )),
                    );
                }
                let registered = self
                    .projection_context
                    .extensions
                    .get::<crate::field_policy::SessionFields>();
                let fields = registered
                    .as_ref()
                    .map_or(&self.config.session.additional_fields, |fields| &fields.0);
                for name in fields.keys() {
                    if !output.contains_field(name) {
                        output.insert(name.clone(), None);
                    }
                }
                output = output.filter_returned(fields);
                return Ok(Some(AdapterRecord::with_output(session, output)));
            }
            if !self.database_session_fallback() || cache.get(token).await?.is_some() {
                return Ok(None);
            }
        }
        let Some(model) = self.get_session(token).await? else {
            return Ok(None);
        };
        let record = self.session_record(model).await?;
        Ok(Some(record))
    }

    async fn get_sessions_by_tokens_record(
        &self,
        tokens: &[String],
    ) -> AuthResult<Vec<AdapterRecord<S::Session>>> {
        if !self.config.session.stateless && self.secondary().is_some() {
            let mut records = std::collections::HashMap::new();
            let mut missing = Vec::new();
            let mut unique = Vec::new();
            for token in tokens {
                if unique.contains(token) {
                    continue;
                }
                unique.push(token.clone());
                if let Some(record) = self.cached_collection_session(token, false, true).await? {
                    _ = records.insert(token.clone(), record);
                } else if let Some(cache) = self.secondary()
                    && cache.get(token).await?.is_none()
                {
                    missing.push(token.clone());
                }
            }
            if self.database_session_fallback() && !missing.is_empty() {
                for model in self.inner.get_sessions_by_tokens(&missing).await? {
                    let record = self.session_record(model).await?;
                    _ = records.insert(record.token().to_owned(), record);
                }
            }
            return Ok(unique
                .into_iter()
                .filter_map(|token| records.remove(&token))
                .collect());
        }
        self.session_records(self.get_sessions_by_tokens(tokens).await?)
            .await
    }

    async fn get_user_sessions_record(
        &self,
        user_id: &str,
    ) -> AuthResult<Vec<AdapterRecord<S::Session>>> {
        if !self.config.session.stateless
            && self.secondary().is_some()
            && !self.database_session_fallback()
        {
            return self.cached_user_session_records(user_id).await;
        }
        self.session_records(self.get_user_sessions(user_id).await?)
            .await
    }

    async fn get_active_user_sessions_record(
        &self,
        user_id: &str,
    ) -> AuthResult<Vec<AdapterRecord<S::Session>>> {
        if !self.config.session.stateless
            && self.secondary().is_some()
            && !self.database_session_fallback()
        {
            return self.cached_user_session_records(user_id).await;
        }
        let now = chrono::Utc::now();
        Ok(self
            .get_user_sessions_record(user_id)
            .await?
            .into_iter()
            .filter(|session| session.expires_at() > now)
            .collect())
    }

    async fn refresh_session_record(
        &self,
        token: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<Option<AdapterRecord<S::Session>>> {
        let Some(model) = self.refresh_session(token, expires_at).await? else {
            return Ok(None);
        };
        let record = self.session_write_record(token, model).await?;
        self.observe(AdapterEvent::SessionUpdated(record.clone()))
            .await?;
        Ok(Some(record))
    }

    async fn update_session_fields_record(
        &self,
        token: &str,
        fields: FieldValues,
    ) -> AuthResult<Option<AdapterRecord<S::Session>>> {
        let Some(model) = self.update_session_fields(token, fields).await? else {
            return Ok(None);
        };
        let record = self.session_write_record(token, model).await?;
        self.observe(AdapterEvent::SessionUpdated(record.clone()))
            .await?;
        Ok(Some(record))
    }

    async fn update_session_active_organization_record(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<AdapterRecord<S::Session>> {
        let record = self
            .session_write_record(
                token,
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
    ) -> AuthResult<AdapterRecord<S::Session>> {
        let record = self
            .session_write_record(
                token,
                self.update_session_active_team(token, team_id).await?,
            )
            .await?;
        self.observe(AdapterEvent::SessionUpdated(record.clone()))
            .await?;
        Ok(record)
    }

    async fn update_session_fields(
        &self,
        token: &str,
        mut fields: FieldValues,
    ) -> AuthResult<Option<S::Session>> {
        if self.session_uses_database() {
            self.adapter_fields.attach(&mut fields, false);
        }
        if self.config.session.stateless {
            return self.update_ephemeral_session(token, None, fields).await;
        }
        if self.secondary().is_some() {
            return self.update_secondary_session(token, None, fields).await;
        }
        self.inner.update_session_fields(token, fields).await
    }
    async fn create_session(&self, create_session: CreateSession) -> AuthResult<S::Session> {
        Ok(self
            .create_projected_session(create_session)
            .await?
            .into_stored())
    }
    async fn get_session_by_id(&self, id: &str) -> AuthResult<Option<S::Session>> {
        self.inner.get_session_by_id(id).await
    }
    async fn get_session(&self, token: &str) -> AuthResult<Option<S::Session>> {
        if self.config.session.stateless {
            return Ok(self.ephemeral()?.get(token).cloned());
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
            let sessions = self.ephemeral()?;
            return Ok(sessions
                .values()
                .filter(|session| tokens.iter().any(|token| token == session.token()))
                .cloned()
                .collect());
        }
        if self.secondary().is_some() {
            return Ok(self
                .get_sessions_by_tokens_record(tokens)
                .await?
                .into_iter()
                .map(AdapterRecord::into_stored)
                .collect());
        }
        self.inner.get_sessions_by_tokens(tokens).await
    }
    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<S::Session>> {
        if self.config.session.stateless {
            return Ok(self
                .ephemeral()?
                .values()
                .filter(|session| session.user_id().as_ref() == user_id)
                .cloned()
                .collect());
        }
        if self.database_session_fallback() {
            // Since 1.7.12 the database lists every live session, including
            // one whose cached copy failed to write.
            let now = chrono::Utc::now();
            return Ok(self
                .inner
                .get_user_sessions(user_id)
                .await?
                .into_iter()
                .filter(|session| session.expires_at() > now)
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
        mut fields: FieldValues,
    ) -> AuthResult<Option<S::Session>> {
        if self.session_uses_database() {
            self.adapter_fields.attach(&mut fields, false);
        }
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
            _ = self.ephemeral()?.shift_remove(token);
            return Ok(());
        }
        let works = if self
            .projection_context
            .extensions
            .get::<crate::store::SessionDeletionHooks<S>>()
            .is_some_and(|hooks| !hooks.0.is_empty())
            && let Some(session) = self.inner.get_session(token).await?
            && (!(self.secondary().is_some() && self.config.session.preserve_in_database)
                || session.expires_at() > chrono::Utc::now())
        {
            self.prepare_session_deletion(&session).await?
        } else {
            Vec::new()
        };
        self.remove_cached_session(token).await?;
        if !self.session_uses_database() {
            return Ok(());
        }
        if self.secondary().is_some() && self.config.session.preserve_in_database {
            if !self.inner.end_session_preserving(token).await? {
                return Ok(());
            }
        } else {
            self.inner.delete_session(token).await?;
        }
        self.complete_session_deletion(token, works).await
    }
    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
        if self.config.session.stateless {
            self.ephemeral()?
                .retain(|_, session| session.user_id().as_ref() != user_id);
            return Ok(());
        }
        _ = self.get_user_sessions_record(user_id).await;
        let tokens = self.cached_user_tokens(user_id).await?;
        let revocation = CacheRevocation {
            store: self,
            user_id,
            tokens,
        };
        if self.session_uses_database() {
            if self.secondary().is_some() && self.config.session.preserve_in_database {
                // Retained audit rows are not a new session end. Capture only
                // live rows, and leave the cache intact if the bulk was vetoed.
                let now = chrono::Utc::now();
                let mut pending = Vec::new();
                for session in self.inner.get_user_sessions(user_id).await? {
                    if session.expires_at() > now {
                        let works = self.prepare_session_deletion(&session).await?;
                        pending.push((session.token().to_owned(), works));
                    }
                }
                if !self
                    .inner
                    .end_user_sessions_preserving_with_revocation(user_id, Some(&revocation))
                    .await?
                {
                    return Ok(());
                }
                for (token, works) in pending {
                    self.complete_session_deletion(&token, works).await?;
                }
            } else {
                // Capture dependants while every physical session FK still exists.
                // Adapter hooks may veto individual rows, so completion below must
                // check each selected token rather than assume the bulk consumed it.
                let mut pending = Vec::new();
                if self
                    .projection_context
                    .extensions
                    .get::<crate::store::SessionDeletionHooks<S>>()
                    .is_some_and(|hooks| !hooks.0.is_empty())
                {
                    for session in self.inner.get_user_sessions(user_id).await? {
                        let works = self.prepare_session_deletion(&session).await?;
                        pending.push((session.token().to_owned(), works));
                    }
                }
                self.inner
                    .delete_user_sessions_with_revocation(user_id, Some(&revocation))
                    .await?;
                for (token, works) in pending {
                    self.complete_session_deletion(&token, works).await?;
                }
            }
        }
        if !self.session_uses_database() {
            revocation.revoke().await?;
        }
        Ok(())
    }
    async fn delete_expired_sessions(&self) -> AuthResult<usize> {
        if self.config.session.stateless {
            let mut sessions = self.ephemeral()?;
            let before = sessions.len();
            sessions.retain(|_, session| session.expires_at() >= chrono::Utc::now());
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
            return self
                .update_session_scope(token, "activeOrganizationId", organization_id)
                .await;
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
            return self
                .update_session_scope(token, "activeTeamId", team_id)
                .await;
        }
        self.inner.update_session_active_team(token, team_id).await
    }
}

impl<S: AuthSchema> PluginStore<S> {
    async fn create_projected_session(
        &self,
        mut create_session: CreateSession,
    ) -> AuthResult<AdapterRecord<S::Session>> {
        let created_at = chrono::Utc::now().trunc_subsecs(3);
        for callback in &self.session_callbacks.callbacks {
            callback
                .before_create(&create_session, &self.projection_context, None)
                .await?;
        }
        self.session_fields
            .defaults(&mut create_session.additional_fields);
        let created_at = match create_session.additional_fields.get("createdAt") {
            Some(crate::utils::json::JsValue::Date(date)) => *date,
            _ => created_at,
        };
        if self.session_uses_database() {
            self.adapter_fields
                .attach(&mut create_session.additional_fields, true);
        }
        let creation_fields = create_session.additional_fields.clone();
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
        let record = self.session_creation_record(session).await?;
        let session = record.stored();
        self.remember_ephemeral_session(session)?;
        self.mirror_created_session(session, created_at, &creation_fields, record.raw_snapshot())
            .await?;
        if self.secondary().is_some() || self.config.session.stateless {
            self.inner
                .complete_secondary_session_creation(session)
                .await?;
        }
        for callback in &self.session_callbacks.callbacks {
            callback.after_create(session, self).await?;
        }
        Ok(record)
    }
    pub(in crate::store) async fn session_write_record(
        &self,
        token: &str,
        session: S::Session,
    ) -> AuthResult<AdapterRecord<S::Session>> {
        if self.session_uses_database() {
            return self.session_record(session).await;
        }
        let record = if self.secondary().is_some() {
            AdapterRecord::with_output(session, self.secondary_session_output(token).await?)
        } else {
            self.session_creation_record(session).await?
        };
        let registered = self
            .projection_context
            .extensions
            .get::<crate::field_policy::SessionFields>();
        let fields = registered
            .as_ref()
            .map_or(&self.config.session.additional_fields, |fields| &fields.0);
        let output = record.raw_snapshot().filter_returned(fields);
        Ok(AdapterRecord::with_output(record.into_stored(), output))
    }

    pub(in crate::store) async fn session_creation_record(
        &self,
        session: S::Session,
    ) -> AuthResult<AdapterRecord<S::Session>> {
        if self.session_uses_database() {
            return self.session_record(session).await;
        }
        let crate::utils::json::JsValue::Object(mut values) = crate::utils::json::to_js_value(
            &self.projection_context.trusted_session_view(&session)?,
        )?
        else {
            return Err(AuthError::internal("Session output must be an object"));
        };
        for name in self.secondary_absent_fields(session.token()).await? {
            _ = values.shift_remove(&name);
        }
        Ok(AdapterRecord::with_output(
            session,
            AdapterOutput::from_js_values(values),
        ))
    }

    async fn prepare_session_deletion(
        &self,
        session: &S::Session,
    ) -> AuthResult<Vec<Box<dyn crate::store::SessionDeletionWork<S>>>> {
        let mut works = Vec::new();
        if let Some(hooks) = self
            .projection_context
            .extensions
            .get::<crate::store::SessionDeletionHooks<S>>()
        {
            for hook in &hooks.0 {
                if let Some(work) = hook.prepare(session, &self.projection_context).await? {
                    works.push(work);
                }
            }
        }
        Ok(works)
    }
    async fn complete_session_deletion(
        &self,
        token: &str,
        works: Vec<Box<dyn crate::store::SessionDeletionWork<S>>>,
    ) -> AuthResult<()> {
        let preserved = self.secondary().is_some() && self.config.session.preserve_in_database;
        if !works.is_empty()
            && self
                .inner
                .get_session(token)
                .await?
                .is_none_or(|session| preserved && session.expires_at() <= chrono::Utc::now())
        {
            for work in works {
                work.complete(&self.projection_context).await?;
            }
        }
        Ok(())
    }
}

fn revive_cached_user_date(
    value: Option<&crate::utils::json::JsValue>,
) -> crate::utils::json::JsValue {
    use crate::utils::json::JsValue as Value;
    if let Some(Value::Date(date)) = value {
        return Value::Date(*date);
    }
    let millis = match value {
        Some(Value::Null) => Some(0),
        Some(Value::Bool(value)) => Some(i64::from(*value)),
        Some(Value::Number(value)) => Some(*value)
            .filter(|value| value.abs() <= 8_640_000_000_000_000.0)
            .map(|value| value.trunc() as i64),
        Some(Value::String(value)) => value
            .as_str()
            .and_then(crate::utils::datetime::parse_date_millis),
        Some(Value::Array(_)) => value
            .and_then(|value| {
                crate::utils::json::JsValue::from(value.clone())
                    .coerce_string()
                    .ok()
            })
            .and_then(|value| crate::utils::datetime::parse_date_millis(&value)),
        _ => None,
    };
    millis
        .map(|millis| Value::String(crate::utils::datetime::json_date_millis(millis).into()))
        .unwrap_or(Value::Null)
}
