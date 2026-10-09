use crate::AdapterRecord;
use crate::field_policy::FieldValues;
use crate::store::{AdapterEvent, PluginStore, SessionStore};
use crate::{AuthError, AuthResult, AuthSchema, AuthSession, CreateSession};
use async_trait::async_trait;
#[async_trait]
impl<S: AuthSchema> SessionStore<S> for PluginStore<S> {
    async fn get_session_user_record(
        &self,
        token: &str,
    ) -> AuthResult<Option<AdapterRecord<S::User>>> {
        let Some(user) = self.get_session_user(token).await? else {
            return Ok(None);
        };
        Ok(Some(self.user_record(user).await?))
    }
    async fn create_session_record(
        &self,
        create_session: CreateSession,
    ) -> AuthResult<AdapterRecord<S::Session>> {
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
    ) -> AuthResult<Option<AdapterRecord<S::Session>>> {
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
        let mut records = Vec::new();
        for model in self.get_sessions_by_tokens(tokens).await? {
            records.push(self.session_record(model).await?);
        }
        Ok(records)
    }

    async fn get_user_sessions_record(
        &self,
        user_id: &str,
    ) -> AuthResult<Vec<AdapterRecord<S::Session>>> {
        self.session_records(self.get_user_sessions(user_id).await?)
            .await
    }

    async fn get_active_user_sessions_record(
        &self,
        user_id: &str,
    ) -> AuthResult<Vec<AdapterRecord<S::Session>>> {
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
    ) -> AuthResult<Option<AdapterRecord<S::Session>>> {
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
        fields: FieldValues,
    ) -> AuthResult<Option<AdapterRecord<S::Session>>> {
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
    ) -> AuthResult<AdapterRecord<S::Session>> {
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
    ) -> AuthResult<AdapterRecord<S::Session>> {
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
        mut fields: FieldValues,
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
                .ephemeral()?
                .values()
                .filter(|session| session.user_id().as_ref() == user_id)
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
        mut fields: FieldValues,
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
            _ = self.ephemeral()?.shift_remove(token);
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
            self.ephemeral()?
                .retain(|_, session| session.user_id().as_ref() != user_id);
            return Ok(());
        }
        _ = self.get_user_sessions_record(user_id).await;
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
