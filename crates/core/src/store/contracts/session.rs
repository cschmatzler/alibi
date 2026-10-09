use crate::field_policy::FieldValues;
use crate::{AdapterRecord, AuthSession};
use crate::{AuthError, AuthResult, AuthSchema, CreateSession};
use async_trait::async_trait;
use std::collections::BTreeSet;
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
        _fields: FieldValues,
    ) -> AuthResult<Option<(S::Session, FieldValues)>> {
        Err(AuthError::NotImplemented(
            "Secondary session updates are unsupported".into(),
        ))
    }
    /// Publish the staged physical update and run after hooks exactly once.
    async fn complete_secondary_session_update(
        &self,
        _session: S::Session,
        _expires_at: Option<chrono::DateTime<chrono::Utc>>,
        _fields: FieldValues,
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
    ) -> AuthResult<Option<AdapterRecord<S::User>>> {
        self.get_session_user(token)
            .await?
            .map(AdapterRecord::physical)
            .transpose()
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
    async fn get_session_record(
        &self,
        token: &str,
    ) -> AuthResult<Option<AdapterRecord<S::Session>>> {
        self.get_session(token)
            .await?
            .map(AdapterRecord::physical)
            .transpose()
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn get_sessions_by_tokens_record(
        &self,
        tokens: &[String],
    ) -> AuthResult<Vec<AdapterRecord<S::Session>>> {
        self.get_sessions_by_tokens(tokens)
            .await?
            .into_iter()
            .map(AdapterRecord::physical)
            .collect()
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn get_user_sessions_record(
        &self,
        user_id: &str,
    ) -> AuthResult<Vec<AdapterRecord<S::Session>>> {
        self.get_user_sessions(user_id)
            .await?
            .into_iter()
            .map(AdapterRecord::physical)
            .collect()
    }

    /// Return active physical sessions after declared output transforms. Expiry
    /// selection runs before application callbacks, without trusting output fields.
    async fn get_active_user_sessions_record(
        &self,
        user_id: &str,
    ) -> AuthResult<Vec<AdapterRecord<S::Session>>> {
        let now = chrono::Utc::now();
        self.get_user_sessions(user_id)
            .await?
            .into_iter()
            .filter(|session| session.expires_at() > now && session.active())
            .map(AdapterRecord::physical)
            .collect()
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn refresh_session_record(
        &self,
        token: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<Option<AdapterRecord<S::Session>>> {
        self.refresh_session(token, expires_at)
            .await?
            .map(AdapterRecord::physical)
            .transpose()
    }

    /// Return a retained adapter record. The default is the physical model's
    /// serialized snapshot; initialized stores apply their declared output policy.
    async fn update_session_fields_record(
        &self,
        token: &str,
        fields: FieldValues,
    ) -> AuthResult<Option<AdapterRecord<S::Session>>> {
        self.update_session_fields(token, fields)
            .await?
            .map(AdapterRecord::physical)
            .transpose()
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

    /// Persist already authorized fields for the currently authenticated token.
    async fn update_session_fields(
        &self,
        _token: &str,
        _fields: FieldValues,
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
        mut fields: FieldValues,
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
