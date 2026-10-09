use crate::store::SessionStore;
use crate::store::stateless::{StatelessSchema, StatelessStore};
use crate::{AuthError, AuthResult, CreateSession, SessionView};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
#[async_trait]
impl SessionStore<StatelessSchema> for StatelessStore {
    async fn prepare_secondary_session_creation(
        &self,
        input: CreateSession,
        persist: bool,
    ) -> AuthResult<SessionView> {
        if persist {
            return Err(AuthError::config("StatelessStore cannot persist sessions"));
        }
        SessionStore::<StatelessSchema>::create_session(self, input).await
    }
    async fn complete_secondary_session_creation(&self, _session: &SessionView) -> AuthResult<()> {
        Ok(())
    }
    async fn create_session(&self, mut input: CreateSession) -> AuthResult<SessionView> {
        input
            .additional_fields
            .apply_adapter_transforms_async()
            .await?;
        let now = Utc::now();
        Ok(SessionView {
            id: uuid::Uuid::new_v4().to_string(),
            token: input
                .token
                .unwrap_or_else(crate::utils::sessions::generate_session_token),
            user_id: input.user_id,
            expires_at: input.expires_at,
            created_at: now,
            updated_at: now,
            ip_address: input.ip_address.or_else(|| Some(String::new())),
            user_agent: input.user_agent.or_else(|| Some(String::new())),
            active_organization_id: input.active_organization_id,
            active_team_id: input.active_team_id,
            impersonated_by: input.impersonated_by,
            extension_fields: input
                .additional_fields
                .into_iter()
                .map(|(key, value)| value.to_json_value().map(|value| (key, value)))
                .collect::<Result<_, _>>()?,
            active: true,
            omitted_fields: std::collections::BTreeSet::default(),
        })
    }
    async fn prepare_secondary_session_update(
        &self,
        mut session: SessionView,
        expires_at: Option<DateTime<Utc>>,
        mut fields: crate::field_policy::FieldValues,
    ) -> AuthResult<Option<(SessionView, crate::field_policy::FieldValues)>> {
        fields.apply_adapter_transforms_async().await?;
        for (key, value) in &fields {
            match key.as_str() {
                "activeOrganizationId" => {
                    session.active_organization_id = value.as_str().map(str::to_owned);
                }
                "activeTeamId" => session.active_team_id = value.as_str().map(str::to_owned),
                "impersonatedBy" => session.impersonated_by = value.as_str().map(str::to_owned),
                _ => {
                    _ = session
                        .extension_fields
                        .insert(key.clone(), value.to_json_value()?);
                }
            }
        }
        if let Some(expires_at) = expires_at {
            session.expires_at = expires_at;
        }
        session.updated_at = Utc::now();
        Ok(Some((session, fields)))
    }
    async fn complete_secondary_session_update(
        &self,
        session: SessionView,
        _expires_at: Option<DateTime<Utc>>,
        _fields: crate::field_policy::FieldValues,
        persist: bool,
    ) -> AuthResult<Option<SessionView>> {
        if persist {
            return Err(AuthError::config(
                "No-database store cannot persist sessions",
            ));
        }
        Ok(Some(session))
    }
    async fn get_session(&self, _token: &str) -> AuthResult<Option<SessionView>> {
        Ok(None)
    }
    async fn get_user_sessions(&self, _user: &str) -> AuthResult<Vec<SessionView>> {
        Ok(Vec::new())
    }
    async fn update_session_expiry(
        &self,
        _token: &str,
        _expires: chrono::DateTime<Utc>,
    ) -> AuthResult<()> {
        Err(AuthError::SessionNotFound)
    }
    async fn update_session_active_organization(
        &self,
        _token: &str,
        _id: Option<&str>,
    ) -> AuthResult<SessionView> {
        Err(AuthError::SessionNotFound)
    }
    async fn delete_session(&self, _token: &str) -> AuthResult<()> {
        Ok(())
    }
    async fn delete_user_sessions(&self, _user: &str) -> AuthResult<()> {
        Ok(())
    }
    async fn delete_expired_sessions(&self) -> AuthResult<usize> {
        Ok(0)
    }
}
