#[cfg(test)]
mod tests;

use super::{SeaOrmStore, cancelled_by_hook, map_db_err};
use crate::schema::{AuthSchema, SeaOrmSessionModel};
use async_trait::async_trait;
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::store::SessionStore;
use better_auth_core::types::CreateSession;
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait, ExprTrait,
    IntoActiveModel, QueryFilter, QueryOrder, QuerySelect,
};

impl<S> SeaOrmStore<S>
where
    S: AuthSchema,
    S::Session: SeaOrmSessionModel,
{
    fn normalize_session_client_field(value: Option<String>) -> Option<String> {
        value.map_or_else(|| Some(String::new()), Some)
    }

    async fn create_session_with_connection<C>(
        &self,
        db: &C,
        tx: Option<&DatabaseTransaction>,
        mut create_session: CreateSession,
    ) -> AuthResult<S::Session>
    where
        C: ConnectionTrait,
    {
        if create_session.token.is_none() {
            create_session.token =
                Some(better_auth_core::utils::sessions::generate_session_token());
        }
        let hook_context = self.hook_context(tx);
        for hook in self.hooks() {
            if hook
                .before_create_session(&mut create_session, &hook_context)
                .await?
                .is_cancelled()
            {
                return Err(AuthError::SessionCreationCancelled);
            }
        }
        let now = Utc::now();
        create_session.ip_address = Self::normalize_session_client_field(create_session.ip_address);
        create_session.user_agent = Self::normalize_session_client_field(create_session.user_agent);
        let token = create_session
            .token
            .take()
            .unwrap_or_else(better_auth_core::utils::sessions::generate_session_token);
        let mut fields = std::mem::take(&mut create_session.additional_fields);
        for (name, value) in [
            (
                "activeOrganizationId",
                create_session.active_organization_id.as_ref(),
            ),
            ("activeTeamId", create_session.active_team_id.as_ref()),
            ("impersonatedBy", create_session.impersonated_by.as_ref()),
        ] {
            if let Some(value) = value {
                fields.preserve_creation_value(
                    name,
                    better_auth_core::utils::json::JsValue::String(value.clone()),
                );
            }
        }
        fields.apply_adapter_transforms_async().await?;
        let mut active = S::Session::new_active(None, token, create_session, now);
        if !fields.is_empty() {
            for (column, value) in
                S::Session::additional_field_bindings(&fields, db.get_database_backend())?
            {
                let value = crate::session_fields::prepare_value(db, &column, value).await?;
                S::Session::set_additional_field(
                    &mut active,
                    column,
                    value,
                    db.get_database_backend(),
                )?;
            }
        }
        let session = active.insert(db).await.map_err(map_db_err)?;
        if tx.is_none() {
            for hook in self.hooks() {
                hook.after_create_session(&session, &hook_context).await?;
            }
        }
        Ok(session)
    }

    pub(crate) async fn create_session_in_tx(
        &self,
        tx: &DatabaseTransaction,
        create_session: CreateSession,
    ) -> AuthResult<S::Session> {
        self.create_session_with_connection(tx, Some(tx), create_session)
            .await
    }
}

pub(super) enum SessionScope<'a> {
    Team(Option<&'a str>),
    Organization(Option<&'a str>),
}

impl<S> SeaOrmStore<S>
where
    S: AuthSchema,
    S::Session: SeaOrmSessionModel,
{
    async fn update_session_with_fields(
        &self,
        token: &str,
        expires_at: Option<DateTime<Utc>>,
        mut fields: better_auth_core::field_policy::FieldValues,
    ) -> AuthResult<Option<S::Session>> {
        let hook_context = self.hook_context(None);
        for hook in self.hooks() {
            if hook
                .before_update_session(token, &mut fields, &hook_context)
                .await?
                .is_cancelled()
            {
                return Ok(None);
            }
        }
        let mut query = <S::Session as SeaOrmSessionModel>::Entity::find()
            .filter(S::Session::token_column().eq(token));
        if expires_at.is_some() {
            query = query.filter(S::Session::active_column().eq(true));
        }
        let Some(model) = query.one(self.connection()).await.map_err(map_db_err)? else {
            return Ok(None);
        };
        fields.apply_adapter_transforms_async().await?;
        let mut active = model.into_active_model();
        let backend = self.connection().get_database_backend();
        if !fields.is_empty() {
            for (column, value) in S::Session::additional_field_bindings(&fields, backend)? {
                let value =
                    crate::session_fields::prepare_value(self.connection(), &column, value).await?;
                S::Session::set_additional_field(&mut active, column, value, backend)?;
            }
        }
        if let Some(expires_at) = expires_at {
            S::Session::set_expires_at(&mut active, expires_at);
        }
        S::Session::set_updated_at(&mut active, Utc::now());
        let session = match active.update(self.connection()).await {
            Ok(session) => session,
            Err(sea_orm::DbErr::RecordNotUpdated) => return Ok(None),
            Err(error) => return Err(map_db_err(error)),
        };
        for hook in self.hooks() {
            hook.after_update_session(&session, &hook_context).await?;
        }
        Ok(Some(session))
    }

    pub(super) async fn update_session_scope_with_connection<C: ConnectionTrait>(
        &self,
        connection: &C,
        token: &str,
        scope: SessionScope<'_>,
    ) -> AuthResult<S::Session> {
        let model = <S::Session as SeaOrmSessionModel>::Entity::find()
            .filter(S::Session::token_column().eq(token))
            .filter(S::Session::active_column().eq(true))
            .one(connection)
            .await
            .map_err(map_db_err)?
            .ok_or(AuthError::SessionNotFound)?;
        let mut active = model.into_active_model();
        match scope {
            SessionScope::Team(team) => {
                S::Session::set_active_team_id(&mut active, team.map(str::to_owned))?;
            }
            SessionScope::Organization(organization) => {
                S::Session::set_active_organization_id(
                    &mut active,
                    organization.map(str::to_owned),
                );
            }
        }
        S::Session::set_updated_at(&mut active, Utc::now());
        active.update(connection).await.map_err(map_db_err)
    }
}

#[async_trait]
impl<S> SessionStore<S> for SeaOrmStore<S>
where
    S: AuthSchema + Send + Sync,
    S::Session: SeaOrmSessionModel,
{
    async fn create_session(&self, create_session: CreateSession) -> AuthResult<S::Session> {
        self.create_session_with_connection(self.connection(), None, create_session)
            .await
    }

    async fn get_session(&self, token: &str) -> AuthResult<Option<S::Session>> {
        <S::Session as SeaOrmSessionModel>::Entity::find()
            .filter(<S::Session as SeaOrmSessionModel>::token_column().eq(token))
            .filter(<S::Session as SeaOrmSessionModel>::active_column().eq(true))
            .one(self.connection())
            .await
            .map_err(map_db_err)
    }

    async fn get_sessions_by_tokens(&self, tokens: &[String]) -> AuthResult<Vec<S::Session>> {
        <S::Session as SeaOrmSessionModel>::Entity::find()
            .filter(
                <S::Session as SeaOrmSessionModel>::token_column().is_in(tokens.iter().cloned()),
            )
            .filter(<S::Session as SeaOrmSessionModel>::active_column().eq(true))
            .limit(self.config().advanced.database.default_find_many_limit as u64)
            .all(self.connection())
            .await
            .map_err(map_db_err)
    }

    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<S::Session>> {
        let user_id = <S::Session as SeaOrmSessionModel>::parse_user_id(user_id)?;
        <S::Session as SeaOrmSessionModel>::Entity::find()
            .filter(<S::Session as SeaOrmSessionModel>::user_id_column().eq(user_id))
            .filter(<S::Session as SeaOrmSessionModel>::active_column().eq(true))
            .order_by_asc(<S::Session as SeaOrmSessionModel>::created_at_column())
            .all(self.connection())
            .await
            .map_err(map_db_err)
    }

    async fn update_session_fields(
        &self,
        token: &str,
        fields: better_auth_core::field_policy::FieldValues,
    ) -> AuthResult<Option<S::Session>> {
        self.update_session_with_fields(token, None, fields).await
    }

    async fn update_session_expiry(
        &self,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<()> {
        self.refresh_session(token, expires_at)
            .await?
            .map(|_| ())
            .ok_or(AuthError::SessionNotFound)
    }

    async fn refresh_session(
        &self,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<Option<S::Session>> {
        self.update_session_with_fields(token, Some(expires_at), Default::default())
            .await
    }

    async fn refresh_session_with_fields(
        &self,
        token: &str,
        expires_at: DateTime<Utc>,
        fields: better_auth_core::field_policy::FieldValues,
    ) -> AuthResult<Option<S::Session>> {
        self.update_session_with_fields(token, Some(expires_at), fields)
            .await
    }

    async fn delete_session(&self, token: &str) -> AuthResult<()> {
        let session = self.get_session(token).await?;
        let hook_context = self.hook_context(None);
        if let Some(session) = &session {
            for hook in self.hooks() {
                if hook
                    .before_delete_session(session, &hook_context)
                    .await?
                    .is_cancelled()
                {
                    return Err(cancelled_by_hook("session deletion"));
                }
            }
        }
        let _ignored_map_err = <S::Session as SeaOrmSessionModel>::Entity::delete_many()
            .filter(<S::Session as SeaOrmSessionModel>::token_column().eq(token))
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;
        if let Some(session) = &session {
            for hook in self.hooks() {
                hook.after_delete_session(session, &hook_context).await?;
            }
        }
        Ok(())
    }

    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
        let user_id = <S::Session as SeaOrmSessionModel>::parse_user_id(user_id)?;
        <S::Session as SeaOrmSessionModel>::Entity::delete_many()
            .filter(<S::Session as SeaOrmSessionModel>::user_id_column().eq(user_id))
            .exec(self.connection())
            .await
            .map(|_| ())
            .map_err(map_db_err)
    }

    async fn delete_expired_sessions(&self) -> AuthResult<usize> {
        <S::Session as SeaOrmSessionModel>::Entity::delete_many()
            .filter(
                <S::Session as SeaOrmSessionModel>::expires_at_column()
                    .lt(Utc::now())
                    .or(<S::Session as SeaOrmSessionModel>::active_column().eq(false)),
            )
            .exec(self.connection())
            .await
            .map_err(map_db_err)
            .and_then(|result| {
                usize::try_from(result.rows_affected)
                    .map_err(|_error| AuthError::internal("Affected row count exceeds usize"))
            })
    }

    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<S::Session> {
        let Some(model) = <S::Session as SeaOrmSessionModel>::Entity::find()
            .filter(<S::Session as SeaOrmSessionModel>::token_column().eq(token))
            .filter(<S::Session as SeaOrmSessionModel>::active_column().eq(true))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(AuthError::SessionNotFound);
        };

        let mut active = model.into_active_model();
        S::Session::set_active_organization_id(&mut active, organization_id.map(str::to_owned));
        S::Session::set_updated_at(&mut active, Utc::now());
        active.update(self.connection()).await.map_err(map_db_err)
    }

    async fn update_session_active_team(
        &self,
        token: &str,
        team_id: Option<&str>,
    ) -> AuthResult<S::Session> {
        let model = self
            .get_session(token)
            .await?
            .ok_or(AuthError::SessionNotFound)?;
        let mut active = model.into_active_model();
        S::Session::set_active_team_id(&mut active, team_id.map(str::to_owned))?;
        S::Session::set_updated_at(&mut active, Utc::now());
        active.update(self.connection()).await.map_err(map_db_err)
    }
}
