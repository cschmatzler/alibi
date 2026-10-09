use super::SqlxStore;
use crate::error::record_not_updated;
use crate::model::{self, ActiveRow, SqlxModel};
use crate::pool::{Exec, SqlxTransaction};
use crate::schema::{AuthSchema, SqlxSessionModel};
use crate::sql::Sql;
use alibi_core::error::{AuthError, AuthResult};
use alibi_core::field_policy::FieldValues;
use alibi_core::store::SessionStore;
use alibi_core::types::CreateSession;
use alibi_core::utils::json::JsValue;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

impl<S> SqlxStore<S>
where
    S: AuthSchema,
    S::Session: SqlxSessionModel,
{
    fn normalize_session_client_field(value: Option<String>) -> Option<String> {
        value.map_or_else(|| Some(String::new()), Some)
    }

    /// `SELECT ... WHERE token = ? AND active = true LIMIT 1`.
    fn active_session_by_token(exec: Exec<'_>, token: &str) -> Sql {
        let table = <S::Session as SqlxModel>::TABLE;
        let mut sql = model::select_model::<S::Session>(exec);
        sql.push(" WHERE ");
        sql.compare_model::<S::Session>(table, S::Session::token_column(), " = ", token);
        sql.push(" AND ");
        sql.compare_model::<S::Session>(table, S::Session::active_column(), " = ", true);
        sql.push(" LIMIT 1");
        sql
    }

    async fn create_session_with_connection(
        &self,
        exec: Exec<'_>,
        tx: Option<&SqlxTransaction>,
        mut create_session: CreateSession,
        persist: bool,
        complete: bool,
    ) -> AuthResult<S::Session> {
        if create_session.token.is_none() {
            create_session.token = Some(alibi_core::utils::sessions::generate_session_token());
        }
        let hook_context = self.hook_context(tx);
        for hook in self.hooks() {
            if hook
                .before_create_session(&mut create_session, &hook_context)
                .await
                .map_err(alibi_core::store::adapter::callback_error)?
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
            .unwrap_or_else(alibi_core::utils::sessions::generate_session_token);
        let mut fields = std::mem::take(&mut create_session.additional_fields);
        let mut typed_fields = [
            (
                "activeOrganizationId",
                &mut create_session.active_organization_id,
            ),
            ("activeTeamId", &mut create_session.active_team_id),
            ("impersonatedBy", &mut create_session.impersonated_by),
        ];
        for (name, destination) in &mut typed_fields {
            if let Some(value) = destination.as_ref() {
                fields.preserve_creation_value(name, JsValue::String(value.clone()));
            }
            // Configured values now belong to the adapter input. A transform
            // that omits one must also omit its original typed creation value.
            if fields.contains_key(*name) {
                **destination = None;
            }
        }
        if persist {
            fields.apply_adapter_transforms_async().await?;
        }
        // These fields are persisted by new_active, including on handwritten
        // schemas with renamed columns and no generic additional-field bindings.
        for (name, destination) in typed_fields {
            if let Some(value) = fields.shift_remove(name) {
                *destination = crate::additional_fields::prepare_string_value(
                    exec,
                    crate::additional_fields::raw_value(&value)?,
                )
                .await?;
            }
        }
        let generated_id = self
            .generated_id(
                exec,
                "session",
                <S::Session as SqlxModel>::TABLE,
                S::Session::id_column(),
            )
            .await?;
        let id = generated_id
            .as_deref()
            .map(S::Session::parse_id)
            .transpose()?;
        let mut active = S::Session::new_active(id, token, create_session, now);
        if !fields.is_empty() {
            stage_additional_fields::<S::Session>(exec, &mut active, &fields).await?;
        }
        let session = if persist {
            model::insert::<S::Session>(exec, &active).await?
        } else {
            S::Session::materialize_secondary(active)?
        };
        if tx.is_none() && complete {
            for hook in self.hooks() {
                hook.after_create_session(&session, &hook_context)
                    .await
                    .map_err(alibi_core::store::adapter::callback_error)?;
            }
        }
        Ok(session)
    }

    pub(crate) async fn prepare_secondary_update_with_connection(
        &self,
        exec: Exec<'_>,
        tx: Option<&SqlxTransaction>,
        session: S::Session,
        expires_at: Option<DateTime<Utc>>,
        mut fields: FieldValues,
    ) -> AuthResult<Option<(S::Session, FieldValues)>> {
        use alibi_core::AuthSession;
        let hook_context = self.hook_context(tx);
        for hook in self.hooks() {
            if hook
                .before_update_session(session.token(), &mut fields, &hook_context)
                .await?
                .is_cancelled()
            {
                return Ok(None);
            }
        }
        // The cache stores hook output before SQL adapter input transformations.
        let mut active = session.into_active();
        stage_additional_fields::<S::Session>(exec, &mut active, &fields).await?;
        if let Some(expiry) = expires_at {
            S::Session::set_expires_at(&mut active, expiry);
        }
        S::Session::set_updated_at(&mut active, Utc::now());
        let session = S::Session::materialize_secondary(active)?;
        Ok(Some((session, fields)))
    }

    pub(crate) async fn complete_secondary_update_with_connection(
        &self,
        exec: Exec<'_>,
        tx: Option<&SqlxTransaction>,
        session: S::Session,
        expires_at: Option<DateTime<Utc>>,
        mut fields: FieldValues,
        persist: bool,
    ) -> AuthResult<Option<S::Session>> {
        use alibi_core::AuthSession;
        let context = self.hook_context(tx);
        let session = if persist {
            fields.apply_adapter_transforms_async().await?;
            let Some(current) = exec
                .fetch_optional::<S::Session>(Self::active_session_by_token(exec, session.token()))
                .await?
            else {
                for hook in self.hooks().iter().filter(|_| tx.is_none()) {
                    hook.after_update_session_missing(session.token(), &context)
                        .await?;
                }
                return Ok(None);
            };
            let mut active = current.into_active();
            stage_additional_fields::<S::Session>(exec, &mut active, &fields).await?;
            if let Some(expiry) = expires_at {
                S::Session::set_expires_at(&mut active, expiry);
            }
            S::Session::set_updated_at(&mut active, session.updated_at());
            if let Some(model) = model::update::<S::Session>(exec, &active).await? {
                model
            } else {
                for hook in self.hooks().iter().filter(|_| tx.is_none()) {
                    hook.after_update_session_missing(session.token(), &context)
                        .await?;
                }
                return Ok(None);
            }
        } else {
            session
        };
        for hook in self.hooks().iter().filter(|_| tx.is_none()) {
            hook.after_update_session(&session, &context).await?;
        }
        Ok(Some(session))
    }

    pub(crate) async fn prepare_secondary_session_in_tx(
        &self,
        tx: &SqlxTransaction,
        input: CreateSession,
        persist: bool,
    ) -> AuthResult<S::Session> {
        self.create_session_with_connection(Exec::tx(tx), Some(tx), input, persist, false)
            .await
    }

    pub(crate) async fn create_session_in_tx(
        &self,
        tx: &SqlxTransaction,
        create_session: CreateSession,
    ) -> AuthResult<S::Session> {
        self.create_session_with_connection(Exec::tx(tx), Some(tx), create_session, true, true)
            .await
    }
}

/// Stage the configured additional fields on the row, coerced to their columns.
async fn stage_additional_fields<M: SqlxSessionModel>(
    exec: Exec<'_>,
    active: &mut ActiveRow,
    fields: &FieldValues,
) -> AuthResult<()> {
    let backend = exec.engine();
    for (column, value) in M::additional_field_bindings(fields, backend)? {
        let value =
            crate::additional_fields::prepare_value(exec, M::column_kind(column), value).await?;
        M::set_additional_field(active, column, value, backend)?;
    }
    Ok(())
}

pub(super) enum SessionScope<'a> {
    Team(Option<&'a str>),
    Organization(Option<&'a str>),
}

impl<S> SqlxStore<S>
where
    S: AuthSchema,
    S::Session: SqlxSessionModel,
{
    async fn update_session_with_fields(
        &self,
        token: &str,
        expires_at: Option<DateTime<Utc>>,
        mut fields: FieldValues,
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
        fields.apply_adapter_transforms_async().await?;
        let table = <S::Session as SqlxModel>::TABLE;
        let mut query = model::select_model::<S::Session>(self.exec());
        query.push(" WHERE ");
        query.compare_model::<S::Session>(table, S::Session::token_column(), " = ", token);
        if expires_at.is_some() {
            query.push(" AND ");
            query.compare_model::<S::Session>(table, S::Session::active_column(), " = ", true);
        }
        query.push(" LIMIT 1");
        let Some(model) = self.exec().fetch_optional::<S::Session>(query).await? else {
            for hook in self.hooks() {
                hook.after_update_session_missing(token, &hook_context)
                    .await?;
            }
            return Ok(None);
        };
        let mut active = model.into_active();
        if !fields.is_empty() {
            stage_additional_fields::<S::Session>(self.exec(), &mut active, &fields).await?;
        }
        if let Some(expires_at) = expires_at {
            S::Session::set_expires_at(&mut active, expires_at);
        }
        S::Session::set_updated_at(&mut active, Utc::now());
        let Some(session) = model::update::<S::Session>(self.exec(), &active).await? else {
            for hook in self.hooks() {
                hook.after_update_session_missing(token, &hook_context)
                    .await?;
            }
            return Ok(None);
        };
        for hook in self.hooks() {
            hook.after_update_session(&session, &hook_context).await?;
        }
        Ok(Some(session))
    }

    pub(super) async fn update_session_scope_with_connection(
        &self,
        exec: Exec<'_>,
        token: &str,
        scope: SessionScope<'_>,
    ) -> AuthResult<S::Session> {
        let model = exec
            .fetch_optional::<S::Session>(Self::active_session_by_token(exec, token))
            .await?
            .ok_or(AuthError::SessionNotFound)?;
        let mut active = model.into_active();
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
        model::update::<S::Session>(exec, &active)
            .await?
            .ok_or_else(record_not_updated)
    }
}

#[async_trait]
impl<S> SessionStore<S> for SqlxStore<S>
where
    S: AuthSchema + Send + Sync,
    S::Session: SqlxSessionModel,
{
    async fn prepare_secondary_session_creation(
        &self,
        input: CreateSession,
        persist: bool,
    ) -> AuthResult<S::Session> {
        self.create_session_with_connection(self.exec(), None, input, persist, false)
            .await
    }
    async fn complete_secondary_session_creation(&self, session: &S::Session) -> AuthResult<()> {
        let context = self.hook_context(None);
        for hook in self.hooks() {
            hook.after_create_session(session, &context)
                .await
                .map_err(alibi_core::store::adapter::callback_error)?;
        }
        Ok(())
    }

    async fn prepare_secondary_session_update(
        &self,
        session: S::Session,
        expires_at: Option<DateTime<Utc>>,
        fields: FieldValues,
    ) -> AuthResult<Option<(S::Session, FieldValues)>> {
        self.prepare_secondary_update_with_connection(
            self.exec(),
            None,
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
        fields: FieldValues,
        persist: bool,
    ) -> AuthResult<Option<S::Session>> {
        self.complete_secondary_update_with_connection(
            self.exec(),
            None,
            session,
            expires_at,
            fields,
            persist,
        )
        .await
    }

    async fn end_session_preserving(&self, token: &str) -> AuthResult<()> {
        use alibi_core::AuthSession;
        let now = Utc::now();
        let Some(session) = self
            .get_session(token)
            .await?
            .filter(|session| session.expires_at() > now)
        else {
            return Ok(());
        };
        let context = self.hook_context(None);
        for hook in self.hooks() {
            if hook
                .before_delete_session(&session, &context)
                .await?
                .is_cancelled()
            {
                return Ok(());
            }
        }
        let table = <S::Session as SqlxModel>::TABLE;
        let mut sql = Sql::with(self.exec().engine(), "UPDATE ");
        sql.ident(table);
        sql.push(" SET ");
        sql.assign(
            S::Session::expires_at_column(),
            S::Session::timestamp_value(S::Session::expires_at_column(), now),
        );
        sql.push(" WHERE ");
        sql.compare_model::<S::Session>(table, S::Session::token_column(), " = ", token);
        sql.push(" AND ");
        sql.compare_model::<S::Session>(
            table,
            S::Session::expires_at_column(),
            " > ",
            S::Session::timestamp_value(S::Session::expires_at_column(), now),
        );
        _ = self.exec().execute(sql).await?;
        for hook in self.hooks() {
            hook.after_delete_session(&session, &context).await?;
        }
        Ok(())
    }
    async fn end_user_sessions_preserving(&self, user_id: &str) -> AuthResult<()> {
        let now = Utc::now();
        let user_id = S::Session::parse_user_id(user_id)?;
        let table = <S::Session as SqlxModel>::TABLE;
        let mut live = model::select_model::<S::Session>(self.exec());
        live.push(" WHERE ");
        live.compare_model::<S::Session>(
            table,
            S::Session::user_id_column(),
            " = ",
            user_id.clone(),
        );
        live.push(" AND ");
        live.compare_model::<S::Session>(
            table,
            S::Session::expires_at_column(),
            " > ",
            S::Session::timestamp_value(S::Session::expires_at_column(), now),
        );
        live.push(" LIMIT ");
        live.bind(self.find_many_limit());
        let sessions: Vec<S::Session> = self.exec().fetch_all(live).await?;
        let context = self.hook_context(None);
        for session in &sessions {
            for hook in self.hooks() {
                if hook
                    .before_delete_session(session, &context)
                    .await?
                    .is_cancelled()
                {
                    return Ok(());
                }
            }
        }
        let mut sql = Sql::with(self.exec().engine(), "UPDATE ");
        sql.ident(table);
        sql.push(" SET ");
        sql.assign(
            S::Session::expires_at_column(),
            S::Session::timestamp_value(S::Session::expires_at_column(), now),
        );
        sql.push(" WHERE ");
        sql.compare_model::<S::Session>(table, S::Session::user_id_column(), " = ", user_id);
        sql.push(" AND ");
        sql.compare_model::<S::Session>(
            table,
            S::Session::expires_at_column(),
            " > ",
            S::Session::timestamp_value(S::Session::expires_at_column(), now),
        );
        _ = self.exec().execute(sql).await?;
        for session in &sessions {
            for hook in self.hooks() {
                hook.after_delete_session(session, &context).await?;
            }
        }
        Ok(())
    }

    async fn create_session(&self, create_session: CreateSession) -> AuthResult<S::Session> {
        self.create_session_with_connection(self.exec(), None, create_session, true, true)
            .await
    }

    async fn get_session(&self, token: &str) -> AuthResult<Option<S::Session>> {
        self.exec()
            .fetch_optional(Self::active_session_by_token(self.exec(), token))
            .await
    }

    async fn get_sessions_by_tokens(&self, tokens: &[String]) -> AuthResult<Vec<S::Session>> {
        let table = <S::Session as SqlxModel>::TABLE;
        let mut sql = model::select_model::<S::Session>(self.exec());
        sql.push(" WHERE ");
        if tokens.is_empty() {
            sql.push("1 = 2");
        } else {
            sql.column(table, S::Session::token_column());
            sql.push(" IN ");
            sql.bind_list(
                tokens.iter().cloned().map(|token| {
                    S::Session::column_value(S::Session::token_column(), token.into())
                }),
            );
        }
        sql.push(" AND ");
        sql.compare_model::<S::Session>(table, S::Session::active_column(), " = ", true);
        sql.push(" LIMIT ");
        sql.bind(self.find_many_limit());
        self.exec().fetch_all(sql).await
    }

    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<S::Session>> {
        let user_id = <S::Session as SqlxSessionModel>::parse_user_id(user_id)?;
        let table = <S::Session as SqlxModel>::TABLE;
        let mut sql = model::select_model::<S::Session>(self.exec());
        sql.push(" WHERE ");
        sql.compare_model::<S::Session>(table, S::Session::user_id_column(), " = ", user_id);
        sql.push(" AND ");
        sql.compare_model::<S::Session>(table, S::Session::active_column(), " = ", true);
        sql.push(" ORDER BY ");
        sql.column(table, S::Session::created_at_column());
        sql.push(" ASC");
        self.exec().fetch_all(sql).await
    }

    async fn update_session_fields(
        &self,
        token: &str,
        fields: FieldValues,
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
        self.update_session_with_fields(token, Some(expires_at), FieldValues::default())
            .await
    }

    async fn refresh_session_with_fields(
        &self,
        token: &str,
        expires_at: DateTime<Utc>,
        fields: FieldValues,
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
                    return Ok(());
                }
            }
        }
        let table = <S::Session as SqlxModel>::TABLE;
        let mut sql = Sql::with(self.exec().engine(), "DELETE FROM ");
        sql.ident(table);
        sql.push(" WHERE ");
        sql.compare_model::<S::Session>(table, S::Session::token_column(), " = ", token);
        _ = self.exec().execute(sql).await?;
        if let Some(session) = &session {
            for hook in self.hooks() {
                hook.after_delete_session(session, &hook_context).await?;
            }
        }
        Ok(())
    }

    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
        let user_id = <S::Session as SqlxSessionModel>::parse_user_id(user_id)?;
        let table = <S::Session as SqlxModel>::TABLE;
        let mut sql = Sql::with(self.exec().engine(), "DELETE FROM ");
        sql.ident(table);
        sql.push(" WHERE ");
        sql.compare_model::<S::Session>(table, S::Session::user_id_column(), " = ", user_id);
        self.exec().execute(sql).await.map(|_| ())
    }

    async fn delete_expired_sessions(&self) -> AuthResult<usize> {
        let table = <S::Session as SqlxModel>::TABLE;
        let mut sql = Sql::with(self.exec().engine(), "DELETE FROM ");
        sql.ident(table);
        sql.push(" WHERE ");
        sql.compare_model::<S::Session>(
            table,
            S::Session::expires_at_column(),
            " < ",
            S::Session::timestamp_value(S::Session::expires_at_column(), Utc::now()),
        );
        sql.push(" OR ");
        sql.compare_model::<S::Session>(table, S::Session::active_column(), " = ", false);
        let deleted = self.exec().execute(sql).await?;
        usize::try_from(deleted)
            .map_err(|_error| AuthError::internal("Affected row count exceeds usize"))
    }

    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<S::Session> {
        let Some(model) = self.get_session(token).await? else {
            return Err(AuthError::SessionNotFound);
        };

        let mut active = model.into_active();
        S::Session::set_active_organization_id(&mut active, organization_id.map(str::to_owned));
        S::Session::set_updated_at(&mut active, Utc::now());
        model::update::<S::Session>(self.exec(), &active)
            .await?
            .ok_or_else(record_not_updated)
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
        let mut active = model.into_active();
        S::Session::set_active_team_id(&mut active, team_id.map(str::to_owned))?;
        S::Session::set_updated_at(&mut active, Utc::now());
        model::update::<S::Session>(self.exec(), &active)
            .await?
            .ok_or_else(record_not_updated)
    }
}
