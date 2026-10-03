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
        persist: bool,
        complete: bool,
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
                fields.preserve_creation_value(
                    name,
                    better_auth_core::utils::json::JsValue::String(value.clone()),
                );
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
                *destination = crate::session_fields::prepare_string_value(
                    db,
                    crate::session_fields::raw_value(&value)?,
                )
                .await?;
            }
        }
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
        let session = if persist {
            active.insert(db).await.map_err(map_db_err)?
        } else {
            S::Session::materialize_secondary(active)?
        };
        if tx.is_none() && complete {
            for hook in self.hooks() {
                hook.after_create_session(&session, &hook_context).await?;
            }
        }
        Ok(session)
    }

    pub(crate) async fn prepare_secondary_update_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        tx: Option<&DatabaseTransaction>,
        session: S::Session,
        expires_at: Option<DateTime<Utc>>,
        mut fields: better_auth_core::field_policy::FieldValues,
    ) -> AuthResult<Option<(S::Session, better_auth_core::field_policy::FieldValues)>> {
        use better_auth_core::AuthSession;
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
        let mut active = session.into_active_model();
        let backend = db.get_database_backend();
        for (column, value) in S::Session::additional_field_bindings(&fields, backend)? {
            let value = crate::session_fields::prepare_value(db, &column, value).await?;
            S::Session::set_additional_field(&mut active, column, value, backend)?;
        }
        if let Some(expiry) = expires_at {
            S::Session::set_expires_at(&mut active, expiry);
        }
        S::Session::set_updated_at(&mut active, Utc::now());
        let session = S::Session::materialize_secondary(active)?;
        Ok(Some((session, fields)))
    }

    pub(crate) async fn complete_secondary_update_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        tx: Option<&DatabaseTransaction>,
        session: S::Session,
        expires_at: Option<DateTime<Utc>>,
        mut fields: better_auth_core::field_policy::FieldValues,
        persist: bool,
    ) -> AuthResult<Option<S::Session>> {
        use better_auth_core::AuthSession;
        let context = self.hook_context(tx);
        let session = if persist {
            fields.apply_adapter_transforms_async().await?;
            let Some(current) = <S::Session as SeaOrmSessionModel>::Entity::find()
                .filter(S::Session::token_column().eq(session.token()))
                .filter(S::Session::active_column().eq(true))
                .one(db)
                .await
                .map_err(map_db_err)?
            else {
                for hook in self.hooks().iter().filter(|_| tx.is_none()) {
                    hook.after_update_session_missing(session.token(), &context)
                        .await?;
                }
                return Ok(None);
            };
            let mut active = current.into_active_model();
            let backend = db.get_database_backend();
            for (column, value) in S::Session::additional_field_bindings(&fields, backend)? {
                let value = crate::session_fields::prepare_value(db, &column, value).await?;
                S::Session::set_additional_field(&mut active, column, value, backend)?;
            }
            if let Some(expiry) = expires_at {
                S::Session::set_expires_at(&mut active, expiry);
            }
            S::Session::set_updated_at(&mut active, session.updated_at());
            match active.update(db).await {
                Ok(model) => model,
                Err(sea_orm::DbErr::RecordNotUpdated) => {
                    for hook in self.hooks().iter().filter(|_| tx.is_none()) {
                        hook.after_update_session_missing(session.token(), &context)
                            .await?;
                    }
                    return Ok(None);
                }
                Err(error) => return Err(map_db_err(error)),
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
        tx: &DatabaseTransaction,
        input: CreateSession,
        persist: bool,
    ) -> AuthResult<S::Session> {
        self.create_session_with_connection(tx, Some(tx), input, persist, false)
            .await
    }

    pub(crate) async fn create_session_in_tx(
        &self,
        tx: &DatabaseTransaction,
        create_session: CreateSession,
    ) -> AuthResult<S::Session> {
        self.create_session_with_connection(tx, Some(tx), create_session, true, true)
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
        fields.apply_adapter_transforms_async().await?;
        let mut query = <S::Session as SeaOrmSessionModel>::Entity::find()
            .filter(S::Session::token_column().eq(token));
        if expires_at.is_some() {
            query = query.filter(S::Session::active_column().eq(true));
        }
        let Some(model) = query.one(self.connection()).await.map_err(map_db_err)? else {
            for hook in self.hooks() {
                hook.after_update_session_missing(token, &hook_context)
                    .await?;
            }
            return Ok(None);
        };
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
            Err(sea_orm::DbErr::RecordNotUpdated) => {
                for hook in self.hooks() {
                    hook.after_update_session_missing(token, &hook_context)
                        .await?;
                }
                return Ok(None);
            }
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
    async fn prepare_secondary_session_creation(
        &self,
        input: CreateSession,
        persist: bool,
    ) -> AuthResult<S::Session> {
        self.create_session_with_connection(self.connection(), None, input, persist, false)
            .await
    }
    async fn complete_secondary_session_creation(&self, session: &S::Session) -> AuthResult<()> {
        let context = self.hook_context(None);
        for hook in self.hooks() {
            hook.after_create_session(session, &context).await?;
        }
        Ok(())
    }

    async fn prepare_secondary_session_update(
        &self,
        session: S::Session,
        expires_at: Option<DateTime<Utc>>,
        fields: better_auth_core::field_policy::FieldValues,
    ) -> AuthResult<Option<(S::Session, better_auth_core::field_policy::FieldValues)>> {
        self.prepare_secondary_update_with_connection(
            self.connection(),
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
        fields: better_auth_core::field_policy::FieldValues,
        persist: bool,
    ) -> AuthResult<Option<S::Session>> {
        self.complete_secondary_update_with_connection(
            self.connection(),
            None,
            session,
            expires_at,
            fields,
            persist,
        )
        .await
    }

    async fn end_session_preserving(&self, token: &str) -> AuthResult<()> {
        use better_auth_core::AuthSession;
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
                return Err(cancelled_by_hook("session deletion"));
            }
        }
        let _ended = <S::Session as SeaOrmSessionModel>::Entity::update_many()
            .col_expr(
                S::Session::expires_at_column(),
                sea_orm::sea_query::Expr::value(now),
            )
            .filter(S::Session::token_column().eq(token))
            .filter(S::Session::expires_at_column().gt(now))
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_delete_session(&session, &context).await?;
        }
        Ok(())
    }
    async fn end_user_sessions_preserving(&self, user_id: &str) -> AuthResult<()> {
        let now = Utc::now();
        let user_id = S::Session::parse_user_id(user_id)?;
        let live = || {
            <S::Session as SeaOrmSessionModel>::Entity::find()
                .filter(S::Session::user_id_column().eq(user_id.clone()))
                .filter(S::Session::expires_at_column().gt(now))
        };
        let sessions = live()
            .limit(self.config().advanced.database.default_find_many_limit as u64)
            .all(self.connection())
            .await
            .map_err(map_db_err)?;
        let context = self.hook_context(None);
        for session in &sessions {
            for hook in self.hooks() {
                if hook
                    .before_delete_session(session, &context)
                    .await?
                    .is_cancelled()
                {
                    return Err(cancelled_by_hook("session deletion"));
                }
            }
        }
        let _ended = <S::Session as SeaOrmSessionModel>::Entity::update_many()
            .col_expr(
                S::Session::expires_at_column(),
                sea_orm::sea_query::Expr::value(now),
            )
            .filter(S::Session::user_id_column().eq(user_id))
            .filter(S::Session::expires_at_column().gt(now))
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;
        for session in &sessions {
            for hook in self.hooks() {
                hook.after_delete_session(session, &context).await?;
            }
        }
        Ok(())
    }

    async fn create_session(&self, create_session: CreateSession) -> AuthResult<S::Session> {
        self.create_session_with_connection(self.connection(), None, create_session, true, true)
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

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::{HookControl, SeaOrmHookContext, SeaOrmHooks};
    use crate::store::{bundled_schema::BundledSchema, migrator::run_migrations};
    use better_auth_core::store::UserStore;
    use better_auth_core::{AuthConfig, AuthSession, CreateUser};
    use chrono::Duration;
    use sea_orm::Database;
    use std::sync::{Arc, Mutex};

    struct TokenHook {
        observed: Arc<Mutex<Option<String>>>,
    }

    #[async_trait]
    impl SeaOrmHooks<BundledSchema> for TokenHook {
        async fn before_create_session(
            &self,
            session: &mut CreateSession,
            _context: &SeaOrmHookContext<'_>,
        ) -> AuthResult<HookControl> {
            *self
                .observed
                .lock()
                .map_err(|_error| AuthError::internal("Hook token observation lock poisoned"))? =
                session.token.clone();
            session.token = Some("hook-assigned-token".to_owned());
            Ok(HookControl::Continue)
        }
    }

    fn input(user_id: &str, token: Option<&str>, expiry: DateTime<Utc>) -> CreateSession {
        CreateSession {
            additional_fields: better_auth_core::field_policy::FieldValues::default(),
            token: token.map(str::to_owned),
            user_id: user_id.to_owned(),
            expires_at: expiry,
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
        }
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn session_cancel_preserves_default_wire_error_and_transaction_rollback()
    -> Result<(), Box<dyn std::error::Error>> {
        struct RejectSession {
            cancel: bool,
            observed_transaction: Arc<Mutex<Option<bool>>>,
        }
        #[async_trait]
        impl SeaOrmHooks<BundledSchema> for RejectSession {
            async fn before_create_session(
                &self,
                _session: &mut CreateSession,
                context: &SeaOrmHookContext<'_>,
            ) -> AuthResult<HookControl> {
                *self.observed_transaction.lock().unwrap() = Some(context.tx.is_some());
                if self.cancel {
                    Ok(HookControl::Cancel)
                } else {
                    Err(AuthError::forbidden(
                        "session creation cancelled by database hook",
                    ))
                }
            }
        }
        for cancel in [false, true] {
            for in_transaction in [false, true] {
                let db = Database::connect("sqlite::memory:").await?;
                run_migrations(&db).await?;
                let observed = Arc::new(Mutex::new(None));
                let store = SeaOrmStore::<BundledSchema>::new(
                    AuthConfig::new("cancel-session-hook-secret-at-least-32"),
                    db.clone(),
                )
                .hook(RejectSession {
                    cancel,
                    observed_transaction: Arc::clone(&observed),
                });
                let email = "cancel-owner@fixture.test";
                let expiry = Utc::now() + Duration::hours(1);
                let error = if in_transaction {
                    better_auth_core::store::transaction(&store, move |tx| {
                        Box::pin(async move {
                            let user = tx.create_user(CreateUser::new().with_email(email)).await?;
                            drop(
                                tx.create_session(input(&user.id, Some("cancel-token"), expiry))
                                    .await?,
                            );
                            Ok(())
                        })
                    })
                    .await
                    .unwrap_err()
                } else {
                    let user = store
                        .create_user(CreateUser::new().with_email(email))
                        .await?;
                    store
                        .create_session(input(&user.id, Some("cancel-token"), expiry))
                        .await
                        .unwrap_err()
                };
                assert_eq!(*observed.lock().unwrap(), Some(in_transaction));
                assert_eq!(matches!(error, AuthError::SessionCreationCancelled), cancel);
                assert_eq!(matches!(error, AuthError::Forbidden(_)), !cancel);
                let response = error.to_auth_response();
                assert_eq!(response.status, 403);
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&response.body)?,
                    serde_json::json!({"message":"session creation cancelled by database hook"})
                );
                assert!(store.get_session("cancel-token").await?.is_none());
                assert_eq!(
                    store.get_user_by_email(email).await?.is_none(),
                    in_transaction
                );
                db.close().await?;
            }
        }
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    async fn generates_default_tokens_before_hooks_and_persists_trusted_overrides()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect("sqlite::memory:").await?;
        run_migrations(&database).await?;
        let store = SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("session-token-hook-local-secret-at-least-32"),
            database,
        );
        let user = store
            .create_user(CreateUser::new().with_email("session-hook@example.com"))
            .await?;
        let expiry = Utc::now() + Duration::hours(1);
        let first = store.create_session(input(&user.id, None, expiry)).await?;
        let second = store.create_session(input(&user.id, None, expiry)).await?;
        assert_eq!(first.token().len(), 32);
        assert!(
            first
                .token()
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric())
        );
        assert_ne!(first.token(), second.token());
        let explicit = store
            .create_session(input(&user.id, Some("trusted-server-override"), expiry))
            .await?;
        assert_eq!(explicit.token(), "trusted-server-override");
        assert!(
            store
                .create_session(input(&user.id, Some(explicit.token()), expiry))
                .await
                .is_err()
        );
        let observed = Arc::new(Mutex::new(None));
        let hooked = store.hook(TokenHook {
            observed: Arc::clone(&observed),
        });
        let overridden = hooked.create_session(input(&user.id, None, expiry)).await?;
        let generated = observed
            .lock()
            .map_err(|_error| std::io::Error::other("Observation lock poisoned"))?
            .clone()
            .ok_or_else(|| std::io::Error::other("Hook saw no token"))?;
        assert_eq!(generated.len(), 32);
        assert!(generated.bytes().all(|byte| byte.is_ascii_alphanumeric()));
        assert_eq!(overridden.token(), "hook-assigned-token");
        assert!(hooked.get_session(&generated).await?.is_none());
        assert_eq!(
            hooked
                .get_session(overridden.token())
                .await?
                .map(|row| row.id),
            Some(overridden.id)
        );
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    async fn batch_session_lookup_returns_token_index_order_and_includes_expired_rows_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect("sqlite::memory:").await?;
        run_migrations(&database).await?;
        let store = SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("session-batch-local-secret-at-least-32"),
            database,
        );
        let user = store
            .create_user(CreateUser::new().with_email("session-batch@example.com"))
            .await?;
        let now = Utc::now();
        for (token, expiry) in [
            ("z-token", now + Duration::hours(1)),
            ("a-token", now - Duration::minutes(1)),
            ("m-token", now + Duration::hours(1)),
        ] {
            drop(
                store
                    .create_session(input(&user.id, Some(token), expiry))
                    .await?,
            );
        }
        let result = store
            .get_sessions_by_tokens(&[
                "z-token".to_owned(),
                "unknown".to_owned(),
                "a-token".to_owned(),
                "z-token".to_owned(),
                "m-token".to_owned(),
            ])
            .await?;
        assert_eq!(
            result.iter().map(AuthSession::token).collect::<Vec<_>>(),
            vec!["a-token", "m-token", "z-token"]
        );
        assert!(result.first().is_some_and(|row| row.expires_at() < now));
        assert_eq!(store.get_sessions_by_tokens(&[]).await?.len(), 0);
        let mut config = store.config().as_ref().clone();
        config.advanced.database.default_find_many_limit = 2;
        let limited = SeaOrmStore::<BundledSchema>::new(config, store.connection().clone());
        assert_eq!(
            limited
                .get_sessions_by_tokens(&[
                    "z-token".to_owned(),
                    "a-token".to_owned(),
                    "m-token".to_owned()
                ])
                .await?
                .iter()
                .map(AuthSession::token)
                .collect::<Vec<_>>(),
            vec!["a-token", "m-token"]
        );
        store.delete_session("m-token").await?;
        assert_eq!(
            store
                .get_sessions_by_tokens(&["m-token".to_owned(), "z-token".to_owned()])
                .await?
                .iter()
                .map(AuthSession::token)
                .collect::<Vec<_>>(),
            vec!["z-token"]
        );
        Ok(())
    }
}
// LCOV_EXCL_STOP
