use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait, ExprTrait,
    IntoActiveModel, QueryFilter, QueryOrder, QuerySelect,
};

use better_auth_core::store::SessionStore;

use crate::error::{AuthError, AuthResult};
use crate::schema::{AuthSchema, SeaOrmSessionModel};
use crate::types::CreateSession;

use super::{SeaOrmStore, cancelled_by_hook, map_db_err};

impl<S> SeaOrmStore<S>
where
    S: AuthSchema,
    S::Session: SeaOrmSessionModel,
{
    fn normalize_session_client_field(value: Option<String>) -> Option<String> {
        match value {
            Some(value) => Some(value),
            None => Some(String::new()),
        }
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
                return Err(cancelled_by_hook("session creation"));
            }
        }
        let now = Utc::now();
        create_session.ip_address = Self::normalize_session_client_field(create_session.ip_address);
        create_session.user_agent = Self::normalize_session_client_field(create_session.user_agent);
        let token = create_session
            .token
            .take()
            .unwrap_or_else(better_auth_core::utils::sessions::generate_session_token);
        let session = S::Session::new_active(None, token, create_session, now)
            .insert(db)
            .await
            .map_err(map_db_err)?;
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
                .map_err(|_| AuthError::internal("Hook token observation lock poisoned"))? =
                session.token.clone();
            session.token = Some("hook-assigned-token".to_owned());
            Ok(HookControl::Continue)
        }
    }

    fn input(user_id: &str, token: Option<&str>, expiry: DateTime<Utc>) -> CreateSession {
        CreateSession {
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
            observed: observed.clone(),
        });
        let overridden = hooked.create_session(input(&user.id, None, expiry)).await?;
        let generated = observed
            .lock()
            .map_err(|_| std::io::Error::other("Observation lock poisoned"))?
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
            let _ = store
                .create_session(input(&user.id, Some(token), expiry))
                .await?;
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
            result.iter().map(|row| row.token()).collect::<Vec<_>>(),
            vec!["a-token", "m-token", "z-token"]
        );
        assert!(result.first().is_some_and(|row| row.expires_at() < now));
        assert!(store.get_sessions_by_tokens(&[]).await?.is_empty());
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
                .map(|row| row.token())
                .collect::<Vec<_>>(),
            vec!["a-token", "m-token"]
        );
        store.delete_session("m-token").await?;
        assert_eq!(
            store
                .get_sessions_by_tokens(&["m-token".to_owned(), "z-token".to_owned()])
                .await?
                .iter()
                .map(|row| row.token())
                .collect::<Vec<_>>(),
            vec!["z-token"]
        );
        Ok(())
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
        let Some(model) = <S::Session as SeaOrmSessionModel>::Entity::find()
            .filter(<S::Session as SeaOrmSessionModel>::token_column().eq(token))
            .filter(<S::Session as SeaOrmSessionModel>::active_column().eq(true))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Ok(None);
        };

        let mut active = model.into_active_model();
        S::Session::set_expires_at(&mut active, expires_at);
        S::Session::set_updated_at(&mut active, Utc::now());
        match active.update(self.connection()).await {
            Ok(updated) => Ok(Some(updated)),
            Err(sea_orm::DbErr::RecordNotUpdated) => Ok(None),
            Err(error) => Err(map_db_err(error)),
        }
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
        let _ = <S::Session as SeaOrmSessionModel>::Entity::delete_many()
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
            .map(|result| result.rows_affected as usize)
            .map_err(map_db_err)
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
