//! Application-owned anonymous identity/link handlers and actual stored-state observer.
use crate::TestSchema;
use async_trait::async_trait;
use axum::{routing::get, Json, Router};
use better_auth::{
    integrations::axum::AxumIntegration,
    middleware::RateLimitConfig,
    plugins::{
        anonymous::{AnonymousConfig, AnonymousIdentity, AnonymousLink, LinkAnonymousAccount},
        oauth::OAuthProvider,
        AnonymousPlugin, EmailPasswordPlugin, OAuthPlugin, SessionManagementPlugin,
    },
    AuthBuilder, AuthConfig, AuthError, AuthResult,
};
use better_auth_core::{AuthRequest, AuthSession, CreateSession, CreateUser};
use better_auth_seaorm::{
    sea_orm::{ConnectionTrait, EntityTrait, QueryOrder, Statement},
    store::entities::{account, session, user},
    DatabaseConnection, HookControl, SeaOrmHookContext, SeaOrmHooks, SeaOrmStore,
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

#[derive(Clone, Default)]
pub(super) struct Fixture {
    sequence: Arc<AtomicUsize>,
    events: Arc<Mutex<Vec<Value>>>,
}
impl Fixture {
    pub(super) fn reset(&self) {
        self.sequence.store(0, Ordering::SeqCst);
        self.events.lock().expect("anonymous receipt lock").clear();
    }
}
struct Application {
    mode: &'static str,
    fixture: Fixture,
}
#[async_trait]
impl AnonymousIdentity for Application {
    async fn email(&self) -> AuthResult<Option<String>> {
        Ok(Some(if self.mode == "invalid-email" {
            "not an email".into()
        } else {
            format!(
                "anonymous-{}@fixture.test",
                self.fixture.sequence.fetch_add(1, Ordering::SeqCst) + 1
            )
        }))
    }
    async fn name(&self, _request: &AuthRequest) -> AuthResult<Option<String>> {
        tokio::task::yield_now().await;
        Ok(Some(
            if self.mode == "empty-name" {
                ""
            } else {
                "Configured Anonymous"
            }
            .into(),
        ))
    }
}
#[async_trait]
impl LinkAnonymousAccount for Application {
    async fn link(&self, accounts: &AnonymousLink, request: &AuthRequest) -> AuthResult<()> {
        tokio::task::yield_now().await;
        self.fixture.events.lock().expect("anonymous receipt lock").push(json!({
            "mode": self.mode, "path": request.path(),
            "anonymousUser": { "user": accounts.anonymous_user, "session": accounts.anonymous_session },
            "newUser": { "user": accounts.new_user, "session": accounts.new_session },
        }));
        if self.mode == "link-error" {
            return Err(AuthError::Api {
                status: 403,
                code: Some("APPLICATION_LINK_DENIED".into()),
                message: "Configured anonymous transfer denied".into(),
            });
        }
        Ok(())
    }
}
struct Hooks {
    mode: &'static str,
}
#[async_trait]
impl SeaOrmHooks<TestSchema> for Hooks {
    async fn before_create_user(
        &self,
        _user: &mut CreateUser,
        context: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        if context
            .request
            .as_ref()
            .is_some_and(|request| request.path == "/sign-in/anonymous")
        {
            if self.mode == "user-cancel" {
                return Ok(HookControl::Cancel);
            }
            if self.mode == "user-forbidden" {
                return Err(AuthError::forbidden(
                    "user creation cancelled by database hook",
                ));
            }
        }
        Ok(HookControl::Continue)
    }
    async fn before_create_session(
        &self,
        _session: &mut CreateSession,
        context: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        if context
            .request
            .as_ref()
            .is_some_and(|request| request.path == "/sign-in/anonymous")
        {
            if self.mode == "session-cancel" {
                return Ok(HookControl::Cancel);
            }
            if self.mode == "session-forbidden" {
                return Err(AuthError::forbidden(
                    "session creation cancelled by database hook",
                ));
            }
        }
        Ok(HookControl::Continue)
    }
    async fn after_create_session(
        &self,
        session: &<TestSchema as better_auth_core::AuthSchema>::Session,
        context: &SeaOrmHookContext<'_>,
    ) -> AuthResult<()> {
        if self.mode == "snapshot"
            && context
                .request
                .as_ref()
                .is_some_and(|request| request.path == "/sign-up/email")
        {
            context
                .db
                .execute_raw(Statement::from_sql_and_values(
                    context.db.get_database_backend(),
                    "UPDATE users SET name=? WHERE id=?",
                    [
                        "Stored Hook Name".into(),
                        session.user_id().into_owned().into(),
                    ],
                ))
                .await
                .map_err(|error| {
                    AuthError::Database(better_auth_core::DatabaseError::Query(error.to_string()))
                })?;
        }
        Ok(())
    }
}
fn date(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}
pub(super) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<(Router, Fixture)> {
    let fixture = Fixture::default();
    let mut router = Router::new();
    for mode in [
        "standard",
        "disabled",
        "link-error",
        "user-cancel",
        "user-forbidden",
        "session-cancel",
        "session-forbidden",
        "snapshot",
        "invalid-email",
        "empty-name",
    ] {
        let path = format!("/__test/profiles/anonymous-{mode}/api/auth");
        let settings = config.clone().base_path(&path);
        let application = Arc::new(Application {
            mode,
            fixture: fixture.clone(),
        });
        let provider = OAuthProvider::gitlab_with_issuer(
            "fixture-social-client",
            "fixture-social-secret",
            &format!("{}/__test/social-provider/gitlab", config.base_url),
        );
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(settings.clone())
                .store(
                    SeaOrmStore::<TestSchema>::new(settings, database.clone())
                        .with_hooks(vec![Arc::new(Hooks { mode })]),
                )
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(SessionManagementPlugin::new())
                .plugin(OAuthPlugin::new().add_provider("gitlab", provider))
                .plugin(AnonymousPlugin::with_config(AnonymousConfig {
                    identity: Some(application.clone()),
                    on_link_account: Some(application),
                    disable_delete_anonymous_user: mode == "disabled",
                    ..Default::default()
                }))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let observer = fixture.clone();
    router = router.route("/__test/anonymous/state", get(move || {
        let database = database.clone(); let observer = observer.clone(); async move {
            let users = user::Entity::find().order_by_asc(user::Column::CreatedAt).all(&database).await;
            let accounts = account::Entity::find().order_by_asc(account::Column::CreatedAt).all(&database).await;
            let sessions = session::Entity::find().order_by_asc(session::Column::CreatedAt).all(&database).await;
            match (users, accounts, sessions) {
                (Ok(users), Ok(accounts), Ok(sessions)) => Ok(Json(json!({
                    "users": users.into_iter().map(|row| json!({"id":row.id,"name":row.name,"email":row.email,"emailVerified":row.email_verified,"image":row.image,"isAnonymous":row.is_anonymous.unwrap_or(false),"createdAt":date(row.created_at),"updatedAt":date(row.updated_at)})).collect::<Vec<_>>(),
                    "accounts": accounts.into_iter().map(|row| json!({"id":row.id,"userId":row.user_id,"accountId":row.account_id,"providerId":row.provider_id,"accessToken":row.access_token,"refreshToken":row.refresh_token,"idToken":row.id_token,"scope":row.scope,"accessTokenExpiresAt":row.access_token_expires_at.map(date),"refreshTokenExpiresAt":row.refresh_token_expires_at.map(date),"createdAt":date(row.created_at),"updatedAt":date(row.updated_at)})).collect::<Vec<_>>(),
                    "sessions": sessions.into_iter().map(|row| json!({"id":row.id,"userId":row.user_id,"token":row.token,"expiresAt":date(row.expires_at),"createdAt":date(row.created_at),"updatedAt":date(row.updated_at),"ipAddress":row.ip_address,"userAgent":row.user_agent})).collect::<Vec<_>>(),
                    "events": observer.events.lock().expect("anonymous receipt lock").clone(),
                }))),
                _ => Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR),
            }
        }
    }));
    Ok((router, fixture))
}
