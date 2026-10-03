//! Stored application fields and awaited callbacks on the real admin lifecycle.
use crate::TestSchema;
use crate::backend::entities::user::Model;
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use better_auth::config::CookieCacheConfig;
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::{
    AdminBannedUserMessage, AdminConfig, AdminPlugin, AnonymousPlugin, EmailPasswordPlugin,
    SessionManagementPlugin, TwoFactorPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use better_auth_core::store::UserStore;
use better_auth_core::{AuthUser, CreateUser};
use better_auth_seaorm::DatabaseConnection;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;

struct CallbackAnonymousIdentity;
#[async_trait::async_trait]
impl better_auth::plugins::anonymous::AnonymousIdentity for CallbackAnonymousIdentity {
    async fn email(&self) -> AuthResult<Option<String>> {
        Ok(Some("callback-anonymous@fixture.test".into()))
    }
}
struct ApplicationMetadata;
#[async_trait::async_trait]
impl better_auth_seaorm::DatabaseHooks<TestSchema, crate::backend::Backend>
    for ApplicationMetadata
{
    async fn before_create_user(
        &self,
        input: &mut CreateUser,
        _context: &crate::backend::HookContext<'_>,
    ) -> AuthResult<better_auth_seaorm::HookControl> {
        input.metadata = Some(json!({"supportCode":"private-fixture-code"}));
        Ok(better_auth_seaorm::HookControl::Continue)
    }
}
struct ApplicationMessage {
    profile: &'static str,
    events: Arc<Mutex<Vec<Value>>>,
}
#[async_trait::async_trait]
impl AdminBannedUserMessage<Model> for ApplicationMessage {
    async fn message(&self, user: &Model) -> AuthResult<String> {
        self.events.lock().await.push(json!({"profile":self.profile,"userId":user.id(),"email":user.email(),"name":user.name(),"role":user.role(),"banned":user.banned(),"banReason":user.ban_reason(),"banExpires":user.ban_expires(),"metadata":user.metadata()}));
        if self.profile.starts_with("admin-banned-message-error")
            && user.ban_reason() == Some("ordinary callback failure")
        {
            return Err(AuthError::internal("private callback failure details"));
        }
        if self.profile.starts_with("admin-banned-message-error")
            && user.ban_reason() == Some("server application ban")
        {
            return Err(AuthError::Upstream {
                status: 500,
                code: "APPLICATION_BAN_MESSAGE_UNAVAILABLE",
                message: "configured message unavailable",
            });
        }
        if self.profile.starts_with("admin-banned-message-error") {
            return Err(AuthError::Upstream {
                status: 400,
                code: "APPLICATION_BAN_MESSAGE_REFUSED",
                message: "configured message refused",
            });
        }
        let code = user
            .metadata()
            .get("supportCode")
            .and_then(Value::as_str)
            .ok_or_else(|| AuthError::internal("Stored support code missing"))?;
        Ok(format!(
            "{}:{}",
            code,
            user.ban_reason().unwrap_or_default()
        ))
    }
}
#[derive(Clone)]
struct FixtureState {
    store: Arc<crate::backend::Store<TestSchema>>,
    events: Arc<Mutex<Vec<Value>>>,
}
#[derive(Deserialize)]
struct EventQuery {
    email: String,
    profile: String,
}
async fn events(
    State(state): State<FixtureState>,
    Query(query): Query<EventQuery>,
) -> AuthResult<Json<Value>> {
    let user = state.store.get_user_by_email(&query.email).await?;
    let events: Vec<_> = state
        .events
        .lock()
        .await
        .iter()
        .filter(|event| {
            event["email"] == query.email
                && event["profile"] == query.profile
                && user
                    .as_ref()
                    .is_some_and(|user| event["userId"].as_str() == Some(user.id().as_ref()))
        })
        .cloned()
        .collect();
    Ok(Json(
        json!({"user":user.map(|u|json!({"userId":u.id(),"metadata":u.metadata()})),"events":events}),
    ))
}
pub(crate) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<Router> {
    let events_log = Arc::new(Mutex::new(Vec::new()));
    let mut router = Router::new();
    for name in [
        "admin-banned-message",
        "admin-banned-message-error",
        "admin-banned-message-error-cache",
    ] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut config = config.clone().base_path(&path);
        if name.ends_with("-cache") {
            config = config.session_cookie_cache(CookieCacheConfig {
                enabled: true,
                ..Default::default()
            });
        }
        let builder = AuthBuilder::<TestSchema>::new(config.clone())
            .store(
                crate::backend::store::<TestSchema>(config, database.clone())
                    .hook(ApplicationMetadata),
            )
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new().enable_username(true))
            .plugin(SessionManagementPlugin::new())
            .plugin(TwoFactorPlugin::new())
            .plugin(
                AdminPlugin::with_config(AdminConfig {
                    default_role: "admin".into(),
                    allow_impersonating_admins: true,
                    ..Default::default()
                })
                .banned_user_message_callback::<Model, _>(ApplicationMessage {
                    profile: name,
                    events: events_log.clone(),
                }),
            );
        let builder = if name.ends_with("-cache") {
            builder.plugin(AnonymousPlugin::with_config(
                better_auth::plugins::anonymous::AnonymousConfig {
                    identity: Some(Arc::new(CallbackAnonymousIdentity)),
                    ..Default::default()
                },
            ))
        } else {
            builder
        };
        let auth = Arc::new(builder.build().await?);
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    Ok(router.merge(
        Router::new()
            .route("/__test/admin-banned-message-events", get(events))
            .with_state(FixtureState {
                store: Arc::new(crate::backend::store(config.clone(), database)),
                events: events_log,
            }),
    ))
}
