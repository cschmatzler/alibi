//! Stored application fields and awaited callbacks on the real admin lifecycle.
use crate::TestSchema;
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::{
    AdminBannedUserMessage, AdminConfig, AdminPlugin, EmailPasswordPlugin, SessionManagementPlugin,
    TwoFactorPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use better_auth_core::store::UserStore;
use better_auth_core::{AuthUser, CreateUser};
use better_auth_seaorm::store::entities::user::Model;
use better_auth_seaorm::{DatabaseConnection, SeaOrmStore};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;

struct ApplicationMetadata;
#[async_trait::async_trait]
impl better_auth_seaorm::SeaOrmHooks<TestSchema> for ApplicationMetadata {
    async fn before_create_user(
        &self,
        input: &mut CreateUser,
        _context: &better_auth_seaorm::SeaOrmHookContext<'_>,
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
        if self.profile == "admin-banned-message-error"
            && user.ban_reason() == Some("server application ban")
        {
            return Err(AuthError::Upstream {
                status: 500,
                code: "APPLICATION_BAN_MESSAGE_UNAVAILABLE",
                message: "configured message unavailable",
            });
        }
        if self.profile == "admin-banned-message-error" {
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
    store: Arc<SeaOrmStore<TestSchema>>,
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
pub(super) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<Router> {
    let events_log = Arc::new(Mutex::new(Vec::new()));
    let mut router = Router::new();
    for name in ["admin-banned-message", "admin-banned-message-error"] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let config = config.clone().base_path(&path);
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(
                    SeaOrmStore::<TestSchema>::new(config, database.clone())
                        .hook(ApplicationMetadata),
                )
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new())
                .plugin(SessionManagementPlugin::new())
                .plugin(TwoFactorPlugin::new())
                .plugin(
                    AdminPlugin::with_config(AdminConfig {
                        default_role: "admin".into(),
                        allow_impersonating_admins: true,
                        ..Default::default()
                    })
                    .banned_user_message_callback::<Model, _>(
                        ApplicationMessage {
                            profile: name,
                            events: events_log.clone(),
                        },
                    ),
                )
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    Ok(router.merge(
        Router::new()
            .route("/__test/admin-banned-message-events", get(events))
            .with_state(FixtureState {
                store: Arc::new(SeaOrmStore::new(config.clone(), database)),
                events: events_log,
            }),
    ))
}
