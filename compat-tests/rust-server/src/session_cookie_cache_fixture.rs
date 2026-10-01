//! Real compact-cache profiles. Application controls never enter public auth routes.
use crate::session_field_model::{application_session, ApplicationSchema};
use async_trait::async_trait;
use axum::{routing::post, Json, Router};
use better_auth::field_policy::FieldConfig;
use better_auth::plugins::anonymous::{
    AnonymousConfig, AnonymousIdentity, AnonymousLink, LinkAnonymousAccount,
};
use better_auth::plugins::{
    AccountManagementPlugin, AnonymousPlugin, EmailPasswordPlugin, OrganizationPlugin,
    PasswordManagementPlugin, SessionManagementPlugin,
};
use better_auth::{
    integrations::axum::AxumIntegration, middleware::RateLimitConfig, AuthBuilder, AuthConfig,
    AuthError, AuthResult,
};
use better_auth_core::{
    AuthRequest, CacheVersionContext, CookieCacheConfig, CookieCacheVersion,
    CookieCacheVersionResolver, UpdateUser,
};
use better_auth_seaorm::{DatabaseConnection, SeaOrmStore};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
#[derive(Default)]
struct State {
    version: String,
    failure: bool,
    sequence: usize,
    events: Vec<Value>,
}
struct Application {
    mode: &'static str,
    state: Arc<Mutex<State>>,
}
#[async_trait]
impl CookieCacheVersionResolver for Application {
    async fn resolve(&self, context: &CacheVersionContext) -> AuthResult<String> {
        tokio::task::yield_now().await;
        let mut session = serde_json::to_value(context.session())?;
        if let Some(raw) = context.stored_session::<application_session::Model>() {
            session
                .as_object_mut()
                .ok_or_else(|| AuthError::internal("Expected session object"))?
                .insert("hidden".into(), json!(raw.hidden));
        }
        let mut state = self.state.lock().expect("cache fixture receipt lock");
        state
            .events
            .push(json!({"mode":self.mode,"session":session,"user":context.user()}));
        if state.failure && context.user().is_anonymous != Some(true) {
            return Err(if self.mode == "version-api" {
                AuthError::Api {
                    status: 500,
                    code: Some("APPLICATION_CACHE_DENIED".into()),
                    message: "Configured cache version rejected issuance".into(),
                }
            } else {
                AuthError::internal("Configured cache version rejected issuance")
            });
        }
        Ok(state.version.clone())
    }
}
#[async_trait]
impl AnonymousIdentity for Application {
    async fn email(&self) -> AuthResult<Option<String>> {
        let mut state = self.state.lock().expect("cache fixture identity lock");
        state.sequence += 1;
        Ok(Some(format!(
            "cache-anonymous-{}-{}@fixture.test",
            self.mode, state.sequence
        )))
    }
    async fn name(&self, _request: &AuthRequest) -> AuthResult<Option<String>> {
        Ok(Some("Cache Anonymous".into()))
    }
}
#[async_trait]
impl LinkAnonymousAccount for Application {
    async fn link(&self, accounts: &AnonymousLink, _request: &AuthRequest) -> AuthResult<()> {
        tokio::task::yield_now().await;
        self.state.lock().expect("cache fixture receipt lock").events.push(json!({"mode":self.mode,"link":{"anonymousUser":{"user":accounts.anonymous_user,"session":accounts.anonymous_session},"newUser":{"user":accounts.new_user,"session":accounts.new_session}}}));
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Control {
    mode: String,
    action: String,
    version: Option<String>,
    failure: Option<bool>,
    user_id: Option<String>,
    token: Option<String>,
    name: Option<String>,
    email: Option<String>,
}
pub(super) async fn router(base: &AuthConfig, db: DatabaseConnection) -> AuthResult<Router> {
    let mut router = Router::new();
    let mut profiles = HashMap::new();
    for mode in [
        "standard",
        "disabled",
        "version",
        "version-api",
        "version-ordinary",
        "zero",
        "nan",
        "fractional",
        "negative",
        "infinite",
        "negative-infinite",
        "date-version",
    ] {
        let state = Arc::new(Mutex::new(State {
            version: "1".into(),
            ..Default::default()
        }));
        let application = Arc::new(Application {
            mode,
            state: state.clone(),
        });
        let path = format!("/__test/profiles/session-cache-{mode}/api/auth");
        let max_age = match mode {
            "zero" => 0.0,
            "nan" => f64::NAN,
            "fractional" => 0.5,
            "negative" => -1.0,
            "infinite" => f64::INFINITY,
            "negative-infinite" => f64::NEG_INFINITY,
            _ => 300.0,
        };
        let version = if mode.starts_with("version") {
            CookieCacheVersion::Resolver(application.clone())
        } else {
            CookieCacheVersion::Literal(if mode == "date-version" {
                "2026-10-01T00:00:00.000Z".into()
            } else {
                "1".into()
            })
        };
        let mut config = base
            .clone()
            .base_path(&path)
            .session_cookie_cache(CookieCacheConfig {
                enabled: mode != "disabled",
                max_age,
                version: Some(version),
                ..Default::default()
            });
        _ = config.session.additional_fields.insert(
            "hidden".into(),
            FieldConfig::new(json!({"type":"string"}))
                .default_value(json!("cache-server-secret"))
                .hidden(),
        );
        _ = config.session.additional_fields.insert(
            "label".into(),
            FieldConfig::new(json!({"type":"string"})).default_value(json!("cache-public-label")),
        );
        let auth = Arc::new(
            AuthBuilder::<ApplicationSchema>::new(config.clone())
                .store(SeaOrmStore::<ApplicationSchema>::new(config, db.clone()))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(SessionManagementPlugin::new())
                .plugin(AccountManagementPlugin::new())
                .plugin(PasswordManagementPlugin::new())
                .plugin(OrganizationPlugin::new())
                .plugin(AnonymousPlugin::with_config(AnonymousConfig {
                    identity: Some(application.clone()),
                    on_link_account: Some(application),
                    ..Default::default()
                }))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth.clone()));
        profiles.insert(mode.to_string(), (auth, state));
    }
    Ok(router.route(
        "/__test/session-cookie-cache/control",
        post(move |Json(control): Json<Control>| {
            let profiles = profiles.clone();
            async move {
                let Some((auth, state)) = profiles.get(&control.mode) else {
                    return Err(axum::http::StatusCode::BAD_REQUEST);
                };
                match control.action.as_str() {
                    "reset" => {
                        let mut state = state.lock().expect("cache fixture reset lock");
                        *state = State {
                            version: "1".into(),
                            ..Default::default()
                        };
                    }
                    "policy" => {
                        let mut state = state.lock().expect("cache fixture policy lock");
                        if let Some(version) = control.version {
                            state.version = version;
                        }
                        if let Some(failure) = control.failure {
                            state.failure = failure;
                        }
                    }
                    "rename" => {
                        auth.store()
                            .update_user(
                                control
                                    .user_id
                                    .as_deref()
                                    .ok_or(axum::http::StatusCode::BAD_REQUEST)?,
                                UpdateUser {
                                    name: Some(
                                        control.name.ok_or(axum::http::StatusCode::BAD_REQUEST)?,
                                    ),
                                    ..Default::default()
                                },
                            )
                            .await
                            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
                    }
                    "revoke" => {
                        auth.store()
                            .delete_session(
                                control
                                    .token
                                    .as_deref()
                                    .ok_or(axum::http::StatusCode::BAD_REQUEST)?,
                            )
                            .await
                            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
                    }
                    "lookup" => {
                        let user = auth
                            .store()
                            .get_user_by_email(
                                control
                                    .email
                                    .as_deref()
                                    .ok_or(axum::http::StatusCode::BAD_REQUEST)?,
                            )
                            .await
                            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
                        return Ok(Json(
                            json!({"user":user.as_ref().map(|user|auth.context().user_view(user))}),
                        ));
                    }
                    "state" => {}
                    _ => return Err(axum::http::StatusCode::BAD_REQUEST),
                }
                let events = state
                    .lock()
                    .expect("cache fixture observer lock")
                    .events
                    .clone();
                Ok(Json(json!({"events":events})))
            }
        }),
    ))
}
