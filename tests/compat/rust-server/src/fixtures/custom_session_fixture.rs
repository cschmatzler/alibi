//! Real application response transform composed with multiple sessions and JWT.
use crate::session_field_model::ApplicationSchema as TestSchema;
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::jwt::JwtPlugin;
use alibi::plugins::{
    CustomSessionPlugin, EmailPasswordPlugin, MultiSessionPlugin, SessionTransform,
};
use alibi::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use alibi::{AuthContext, AuthRequest};
use alibi::seaorm::sea_orm::DatabaseConnection;
use async_trait::async_trait;
use axum::Router;
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
struct TokenHook(Arc<AtomicUsize>);
#[async_trait]
impl alibi::seaorm::DatabaseHooks<TestSchema, crate::backend::Backend> for TokenHook {
    async fn before_create_session(
        &self,
        session: &mut alibi::prelude::CreateSession,
        _: &crate::backend::HookContext<'_>,
    ) -> AuthResult<alibi::seaorm::HookControl> {
        session.token = Some(format!(
            "custom{:027}",
            self.0.fetch_add(1, Ordering::SeqCst) + 1
        ));
        Ok(alibi::seaorm::HookControl::Continue)
    }
}

struct DeviceListApplication {
    policy: std::sync::Mutex<(String, String, String)>,
    events: std::sync::Mutex<Vec<Value>>,
    entered: AtomicUsize,
    release: tokio::sync::watch::Sender<bool>,
    both: tokio::sync::watch::Sender<bool>,
}
impl Default for DeviceListApplication {
    fn default() -> Self {
        Self {
            policy: std::sync::Mutex::new(("idle".into(), String::new(), String::new())),
            events: std::sync::Mutex::new(Vec::new()),
            entered: AtomicUsize::new(0),
            release: tokio::sync::watch::channel(true).0,
            both: tokio::sync::watch::channel(true).0,
        }
    }
}
async fn wait_projection(signal: &tokio::sync::watch::Sender<bool>) -> AuthResult<()> {
    let mut receiver = signal.subscribe();
    while !*receiver.borrow_and_update() {
        receiver
            .changed()
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
    }
    Ok(())
}
impl DeviceListApplication {
    async fn work(
        &self,
        session: &Value,
        request: &AuthRequest,
        context: &AuthContext<TestSchema>,
    ) -> AuthResult<()> {
        let (mode, held, reject) = self.policy.lock().unwrap().clone();
        if mode == "idle" || request.path() != "/multi-session/list-device-sessions" {
            return Ok(());
        }
        let token = session
            .pointer("/session/token")
            .and_then(Value::as_str)
            .unwrap();
        let user_id = session.pointer("/user/id").and_then(Value::as_str).unwrap();
        let receipt = json!({"path":request.path(),"method":format!("{:?}",request.method()).to_uppercase(),"marker":request.header("x-device-list-marker")});
        self.events
            .lock()
            .unwrap()
            .push(json!({"stage":"started","token":token,"userId":user_id,"request":receipt}));
        if self.entered.fetch_add(1, Ordering::SeqCst) + 1 == 2 {
            self.both.send_replace(true);
        }
        if token == held {
            wait_projection(&self.release).await?;
            if mode != "success" {
                let retained =
                    alibi::hooks::current_request_hook_context().ok_or_else(|| {
                        AuthError::internal("Original device list request context was lost")
                    })?;
                let endpoint = alibi::endpoint::current_endpoint_call_context()
                    .and_then(|context| context.path().map(str::to_owned))
                    .unwrap_or_else(|| retained.path.clone());
                let marker = retained.headers.get("x-device-list-marker").cloned();
                let name = format!("{}@{}", marker.clone().unwrap_or_default(), endpoint);
                let user = context
                    .database
                    .update_user(
                        user_id,
                        alibi::UpdateUser {
                            name: Some(name),
                            ..Default::default()
                        },
                    )
                    .await?;
                use alibi::AuthUser;
                self.events.lock().unwrap().push(json!({"stage":"updated","token":token,"userId":user.id(),"request":{"path":endpoint,"method":format!("{:?}",retained.method).to_uppercase(),"marker":marker},"name":user.name()}));
            } else {
                self.events.lock().unwrap().push(
                    json!({"stage":"completed","token":token,"userId":user_id,"request":receipt}),
                );
            }
        } else if token == reject {
            wait_projection(&self.both).await?;
            if mode != "success" {
                self.events.lock().unwrap().push(
                    json!({"stage":"rejected","token":token,"userId":user_id,"request":receipt}),
                );
                if mode == "coded" {
                    return Err(AuthError::Api {
                        status: 403,
                        code: Some("DEVICE_LIST_REJECTED".into()),
                        message: "Application device projection rejected".into(),
                    });
                }
                return Err(AuthError::internal("Private device projection failure"));
            }
            self.events.lock().unwrap().push(
                json!({"stage":"completed","token":token,"userId":user_id,"request":receipt}),
            );
        }
        Ok(())
    }
}
struct ApplicationTransform {
    calls: Arc<AtomicUsize>,
    record: bool,
    application: Option<Arc<DeviceListApplication>>,
}
#[async_trait]
impl SessionTransform<TestSchema> for ApplicationTransform {
    async fn transform(
        &self,
        session: Value,
        request: &AuthRequest,
        context: &AuthContext<TestSchema>,
    ) -> AuthResult<Value> {
        let count = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        match request.header("x-custom-session").map(String::as_str) {
            Some("error") => {
                return Err(AuthError::Api {
                    status: 403,
                    code: Some("CUSTOM_SESSION_DENIED".into()),
                    message: "Application session denied".into(),
                });
            }
            Some("ordinary") => return Err(AuthError::internal("Application session failed")),
            Some("null") => return Ok(Value::Null),
            Some("filtered") => {
                return Ok(
                    json!({"userId":session.pointer("/user/id"),"label":session.pointer("/user/name")}),
                );
            }
            _ => {}
        }
        if let Some(application) = &self.application {
            application.work(&session, request, context).await?;
        }
        let id = session
            .pointer("/user/id")
            .and_then(Value::as_str)
            .ok_or_else(|| AuthError::internal("Missing authenticated owner"))?;
        let user = context
            .database
            .get_user_by_id(id)
            .await?
            .ok_or_else(|| AuthError::internal("Authenticated user is missing"))?;
        let mut session = session;
        let object = session
            .as_object_mut()
            .ok_or_else(|| AuthError::internal("Invalid session projection"))?;
        use alibi::prelude::AuthUser;
        drop(object.insert(
            "application".into(),
            json!({"userId":user.id(),"label":user.name(),"path":request.path()}),
        ));
        if self.record {
            object.get_mut("application").unwrap()["calls"] = json!(count);
        }
        Ok(session)
    }
}

pub(crate) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
    counter: Arc<AtomicUsize>,
) -> AuthResult<Router> {
    let mut router = Router::new();
    let application = Arc::new(DeviceListApplication::default());
    for name in [
        "custom-session-gated",
        "custom-session-list-default",
        "custom-session-list-false",
        "custom-session",
        "custom-session-jwt",
        "custom-session-deferred",
        "custom-session-core-error",
    ] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut config = config.clone().base_path(&path);
        config.session.defer_session_refresh = name.ends_with("-deferred");
        drop(
            config.session.additional_fields.insert(
                "label".into(),
                alibi::field_policy::FieldConfig::new(json!({"type":"string"}))
                    .default_value(json!("custom-public-label")),
            ),
        );
        drop(
            config.session.additional_fields.insert(
                "hidden".into(),
                alibi::field_policy::FieldConfig::new(json!({"type":"string"}))
                    .default_value(json!("custom-server-secret"))
                    .hidden(),
            ),
        );
        if name.ends_with("-core-error") {
            drop(config.session.additional_fields.insert(
                "label".into(),
                alibi::field_policy::FieldConfig::new(json!({"type":"string"})).transform_output(
                    |_| async { Err(AuthError::internal("Configured session projection failed")) },
                ),
            ));
        }
        let builder = AuthBuilder::<TestSchema>::new(config.clone())
            .store(
                crate::backend::store::<TestSchema>(config, database.clone())
                    .hook(TokenHook(counter.clone())),
            )
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin({
                let plugin = CustomSessionPlugin::new(ApplicationTransform {
                    calls: Arc::new(AtomicUsize::new(0)),
                    record: name.starts_with("custom-session-list-"),
                    application: (name == "custom-session-gated").then(|| application.clone()),
                });
                match name {
                    "custom-session-list-default" => plugin,
                    "custom-session-list-false" => plugin.mutate_device_sessions(false),
                    _ => plugin.mutate_device_sessions(true),
                }
            })
            .plugin(EmailPasswordPlugin::new().enable_username(false))
            .plugin(MultiSessionPlugin::new());
        let builder = if !name.ends_with("-jwt") && !name.ends_with("-deferred") {
            builder
        } else {
            builder.plugin(JwtPlugin::new())
        };
        let auth = Arc::new(builder.build().await?);
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let read = application.clone();
    router = router.route(
        "/__test/custom-session-work",
        axum::routing::get(move || {
            let app = read.clone();
            async move { axum::Json(json!({"events":*app.events.lock().unwrap()})) }
        })
        .post(move |axum::Json(body): axum::Json<Value>| {
            let app = application.clone();
            async move {
                match body["operation"].as_str().unwrap() {
                    "arm" => {
                        *app.policy.lock().unwrap() = (
                            body["mode"].as_str().unwrap().to_owned(),
                            body["heldToken"].as_str().unwrap().to_owned(),
                            body["rejectToken"].as_str().unwrap().to_owned(),
                        );
                        app.events.lock().unwrap().clear();
                        app.entered.store(0, Ordering::SeqCst);
                        app.release.send_replace(false);
                        app.both.send_replace(false);
                    }
                    "release" => {
                        app.release.send_replace(true);
                    }
                    "restore" => {
                        app.release.send_replace(true);
                        app.both.send_replace(true);
                        app.policy.lock().unwrap().0 = "idle".into();
                    }
                    _ => {}
                }
                axum::Json(json!({"events":*app.events.lock().unwrap()}))
            }
        }),
    );
    Ok(router)
}
