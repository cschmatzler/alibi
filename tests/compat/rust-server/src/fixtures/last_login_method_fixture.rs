//! Application callbacks and physical tracking state for actual public login flows.
use crate::{OAuthRefreshMode, SocialProfile, TestSchema};
use alibi::plugins::siwe::{
    Eip191Verifier, SiweCallbackResult, SiweConfig, SiweNonceProvider, SiwePlugin,
};
use alibi::{
    AuthBuilder, AuthConfig, AuthError, AuthResult,
    integrations::axum::AxumIntegration,
    middleware::RateLimitConfig,
    plugins::{
        AnonymousPlugin, BeforeStoreLastLoginMethodCookie, EmailPasswordPlugin,
        LastLoginMethodConfig, LastLoginMethodContext, LastLoginMethodPlugin, MultiSessionPlugin,
        PasskeyPlugin, ResolveLastLoginMethod, SessionManagementPlugin,
        anonymous::{AnonymousConfig, AnonymousIdentity},
        email_otp::{EmailOtpConfig, EmailOtpDelivery, EmailOtpPlugin, SendEmailOtp},
        magic_link::{MagicLinkConfig, MagicLinkDelivery, MagicLinkPlugin, SendMagicLink},
    },
};
use alibi::{AuthRequest, HttpMethod};
use alibi::seaorm::{
    DatabaseConnection, DatabaseHooks, HookControl,
    sea_orm::{ConnectionTrait, DbBackend, Statement},
};
use axum::{Json, Router, routing::get};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

fn callback_value(value: &alibi::utils::json::JsValue) -> Value {
    use alibi::utils::json::JsValue;
    match value {
        JsValue::Number(number)
            if !number.is_finite() || (*number == 0.0 && number.is_sign_negative()) =>
        {
            json!({"$number":if number.is_nan(){"NaN"}else if *number == f64::INFINITY{"Infinity"}else if *number == f64::NEG_INFINITY{"-Infinity"}else{"-0"}})
        }
        JsValue::Array(items) => Value::Array(items.iter().map(callback_value).collect()),
        JsValue::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(name, item)| (name.clone(), callback_value(item)))
                .collect(),
        ),
        other => serde_json::to_value(other).unwrap_or(Value::Null),
    }
}
#[derive(Clone, Default)]
struct State {
    events: Arc<Mutex<Vec<Value>>>,
    deliveries: Arc<Mutex<HashMap<String, Value>>>,
    sequence: Arc<AtomicUsize>,
}
#[derive(Clone)]
struct Application {
    state: State,
    mode: &'static str,
}
impl Application {
    fn observe(
        &self,
        kind: &str,
        context: &LastLoginMethodContext,
        method: Option<&str>,
    ) -> AuthResult<()> {
        let header =
            |name: &str| {
                context.request.headers.iter().find_map(|(key, value)| {
                    key.eq_ignore_ascii_case(name).then_some(value.as_str())
                })
            };
        let new_session = context
            .new_session
            .as_ref()
            .map(|session| json!({"user":session.user,"session":session.session}));
        let mut event = json!({"kind":kind,"path":context.route_path,"params":context.params,"requestPath":context.request.path,"method":match context.request.method {HttpMethod::Get=>"GET",HttpMethod::Post=>"POST",_=>"OTHER"},"body":context.body.as_ref().map(callback_value),"query":context.request.query,"probe":header("x-last-login-probe"),"newSession":new_session,"loginMethod":method});
        if kind == "cookie" && header("x-last-login-body") == Some("true") {
            event["requestBody"] = context
                .request
                .body
                .as_deref()
                .map(|body| String::from_utf8_lossy(body).into_owned())
                .into();
        }
        self.state
            .events
            .lock()
            .map_err(|_| AuthError::internal("observer lock"))?
            .push(event);

        Ok(())
    }
    fn deliver(&self, key: String, value: Value) -> AuthResult<()> {
        self.state
            .deliveries
            .lock()
            .map_err(|_| AuthError::internal("delivery lock"))?
            .insert(key, value);
        Ok(())
    }
}
impl ResolveLastLoginMethod for Application {
    fn resolve(&self, context: &LastLoginMethodContext) -> AuthResult<Option<String>> {
        self.observe("resolve", context, None)?;
        let header = |name: &str| {
            context
                .request
                .headers
                .iter()
                .find_map(|(key, value)| key.eq_ignore_ascii_case(name).then_some(value))
        };
        if self.mode == "resolver-error"
            && header("x-last-login-resolver-error").is_some_and(|value| value == "true")
        {
            return Err(AuthError::internal("application resolver failed"));
        }
        if self.mode == "custom" && header("x-last-login-body").is_some_and(|value| value == "true")
        {
            let extra = context
                .body
                .as_ref()
                .and_then(|body| body.get("extra"))
                .ok_or_else(|| AuthError::internal("missing actual callback input"))?;
            let overflow = extra
                .get("overflow")
                .and_then(alibi::utils::json::JsValue::as_f64);
            let zero = extra
                .get("zero")
                .and_then(alibi::utils::json::JsValue::as_f64);
            return Ok(Some(format!(
                "body:{}:{}",
                if overflow == Some(f64::INFINITY) {
                    "Infinity"
                } else {
                    "other"
                },
                if zero.is_some_and(|value| value == 0.0 && value.is_sign_negative()) {
                    "-0"
                } else {
                    "other"
                }
            )));
        }
        Ok((matches!(self.mode, "custom" | "update-error"))
            .then(|| header("x-last-login-method").cloned())
            .flatten())
    }
}
#[async_trait::async_trait]
impl alibi::AuthPlugin<TestSchema> for Application {
    fn name(&self) -> &'static str {
        "tracking-application"
    }
    fn routes(&self) -> Vec<alibi::AuthRoute> {
        Vec::new()
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &alibi::AuthContext<TestSchema>,
    ) -> AuthResult<Option<alibi::AuthResponse>> {
        Ok(None)
    }
    async fn on_init(&self, ctx: &mut alibi::AuthInitContext<TestSchema>) -> AuthResult<()> {
        if self.mode == "transform" {
            ctx.register_user_update_transform(|_, mut update| {
                if let Some(Some(method)) = update.last_login_method {
                    update.last_login_method = Some(Some(format!("stored:{method}")));
                }
                Ok(update)
            });
        }
        Ok(())
    }
}
#[async_trait::async_trait]
impl DatabaseHooks<TestSchema, crate::backend::Backend> for Application {
    async fn before_create_session(
        &self,
        session: &mut alibi::CreateSession,
        _: &crate::backend::HookContext<'_>,
    ) -> AuthResult<HookControl> {
        if self.mode == "composition" {
            session.token = Some(format!(
                "LastLoginMethodSession{:011}",
                self.state.sequence.fetch_add(1, Ordering::SeqCst) + 1
            ));
        }
        Ok(HookControl::Continue)
    }
}
#[async_trait::async_trait]
impl BeforeStoreLastLoginMethodCookie for Application {
    async fn before_store(
        &self,
        context: &LastLoginMethodContext,
        method: &str,
    ) -> AuthResult<bool> {
        tokio::task::yield_now().await;
        self.observe("cookie", context, Some(method))?;
        if self.mode == "cookie-error" {
            return Err(AuthError::internal("application consent failed"));
        }
        Ok(self.mode != "denied")
    }
}
#[async_trait::async_trait]
impl SiweNonceProvider for Application {
    async fn get_nonce(&self) -> SiweCallbackResult<String> {
        Ok(format!(
            "LastLoginMethodNonce{:016}",
            self.state.sequence.fetch_add(1, Ordering::SeqCst) + 1
        ))
    }
}
#[async_trait::async_trait]
impl AnonymousIdentity for Application {
    async fn email(&self) -> AuthResult<Option<String>> {
        Ok(Some(format!(
            "last-login-anonymous-{}@fixture.test",
            self.state.sequence.fetch_add(1, Ordering::SeqCst) + 1
        )))
    }
    async fn name(&self, _request: &AuthRequest) -> AuthResult<Option<String>> {
        Ok(Some("Anonymous Owner".into()))
    }
}
#[async_trait::async_trait]
impl SendMagicLink for Application {
    async fn send(
        &self,
        delivery: &MagicLinkDelivery,
        _context: &alibi::CallbackContext,
    ) -> AuthResult<()> {
        self.deliver(format!("magic:{}",delivery.email),json!({"email":delivery.email,"url":delivery.url,"token":delivery.token,"metadata":delivery.metadata}))
    }
}
#[async_trait::async_trait]
impl SendEmailOtp for Application {
    async fn send(
        &self,
        delivery: &EmailOtpDelivery,
        _context: &alibi::CallbackContext,
    ) -> AuthResult<()> {
        self.deliver(
            format!("{}:{}", delivery.otp_type.as_str(), delivery.email),
            json!({"email":delivery.email,"otp":delivery.otp,"type":delivery.otp_type.as_str()}),
        )
    }
}
pub(crate) async fn router(
    base: &AuthConfig,
    database: DatabaseConnection,
    port: u16,
    social: Arc<tokio::sync::Mutex<SocialProfile>>,
    valid: Arc<tokio::sync::Mutex<bool>>,
    refresh: Arc<tokio::sync::Mutex<OAuthRefreshMode>>,
) -> AuthResult<Router> {
    let state = State::default();
    let mut router = Router::new();
    for mode in [
        "default",
        "database",
        "custom",
        "denied",
        "cookie-error",
        "resolver-error",
        "update-error",
        "transform",
        "policy",
        "composition",
        "nan",
        "negative",
        "excess",
    ] {
        let application = Arc::new(Application {
            state: state.clone(),
            mode,
        });
        let mut login = LastLoginMethodConfig {
            store_in_database: mode != "default",
            resolver: Some(application.clone()),
            before_store_cookie: Some(application.clone()),
            ..Default::default()
        };
        if mode == "custom" {
            login.cookie_name = "fixture.last_login_method".into();
            login.max_age = 123.9;
        }
        if mode == "nan" {
            login.max_age = f64::NAN;
        }
        if mode == "negative" {
            login.max_age = f64::NEG_INFINITY;
        }
        if mode == "excess" {
            login.max_age = f64::INFINITY;
        }
        let path = format!("/__test/profiles/last-login-{mode}/api/auth");
        let mut config = base.clone().base_path(&path);
        if mode == "policy" {
            config.session.cookie_same_site = alibi::config::SameSite::Strict;
            login.cookie_name = "policy.last_login_method".into();
            login.max_age = 0.0;
        }
        let mut builder = AuthBuilder::<TestSchema>::new(config.clone())
            .store(
                crate::backend::store::<TestSchema>(config, database.clone())
                    .with_hooks(vec![application.clone()]),
            )
            .plugin(application.as_ref().clone())
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(
                EmailPasswordPlugin::new()
                    .enable_signup(true)
                    .enable_username(true),
            )
            .plugin(SessionManagementPlugin::new())
            .plugin(SiwePlugin::new(SiweConfig::new(
                "last-login.fixture",
                application.clone(),
                Arc::new(Eip191Verifier),
            )))
            .plugin(PasskeyPlugin::new())
            .plugin(AnonymousPlugin::with_config(AnonymousConfig {
                identity: Some(application.clone()),
                ..Default::default()
            }))
            .plugin(EmailOtpPlugin::new(EmailOtpConfig {
                send_verification_otp: Some(application.clone()),
                ..Default::default()
            }))
            .plugin(MagicLinkPlugin::new(MagicLinkConfig {
                send_magic_link: Some(application.clone()),
                ..Default::default()
            }))
            .plugin(crate::mock_oauth_plugin(
                port,
                social.clone(),
                valid.clone(),
                refresh.clone(),
            ));
        if mode == "composition" {
            builder = builder.plugin(MultiSessionPlugin::new());
        }
        let auth = Arc::new(
            builder
                .plugin(LastLoginMethodPlugin::with_config(login))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let observed = state.clone();
    let read_db = database.clone();
    router=router.route("/__test/last-login-method",get(move || {let state=observed.clone();let database=read_db.clone();async move {
        let rows=database.query_all_raw(Statement::from_string(DbBackend::Sqlite,"SELECT id,email,name,last_login_method FROM users ORDER BY email,id")).await.map_err(|error|AuthError::internal(error.to_string()))?;
        let mut users=Vec::new();for row in rows {users.push(json!({"id":row.try_get::<String>("","id").map_err(|error|AuthError::internal(error.to_string()))?,"email":row.try_get::<String>("","email").map_err(|error|AuthError::internal(error.to_string()))?,"name":row.try_get::<Option<String>>("","name").map_err(|error|AuthError::internal(error.to_string()))?,"lastLoginMethod":row.try_get::<Option<String>>("","last_login_method").map_err(|error|AuthError::internal(error.to_string()))?}));}
        let events=state.events.lock().map_err(|_|AuthError::internal("observer lock"))?.clone();Ok::<_,AuthError>(Json(json!({"events":events,"users":users})))
    }}).post(move |Json(body):Json<Value>| {let state=state.clone();let database=database.clone();async move {
        match body["action"].as_str().unwrap_or_default() {
            "clear"=>state.events.lock().map_err(|_|AuthError::internal("observer lock"))?.clear(),
            "reset"=>{state.events.lock().map_err(|_|AuthError::internal("observer lock"))?.clear();state.deliveries.lock().map_err(|_|AuthError::internal("delivery lock"))?.clear();state.sequence.store(0,Ordering::SeqCst);},
            "delivery"=>return Ok::<_,AuthError>(Json(state.deliveries.lock().map_err(|_|AuthError::internal("delivery lock"))?.get(body["key"].as_str().unwrap_or_default()).cloned().unwrap_or(Value::Null))),
            "update-error"=>{database.execute_raw(Statement::from_string(DbBackend::Sqlite,"CREATE TRIGGER last_login_update_error BEFORE UPDATE OF last_login_method ON users BEGIN SELECT RAISE(ABORT,'application update rejected'); END")).await.map_err(|error|AuthError::internal(error.to_string()))?;},
            "restore-updates"=>{database.execute_raw(Statement::from_string(DbBackend::Sqlite,"DROP TRIGGER IF EXISTS last_login_update_error")).await.map_err(|error|AuthError::internal(error.to_string()))?;},
            _=>{}
        } Ok(Json(json!({"changed":true})))
    }}));
    Ok(router)
}
