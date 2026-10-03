//! Real compact-cache profiles. Application controls never enter public auth routes.
use crate::backend::entities::{account, user, verification};
use crate::session_field_model::{ApplicationSchema, application_session};
use async_trait::async_trait;
use axum::{Json, Router, routing::post};
use better_auth::field_policy::FieldConfig;
use better_auth::plugins::anonymous::{
    AnonymousConfig, AnonymousIdentity, AnonymousLink, LinkAnonymousAccount,
};
use better_auth::plugins::email_verification::{EmailVerificationPlugin, SendVerificationEmail};
use better_auth::plugins::jwt::{JwtPlugin, JwtPluginConfig};
use better_auth::plugins::multi_session::MultiSessionPlugin;
use better_auth::plugins::one_time_token::OneTimeTokenPlugin;
use better_auth::plugins::phone_number::{
    PhoneNumberConfig, PhoneNumberPlugin, PhoneNumberVerification, PhoneOtpDelivery,
    PhoneVerificationHook, SendPhoneOtp,
};
use better_auth::plugins::{
    AccountManagementPlugin, AdminConfig, AdminPlugin, AnonymousPlugin, ApiKeyConfig, ApiKeyPlugin,
    DeviceAuthorizationPlugin, EmailPasswordPlugin, OrganizationPlugin, PasskeyPlugin,
    PasswordManagementPlugin, SendTwoFactorOtp, SessionManagementPlugin, TwoFactorPlugin,
    UserManagementPlugin,
};
use better_auth::{
    AuthBuilder, AuthConfig, AuthError, AuthResult, integrations::axum::AxumIntegration,
    middleware::RateLimitConfig,
};
use better_auth_core::{
    AuthRequest, CacheVersionContext, CookieCacheConfig, CookieCacheVersion,
    CookieCacheVersionResolver, UpdateUser,
};
use better_auth_seaorm::DatabaseConnection;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
#[derive(Default)]
struct State {
    version: String,
    failure: bool,
    sequence: usize,
    session_sequence: usize,
    events: Vec<Value>,
}
struct Application {
    mode: &'static str,
    state: Arc<Mutex<State>>,
}
struct SessionTokens(Arc<Mutex<State>>);
#[async_trait]
impl better_auth_seaorm::DatabaseHooks<ApplicationSchema, crate::backend::Backend>
    for SessionTokens
{
    async fn before_create_session(
        &self,
        session: &mut better_auth_core::CreateSession,
        _context: &crate::backend::HookContext<'_>,
    ) -> AuthResult<better_auth_seaorm::HookControl> {
        let mut state = self.0.lock().expect("configured session token policy");
        state.session_sequence += 1;
        session.token = Some(format!("0001{:028}", state.session_sequence));
        Ok(better_auth_seaorm::HookControl::Continue)
    }
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
#[async_trait]
impl SendTwoFactorOtp for Application {
    async fn send(&self, user: &better_auth_core::UserView, otp: &str) -> AuthResult<()> {
        self.state
            .lock()
            .expect("cache OTP receipt lock")
            .events
            .push(json!({"mode":self.mode,"otp":otp,"user":user}));
        Ok(())
    }
}
#[async_trait]
impl SendPhoneOtp for Application {
    async fn send(
        &self,
        delivery: &PhoneOtpDelivery,
        _context: &better_auth_core::CallbackContext,
    ) -> AuthResult<()> {
        self.state.lock().expect("cache phone delivery").events.push(json!({"mode":self.mode,"stage":"phone-delivery","phoneNumber":delivery.phone_number,"code":delivery.code}));
        Ok(())
    }
}
#[async_trait]
impl PhoneVerificationHook for Application {
    async fn verified(
        &self,
        receipt: &PhoneNumberVerification,
        _context: &better_auth_core::CallbackContext,
    ) -> AuthResult<()> {
        self.state.lock().expect("cache phone verification").events.push(json!({"mode":self.mode,"stage":"phone-verified","phoneNumber":receipt.phone_number,"user":receipt.user}));
        Ok(())
    }
}
impl Application {
    fn verification_event(&self, stage: &str, user: Value, extra: Value) -> AuthResult<()> {
        let request=better_auth_core::hooks::current_request_hook_context().map(|context|json!({"method":format!("{:?}",context.method).to_uppercase(),"url":context.url,"marker":context.headers.get("x-lifecycle-marker")}));
        let mut event = json!({"mode":self.mode,"stage":stage,"user":user,"request":request});
        if let Some(extra) = extra.as_object() {
            for (name, value) in extra {
                event[name] = value.clone();
            }
        }
        self.state
            .lock()
            .expect("cache verification receipt")
            .events
            .push(event);
        Ok(())
    }
}
#[async_trait]
impl SendVerificationEmail for Application {
    async fn send(
        &self,
        user: &better_auth_core::UserView,
        url: &str,
        token: &str,
    ) -> AuthResult<()> {
        self.verification_event(
            "verification-mail",
            serde_json::to_value(user)?,
            json!({"url":url,"token":token}),
        )
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
    key: Option<ImportedKey>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportedKey {
    id: String,
    public_key: String,
    private_key: String,
    created_at: chrono::DateTime<chrono::Utc>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    alg: Option<String>,
    crv: Option<String>,
}
pub(crate) async fn router(base: &AuthConfig, db: DatabaseConnection) -> AuthResult<Router> {
    let mut router = Router::new();
    let mut profiles = HashMap::new();
    for mode in [
        "jwt-interactions",
        "jwe-interactions",
        "jwe-old",
        "jwe-retained",
        "jwe-retired",
        "jwt",
        "jwe",
        "managed",
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
        "guards",
        "interactions",
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
        let version = if mode.starts_with("version") || mode.ends_with("interactions") {
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
                strategy: match mode {
                    "jwe" | "jwe-interactions" | "jwe-old" | "jwe-retained" | "jwe-retired" => {
                        better_auth_core::CookieCacheStrategy::Jwe
                    }
                    "jwt" | "jwt-interactions" | "managed" => {
                        better_auth_core::CookieCacheStrategy::Jwt
                    }
                    _ => better_auth_core::CookieCacheStrategy::Compact,
                },
                max_age,
                version: Some(version),
            });
        if matches!(mode, "jwe-old" | "jwe-retained" | "jwe-retired") {
            let keys = if mode == "jwe-old" {
                better_auth_core::ManagedSecrets::new(1, base.current_secret())
            } else {
                better_auth_core::ManagedSecrets::new(
                    2,
                    "cache-managed-new-secret-at-least-32-characters",
                )
            };
            let keys = if mode == "jwe-retained" {
                keys.retain(1, base.current_secret())
            } else {
                keys
            };
            config = config.managed_secrets(keys);
        }
        if mode == "managed" {
            config = config
                .base_url("https://session-cache.fixture.test")
                .trusted_origin(&base.base_url);
            config.session.cookie_secure = false;
        }
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
        let mut store = crate::backend::store::<ApplicationSchema>(config.clone(), db.clone());
        if mode.ends_with("interactions") {
            store = store.hook(SessionTokens(state.clone()));
        }
        let mut builder = AuthBuilder::<ApplicationSchema>::new(config.clone())
            .store(store)
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new().enable_username(false))
            .plugin(SessionManagementPlugin::new())
            .plugin(AccountManagementPlugin::new())
            .plugin(PasswordManagementPlugin::new())
            .plugin(OrganizationPlugin::new())
            .plugin(AnonymousPlugin::with_config(AnonymousConfig {
                identity: Some(application.clone()),
                on_link_account: Some(application.clone()),
                ..Default::default()
            }));
        if mode == "guards" {
            builder = builder
                .plugin(AdminPlugin::with_config(AdminConfig {
                    default_role: "admin".into(),
                    ..Default::default()
                }))
                .plugin(ApiKeyPlugin::with_config(ApiKeyConfig {
                    enable_session_for_api_keys: true,
                    ..Default::default()
                }))
                .plugin(PasskeyPlugin::new())
                .plugin(OneTimeTokenPlugin::new())
                .plugin(DeviceAuthorizationPlugin::new())
                .plugin(
                    UserManagementPlugin::new()
                        .delete_user_enabled(true)
                        .require_delete_verification(false),
                )
                .plugin(PhoneNumberPlugin::new(PhoneNumberConfig {
                    send_otp: Some(application.clone()),
                    callback_on_verification: Some(application.clone()),
                    ..Default::default()
                }));
        }
        if mode.ends_with("interactions") {
            let before = application.clone();
            let after = application.clone();
            builder = builder
                .plugin(
                    EmailVerificationPlugin::new()
                        .auto_sign_in_after_verification(true)
                        .custom_send_verification_email(application.clone())
                        .before_email_verification(Arc::new(move |user| {
                            let app = before.clone();
                            let user = user.clone();
                            Box::pin(async move {
                                app.verification_event(
                                    "before-verification",
                                    serde_json::to_value(user)?,
                                    json!({}),
                                )
                            })
                        }))
                        .after_email_verification(Arc::new(move |user| {
                            let app = after.clone();
                            let user = user.clone();
                            Box::pin(async move {
                                app.verification_event(
                                    "after-verification",
                                    serde_json::to_value(user)?,
                                    json!({}),
                                )
                            })
                        })),
                )
                .plugin(TwoFactorPlugin::new().custom_send_otp(application))
                .plugin(MultiSessionPlugin::new())
                .plugin(JwtPlugin::new());
        }
        if mode == "managed" {
            builder = builder.plugin(JwtPlugin::with_config(JwtPluginConfig {
                session_cookie_cache: true,
                ..Default::default()
            }));
        }
        let auth = Arc::new(builder.build().await?);
        router = router.nest(&path, auth.clone().axum_router().with_state(auth.clone()));
        profiles.insert(mode.to_string(), (auth, state));
    }
    Ok(router.route(
        "/__test/session-cookie-cache/control",
        post(move |Json(control): Json<Control>| {
            let profiles = profiles.clone();
            let db = db.clone();
            async move {
                let Some((auth, state)) = profiles.get(&control.mode) else {
                    return Err(axum::http::StatusCode::BAD_REQUEST);
                };
                match control.action.as_str() {
                    "cache-keys" | "import-cache-key" | "rotate-cache-key" | "retire-cache-key" => {
                        if control.action=="import-cache-key" {
                            let key=control.key.ok_or(axum::http::StatusCode::BAD_REQUEST)?;
                            if auth.store().get_jwk_by_id(&key.id).await.map_err(|_|axum::http::StatusCode::INTERNAL_SERVER_ERROR)?.is_none() {
                                auth.store().create_jwk(better_auth_core::CreateJwk{id:Some(key.id),public_key:key.public_key,private_key:key.private_key,created_at:key.created_at,expires_at:key.expires_at,alg:key.alg,crv:key.crv}).await.map_err(|_|axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
                            }
                        } else if control.action=="rotate-cache-key" {
                            JwtPlugin::new().create_jwk(None,None,auth.context()).await.map_err(|_|axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
                        } else if control.action=="retire-cache-key" {
                            { use better_auth_seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement}; db.execute_raw(Statement::from_sql_and_values(DbBackend::Sqlite, "DELETE FROM jwks WHERE id = ?", [control.token.ok_or(axum::http::StatusCode::BAD_REQUEST)?.into()])).await.map_err(|_|axum::http::StatusCode::INTERNAL_SERVER_ERROR)?; }
                        }
                        let keys=auth.store().list_jwks().await.map_err(|_|axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
                        return Ok(Json(json!({"keys":keys.into_iter().map(|key|json!({"id":key.id,"publicKey":key.public_key,"privateKey":key.private_key,"createdAt":key.created_at,"expiresAt":key.expires_at,"alg":key.alg,"crv":key.crv})).collect::<Vec<_>>()})));
                    }

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
                    "clear-events" => state.lock().expect("cache receipt clear").events.clear(),
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
                    "rows" => {
                        let user_id = control.user_id.as_deref().ok_or(axum::http::StatusCode::BAD_REQUEST)?;
                        let failed = |_| axum::http::StatusCode::INTERNAL_SERVER_ERROR;
                        let users = crate::backend::rows::<user::Model>(&db, "SELECT * FROM users WHERE id = ?", vec![user_id.to_owned()]).await.map_err(failed)?;
                        let accounts = crate::backend::rows::<account::Model>(&db, "SELECT * FROM accounts WHERE user_id = ?", vec![user_id.to_owned()]).await.map_err(failed)?;
                        let sessions = crate::backend::rows::<application_session::Model>(&db, "SELECT * FROM sessions WHERE user_id = ? ORDER BY created_at", vec![user_id.to_owned()]).await.map_err(failed)?;
                        let proofs = crate::backend::rows::<verification::Model>(&db, "SELECT * FROM verifications ORDER BY created_at", vec![]).await.map_err(failed)?;
                        let accounts = accounts.iter().map(|account| { let mut value=serde_json::to_value(better_auth_core::wire::AccountView::from(account)).expect("actual account row"); value["password"]=json!(account.password);value }).collect::<Vec<_>>();
                        let sessions = sessions.iter().map(|session| { let mut value=serde_json::to_value(auth.context().session_view(session)).expect("actual session row");value["hidden"]=json!(session.hidden);value }).collect::<Vec<_>>();
                        return Ok(Json(json!({"users":users.iter().map(|user|auth.context().user_view(user)).collect::<Vec<_>>(),"accounts":accounts,"sessions":sessions,"verifications":proofs.iter().map(better_auth_core::wire::VerificationView::from).collect::<Vec<_>>()})));
                    }
                    "api-key-rows" => {
                        let user_id=control.user_id.as_deref().ok_or(axum::http::StatusCode::BAD_REQUEST)?;
                        let keys=auth.store().list_api_keys_by_reference(user_id).await.map_err(|_|axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
                        let keys=keys.iter().map(|key|{
                            let mut value=serde_json::to_value(key).map_err(|_|axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
                            value["storedMetadata"]=json!(key.metadata);
                            value["metadata"]=key.metadata.as_deref().map(serde_json::from_str::<Value>).transpose().map_err(|_|axum::http::StatusCode::INTERNAL_SERVER_ERROR)?.unwrap_or(Value::Null);
                            Ok(value)
                        }).collect::<Result<Vec<_>,axum::http::StatusCode>>()?;
                        return Ok(Json(json!({"keys":keys})));
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
