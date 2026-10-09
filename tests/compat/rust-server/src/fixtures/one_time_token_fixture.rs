use crate::TestSchema;
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::anonymous::{AnonymousConfig, AnonymousIdentity};
use alibi::plugins::jwt::{DefineJwtPayload, JwtPlugin, JwtPluginConfig, JwtSession};
use alibi::plugins::one_time_token::{
    GenerateOneTimeToken, HashOneTimeToken, OneTimeTokenConfig, OneTimeTokenPlugin,
    OneTimeTokenSession, OneTimeTokenStorage,
};
use alibi::plugins::{
    AccountManagementPlugin, AdminPlugin, AnonymousPlugin, ApiKeyPlugin, DeviceAuthorizationPlugin,
    EmailPasswordPlugin, EmailVerificationPlugin, MultiSessionPlugin, OrganizationPlugin,
    PasskeyPlugin, PasswordManagementPlugin, SessionManagementPlugin, TwoFactorPlugin,
    UserManagementPlugin,
};
use alibi::prelude::{AuthRequest, HttpMethod};
use alibi::{AuthBuilder, AuthConfig, AuthError, AuthResult, BetterAuth};
use alibi::{AuthContext, AuthPlugin, AuthResponse, AuthRoute};
use alibi::seaorm::DatabaseConnection;
use axum::{
    Json, Router,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

type Auth = Arc<BetterAuth<TestSchema>>;
const PROFILES: &[&str] = &[
    "ott-composed",
    "ott-custom-callback",
    "ott-custom-header",
    "ott-default",
    "ott-short-lived",
    "ott-hashed",
    "ott-no-cookie",
    "ott-server-header",
    "ott-refresh-disabled",
    "ott-refresh-deferred",
];

#[derive(Default)]
struct CallbackState {
    mode: String,
    serial: usize,
    events: Vec<serde_json::Value>,
}
#[derive(Clone, Default)]
struct CustomCallbacks(Arc<Mutex<CallbackState>>);

struct ComposedJwtPayload;
#[async_trait::async_trait]
impl DefineJwtPayload for ComposedJwtPayload {
    async fn define_payload(
        &self,
        session: &JwtSession,
    ) -> AuthResult<serde_json::Map<String, serde_json::Value>> {
        let mut payload = serde_json::to_value(&session.user)
            .map_err(|error| AuthError::internal(error.to_string()))?
            .as_object()
            .cloned()
            .ok_or_else(|| AuthError::internal("JWT user payload must be an object"))?;
        let _ = payload.insert("iat".into(), json!(session.user.created_at.timestamp()));
        Ok(payload)
    }
}

struct ComposedIdentity;
#[async_trait::async_trait]
impl AnonymousIdentity for ComposedIdentity {
    async fn email(&self) -> AuthResult<Option<String>> {
        Ok(Some("ott-composed-anonymous@fixture.test".into()))
    }
}
#[async_trait::async_trait]
impl alibi::seaorm::DatabaseHooks<TestSchema, crate::backend::Backend> for CustomCallbacks {
    async fn before_create_session(
        &self,
        session: &mut alibi::CreateSession,
        _: &crate::backend::HookContext<'_>,
    ) -> AuthResult<alibi::seaorm::HookControl> {
        let mut state = self.0.lock().unwrap();
        state.serial += 1;
        session.token = Some(format!("{:032}", state.serial));
        Ok(alibi::seaorm::HookControl::Continue)
    }
    async fn before_create_verification(
        &self,
        verification: &mut alibi::CreateVerification,
        _: &crate::backend::HookContext<'_>,
    ) -> AuthResult<alibi::seaorm::HookControl> {
        let mut state = self.0.lock().unwrap();
        if verification.identifier.starts_with("one-time-token:")
            && state.mode == "verification-cancel"
        {
            state.events.push(json!({"stage":"verification-cancel", "identifier":verification.identifier, "value":verification.value}));
            Ok(alibi::seaorm::HookControl::Cancel)
        } else {
            Ok(alibi::seaorm::HookControl::Continue)
        }
    }
}

fn callback_result(mode: &str, stage: &str) -> AuthResult<()> {
    if mode == format!("{stage}-ordinary") {
        Err(AuthError::internal("private OTT callback cause"))
    } else if mode == format!("{stage}-veto") {
        Err(AuthError::Api {
            status: 403,
            code: Some("OTT_VETO".into()),
            message: "OTT callback veto".into(),
        })
    } else {
        Ok(())
    }
}
#[async_trait::async_trait]
impl GenerateOneTimeToken for CustomCallbacks {
    async fn generate(
        &self,
        session: &OneTimeTokenSession,
        request: Option<&AuthRequest>,
    ) -> AuthResult<String> {
        let mut state = self.0.lock().unwrap();
        state.events.push(json!({"stage":"generate", "userId":session.user.id, "session":{"id":session.session.id, "userId":session.session.user_id, "token":session.session.token, "expiresAt":session.session.expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)}, "request":request.map(|req| json!({"path":req.path(), "method":format!("{:?}", req.method()).to_uppercase(), "marker":req.headers.get("x-ott-marker")}))}));
        callback_result(&state.mode, "generate")?;
        Ok(if request.is_none() {
            "ott-custom-server-token"
        } else {
            "ott-custom-token"
        }
        .into())
    }
}
#[async_trait::async_trait]
impl HashOneTimeToken for CustomCallbacks {
    async fn hash(&self, token: &str) -> AuthResult<String> {
        let mut state = self.0.lock().unwrap();
        state.events.push(json!({"stage":"hash", "token":token}));
        callback_result(&state.mode, "hash")?;
        Ok(format!("digest-{token}"))
    }
}

struct HeaderCallbacks(CustomCallbacks);
#[async_trait::async_trait]
impl GenerateOneTimeToken for HeaderCallbacks {
    async fn generate(
        &self,
        session: &OneTimeTokenSession,
        request: Option<&AuthRequest>,
    ) -> AuthResult<String> {
        self.0.generate(session, request).await?;
        let mut state = self.0.0.lock().unwrap();
        state.serial += 1;
        Ok(format!("ott-header-token-{}", state.serial))
    }
}

struct ExposedHeaderFixture(bool);

#[async_trait::async_trait]
impl AuthPlugin<TestSchema> for ExposedHeaderFixture {
    fn name(&self) -> &'static str {
        "ott-exposed-header-fixture"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<TestSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
    async fn after_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<TestSchema>,
        response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        Ok(if self.0 {
            response.with_header(
                "access-control-expose-headers",
                " existing, ,existing, set-ott, set-ott, Existing ",
            )
        } else {
            response
        })
    }
}

#[derive(Deserialize)]
struct ServerOperation {
    operation: String,
    profile: Option<String>,
    mode: Option<String>,
}
fn failure(error: impl std::fmt::Display) -> axum::response::Response {
    tracing::error!(%error,"one-time-token fixture operation failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"message":"Internal server error"})),
    )
        .into_response()
}

pub(crate) async fn router(
    base: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<Router<Auth>> {
    let mut router = Router::new();
    let mut profiles = HashMap::new();
    let callbacks = CustomCallbacks::default();
    for name in PROFILES {
        let ott = OneTimeTokenPlugin::with_config(OneTimeTokenConfig {
            expires_in: if *name == "ott-short-lived" {
                chrono::Duration::seconds(3)
            } else {
                chrono::Duration::minutes(3)
            },
            generator: if *name == "ott-custom-header" {
                Some(Arc::new(HeaderCallbacks(callbacks.clone())))
            } else {
                (*name == "ott-custom-callback")
                    .then(|| Arc::new(callbacks.clone()) as Arc<dyn GenerateOneTimeToken>)
            },
            storage: if matches!(*name, "ott-custom-callback" | "ott-custom-header") {
                OneTimeTokenStorage::Custom(Arc::new(callbacks.clone()))
            } else if *name == "ott-hashed" {
                OneTimeTokenStorage::Hashed
            } else {
                OneTimeTokenStorage::Plain
            },
            disable_client_request: *name == "ott-server-header",
            disable_set_session_cookie: *name == "ott-no-cookie",
            set_ott_header_on_new_session: matches!(
                *name,
                "ott-server-header" | "ott-composed" | "ott-custom-header"
            ),
        });
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut config = base.clone().base_path(&path);
        config.session.disable_session_refresh = *name == "ott-refresh-disabled";
        config.session.defer_session_refresh = *name == "ott-refresh-deferred";
        if *name == "ott-composed" {
            config.session.cookie_cache = Some(alibi::CookieCacheConfig {
                enabled: true,
                ..Default::default()
            });
        }
        let mut store = crate::backend::store::<TestSchema>(config.clone(), database.clone());
        if *name == "ott-composed" {
            store = store.with_hooks(vec![Arc::new(callbacks.clone())]);
        }
        let mut builder = AuthBuilder::<TestSchema>::new(config.clone())
            .store(store)
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new().enable_signup(true))
            .plugin(SessionManagementPlugin::new())
            .plugin(AccountManagementPlugin::new())
            .plugin(DeviceAuthorizationPlugin::new())
            .plugin(ApiKeyPlugin::builder().enable_metadata(true).build())
            .plugin(OrganizationPlugin::new())
            .plugin(AdminPlugin::new())
            .plugin(PasskeyPlugin::new())
            .plugin(PasswordManagementPlugin::new())
            .plugin(EmailVerificationPlugin::new())
            .plugin(
                UserManagementPlugin::new()
                    .change_email_enabled(true)
                    .delete_user_enabled(true)
                    .require_delete_verification(false),
            )
            .plugin(TwoFactorPlugin::new())
            .plugin(ExposedHeaderFixture(*name == "ott-server-header"))
            .plugin(ott.clone());
        if *name == "ott-composed" {
            builder = builder
                .plugin(AnonymousPlugin::with_config(AnonymousConfig {
                    identity: Some(Arc::new(ComposedIdentity)),
                    ..Default::default()
                }))
                .plugin(MultiSessionPlugin::new())
                .plugin(JwtPlugin::with_config(JwtPluginConfig {
                    define_payload: Some(Arc::new(ComposedJwtPayload)),
                    ..Default::default()
                }));
        }
        let auth = Arc::new(builder.build().await?);
        let routes: Router<Auth> = auth.clone().axum_router().with_state(auth.clone());
        router = router.nest(&path, routes);
        let _ = profiles.insert((*name).to_owned(), (auth, ott));
    }
    let profiles = Arc::new(profiles);
    router = router.route(
        "/__test/one-time-token",
        post(
            move |headers: HeaderMap, Json(body): Json<ServerOperation>| {
                let profiles = profiles.clone();
                let callbacks = callbacks.clone();
                async move {
                    let operation = async {
                        if body.operation == "callbacks" {
                            let mut state = callbacks.0.lock().unwrap();
                            if let Some(mode) = body.mode {
                                state.mode = mode;
                                state.events.clear();
                            }
                            return Ok(json!({"events":state.events}));
                        }
                        if body.operation == "generate-endpoint" {
                            let (auth, _) = profiles.get("ott-custom-callback").unwrap();
                            let result = auth.dispatch_endpoint(
                                OneTimeTokenPlugin::generate_endpoint(),
                                alibi::endpoint::EndpointOptions {
                                    headers: Some(headers.iter().filter_map(|(name,value)| value.to_str().ok().map(|value| (name.to_string(),value.to_owned()))).collect()),
                                    ..Default::default()
                                },
                            ).await;
                            return Ok(match result {
                                Ok(response) => json!({"token":response.decode()?.token}),
                                Err(error) => json!({"status":error.error.status_code(), "ordinary":matches!(error.error, AuthError::Internal(_) | AuthError::CallbackFailure(_)), "message":if matches!(error.error, AuthError::Api {..}) {Some(error.to_string())} else {None}}),
                            });
                        }
                        if body.operation != "generate" {
                            return Err(AuthError::bad_request("invalid server operation"));
                        }
                        let (auth, ott) = profiles
                            .get(body.profile.as_deref().unwrap_or("ott-default"))
                            .ok_or_else(|| AuthError::bad_request("unknown fixture profile"))?;
                        let mut request =
                            AuthRequest::new(HttpMethod::Post, "/__test/one-time-token");
                        for (name, value) in &headers {
                            if let Ok(value) = value.to_str() {
                                let _ = request
                                    .headers
                                    .insert(name.as_str().to_owned(), value.to_owned());
                            }
                        }
                        let (user, session) = auth.context().require_session(&request).await?;
                        let token = ott
                            .generate_for_session(
                                &OneTimeTokenSession {
                                    user: auth.context().user_view(&user),
                                    session: auth.context().session_view(&session),
                                },
                                Some(&request),
                                auth.context(),
                            )
                            .await?;
                        Ok(json!({"token":token}))
                    }
                    .await;
                    match operation {
                        Ok(value) => Json(value).into_response(),
                        Err(error) => failure(error),
                    }
                }
            },
        ),
    );
    Ok(router)
}
