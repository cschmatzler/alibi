use crate::TestSchema;
use axum::{
    Json, Router,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::one_time_token::{
    GenerateOneTimeToken, HashOneTimeToken, OneTimeTokenConfig, OneTimeTokenPlugin,
    OneTimeTokenSession, OneTimeTokenStorage,
};
use better_auth::plugins::{
    AccountManagementPlugin, AdminPlugin, ApiKeyPlugin, DeviceAuthorizationPlugin,
    EmailPasswordPlugin, EmailVerificationPlugin, OrganizationPlugin, PasskeyPlugin,
    PasswordManagementPlugin, SessionManagementPlugin, TwoFactorPlugin, UserManagementPlugin,
};
use better_auth::prelude::{AuthRequest, HttpMethod};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult, BetterAuth};
use better_auth_core::{AuthContext, AuthPlugin, AuthResponse, AuthRoute};
use better_auth_seaorm::DatabaseConnection;
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

type Auth = Arc<BetterAuth<TestSchema>>;
const PROFILES: &[&str] = &[
    "ott-custom-callback",
    "ott-default",
    "ott-hashed",
    "ott-no-cookie",
    "ott-server-header",
    "ott-refresh-disabled",
    "ott-refresh-deferred",
];

#[derive(Default)]
struct CallbackState {
    mode: String,
    events: Vec<serde_json::Value>,
}
#[derive(Clone, Default)]
struct CustomCallbacks(Arc<Mutex<CallbackState>>);

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
        Ok("ott-custom-token".into())
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
            generator: (*name == "ott-custom-callback")
                .then(|| Arc::new(callbacks.clone()) as Arc<dyn GenerateOneTimeToken>),
            storage: if *name == "ott-custom-callback" {
                OneTimeTokenStorage::Custom(Arc::new(callbacks.clone()))
            } else if *name == "ott-hashed" {
                OneTimeTokenStorage::Hashed
            } else {
                OneTimeTokenStorage::Plain
            },
            disable_client_request: *name == "ott-server-header",
            disable_set_session_cookie: *name == "ott-no-cookie",
            set_ott_header_on_new_session: *name == "ott-server-header",
            ..Default::default()
        });
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut config = base.clone().base_path(&path);
        config.session.disable_session_refresh = *name == "ott-refresh-disabled";
        config.session.defer_session_refresh = *name == "ott-refresh-deferred";
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(crate::backend::store::<TestSchema>(
                    config,
                    database.clone(),
                ))
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
                .plugin(ott.clone())
                .build()
                .await?,
        );
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
                                better_auth::endpoint::EndpointOptions {
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
