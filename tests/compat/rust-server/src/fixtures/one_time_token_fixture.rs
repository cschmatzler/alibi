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
    OneTimeTokenConfig, OneTimeTokenPlugin, OneTimeTokenSession, OneTimeTokenStorage,
};
use better_auth::plugins::{
    AccountManagementPlugin, AdminPlugin, ApiKeyPlugin, DeviceAuthorizationPlugin,
    EmailPasswordPlugin, EmailVerificationPlugin, OrganizationPlugin, PasskeyPlugin,
    PasswordManagementPlugin, SessionManagementPlugin, TwoFactorPlugin, UserManagementPlugin,
};
use better_auth::prelude::{AuthRequest, HttpMethod};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult, BetterAuth};
use better_auth_core::{AuthContext, AuthPlugin, AuthResponse, AuthRoute};
use better_auth_seaorm::{DatabaseConnection, SeaOrmStore};
use serde::Deserialize;
use serde_json::json;
use std::{collections::HashMap, sync::Arc};

type Auth = Arc<BetterAuth<TestSchema>>;
const PROFILES: &[&str] = &[
    "ott-default",
    "ott-hashed",
    "ott-no-cookie",
    "ott-server-header",
    "ott-refresh-disabled",
    "ott-refresh-deferred",
];

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
    for name in PROFILES {
        let ott = OneTimeTokenPlugin::with_config(OneTimeTokenConfig {
            storage: if *name == "ott-hashed" {
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
                .store(SeaOrmStore::<TestSchema>::new(config, database.clone()))
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
                async move {
                    let operation = async {
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
