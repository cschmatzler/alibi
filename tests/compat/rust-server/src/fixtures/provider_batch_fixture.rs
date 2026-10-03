//! Shared official-client provider boundary. HTTP responses are inputs, not mapped outcomes.
use crate::TestSchema;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use base64::Engine;
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::oauth::*;
use better_auth::plugins::{EmailPasswordPlugin, OAuthPlugin, SessionManagementPlugin};
use better_auth::{AuthBuilder, AuthConfig, AuthResult};
use better_auth_seaorm::DatabaseConnection;
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::Mutex;
const INPUTS: &str = include_str!("../../../fixtures/provider-batch-profiles.json");
const MODES: &[&str] = &[
    "default",
    "configured",
    "disabled-configured",
    "mapped-async",
    "custom-async",
    "custom-error",
    "mapper-error",
    "refresh-callback",
    "override",
    "encrypted",
    "client-array",
    "empty-primary",
    "signup-disabled",
    "implicit-disabled",
    "required",
];
const PROVIDERS: &[&str] = &[
    "notion",
    "paybin",
    "paypal",
    "polar",
    "railway",
    "reddit",
    "roblox",
    "salesforce",
    "slack",
    "spotify",
    "tiktok",
    "twitch",
    "twitter",
    "vercel",
    "vk",
    "wechat",
    "zoom",
];
#[derive(Clone, Default)]
pub(crate) struct Fixture {
    control: Arc<Mutex<Value>>,
    receipts: Arc<Mutex<Vec<Value>>>,
    callbacks: Arc<Mutex<Vec<Value>>>,
}
impl Fixture {
    pub(crate) async fn reset(&self) {
        *self.control.lock().await = json!({});
        self.receipts.lock().await.clear();
        self.callbacks.lock().await.clear();
    }
}
fn profile(provider: &str) -> Value {
    serde_json::from_str::<Value>(INPUTS).expect("static batch inputs")[provider].clone()
}
fn configured(mode: &str) -> Vec<String> {
    if mode == "configured" || mode == "disabled-configured" {
        vec!["configured".into(), "shared".into(), "configured".into()]
    } else {
        Vec::new()
    }
}
fn factory(provider: &str, mode: &str, local: Option<&str>) -> OAuthProvider {
    let client = "batch-client";
    let secret = "batch-secret";
    match provider {
        "notion" => {
            let mut options = NotionOptions::new(client, Some(secret.into()));
            options.scope = configured(mode);
            options.disable_default_scope = mode == "disabled-configured";
            options.user_info_endpoint =
                local.map(|base| format!("{base}/__test/provider-batch/notion/user"));
            OAuthProvider::notion_with_options(options)
        }
        "paybin" => {
            let mut options = PaybinOptions::new(client, Some(secret.into()));
            options.scope = configured(mode);
            options.disable_default_scope = mode == "disabled-configured";
            OAuthProvider::paybin_with_options(options)
        }
        "paypal" => {
            let mut options = PayPalOptions::new(client, secret);
            options.user_info_endpoint =
                local.map(|base| format!("{base}/__test/provider-batch/paypal/user"));
            OAuthProvider::paypal_with_options(options)
        }
        "polar" => {
            let mut options = PolarOptions::new(client, Some(secret.into()));
            options.scope = configured(mode);
            options.disable_default_scope = mode == "disabled-configured";
            options.user_info_endpoint =
                local.map(|base| format!("{base}/__test/provider-batch/polar/user"));
            OAuthProvider::polar_with_options(options)
        }
        "railway" => {
            let mut options = RailwayOptions::new(client, Some(secret.into()));
            options.scope = configured(mode);
            options.disable_default_scope = mode == "disabled-configured";
            options.user_info_endpoint =
                local.map(|base| format!("{base}/__test/provider-batch/railway/user"));
            OAuthProvider::railway_with_options(options)
        }
        "reddit" => {
            let mut options = RedditOptions::new(client, Some(secret.into()));
            options.scope = configured(mode);
            options.disable_default_scope = mode == "disabled-configured";
            options.user_info_endpoint =
                local.map(|base| format!("{base}/__test/provider-batch/reddit/user"));
            OAuthProvider::reddit_with_options(options)
        }
        "roblox" => {
            let mut options = RobloxOptions::new(client, Some(secret.into()));
            options.scope = configured(mode);
            options.disable_default_scope = mode == "disabled-configured";
            options.user_info_endpoint =
                local.map(|base| format!("{base}/__test/provider-batch/roblox/user"));
            OAuthProvider::roblox_with_options(options)
        }
        "salesforce" => {
            let mut options = SalesforceOptions::new(client, Some(secret.into()));
            options.scope = configured(mode);
            options.disable_default_scope = mode == "disabled-configured";
            options.user_info_endpoint =
                local.map(|base| format!("{base}/__test/provider-batch/salesforce/user"));
            OAuthProvider::salesforce_with_options(options)
        }
        "slack" => {
            let mut options = SlackOptions::new(client, Some(secret.into()));
            options.scope = configured(mode);
            options.disable_default_scope = mode == "disabled-configured";
            options.user_info_endpoint =
                local.map(|base| format!("{base}/__test/provider-batch/slack/user"));
            OAuthProvider::slack_with_options(options)
        }
        "spotify" => {
            let mut options = SpotifyOptions::new(client, Some(secret.into()));
            options.scope = configured(mode);
            options.disable_default_scope = mode == "disabled-configured";
            options.user_info_endpoint =
                local.map(|base| format!("{base}/__test/provider-batch/spotify/user"));
            OAuthProvider::spotify_with_options(options)
        }
        "tiktok" => {
            let mut options = TikTokOptions::new(client, secret);
            options.scope = configured(mode);
            options.disable_default_scope = mode == "disabled-configured";
            options.user_info_endpoint =
                local.map(|base| format!("{base}/__test/provider-batch/tiktok/user"));
            OAuthProvider::tiktok_with_options(options)
        }
        "twitch" => {
            let mut options = TwitchOptions::new(client, Some(secret.into()));
            options.scope = configured(mode);
            options.disable_default_scope = mode == "disabled-configured";
            OAuthProvider::twitch_with_options(options)
        }
        "twitter" => {
            let mut options = TwitterOptions::new(client, Some(secret.into()));
            options.scope = configured(mode);
            options.disable_default_scope = mode == "disabled-configured";
            options.user_info_endpoint = local.map(|base| {
                format!("{base}/__test/provider-batch/twitter/user?user.fields=profile_image_url")
            });
            options.email_info_endpoint = local.map(|base| {
                format!("{base}/__test/provider-batch/twitter/email?user.fields=confirmed_email")
            });
            OAuthProvider::twitter_with_options(options)
        }
        "vercel" => {
            let mut options = VercelOptions::new(client, Some(secret.into()));
            options.scope = configured(mode);
            options.user_info_endpoint =
                local.map(|base| format!("{base}/__test/provider-batch/vercel/user"));
            OAuthProvider::vercel_with_options(options)
        }
        "vk" => {
            let mut options = VkOptions::new(client, Some(secret.into()));
            options.scope = configured(mode);
            options.disable_default_scope = mode == "disabled-configured";
            options.user_info_endpoint =
                local.map(|base| format!("{base}/__test/provider-batch/vk/user"));
            OAuthProvider::vk_with_options(options)
        }
        "wechat" => {
            let mut options = WeChatOptions::new(client, secret);
            options.scope = configured(mode);
            options.disable_default_scope = mode == "disabled-configured";
            options.user_info_endpoint =
                local.map(|base| format!("{base}/__test/provider-batch/wechat/user"));
            options.token_endpoint =
                local.map(|base| format!("{base}/__test/provider-batch/wechat/token"));
            options.refresh_endpoint =
                local.map(|base| format!("{base}/__test/provider-batch/wechat/refresh"));
            OAuthProvider::wechat_with_options(options)
        }
        "zoom" => {
            let mut options = ZoomOptions::new(client, Some(secret.into()));
            options.user_info_endpoint =
                local.map(|base| format!("{base}/__test/provider-batch/zoom/user"));
            OAuthProvider::zoom_with_options(options)
        }
        _ => unreachable!("static provider inventory"),
    }
}

pub(crate) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<(Router, Fixture)> {
    let fixture = Fixture::default();
    let mut router = Router::new();
    for provider_id in PROVIDERS {
        for mode in MODES {
            let path = format!("/__test/profiles/provider-batch-{provider_id}-{mode}/api/auth");
            let mut settings = config.clone().base_path(&path);
            settings.account.encrypt_oauth_tokens = *mode == "encrypted";
            let mut provider = factory(provider_id, mode, Some(&config.base_url));
            provider.token_url = format!(
                "{}/__test/provider-batch/{provider_id}/token",
                config.base_url
            );
            if *provider_id != "tiktok" && (*mode == "client-array" || *mode == "empty-primary") {
                provider = provider.with_client_ids(vec![
                    if *mode == "empty-primary" {
                        "".into()
                    } else {
                        "batch-client".into()
                    },
                    "secondary-client".into(),
                ]);
            }
            provider.disable_sign_up = *mode == "signup-disabled";
            provider.disable_implicit_sign_up = *mode == "implicit-disabled";
            provider.require_email_verification = *mode == "required";
            provider.override_user_info_on_sign_in = *mode == "override";
            if *mode == "mapped-async" || *mode == "mapper-error" {
                provider = provider.with_profile_mapper(Arc::new(Mapper {
                    fixture: fixture.clone(),
                    provider: provider_id.to_string(),
                    fail: *mode == "mapper-error",
                }));
            }
            if *mode == "custom-async" || *mode == "custom-error" {
                provider.get_user_info = Some(Arc::new(UserInfo {
                    fixture: fixture.clone(),
                    provider: provider_id.to_string(),
                    fail: *mode == "custom-error",
                }));
            }
            if *mode == "refresh-callback" && *provider_id != "vercel" {
                provider.refresh_access_token = Some(Arc::new(Refresh {
                    fixture: fixture.clone(),
                    provider: provider_id.to_string(),
                }));
            }
            let auth = Arc::new(
                AuthBuilder::<TestSchema>::new(settings.clone())
                    .store(crate::backend::store::<TestSchema>(
                        settings,
                        database.clone(),
                    ))
                    .rate_limit(RateLimitConfig::new().enabled(false))
                    .plugin(EmailPasswordPlugin::new().enable_username(false))
                    .plugin(SessionManagementPlugin::new())
                    .plugin(OAuthPlugin::new().add_provider(provider_id, provider))
                    .build()
                    .await?,
            );
            router = router.nest(&path, auth.clone().axum_router().with_state(auth));
        }
    }
    let state_db = database.clone();
    let sql_state = Router::new().route(
        "/__test/provider-batch/sql-state",
        get(move || {
            let db = state_db.clone();
            async move {
                match raw_sql_state(&db).await {
                    Ok(value) => (StatusCode::OK, Json(value)),
                    Err(error) => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"message":error.to_string()})),
                    ),
                }
            }
        }),
    );
    let transport = Router::new()
        .route(
            "/__test/provider-batch/control",
            post(
                |State(f): State<Fixture>, Json(value): Json<Value>| async move {
                    *f.control.lock().await = value;
                    Json(json!({"status":true}))
                },
            ),
        )
        .route(
            "/__test/provider-batch/receipts",
            get(|State(f): State<Fixture>| async move { Json(f.receipts.lock().await.clone()) }),
        )
        .route(
            "/__test/provider-batch/callbacks",
            get(|State(f): State<Fixture>| async move { Json(f.callbacks.lock().await.clone()) }),
        )
        .route(
            "/__test/provider-batch/{provider}/{stage}",
            get(transport_get).post(transport_post),
        )
        .with_state(fixture.clone());
    Ok((router.merge(transport).merge(sql_state), fixture))
}
struct Mapper {
    fixture: Fixture,
    provider: String,
    fail: bool,
}
#[async_trait::async_trait]
impl OAuthProfileMapper for Mapper {
    async fn map_profile(
        &self,
        profile: Value,
    ) -> Result<better_auth_core::field_policy::FieldOutput, String> {
        self.fixture
            .callbacks
            .lock()
            .await
            .push(json!({"kind":"mapper","provider":self.provider,"profile":profile}));
        tokio::task::yield_now().await;
        if self.fail {
            return Err("fixture mapper exception".into());
        }
        self.fixture.control.lock().await.get("mapped").cloned()
            .unwrap_or_else(||json!({"id":"mapped-id-cannot-replace-subject","name":"Async Name","email":"mapped@example.invalid","emailVerified":true,"image":null}))
            .as_object().cloned().ok_or_else(||"invalid mapped fixture input".into())
    }
}
struct UserInfo {
    fixture: Fixture,
    provider: String,
    fail: bool,
}
#[async_trait::async_trait]
impl OAuthUserInfoHandler for UserInfo {
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        self.fixture.callbacks.lock().await.push(json!({"kind":"userinfo","provider":self.provider,"token":{"tokenType":request.token_type,"accessToken":request.access_token,"refreshToken":request.refresh_token,"accessTokenExpiresAt":request.access_token_expires_at,"refreshTokenExpiresAt":request.refresh_token_expires_at,"scopes":request.scopes,"idToken":request.id_token,"raw":request.raw}}));
        tokio::task::yield_now().await;
        if self.fail {
            return Err("fixture userinfo exception".into());
        }
        let control = self.fixture.control.lock().await;
        let data = control.get("profile").cloned().unwrap_or_else(|| {
            if self.provider == "notion" {
                profile("notion")["bot"]["owner"]["user"].clone()
            } else {
                profile(&self.provider)
            }
        });
        let output=json!({"id":"callback-id-cannot-replace-subject","name":"Callback Name","email":"callback@example.invalid","emailVerified":true,"image":null}).as_object().cloned().unwrap();
        Ok(OAuthUserInfoResponse {
            user: OAuthUserInfo {
                additional_fields: Default::default(),
                id: "callback-id-cannot-replace-subject".into(),
                name: Some("Callback Name".into()),
                email: "callback@example.invalid".into(),
                email_verified: true,
                image: None,
            },
            data,
            user_output: Some(output),
        })
    }
}
struct Refresh {
    fixture: Fixture,
    provider: String,
}
#[async_trait::async_trait]
impl OAuthRefreshTokenHandler for Refresh {
    async fn refresh_access_token(&self, token: &str) -> Result<OAuthTokenSet, String> {
        self.fixture
            .callbacks
            .lock()
            .await
            .push(json!({"kind":"refresh","provider":self.provider,"refreshToken":token}));
        tokio::task::yield_now().await;
        Ok(OAuthTokenSet {
            access_token: Some("callback-access".into()),
            refresh_token: Some("callback-refresh".into()),
            access_token_expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            scopes: vec!["callback-scope".into()],
            ..Default::default()
        })
    }
}
async fn transport_get(
    State(f): State<Fixture>,
    Path((provider, stage)): Path<(String, String)>,
    Query(query): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    transport(f, provider, stage, "GET", query, None, headers).await
}
async fn transport_post(
    State(f): State<Fixture>,
    Path((provider, stage)): Path<(String, String)>,
    Query(query): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
    body: String,
) -> (StatusCode, Json<Value>) {
    transport(
        f,
        provider,
        stage,
        "POST",
        query,
        Some(
            url::form_urlencoded::parse(body.as_bytes())
                .into_owned()
                .collect(),
        ),
        headers,
    )
    .await
}
async fn transport(
    f: Fixture,
    provider: String,
    stage: String,
    method: &str,
    query: BTreeMap<String, String>,
    body: Option<BTreeMap<String, String>>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    f.receipts.lock().await.push(json!({"provider":provider,"stage":stage,"method":method,"query":query,"body":body,"headers":headers.iter().map(|(name,value)|(name.as_str(),value.to_str().unwrap_or_default())).collect::<BTreeMap<_,_>>() }));
    let control = f.control.lock().await;
    let (value, status) = if stage == "token" || stage == "refresh" {
        let claims = control
            .get("profile")
            .cloned()
            .unwrap_or_else(|| profile(&provider));
        let jwt = format!(
            "e30.{}.fixture",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&claims).unwrap())
        );
        (control.get("tokenResponse").cloned().unwrap_or_else(||json!({"access_token":"batch-access","refresh_token":"batch-refresh","token_type":"Bearer","expires_in":3600,"scope":"identity email","openid":"batch-subject","id_token":if provider=="paybin"||provider=="twitch" {Some(jwt)}else{None}})),control.get("tokenStatus"))
    } else if stage == "email" {
        (
            control
                .get("emailProfile")
                .cloned()
                .unwrap_or_else(|| json!({"data":{"confirmed_email":"batch@example.invalid"}})),
            control.get("emailStatus"),
        )
    } else {
        (
            control
                .get("profile")
                .cloned()
                .unwrap_or_else(|| profile(&provider)),
            control.get("profileStatus"),
        )
    };
    (
        StatusCode::from_u16(
            status
                .and_then(Value::as_u64)
                .unwrap_or(200)
                .try_into()
                .unwrap_or(500),
        )
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        Json(value),
    )
}

// Read every physical column and row. No model bool decoder or expected outcome
// supplies observations; both backend builds inspect the actual committed SQLite.
async fn raw_sql_state(
    db: &DatabaseConnection,
) -> Result<Value, better_auth_seaorm::sea_orm::DbErr> {
    use better_auth_seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};
    let mut state = serde_json::Map::new();
    for table in ["users", "accounts", "sessions", "verifications"] {
        let columns = db
            .query_all_raw(Statement::from_string(
                DbBackend::Sqlite,
                format!("PRAGMA table_info(\"{table}\")"),
            ))
            .await?;
        let columns = columns
            .iter()
            .map(|row| row.try_get::<String>("", "name"))
            .collect::<Result<Vec<_>, _>>()?;
        let fields = columns
            .iter()
            .map(|column| {
                format!(
                    "'{}',\"{}\"",
                    column.replace('\'', "''"),
                    column.replace('\"', "\"\"")
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let rows = db
            .query_all_raw(Statement::from_string(
                DbBackend::Sqlite,
                format!("SELECT json_object({fields}) AS row FROM \"{table}\" ORDER BY rowid"),
            ))
            .await?;
        let rows = rows
            .iter()
            .map(|row| {
                let raw = row.try_get::<String>("", "row")?;
                serde_json::from_str::<Value>(&raw)
                    .map_err(|error| better_auth_seaorm::sea_orm::DbErr::Custom(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        state.insert(table.into(), Value::Array(rows));
    }
    Ok(Value::Object(state))
}
