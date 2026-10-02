//! Genuine provider HTTP and public dispatch own proxy state, row and principal transitions.
#![allow(
    clippy::unwrap_used,
    reason = "local fixture setup and contract assertions must succeed"
)]

use axum::{
    Json, Router,
    extract::{Form, State},
    routing::{get, post},
};
use better_auth::plugins::oauth::OAuthProvider;
use better_auth::plugins::{
    EmailPasswordPlugin, OAuthPlugin, OAuthProxyConfig, OAuthProxyPlugin, SessionManagementPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, BetterAuth};
use better_auth_core::{AuthRequest, AuthResponse, AuthSession, AuthUser, HttpMethod};
use better_auth_seaorm::sea_orm::{ConnectionTrait, Statement};
use better_auth_seaorm::{Database, SeaOrmStore};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

const PREVIEW: &str = "http://localhost:42681";

const PRODUCTION: &str = "http://127.0.0.1:42681";

const SECRET: &str = "local-proxy-test-session-secret-32";

const PROXY_SECRET: &str = "local-proxy-test-dedicated-secret-32";

#[derive(Default)]
struct Provider {
    verifier: String,
    code: usize,
    consumed: bool,
    receipts: Vec<Value>,
}

struct Fixture {
    preview: BetterAuth<Schema>,
    production: BetterAuth<Schema>,
    preview_db: better_auth_seaorm::DatabaseConnection,
    production_db: better_auth_seaorm::DatabaseConnection,
    provider: Arc<Mutex<Provider>>,
    task: tokio::task::JoinHandle<()>,
}

impl Fixture {
    async fn new() -> Self {
        let provider = Arc::new(Mutex::new(Provider::default()));
        let router = Router::new().route("/oauth/token", post(|State(state): State<Arc<Mutex<Provider>>>, Form(form): Form<HashMap<String, String>>| async move {
            let mut provider_2 = state.lock().unwrap(); provider_2.receipts.push(json!({"stage":"token", "form":form}));
            assert_eq!(form.get("client_id").expect("provider fixture contains this parameter"), "local-client"); assert_eq!(form.get("client_secret").expect("provider fixture contains this parameter"), "local-secret");
            assert_eq!(form.get("redirect_uri").expect("provider fixture contains this parameter"), &format!("{PRODUCTION}/api/auth/callback/gitlab"));
            assert_eq!(form.get("code_verifier").expect("provider fixture contains this parameter"), &provider_2.verifier); assert_eq!(provider_2.verifier.len(), 128);
            if provider_2.consumed || form.get("code").expect("provider fixture contains this parameter") != &format!("real-code-{}", provider_2.code) { return (axum::http::StatusCode::BAD_REQUEST, Json(json!({"error":"invalid_grant"}))); }
            provider_2.consumed = true; drop(provider_2);
            (axum::http::StatusCode::OK, Json(json!({"access_token":"real-provider-access", "refresh_token":"real-provider-refresh", "token_type":"Bearer", "scope":"read_user issued", "expires_in":3600})))
        })).route("/api/v4/user", get(|State(state): State<Arc<Mutex<Provider>>>, headers: axum::http::HeaderMap| async move {
            state.lock().unwrap().receipts.push(json!({"stage":"userinfo", "authorization":headers.get("authorization").expect("provider fixture contains this parameter").to_str().unwrap()}));
            Json(json!({"id":777,"email":"proxy-owner@fixture.test","email_verified":true,"name":"Actual Provider Owner","state":"active","locked":false,"avatar_url":"https://assets.fixture.test/owner.png"}))
        })).with_state(Arc::clone(&provider));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let preview_db = Database::connect("sqlite::memory:").await.unwrap();
        let production_db = Database::connect("sqlite::memory:").await.unwrap();
        for db in [&preview_db, &production_db] {
            better_auth_seaorm::store::__private_test_support::migrator::run_migrations(db)
                .await
                .unwrap();
        }
        let enabled = std::env::var_os("OAUTH_PROXY_BASELINE").is_none();
        let preview = build(PREVIEW, &issuer, preview_db.clone(), enabled).await;
        let production = build(PRODUCTION, &issuer, production_db.clone(), enabled).await;
        Self {
            preview,
            production,
            preview_db,
            production_db,
            provider,
            task,
        }
    }
    async fn issue(&self, endpoint: &str, cookie: Option<&str>) -> (url::Url, Value) {
        let issued = request(&self.preview, endpoint, Some(json!({"provider":"gitlab", "callbackURL":format!("{PREVIEW}/complete?application=kept"), "newUserCallbackURL":format!("{PREVIEW}/new-owner"), "errorCallbackURL":format!("{PREVIEW}/failure"), "disableRedirect":true, "additionalData":{"serverContext":{"anonymousUserId":"forged-foreign"},"application":{"kept":true}}})), cookie).await;
        assert_eq!(issued.status, 200);
        let body: Value = serde_json::from_slice(&issued.body).unwrap();
        let url = url::Url::parse(
            body.get("url")
                .expect("provider fixture contains this parameter")
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(
            query
                .get("redirect_uri")
                .expect("provider fixture contains this parameter"),
            &format!("{PRODUCTION}/api/auth/callback/gitlab"),
            "original Native OAuth redirected to preview instead of production"
        );
        let raw = self
            .preview_db
            .query_one_raw(Statement::from_string(
                self.preview_db.get_database_backend(),
                "SELECT value FROM verifications".to_owned(),
            ))
            .await
            .unwrap()
            .unwrap();
        let state: Value =
            serde_json::from_str(&raw.try_get::<String>("", "value").unwrap()).unwrap();
        assert_eq!(
            state
                .get("application")
                .expect("provider fixture contains this parameter"),
            &json!({"kept":true})
        );
        assert!(state.get("serverContext").is_none());
        let mut provider = self.provider.lock().unwrap();
        provider.code += 1;
        provider.consumed = false;
        provider.verifier = state
            .get("codeVerifier")
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        drop(provider);
        (url, state)
    }
    async fn forward(&self, authorization: &url::Url) -> (AuthResponse, url::Url) {
        let query: HashMap<_, _> = authorization.query_pairs().into_owned().collect();
        let mut callback = url::Url::parse(
            query
                .get("redirect_uri")
                .expect("provider fixture contains this parameter"),
        )
        .unwrap();
        _ = callback
            .query_pairs_mut()
            .append_pair(
                "state",
                query
                    .get("state")
                    .expect("provider fixture contains this parameter"),
            )
            .append_pair(
                "code",
                &format!("real-code-{}", self.provider.lock().unwrap().code),
            );
        let response = request(&self.production, &target(&callback), None, None).await;
        assert_eq!(response.status, 302);
        let bridge = location(&response);
        assert_eq!(bridge.origin().ascii_serialization(), PREVIEW);
        assert_eq!(bridge.path(), "/api/auth/callback/gitlab/oauth-proxy");
        (response, bridge)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn request(
    auth: &BetterAuth<Schema>,
    path: &str,
    body: Option<Value>,
    cookie: Option<&str>,
) -> AuthResponse {
    let mut req = AuthRequest::new(
        if body.is_some() {
            HttpMethod::Post
        } else {
            HttpMethod::Get
        },
        path.split('?').next().unwrap(),
    );
    if let Some((_, query)) = path.split_once('?') {
        req.query = url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
    }
    drop(req.headers.insert("origin".into(), PREVIEW.into()));
    if let Some(body) = body {
        req.body = Some(body.to_string().into_bytes());
        drop(
            req.headers
                .insert("content-type".into(), "application/json".into()),
        );
    }
    if let Some(cookie) = cookie {
        drop(req.headers.insert("cookie".into(), cookie.into()));
    }
    auth.handle_request(req).await.unwrap()
}

fn cookies(response: &AuthResponse) -> String {
    response
        .headers
        .get_all("set-cookie")
        .map(|value| value.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ")
}

fn location(response: &AuthResponse) -> url::Url {
    url::Url::parse(
        response
            .headers
            .get("location")
            .expect("provider fixture contains this parameter"),
    )
    .unwrap()
}

fn target(url: &url::Url) -> String {
    format!("{}?{}", url.path(), url.query().unwrap_or_default())
}

async fn rows(database: &better_auth_seaorm::DatabaseConnection) -> Value {
    let mut value = serde_json::Map::new();
    for table in ["users", "accounts", "sessions", "verifications"] {
        let columns = database
            .query_all_raw(Statement::from_string(
                database.get_database_backend(),
                format!("PRAGMA table_info({table})"),
            ))
            .await
            .unwrap();
        let pairs = columns
            .iter()
            .map(|row| {
                let name = row.try_get::<String>("", "name").unwrap();
                format!("'{name}',\"{name}\"")
            })
            .collect::<Vec<_>>()
            .join(",");
        let rows = database
            .query_all_raw(Statement::from_string(
                database.get_database_backend(),
                format!("SELECT json_object({pairs}) AS row_json FROM {table} ORDER BY rowid"),
            ))
            .await
            .unwrap();
        let serialized = rows
            .into_iter()
            .map(|row| {
                serde_json::from_str::<Value>(&row.try_get::<String>("", "row_json").unwrap())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        drop(value.insert(table.into(), json!(serialized)));
    }
    Value::Object(value)
}

async fn build(
    origin: &str,
    issuer: &str,
    database: better_auth_seaorm::DatabaseConnection,
    proxy: bool,
) -> BetterAuth<Schema> {
    let config = AuthConfig::new(SECRET)
        .base_url(origin)
        .trusted_origin(PREVIEW)
        .trusted_origin(PRODUCTION);
    let builder = AuthBuilder::<Schema>::new(config.clone())
        .store(SeaOrmStore::<Schema>::new(config, database))
        .plugin(EmailPasswordPlugin::new().enable_username(false))
        .plugin(SessionManagementPlugin::new())
        .plugin(OAuthPlugin::new().add_provider(
            "gitlab",
            OAuthProvider::gitlab_with_issuer("local-client", "local-secret", issuer),
        ));
    if proxy {
        builder
            .plugin(OAuthProxyPlugin::with_config(OAuthProxyConfig {
                current_url: Some(origin.into()),
                production_url: Some(PRODUCTION.into()),
                secret: Some(PROXY_SECRET.into()),
                ..Default::default()
            }))
            .build()
            .await
            .unwrap()
    } else {
        builder.build().await.unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn production_exchange_preserves_rows_then_preview_consumes_state_and_issues_only_the_actual_owner()
     {
        let fixture = Fixture::new().await;
        let foreign = request(
        &fixture.preview,
        "/api/auth/sign-up/email",
        Some(
            json!({"email":"foreign-proxy@fixture.test","name":"Foreign","password":"password123"}),
        ),
        None,
    )
    .await;
        assert_eq!(foreign.status, 200);
        let foreign_body: Value = serde_json::from_slice(&foreign.body).unwrap();
        let foreign_id = foreign_body
            .get("user")
            .unwrap()
            .get("id")
            .unwrap()
            .as_str()
            .unwrap();
        let before = rows(&fixture.preview_db).await;
        let prod_before = rows(&fixture.production_db).await;
        let (authorization, state) = fixture.issue("/api/auth/sign-in/social", None).await;
        let original_state = state
            .get("oauthState")
            .expect("provider fixture contains this parameter")
            .as_str()
            .unwrap();
        let issued = rows(&fixture.preview_db).await;
        let (_, bridge) = fixture.forward(&authorization).await;
        assert_eq!(rows(&fixture.production_db).await, prod_before);
        assert_eq!(rows(&fixture.preview_db).await, issued);
        let completed = request(&fixture.preview, &target(&bridge), None, None).await;
        assert_eq!(completed.status, 302);
        assert_eq!(
            location(&completed).as_str(),
            &format!("{PREVIEW}/new-owner")
        );
        assert!(
            fixture
                .preview
                .store()
                .get_verification_by_identifier(original_state)
                .await
                .unwrap()
                .is_none()
        );
        let owner = fixture
            .preview
            .store()
            .get_user_by_email("proxy-owner@fixture.test")
            .await
            .unwrap()
            .unwrap();
        let sessions = fixture
            .preview
            .store()
            .get_user_sessions(&owner.id())
            .await
            .unwrap();
        assert_eq!(sessions.len(), 1);
        let current = request(
            &fixture.preview,
            "/api/auth/get-session",
            None,
            Some(&cookies(&completed)),
        )
        .await;
        let current: Value = serde_json::from_slice(&current.body).unwrap();
        assert_eq!(
            current
                .get("user")
                .expect("provider fixture contains this parameter")
                .get("id")
                .expect("provider fixture contains this parameter"),
            owner.id().as_ref()
        );
        assert_eq!(
            current
                .get("session")
                .expect("provider fixture contains this parameter")
                .get("token")
                .expect("provider fixture contains this parameter"),
            sessions.first().unwrap().token()
        );
        assert_eq!(
            fixture
                .preview
                .store()
                .get_user_sessions(foreign_id)
                .await
                .unwrap()
                .len(),
            1
        );
        let accounts = fixture
            .preview
            .store()
            .get_user_accounts(&owner.id())
            .await
            .unwrap();
        assert_eq!(accounts.len(), 1);
        let after = rows(&fixture.preview_db).await;
        let replay = request(&fixture.preview, &target(&bridge), None, None).await;
        assert!(location(&replay).as_str().contains("error=state_mismatch"));
        assert_eq!(rows(&fixture.preview_db).await, after);
        let query: HashMap<_, _> = authorization.query_pairs().into_owned().collect();
        let mut callback = url::Url::parse(
            query
                .get("redirect_uri")
                .expect("provider fixture contains this parameter"),
        )
        .unwrap();
        _ = callback
            .query_pairs_mut()
            .append_pair(
                "state",
                query
                    .get("state")
                    .expect("provider fixture contains this parameter"),
            )
            .append_pair("code", "real-code-1");
        let retry = request(&fixture.production, &target(&callback), None, None).await;
        assert!(location(&retry).as_str().contains("error=invalid_code"));
        assert_eq!(rows(&fixture.preview_db).await, after);
        assert_eq!(rows(&fixture.production_db).await, prod_before);
        writeln!(std::io::stderr(),
        "PROXY_NATIVE_LIFECYCLE {}",
        json!({"before":before,"issued":issued,"authorization":authorization.as_str(),"bridge":bridge.as_str(),"completed":{"status":completed.status,"headers":completed.headers.iter().collect::<Vec<_>>()},"current":current,"after":after,"production":prod_before,"receipts":fixture.provider.lock().unwrap().receipts})
    ).expect("write native lifecycle observation");
    }

    #[tokio::test]
    async fn completion_rejects_foreign_origin_provider_tampering_and_expired_state_before_any_principal_write()
     {
        let fixture = Fixture::new().await;
        let (authorization, state) = fixture.issue("/api/auth/sign-in/social", None).await;
        let (_, bridge) = fixture.forward(&authorization).await;
        let issued = rows(&fixture.preview_db).await;
        let mut foreign = bridge.clone();
        let profile = foreign
            .query_pairs()
            .find(|(key, _)| key == "profile")
            .unwrap()
            .1
            .into_owned();
        foreign.set_query(None);
        _ = foreign
            .query_pairs_mut()
            .append_pair("callbackURL", "https://foreign.fixture.test/leak")
            .append_pair("profile", &profile);
        let denied = request(&fixture.preview, &target(&foreign), None, None).await;
        assert_eq!(denied.status, 403);
        assert_eq!(rows(&fixture.preview_db).await, issued);
        let mut provider = bridge.clone();
        provider.set_path("/api/auth/callback/google/oauth-proxy");
        let denied_2 = request(&fixture.preview, &target(&provider), None, None).await;
        assert!(
            location(&denied_2)
                .as_str()
                .contains("error=provider_mismatch")
        );
        assert_eq!(rows(&fixture.preview_db).await, issued);
        let mut invalid = bridge.clone();
        invalid.set_query(None);
        _ = invalid
            .query_pairs_mut()
            .append_pair("callbackURL", PREVIEW)
            .append_pair("profile", &format!("{profile}00"));
        let denied_3 = request(&fixture.preview, &target(&invalid), None, None).await;
        assert!(
            location(&denied_3)
                .as_str()
                .contains("error=invalid_profile")
        );
        assert_eq!(rows(&fixture.preview_db).await, issued);
        let mut expired = state.clone();
        *expired.get_mut("expiresAt").unwrap() = json!(chrono::Utc::now().timestamp_millis() - 1);
        _ = fixture
            .preview_db
            .execute_raw(Statement::from_sql_and_values(
                fixture.preview_db.get_database_backend(),
                "UPDATE verifications SET value=?",
                [expired.to_string().into()],
            ))
            .await
            .unwrap();
        let denied_4 = request(&fixture.preview, &target(&bridge), None, None).await;
        assert!(
            location(&denied_4)
                .as_str()
                .contains("error=state_mismatch")
        );
        let after = rows(&fixture.preview_db).await;
        assert_eq!(
            after
                .get("users")
                .expect("provider fixture contains this parameter"),
            issued
                .get("users")
                .expect("provider fixture contains this parameter")
        );
        assert_eq!(
            after
                .get("accounts")
                .expect("provider fixture contains this parameter"),
            issued
                .get("accounts")
                .expect("provider fixture contains this parameter")
        );
        assert_eq!(
            after
                .get("sessions")
                .expect("provider fixture contains this parameter"),
            issued
                .get("sessions")
                .expect("provider fixture contains this parameter")
        );
        assert_eq!(
            after
                .get("verifications")
                .expect("provider fixture contains this parameter"),
            &json!([])
        );
    }
}
