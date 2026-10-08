//! Plugin initialization, HTTP dispatch and persisted effects on both adapters.
//! Validation tables remain owned by plugin units; these exercise composition.
mod account_sessions;
mod admin;
mod admin_matrix;
mod api_key_callbacks;
mod api_key_matrix;
mod credentials;
mod crypto;
mod device_callbacks;
mod device_grant;
mod factor_policy;
mod identity_policy;
mod oauth_configuration;
mod oauth_profiles;
mod oauth_refresh;
mod oauth_remote;
mod oauth_signed;
mod oidc;
mod organization;
mod organization_callbacks;
mod organization_matrix;
mod otp_callbacks;
mod passkey_matrix;
mod passwordless;
mod providers;
mod server_endpoints;
#[cfg(all(feature = "sqlx", feature = "seaorm"))]
mod session_fields;
mod session_plugins;
mod signup_privacy;
mod social_flows;
mod two_factor;
mod user_lifecycle;

use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use alibi::plugins::{EmailPasswordPlugin, SessionManagementPlugin};
use alibi::{AuthBuilder, AuthConfig, AuthSchema, BetterAuth};
use alibi_core::{AuthRequest, AuthResponse, HttpMethod};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

const SECRET: &str = "native-plugin-composition-secret-at-least-32";
const ORIGIN: &str = "http://localhost:43219";
const PASSWORD: &str = "a-native-password-123";

fn builder<B: Backend>(connection: &B::Connection) -> AuthBuilder<B::Schema> {
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
}

fn request(path: &str, body: Option<Value>, cookie: &str) -> AuthRequest {
    let mut request = AuthRequest::new(
        if body.is_some() {
            HttpMethod::Post
        } else {
            HttpMethod::Get
        },
        format!("/api/auth{path}"),
    );
    request.headers.extend([
        ("origin".into(), ORIGIN.into()),
        ("content-type".into(), "application/json".into()),
        ("cookie".into(), cookie.into()),
    ]);
    request.body = body.map(|body| body.to_string().into_bytes());
    request
}

async fn call<S: AuthSchema>(
    auth: &BetterAuth<S>,
    request: AuthRequest,
    status: u16,
) -> AuthResponse {
    let path = request.path.clone();
    let response = Box::pin(auth.handle_request(request)).await.unwrap();
    assert_eq!(
        response.status,
        status,
        "{path}: {}",
        String::from_utf8_lossy(&response.body)
    );
    response
}

fn body(response: &AuthResponse) -> Value {
    serde_json::from_slice(&response.body).unwrap()
}

fn cookies(response: &AuthResponse) -> String {
    // Apply repeated Set-Cookie fields in wire order, as a browser does. In
    // particular, impersonation clears the old session before publishing a new one.
    let mut jar = std::collections::BTreeMap::new();
    for header in response.headers.get_all("set-cookie") {
        let (name, value) = header.split(';').next().unwrap().split_once('=').unwrap();
        if value.is_empty() {
            let _ = jar.remove(name);
        } else {
            let _ = jar.insert(name, value);
        }
    }
    jar.into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ")
}

async fn signup<S: AuthSchema>(auth: &BetterAuth<S>, email: &str) -> AuthResponse {
    call(
        auth,
        request(
            "/sign-up/email",
            Some(json!({"email":email,"password":PASSWORD,"name":"Native owner"})),
            "",
        ),
        200,
    )
    .await
}

async fn authenticated<S: AuthSchema>(auth: &BetterAuth<S>, cookie: &str, email: &str) {
    let session = call(auth, request("/get-session", None, cookie), 200).await;
    assert_eq!(body(&session)["user"]["email"], email);
    assert!(
        body(&session)["session"]["token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
}

#[derive(Clone)]
struct Exchange {
    method: axum::http::Method,
    path: String,
    headers: axum::http::HeaderMap,
    body: Vec<u8>,
}

type ProviderReply = (u16, &'static str, String);

/// Only the remote protocol is replaced. Auth handlers, crypto and stores stay real.
struct Provider {
    url: url::Url,
    requests: Arc<Mutex<Vec<Exchange>>>,
    reply: Arc<Mutex<ProviderReply>>,
    routes: Arc<Mutex<std::collections::HashMap<String, ProviderReply>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Provider {
    async fn start(content_type: &'static str, body: impl Into<String>) -> Self {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let reply = Arc::new(Mutex::new((200, content_type, body.into())));
        let routes = Arc::new(Mutex::new(std::collections::HashMap::<
            String,
            (u16, &'static str, String),
        >::new()));
        let route_replies = Arc::clone(&routes);
        let captured = Arc::clone(&requests);
        let served = Arc::clone(&reply);
        let router = axum::Router::new().fallback(move |request: axum::extract::Request| {
            let route_replies = Arc::clone(&route_replies);
            let captured = Arc::clone(&captured);
            let served = Arc::clone(&served);
            async move {
                let (parts, body) = request.into_parts();
                let bytes = axum::body::to_bytes(body, 16_384).await.unwrap();
                captured.lock().unwrap().push(Exchange {
                    method: parts.method,
                    path: parts.uri.to_string(),
                    headers: parts.headers,
                    body: bytes.to_vec(),
                });
                let (status, content_type, body) = route_replies
                    .lock()
                    .unwrap()
                    .get(parts.uri.path())
                    .cloned()
                    .unwrap_or_else(|| served.lock().unwrap().clone());
                (
                    axum::http::StatusCode::from_u16(status).unwrap(),
                    [("content-type", content_type)],
                    body,
                )
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = url::Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Self {
            url,
            requests,
            reply,
            routes,
            task,
        }
    }

    fn respond(&self, status: u16, content_type: &'static str, body: impl Into<String>) {
        *self.reply.lock().unwrap() = (status, content_type, body.into());
    }

    fn respond_at(&self, path: &str, status: u16, body: Value) {
        drop(
            self.routes
                .lock()
                .unwrap()
                .insert(path.into(), (status, "application/json", body.to_string())),
        );
    }

    fn take(&self) -> Vec<Exchange> {
        std::mem::take(&mut *self.requests.lock().unwrap())
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        self.task.abort();
    }
}
