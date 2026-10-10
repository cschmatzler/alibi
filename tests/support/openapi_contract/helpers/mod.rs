//! Auth setup, HTTP request builders, and signup/signin helpers.
//!
//! This is the **canonical** location for all shared test utilities.
//! All integration test files should use `use compat::helpers::*;`.

use alibi::middleware::RateLimitConfig;
use alibi::plugins::magic_link::MagicLinkConfig;
use alibi::plugins::multi_session::MultiSessionPlugin;
use alibi::plugins::one_time_token::OneTimeTokenPlugin;
use alibi::plugins::phone_number::PhoneNumberConfig;
use alibi::plugins::phone_number::PhoneNumberPlugin;
use alibi::plugins::siwe::{Eip191Verifier, RandomSiweNonce, SiweConfig, SiwePlugin};
use alibi::seaorm::{Database, DatabaseConnection, SeaOrmStore};
use alibi::{
    Alibi, AuthBuilder, AuthConfig,
    plugins::{
        AccountManagementPlugin, AdminPlugin, ApiKeyPlugin, DeviceAuthorizationPlugin,
        EmailOtpConfig, EmailOtpPlugin, EmailPasswordPlugin, EmailVerificationPlugin,
        MagicLinkPlugin, OAuthPlugin, OpenApiPlugin, OrganizationPlugin, PasskeyPlugin,
        PasswordManagementPlugin, SessionManagementPlugin, TwoFactorPlugin, UserManagementPlugin,
        jwt::JwtPlugin,
        oauth::{
            OAuthProvider, OAuthUserInfo, OAuthUserInfoHandler, OAuthUserInfoRequest,
            OAuthUserInfoResponse,
        },
        one_tap::OneTapPlugin,
        organization::{
            DynamicAccessControlConfig, OrganizationConfig, TeamsConfig,
            default_organization_statements,
        },
        password_management::SendResetPassword,
    },
    prelude::{AuthRequest, HttpMethod},
};
use serde_json::Value;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

type TestSchema = alibi::seaorm::store::__private_test_support::bundled_schema::BundledSchema;

type TestAuth = Alibi<TestSchema>;

const MOCK_OAUTH_BASE_URL: &str = "http://127.0.0.1:3110";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ResetSenderMode {
    #[default]
    Capture,
    Fail,
}

#[derive(Debug, Clone, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "Configure independent authentication features in shared integration fixtures"
)]
pub struct TestAuthOptions {
    pub reset_sender_mode: ResetSenderMode,
    pub creator_role: Option<String>,
    pub teams_enabled: bool,
    pub dynamic_roles_enabled: bool,
    pub phone_enabled: bool,
    pub multi_session_enabled: bool,
    pub one_tap_enabled: bool,
    pub anonymous_enabled: bool,
    pub oauth_proxy_enabled: bool,
}

struct TestResetSender {
    mode: ResetSenderMode,
}

static RESET_PASSWORD_OUTBOX: OnceLock<Mutex<std::collections::HashMap<String, String>>> =
    OnceLock::new();

#[async_trait::async_trait]
impl SendResetPassword for TestResetSender {
    async fn send(&self, user: &Value, _url: &str, token: &str) -> alibi::AuthResult<()> {
        if self.mode == ResetSenderMode::Fail {
            return Err(alibi::AuthError::internal(
                "test reset sender failure".to_owned(),
            ));
        }
        if let Some(email) = user.get("email").and_then(|value| value.as_str()) {
            reset_password_outbox()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(email.to_owned(), token.to_owned());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Unique email generator
// ---------------------------------------------------------------------------

static EMAIL_COUNTER: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// TestHarness
// ---------------------------------------------------------------------------

/// Minimal authentication application shared by integration tests.
pub struct TestHarness {
    auth: Arc<TestAuth>,
}

impl TestHarness {
    /// Create a harness with a **minimal** plugin set matching
    /// `tests/integration/core/http_flow.rs` conventions (`EmailPassword`, `SessionManagement`,
    /// `PasswordManagement`, `AccountManagement`, `ApiKey`).
    pub async fn minimal() -> Self {
        let config = test_config().base_url("http://localhost:3000");
        Self::minimal_with_config(config).await
    }

    /// Build the minimal application with real public configuration overrides.
    pub async fn minimal_with_config(config: AuthConfig) -> Self {
        let store = test_store(&config).await;
        let auth = AuthBuilder::<TestSchema>::new(config)
            .rate_limit(RateLimitConfig::new().enabled(false))
            .store(store)
            .plugin(EmailPasswordPlugin::new().enable_signup(true))
            .plugin(SessionManagementPlugin::new())
            .plugin(
                PasswordManagementPlugin::new().send_reset_password(Arc::new(TestResetSender {
                    mode: ResetSenderMode::Capture,
                })),
            )
            .plugin(AccountManagementPlugin::new())
            .plugin(EmailVerificationPlugin::new())
            .plugin(
                UserManagementPlugin::new()
                    .change_email_enabled(true)
                    .delete_user_enabled(true)
                    .require_delete_verification(false),
            )
            .plugin(ApiKeyPlugin::builder().build())
            .plugin(mock_oauth_plugin())
            .build()
            .await
            .unwrap_or_else(|e| panic!("Failed to create test auth instance: {e}"));
        Self {
            auth: Arc::new(auth),
        }
    }

    /// Access the inner `Alibi` reference.
    pub fn auth(&self) -> &TestAuth {
        &self.auth
    }

    /// Consume the harness and return the inner `Arc`.
    pub fn into_arc(self) -> Arc<TestAuth> {
        self.auth
    }
}

fn reset_password_outbox() -> &'static Mutex<std::collections::HashMap<String, String>> {
    RESET_PASSWORD_OUTBOX.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

pub fn take_reset_password_token(email: &str) -> Option<String> {
    reset_password_outbox()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(email)
}

/// Generate a unique email address for testing, avoiding hard-coded collisions.
pub fn unique_email(prefix: &str) -> String {
    let n = EMAIL_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}_{n}_{}@test.com", std::process::id())
}

// ---------------------------------------------------------------------------
// Auth setup
// ---------------------------------------------------------------------------

/// Generate a deterministic test-only key (not a real secret).
pub fn test_secret() -> String {
    "t]e]s]t]-]o]n]l]y]-]k]e]y]-]n]o]t]-]a]-]r]e]a]l]-]s]e]c]r]e]t]-]3]2]c]h".replace(']', "")
}

pub fn test_config() -> AuthConfig {
    AuthConfig::new(test_secret()).base_url("http://localhost:3000")
}

fn mock_oauth_plugin() -> OAuthPlugin {
    struct MockUserInfoHandler;

    #[async_trait::async_trait]
    impl OAuthUserInfoHandler for MockUserInfoHandler {
        async fn get_user_info(
            &self,
            _request: OAuthUserInfoRequest,
        ) -> Result<OAuthUserInfoResponse, String> {
            Ok(OAuthUserInfoResponse {
                user_output: None,
                user: OAuthUserInfo {
                    additional_fields: Default::default(),
                    id: "mock-account-id".to_owned(),
                    email: "mock@example.com".to_owned(),
                    name: Some("Mock OAuth User".to_owned()),
                    image: None,
                    email_verified: true,
                },
                data: serde_json::json!({
                    "id": "mock-account-id",
                    "email": "mock@example.com",
                    "name": "Mock OAuth User",
                    "image": null,
                    "emailVerified": true,
                }),
            })
        }
    }

    OAuthPlugin::new().add_provider(
        "mock",
        OAuthProvider {
            account_subject: None,
            client_id: "mock-client-id".to_owned(),
            additional_client_ids: Vec::new(),
            hosted_domain: None,
            require_email_verification: false,
            client_secret: "mock-client-secret".to_owned(),
            auth_url: format!("{MOCK_OAUTH_BASE_URL}/__test/oauth/authorize"),
            token_url: format!("{MOCK_OAUTH_BASE_URL}/__test/oauth/token"),
            user_info_url: Some(format!("{MOCK_OAUTH_BASE_URL}/__test/oauth/userinfo")),
            scopes: vec![
                "openid".to_owned(),
                "email".to_owned(),
                "profile".to_owned(),
            ],
            authorization: None,
            authorization_params: Vec::new(),
            allowed_request_params: Vec::new(),
            map_user_info: Some(|_value| {
                Ok(OAuthUserInfo {
                    additional_fields: Default::default(),
                    id: "mock-account-id".to_owned(),
                    email: "mock@example.com".to_owned(),
                    name: Some("Mock OAuth User".to_owned()),
                    image: None,
                    email_verified: true,
                })
            }),
            get_user_info: Some(Arc::new(MockUserInfoHandler)),
            refresh_access_token: None,
            verify_id_token: None,
            id_token: None,
            disable_id_token_sign_in: false,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            allow_idp_initiated: false,
            override_user_info_on_sign_in: false,
        },
    )
}

fn test_session_cookie(token: &str) -> String {
    format!(
        "better-auth.session_token={}",
        alibi::utils::cookie_utils::sign_cookie_value(token, &test_secret())
    )
}

async fn test_database() -> DatabaseConnection {
    let database = Database::connect("sqlite::memory:")
        .await
        .unwrap_or_else(|e| panic!("sqlite test database should connect: {e}"));
    alibi::seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap_or_else(|e| panic!("sqlite test migrations should run: {e}"));
    database
}

async fn test_store(config: &AuthConfig) -> SeaOrmStore<TestSchema> {
    SeaOrmStore::<TestSchema>::new(config.clone(), test_database().await)
}

pub async fn create_test_auth() -> TestAuth {
    create_test_auth_with_options(TestAuthOptions::default()).await
}

pub async fn create_test_auth_with_options(options: TestAuthOptions) -> TestAuth {
    build_test_auth(test_config(), options).await
}

pub async fn create_test_auth_with_config(config: AuthConfig) -> TestAuth {
    build_test_auth(config, TestAuthOptions::default()).await
}

async fn build_test_auth(config: AuthConfig, options: TestAuthOptions) -> TestAuth {
    let store = test_store(&config).await;
    let organization_plugin = OrganizationPlugin::with_config(OrganizationConfig {
        creator_role: options
            .creator_role
            .clone()
            .unwrap_or_else(|| "owner".to_owned()),
        teams: TeamsConfig {
            enabled: options.teams_enabled,
            ..Default::default()
        },
        dynamic_access_control: DynamicAccessControlConfig {
            enabled: options.dynamic_roles_enabled,
            ..Default::default()
        },
        access_control: options
            .dynamic_roles_enabled
            .then(default_organization_statements),
        ..Default::default()
    });

    let builder = AuthBuilder::<TestSchema>::new(config)
        .rate_limit(RateLimitConfig::new().enabled(false))
        .store(store)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(SessionManagementPlugin::new())
        .plugin(OneTimeTokenPlugin::new())
        .plugin(
            PasswordManagementPlugin::new()
                .require_current_password(true)
                .send_reset_password(Arc::new(TestResetSender {
                    mode: options.reset_sender_mode,
                })),
        )
        .plugin(AccountManagementPlugin::new())
        .plugin(EmailVerificationPlugin::new())
        .plugin(EmailOtpPlugin::new(EmailOtpConfig {
            change_email_enabled: true,
            ..Default::default()
        }))
        .plugin(MagicLinkPlugin::new(MagicLinkConfig::default()))
        .plugin(
            UserManagementPlugin::new()
                .change_email_enabled(true)
                .delete_user_enabled(true)
                .require_delete_verification(false),
        )
        .plugin(ApiKeyPlugin::builder().build())
        .plugin(mock_oauth_plugin())
        .plugin(TwoFactorPlugin::new())
        .plugin(organization_plugin)
        .plugin(DeviceAuthorizationPlugin::new())
        .plugin(
            PasskeyPlugin::new()
                .rp_id("localhost")
                .rp_name("Better Auth Test")
                .origin("http://localhost:3000"),
        )
        .plugin(AdminPlugin::new())
        .plugin(JwtPlugin::new())
        .plugin(OpenApiPlugin::new())
        .plugin(SiwePlugin::new(SiweConfig::new(
            "localhost",
            Arc::new(RandomSiweNonce),
            Arc::new(Eip191Verifier),
        )));
    let builder = if options.phone_enabled {
        builder.plugin(PhoneNumberPlugin::new(PhoneNumberConfig::default()))
    } else {
        builder
    };
    let builder = if options.multi_session_enabled {
        builder.plugin(MultiSessionPlugin::new())
    } else {
        builder
    };
    let builder = if options.one_tap_enabled {
        builder.plugin(OneTapPlugin::new())
    } else {
        builder
    };
    let builder = if options.anonymous_enabled {
        builder.plugin(alibi::plugins::AnonymousPlugin::new())
    } else {
        builder
    };
    let builder = if options.oauth_proxy_enabled {
        builder.plugin(alibi::plugins::OAuthProxyPlugin::new())
    } else {
        builder
    };
    builder
        .build()
        .await
        .unwrap_or_else(|e| panic!("Failed to create test auth instance: {e}"))
}

// ---------------------------------------------------------------------------
// Request builders
// ---------------------------------------------------------------------------

pub fn post_json(path: &str, body: Value) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Post, path);
    req.body = Some(serde_json::to_vec(&body).expect("JSON values serialize"));
    drop(body);
    drop(
        req.headers
            .insert("content-type".to_owned(), "application/json".to_owned()),
    );
    drop(
        req.headers
            .insert("origin".to_owned(), "http://localhost:3000".to_owned()),
    );
    req
}

pub fn get_request(path: &str) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Get, path);
    drop(
        req.headers
            .insert("origin".to_owned(), "http://localhost:3000".to_owned()),
    );
    req
}

pub fn get_with_auth(path: &str, token: &str) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Get, path);
    drop(
        req.headers
            .insert("cookie".to_owned(), test_session_cookie(token)),
    );
    drop(
        req.headers
            .insert("origin".to_owned(), "http://localhost:3000".to_owned()),
    );
    req
}

pub fn get_with_auth_and_query(path: &str, token: &str, query: Vec<(&str, &str)>) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Get, path);
    drop(
        req.headers
            .insert("cookie".to_owned(), test_session_cookie(token)),
    );
    drop(
        req.headers
            .insert("origin".to_owned(), "http://localhost:3000".to_owned()),
    );
    for (k, v) in query {
        drop(req.query.insert(k.to_owned(), v.to_owned()));
    }
    req
}

pub fn post_json_with_auth(path: &str, body: Value, token: &str) -> AuthRequest {
    let mut req = post_json(path, body);
    drop(
        req.headers
            .insert("cookie".to_owned(), test_session_cookie(token)),
    );
    req
}

pub fn delete_with_auth(path: &str, token: &str) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Delete, path);
    drop(
        req.headers
            .insert("cookie".to_owned(), test_session_cookie(token)),
    );
    drop(
        req.headers
            .insert("origin".to_owned(), "http://localhost:3000".to_owned()),
    );
    req
}

/// Build an authenticated POST request with an empty JSON `{}` body.
///
/// Matches the pattern used by many integration tests for action endpoints
/// like `/sign-out`, `/revoke-sessions`, `/delete-user`, etc.
pub fn post_with_auth(path: &str, token: &str) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Post, path);
    req.body = Some(b"{}".to_vec());
    drop(
        req.headers
            .insert("content-type".to_owned(), "application/json".to_owned()),
    );
    drop(
        req.headers
            .insert("cookie".to_owned(), test_session_cookie(token)),
    );
    drop(
        req.headers
            .insert("origin".to_owned(), "http://localhost:3000".to_owned()),
    );
    req
}

// ---------------------------------------------------------------------------
// Send / signup / signin
// ---------------------------------------------------------------------------

pub async fn send_request(auth: &TestAuth, req: AuthRequest) -> (u16, Value) {
    // Heap-allocate dispatch so composed endpoint scenarios fit the default test stack.
    let resp = Box::pin(auth.handle_request(req))
        .await
        .unwrap_or_else(|e| panic!("Request should not panic: {e}"));
    let status = resp.status;
    let json: Value = serde_json::from_slice(&resp.body)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&resp.body).to_string()));
    (status, json)
}

fn decode_html_entities(text: &str) -> String {
    let mut decoded = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'&'
            && let Some(offset) = (*(text)
                .get(i + 1..)
                .expect("fixture range is on a UTF-8 boundary"))
            .find(';')
        {
            let end = i + 1 + offset;
            let entity = (text)
                .get(i + 1..end)
                .expect("fixture range is on a UTF-8 boundary");

            let replacement = match entity {
                "nbsp" => Some(" ".to_owned()),
                "amp" => Some("&".to_owned()),
                "lt" => Some("<".to_owned()),
                "gt" => Some(">".to_owned()),
                "quot" => Some("\"".to_owned()),
                "apos" => Some("'".to_owned()),
                _ => decode_numeric_html_entity(entity),
            };

            if let Some(replacement) = replacement {
                decoded.push_str(&replacement);
                i = end + 1;
                continue;
            }
        }

        let ch = (*(text)
            .get(i..)
            .expect("fixture range is on a UTF-8 boundary"))
        .chars()
        .next()
        .unwrap_or_else(|| panic!("text slice should start with a valid UTF-8 character"));
        decoded.push(ch);
        i += ch.len_utf8();
    }

    decoded
}

fn decode_numeric_html_entity(entity: &str) -> Option<String> {
    let codepoint = if let Some(hex) = entity
        .strip_prefix("#x")
        .or_else(|| entity.strip_prefix("#X"))
    {
        u32::from_str_radix(hex, 16).ok()?
    } else {
        let decimal = entity.strip_prefix('#')?;
        decimal.parse::<u32>().ok()?
    };

    char::from_u32(codepoint).map(|ch| ch.to_string())
}

fn normalize_whitespace(text: &str) -> String {
    let mut normalized = String::with_capacity(text.len());
    let mut pending_space = false;

    for ch in text.chars() {
        if ch.is_whitespace() {
            pending_space = !normalized.is_empty();
            continue;
        }

        if pending_space {
            normalized.push(' ');
            pending_space = false;
        }

        normalized.push(ch);
    }

    normalized.trim().to_owned()
}

/// Strip markup, decode common HTML entities, and normalize whitespace so tests
/// can assert on rendered text.
pub fn html_text_content(html: &str) -> String {
    let mut text = String::with_capacity(html.len());
    let mut in_tag = false;
    let mut pending_space = false;

    for ch in html.chars() {
        match ch {
            '<' => {
                in_tag = true;
                pending_space = !text.is_empty();
            }
            '>' => in_tag = false,
            _ if in_tag => {}
            _ if ch.is_whitespace() => pending_space = !text.is_empty(),
            _ => {
                if pending_space {
                    text.push(' ');
                    pending_space = false;
                }
                text.push(ch);
            }
        }
    }

    normalize_whitespace(&decode_html_entities(&text))
}

pub async fn signup_user(
    auth: &TestAuth,
    email: &str,
    password: &str,
    name: &str,
) -> (String, Value) {
    let req = post_json(
        "/sign-up/email",
        serde_json::json!({
            "name": name,
            "email": email,
            "password": password,
        }),
    );
    let (status, json) = send_request(auth, req).await;
    assert_eq!(
        status, 200,
        "signup should succeed, got status {status}: {json}"
    );
    let token = json
        .get("token")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("signup response missing token"))
        .to_owned();
    (token, json)
}

pub async fn signin_user(auth: &TestAuth, email: &str, password: &str) -> (String, Value) {
    let req = post_json(
        "/sign-in/email",
        serde_json::json!({
            "email": email,
            "password": password,
        }),
    );
    let (status, json) = send_request(auth, req).await;
    assert_eq!(
        status, 200,
        "signin should succeed, got status {status}: {json}"
    );
    let token = json
        .get("token")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("signin response missing token"))
        .to_owned();
    (token, json)
}
