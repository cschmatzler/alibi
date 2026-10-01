#![cfg(test)]
//! Integration tests for Account and OAuth advanced options:
//!
//! 1. Token encryption: encrypted tokens stored in DB, decrypted via get-access-token
//! 2. `allow_unlinking_all`: unlink-account respects the config flag
//! 3. `account_linking.enabled=false`: callback rejects linking for existing emails
//! 4. `handle_link_social`: confirm token handling in the link flow
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
#![allow(
    unused_results,
    reason = "oauth integration tests intentionally discard setup return values from inserts and config mutation helpers"
)]

#[cfg(test)]
#[path = "account_oauth_tests/tests.rs"]
mod tests;

use async_trait::async_trait;
use better_auth_api::AccountManagementPlugin;
use better_auth_api::OAuthPlugin;
use better_auth_api::plugins::oauth::encryption::{decrypt_token, encrypt_token, maybe_encrypt};
use better_auth_api::plugins::oauth::{
    OAuthConfig, OAuthProvider, OAuthRefreshTokenHandler, OAuthTokenSet, OAuthUserInfo,
    OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use better_auth_core::entity::{AuthAccount, AuthSession, AuthUser};
use better_auth_core::store::AuthStore;
use better_auth_core::{
    AccountConfig, AccountLinkingConfig, AuthConfig, AuthContext, AuthPlugin, AuthRequest,
    CreateAccount, CreateUser, CreateVerification, HttpMethod, SessionManager,
};
use better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema as TestSchema;
use better_auth_seaorm::{Database, SeaOrmStore};
use chrono::{Duration, Utc};
use serde_json::json;
use std::sync::Arc;

const TEST_SECRET: &str = "test-secret-key-that-is-at-least-32-characters-long";

#[derive(Debug, Clone)]
struct RotatingRefreshHandler {
    sequence: Arc<std::sync::Mutex<Vec<(String, OAuthTokenSet)>>>,
}

#[async_trait]
impl OAuthRefreshTokenHandler for RotatingRefreshHandler {
    async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuthTokenSet, String> {
        let mut sequence = self.sequence.lock().unwrap();
        let (expected, response) = sequence.remove(0);
        drop(sequence);

        if refresh_token != expected {
            return Err(format!(
                "unexpected refresh token: expected {expected}, got {refresh_token}"
            ));
        }
        Ok(response)
    }
}

#[derive(Clone)]
struct CookieIssuerProfile(OAuthUserInfo);

#[async_trait]
impl OAuthUserInfoHandler for CookieIssuerProfile {
    async fn get_user_info(
        &self,
        _: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        Ok(OAuthUserInfoResponse {
            user: self.0.clone(),
            data: json!({}),
        })
    }
}

fn test_config() -> AuthConfig {
    AuthConfig::new(TEST_SECRET)
        .base_url("http://localhost:3000")
        .password_min_length(6)
}

fn test_config_with_encryption() -> AuthConfig {
    AuthConfig::new(TEST_SECRET)
        .base_url("http://localhost:3000")
        .password_min_length(6)
        .account(AccountConfig {
            encrypt_oauth_tokens: true,
            ..Default::default()
        })
}

fn test_config_with_encryption_skip_state_cookie_check() -> AuthConfig {
    AuthConfig::new(TEST_SECRET)
        .base_url("http://localhost:3000")
        .password_min_length(6)
        .account(AccountConfig {
            encrypt_oauth_tokens: true,
            skip_state_cookie_check: true,
            ..Default::default()
        })
}

fn test_config_linking_disabled() -> AuthConfig {
    AuthConfig::new(TEST_SECRET)
        .base_url("http://localhost:3000")
        .password_min_length(6)
        .account(AccountConfig {
            account_linking: AccountLinkingConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        })
}

fn test_config_allow_unlinking_all() -> AuthConfig {
    AuthConfig::new(TEST_SECRET)
        .base_url("http://localhost:3000")
        .password_min_length(6)
        .account(AccountConfig {
            account_linking: AccountLinkingConfig {
                allow_unlinking_all: true,
                ..Default::default()
            },
            ..Default::default()
        })
}

fn test_config_with_account_cookie() -> AuthConfig {
    AuthConfig::new(TEST_SECRET)
        .base_url("http://localhost:3000")
        .password_min_length(6)
        .account(AccountConfig {
            store_account_cookie: true,
            ..Default::default()
        })
}

/// Helper: create a user + OAuth account + session, returning (`user_id`, `session_token`, `account_id`).
async fn setup_user_with_account(
    db: &Arc<dyn AuthStore<TestSchema>>,
    config: &Arc<AuthConfig>,
    email: &str,
    provider: &str,
    access_token: Option<String>,
    refresh_token: Option<String>,
) -> (String, String, String) {
    let user = db
        .create_user(
            CreateUser::new()
                .with_email(email)
                .with_name("Test User")
                .with_email_verified(true),
        )
        .await
        .unwrap();

    let user_id = user.id().to_string();

    let account = db
        .create_account(CreateAccount {
            user_id: user_id.clone(),
            account_id: format!("{provider}-account-id"),
            provider_id: provider.to_owned(),
            access_token,
            refresh_token,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: Some("email profile".to_owned()),
            password: None,
        })
        .await
        .unwrap();

    // Create a session for the user
    let session_manager = SessionManager::new(Arc::clone(config), Arc::clone(db));
    let session = session_manager
        .create_session(&user, None, None)
        .await
        .unwrap();
    let token = session.token().to_owned();

    (user_id, token, account.id().to_string())
}

async fn create_test_database() -> Arc<dyn AuthStore<TestSchema>> {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap();
    Arc::new(SeaOrmStore::<TestSchema>::new(
        Arc::new(test_config()),
        database,
    ))
}

/// Issue the production encrypted cookie through the OAuth callback lifecycle.
async fn issue_account_cookie(
    account: &impl AuthAccount,
    db: &Arc<dyn AuthStore<TestSchema>>,
    config: &Arc<AuthConfig>,
    access_token: Option<&str>,
    refresh_token: Option<&str>,
    access_token_expires_at: Option<chrono::DateTime<Utc>>,
) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://localhost:{}", listener.local_addr().unwrap().port());
    let token_body = json!({
        "access_token":access_token, "refresh_token":refresh_token, "token_type":"Bearer",
        "expires_in":access_token_expires_at.map(|date| (date-Utc::now()).num_seconds()),
    })
    .to_string();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        let read = stream.read(&mut request).await.unwrap();
        assert!(read > 0, "mock provider received a request");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            token_body.len(),
            token_body
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    });
    let user = db
        .get_user_by_id(account.user_id().as_ref())
        .await
        .unwrap()
        .unwrap();
    let mut provider = make_test_provider(&url);
    provider.get_user_info = Some(Arc::new(CookieIssuerProfile(OAuthUserInfo {
        id: account.account_id().to_owned(),
        email: user.email().unwrap().to_owned(),
        name: user.name().map(str::to_owned),
        image: None,
        email_verified: true,
    })));
    let mut oauth_config = OAuthConfig::default();
    oauth_config
        .providers
        .insert(account.provider_id().to_owned(), provider);
    let plugin = OAuthPlugin::with_config(oauth_config);
    let mut issuer_config = (**config).clone();
    issuer_config.account.skip_state_cookie_check = true;
    let ctx = AuthContext::new(Arc::new(issuer_config), Arc::clone(db));
    let state = uuid::Uuid::new_v4().to_string();
    db.create_verification(CreateVerification {
        identifier:format!("oauth:{state}"),
        value:json!({"callbackURL":"http://localhost:3000", "codeVerifier":"native-cookie-verifier", "expiresAt":(Utc::now()+Duration::minutes(10)).timestamp_millis()}).to_string(),
        expires_at:Utc::now()+Duration::minutes(10),
    }).await.unwrap();
    let mut req = AuthRequest::new(
        HttpMethod::Get,
        format!("/callback/{}", account.provider_id()),
    );
    req.query.insert("state".into(), state);
    req.query
        .insert("code".into(), "native-cookie-authorization-code".into());
    let response = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(response.status, 302);
    assert_eq!(
        response.headers.get("Location").map(String::as_str),
        Some("http://localhost:3000")
    );
    response
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
        .find_map(|(_, value)| {
            value
                .split(';')
                .next()?
                .strip_prefix("better-auth.account_data=")
                .map(str::to_owned)
        })
        .expect("authenticated callback must issue the account cookie")
}

fn set_session_and_account_cookies(
    req: &mut AuthRequest,
    session_token: &str,
    account_cookie: &str,
) {
    req.headers.insert(
        "cookie".to_owned(),
        format!(
            "better-auth.session_token={}; better-auth.account_data={}",
            better_auth_core::utils::cookie_utils::sign_cookie_value(session_token, TEST_SECRET),
            account_cookie
        ),
    );
}

/// Start a mock HTTP server that responds to OAuth token + userinfo requests.
/// `email` is the email returned from the userinfo endpoint.
async fn start_mock_oauth_server(email: &str) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mock_url = format!("http://localhost:{}", addr.port());
    let email = email.to_owned();

    tokio::spawn(async move {
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                let email = email.clone();
                tokio::spawn(async move {
                    handle_mock_connection(stream, &email).await;
                });
            }
        }
    });

    tokio::time::sleep(std::time::Duration::from_millis(25)).await;

    mock_url
}

async fn handle_mock_connection(stream: tokio::net::TcpStream, email: &str) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = stream;
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    let request = String::from_utf8_lossy(
        (buf)
            .get(..n)
            .expect("fixture contains the requested index"),
    );

    let (status, body) = if request.contains("POST") && request.contains("/token") {
        let body = json!({
            "access_token": "mock-access-token",
            "refresh_token": "mock-refresh-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "email"
        });
        ("200 OK", body.to_string())
    } else if request.contains("GET") && request.contains("/userinfo") {
        let body = json!({
            "sub": "mock-user-id-123",
            "email": email,
            "name": "Mock OAuth User",
            "email_verified": true
        });
        ("200 OK", body.to_string())
    } else {
        ("404 Not Found", json!({"error": "not found"}).to_string())
    };

    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        body.len(),
        body
    );

    drop(stream.write_all(response.as_bytes()).await);
    drop(stream.flush().await);
}

fn make_test_provider(mock_url: &str) -> OAuthProvider {
    OAuthProvider {
        client_id: "client".to_owned(),
        additional_client_ids: Vec::new(),
        hosted_domain: None,
        require_email_verification: false,
        client_secret: "secret".to_owned(),
        auth_url: format!("{mock_url}/auth"),
        token_url: format!("{mock_url}/token"),
        user_info_url: Some(format!("{mock_url}/userinfo")),
        scopes: vec!["email".to_owned()],
        authorization: None,
        authorization_params: Vec::new(),
        map_user_info: Some(|v| {
            Ok(OAuthUserInfo {
                id: (*(v).get("sub").unwrap_or(&serde_json::Value::Null))
                    .as_str()
                    .unwrap_or("mock-user-id-123")
                    .to_owned(),
                email: (*(v).get("email").unwrap_or(&serde_json::Value::Null))
                    .as_str()
                    .unwrap_or("unknown@example.com")
                    .to_owned(),
                name: (*(v).get("name").unwrap_or(&serde_json::Value::Null))
                    .as_str()
                    .map(String::from),
                image: None,
                email_verified: true,
            })
        }),
        get_user_info: None,
        refresh_access_token: None,
        verify_id_token: None,
        disable_implicit_sign_up: false,
        disable_sign_up: false,
        override_user_info_on_sign_in: false,
    }
}
