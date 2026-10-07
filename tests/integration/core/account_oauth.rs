//! Integration tests for Account and OAuth advanced options:
//!
//! 1. Token encryption: encrypted tokens stored in DB, decrypted via get-access-token
//! 2. `allow_unlinking_all`: unlink-account respects the config flag
//! 3. `account_linking.enabled=false`: callback rejects linking for existing emails
//! 4. `handle_link_social`: confirm token handling in the link flow
#![allow(
    unused_results,
    reason = "oauth integration tests intentionally discard setup return values from inserts and config mutation helpers"
)]

use alibi_api::AccountManagementPlugin;
use alibi_api::OAuthPlugin;
use alibi_api::plugins::oauth::encryption::{decrypt_token, encrypt_token, maybe_encrypt};
use alibi_api::plugins::oauth::{
    OAuthConfig, OAuthProvider, OAuthRefreshTokenHandler, OAuthTokenSet, OAuthUserInfo,
    OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use alibi_core::entity::{AuthAccount, AuthSession, AuthUser};
use alibi_core::store::AuthStore;
use alibi_core::{
    AccountConfig, AccountLinkingConfig, AuthConfig, AuthContext, AuthPlugin, AuthRequest,
    CreateAccount, CreateUser, CreateVerification, HttpMethod, SessionManager,
};
use alibi_seaorm::store::__private_test_support::bundled_schema::BundledSchema as TestSchema;
use alibi_seaorm::{Database, SeaOrmStore};
use async_trait::async_trait;
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
            user_output: None,
            user: self.0.clone(),
            data: json!({}),
        })
    }
}

fn test_config() -> AuthConfig {
    AuthConfig::new(TEST_SECRET).base_url("http://localhost:3000")
}

fn test_config_with_encryption() -> AuthConfig {
    AuthConfig::new(TEST_SECRET)
        .base_url("http://localhost:3000")
        .account(AccountConfig {
            encrypt_oauth_tokens: true,
            ..Default::default()
        })
}

fn test_config_with_encryption_skip_state_cookie_check() -> AuthConfig {
    AuthConfig::new(TEST_SECRET)
        .base_url("http://localhost:3000")
        .account(AccountConfig {
            encrypt_oauth_tokens: true,
            skip_state_cookie_check: true,
            ..Default::default()
        })
}

fn test_config_linking_disabled() -> AuthConfig {
    AuthConfig::new(TEST_SECRET)
        .base_url("http://localhost:3000")
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
        .account(AccountConfig {
            store_account_cookie: true,
            ..Default::default()
        })
}

/// Helper: create a user + OAuth account + session, returning (`user_id`, `session_token`, `account_id`).
async fn setup_user_with_account<S: alibi_core::AuthSchema>(
    db: &Arc<dyn AuthStore<S>>,
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
            additional_fields: Default::default(),
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
    alibi_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap();
    Arc::new(SeaOrmStore::<TestSchema>::new(
        Arc::new(test_config()),
        database,
    ))
}

/// Issue the production encrypted cookie through the OAuth callback lifecycle.
async fn issue_account_cookie<S: alibi_core::AuthSchema>(
    account: &impl AuthAccount,
    db: &Arc<dyn AuthStore<S>>,
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
        additional_fields: Default::default(),
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
    let auth = alibi::BetterAuth::<S>::new(issuer_config)
        .store_arc(Arc::clone(db))
        .plugin(plugin)
        .build()
        .await
        .unwrap();
    let state = uuid::Uuid::new_v4().to_string();
    db.create_verification(CreateVerification {
        identifier:format!("auth-state:{state}"),
        value:json!({"callbackURL":"http://localhost:3000", "codeVerifier":"native-cookie-verifier", "oauthState":state, "expiresAt":(Utc::now()+Duration::minutes(10)).timestamp_millis()}).to_string(),
        expires_at:Utc::now()+Duration::minutes(10),
    }).await.unwrap();
    let mut req = AuthRequest::new(
        HttpMethod::Get,
        format!("/callback/{}", account.provider_id()),
    );
    req.query.insert("state".into(), state);
    req.query
        .insert("code".into(), "native-cookie-authorization-code".into());
    let response = Box::pin(auth.handle_request(req)).await.unwrap();
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
            alibi_core::utils::cookie_utils::sign_cookie_value(session_token, TEST_SECRET),
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
        account_subject: None,
        authorization_params: Vec::new(),
        map_user_info: Some(|v| {
            Ok(OAuthUserInfo {
                additional_fields: Default::default(),
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
        id_token: None,
        disable_id_token_sign_in: false,
        disable_implicit_sign_up: false,
        disable_sign_up: false,
        override_user_info_on_sign_in: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────────────────────────────────────────
    // Test 1: Token encryption — encrypted tokens in DB, decrypted via get-access-token
    // ─────────────────────────────────────────────────────────────────────────────

    // Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/link-account.test.ts; adapted to the Rust account and OAuth route behavior.
    #[tokio::test]
    async fn test_encrypt_oauth_tokens_stored_encrypted_in_db() {
        let config = Arc::new(test_config_with_encryption());
        let db = create_test_database().await;

        let plaintext_access = "ya29.real-access-token-value";
        let plaintext_refresh = "1//real-refresh-token-value";

        // Encrypt before storing (simulating what handle_callback does)
        let encrypted_access =
            maybe_encrypt(Some(plaintext_access.to_owned()), true, TEST_SECRET).unwrap();
        let encrypted_refresh =
            maybe_encrypt(Some(plaintext_refresh.to_owned()), true, TEST_SECRET).unwrap();

        // Verify the encrypted values are different from plaintext
        assert_ne!(encrypted_access.as_deref(), Some(plaintext_access));
        assert_ne!(encrypted_refresh.as_deref(), Some(plaintext_refresh));

        // Store encrypted tokens in DB (simulating what the callback handler would do)
        let (user_id, session_token, account_id) = setup_user_with_account(
            &db,
            &config,
            "encrypt@example.com",
            "google",
            encrypted_access.clone(),
            encrypted_refresh.clone(),
        )
        .await;

        // Verify tokens in DB are encrypted (not plaintext)
        let accounts = db.get_user_accounts(&user_id).await.unwrap();
        assert_eq!(accounts.len(), 1);
        let stored_access = (*(accounts)
            .first()
            .expect("fixture contains the requested index"))
        .access_token()
        .unwrap();
        let stored_refresh = (*(accounts)
            .first()
            .expect("fixture contains the requested index"))
        .refresh_token()
        .unwrap();
        assert_ne!(stored_access, plaintext_access);
        assert_ne!(stored_refresh, plaintext_refresh);

        // Verify the stored encrypted values can be decrypted back to original plaintext
        let decrypted_access = decrypt_token(stored_access, TEST_SECRET).unwrap();
        let decrypted_refresh = decrypt_token(stored_refresh, TEST_SECRET).unwrap();
        assert_eq!(decrypted_access, plaintext_access);
        assert_eq!(decrypted_refresh, plaintext_refresh);

        // Now test via the get-access-token handler which should decrypt transparently
        let ctx = AuthContext::new(Arc::clone(&config), Arc::clone(&db));

        let mut req = AuthRequest::new(HttpMethod::Post, "/get-access-token");
        req.body = Some(json!({"accountId": account_id}).to_string().into_bytes());
        req.headers
            .insert("content-type".to_owned(), "application/json".to_owned());
        req.headers.insert(
            "cookie".to_owned(),
            format!(
                "better-auth.session_token={}",
                alibi_core::utils::cookie_utils::sign_cookie_value(&session_token, TEST_SECRET)
            ),
        );

        let mut oauth_config = OAuthConfig::default();
        let provider = make_test_provider("http://localhost:65535");
        oauth_config.providers.insert(
            "google".to_owned(),
            OAuthProvider {
                client_id: provider.client_id,
                additional_client_ids: Vec::new(),
                hosted_domain: None,
                require_email_verification: false,
                client_secret: provider.client_secret,
                auth_url: provider.auth_url,
                token_url: provider.token_url,
                user_info_url: provider.user_info_url,
                scopes: provider.scopes,
                authorization: None,
                account_subject: provider.account_subject,
                authorization_params: provider.authorization_params,
                map_user_info: provider.map_user_info,
                get_user_info: provider.get_user_info,
                refresh_access_token: provider.refresh_access_token,
                verify_id_token: provider.verify_id_token,
                id_token: provider.id_token,
                disable_id_token_sign_in: provider.disable_id_token_sign_in,
                disable_implicit_sign_up: provider.disable_implicit_sign_up,
                disable_sign_up: provider.disable_sign_up,
                override_user_info_on_sign_in: provider.override_user_info_on_sign_in,
            },
        );
        let oauth_plugin = OAuthPlugin::with_config(oauth_config);
        let result = oauth_plugin.on_request(&req, &ctx).await;

        match result {
            Ok(Some(resp)) => {
                assert_eq!(resp.status, 200);
                let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
                // The access token returned should be the DECRYPTED plaintext
                assert_eq!(
                    (*(body)
                        .get("accessToken")
                        .unwrap_or(&serde_json::Value::Null)),
                    plaintext_access
                );
            }
            Ok(None) => panic!("Expected response from get-access-token but got None"),
            Err(e) => panic!("get-access-token handler error: {e:?}"),
        }
    }

    // Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/link-account.test.ts; adapted to the Rust account and OAuth route behavior.
    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        let secret = TEST_SECRET;
        let tokens = vec![
            "ya29.a0AfH6SMBx-some-access-token",
            "1//0eXXXXXXXXXXXXX-refresh-token",
            "eyJhbGciOiJSUzI1NiJ9.id-token-body",
        ];

        for plaintext in tokens {
            let encrypted = encrypt_token(plaintext, secret).unwrap();
            assert_ne!(
                encrypted, plaintext,
                "encrypted should differ from plaintext"
            );

            let decrypted = decrypt_token(&encrypted, secret).unwrap();
            assert_eq!(decrypted, plaintext, "roundtrip should yield original");
        }
    }

    // Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/link-account.test.ts; adapted to the Rust account and OAuth route behavior.
    #[tokio::test]
    async fn test_encryption_disabled_stores_plaintext() {
        let config = Arc::new(test_config()); // encryption OFF by default
        let db = create_test_database().await;

        let plaintext_access = "ya29.plaintext-access-token";

        let (user_id, _, _) = setup_user_with_account(
            &db,
            &config,
            "plain@example.com",
            "github",
            Some(plaintext_access.to_owned()),
            None,
        )
        .await;

        // Tokens should be stored as-is when encryption is disabled
        let accounts = db.get_user_accounts(&user_id).await.unwrap();
        assert_eq!(
            (*(accounts)
                .first()
                .expect("fixture contains the requested index"))
            .access_token(),
            Some(plaintext_access)
        );
    }

    // Better Auth 1.7.6 account.ts selects the signed cookie's owner and persists
    // rotated tokens. Exercise the initialized HTTP path on both actual stores.
    #[tokio::test]
    async fn test_refresh_token_persists_rotated_tokens_for_cookie_matched_account() {
        Box::pin(cookie_token_rotation::<crate::storage::SeaOrm>(
            "/refresh-token",
        ))
        .await;
        Box::pin(cookie_token_rotation::<crate::storage::Sqlx>(
            "/refresh-token",
        ))
        .await;
    }

    #[tokio::test]
    async fn test_get_access_token_refresh_persists_rotated_tokens_for_cookie_matched_account() {
        Box::pin(cookie_token_rotation::<crate::storage::SeaOrm>(
            "/get-access-token",
        ))
        .await;
        Box::pin(cookie_token_rotation::<crate::storage::Sqlx>(
            "/get-access-token",
        ))
        .await;
    }

    async fn cookie_token_rotation<B: crate::storage::Backend>(path: &str) {
        let config = Arc::new(test_config_with_account_cookie());
        let physical = crate::storage::Db::sqlite().await.unwrap();
        let (connection, store) = physical.migrated::<B>(TEST_SECRET).await.unwrap();
        let db: Arc<dyn AuthStore<B::Schema>> = Arc::new(store);
        let (user_id, session_token, _) = setup_user_with_account(
            &db,
            &config,
            "rotate-owner@example.com",
            "google",
            Some("old-access-token".to_owned()),
            Some("old-refresh-token".to_owned()),
        )
        .await;
        let account = db.get_user_accounts(&user_id).await.unwrap().remove(0);
        let foreign_user = db
            .create_user(
                CreateUser::new()
                    .with_email("foreign-owner@example.com")
                    .with_name("Foreign owner"),
            )
            .await
            .unwrap();
        let foreign_session = SessionManager::new(Arc::clone(&config), Arc::clone(&db))
            .create_session(&foreign_user, None, None)
            .await
            .unwrap();
        let foreign_account = db
            .create_account(CreateAccount {
                user_id: foreign_user.id().to_string(),
                provider_id: "google".into(),
                account_id: "foreign-subject".into(),
                access_token: Some("foreign-access-token".into()),
                refresh_token: Some("foreign-refresh-token".into()),
                additional_fields: Default::default(),
                id_token: None,
                access_token_expires_at: None,
                refresh_token_expires_at: None,
                scope: None,
                password: None,
            })
            .await
            .unwrap();
        let account_cookie = issue_account_cookie(
            &account,
            &db,
            &config,
            Some("old-access-token"),
            Some("old-refresh-token"),
            Some(Utc::now() - Duration::seconds(10)),
        )
        .await;
        // The issuer must produce a valid authenticated, canonical cookie, so a
        // foreign-owner denial cannot pass because of malformed fixture data.
        let issued =
            alibi_core::utils::jwe::decode(TEST_SECRET, "better-auth-account", &account_cookie)
                .unwrap();
        assert_eq!(issued.get("userId"), Some(&json!(user_id)));
        assert_eq!(issued.get("id"), Some(&json!(account.id())));
        assert_eq!(issued.get("providerId"), Some(&json!("google")));
        assert_eq!(issued.get("accountId"), Some(&json!(account.account_id())));
        let before = physical
            .tables(&["accounts", "users", "sessions"])
            .await
            .unwrap();
        let sequence = Arc::new(std::sync::Mutex::new(vec![(
            "old-refresh-token".to_owned(),
            OAuthTokenSet {
                access_token: Some("rotated-access-token".to_owned()),
                refresh_token: Some("rotated-refresh-token".to_owned()),
                access_token_expires_at: Some(Utc::now() + Duration::minutes(30)),
                refresh_token_expires_at: Some(Utc::now() + Duration::hours(24)),
                scopes: vec!["email".to_owned()],
                ..Default::default()
            },
        )]));
        let mut oauth_config = OAuthConfig::default();
        let mut provider = make_test_provider("http://localhost:65535");
        provider.refresh_access_token = Some(Arc::new(RotatingRefreshHandler {
            sequence: Arc::clone(&sequence),
        }));
        oauth_config.providers.insert("google".to_owned(), provider);
        let auth = alibi::BetterAuth::<B::Schema>::new((*config).clone())
            .store_arc(Arc::clone(&db))
            .plugin(OAuthPlugin::with_config(oauth_config))
            .build()
            .await
            .unwrap();
        let mut req = AuthRequest::new(HttpMethod::Post, path);
        req.body = Some(json!({"useAccountCookie": true}).to_string().into_bytes());
        req.headers
            .insert("content-type".to_owned(), "application/json".to_owned());
        req.headers
            .insert("origin".to_owned(), "http://localhost:3000".to_owned());
        set_session_and_account_cookies(&mut req, foreign_session.token(), &account_cookie);
        let denied = Box::pin(auth.handle_request(req.clone())).await.unwrap();
        assert_eq!(denied.status, 400);
        let denied_body: serde_json::Value = serde_json::from_slice(&denied.body).unwrap();
        assert_eq!(denied_body.get("code"), Some(&json!("ACCOUNT_NOT_FOUND")));
        assert_eq!(
            physical
                .tables(&["accounts", "users", "sessions"])
                .await
                .unwrap(),
            before
        );
        assert_eq!(
            sequence.lock().unwrap().len(),
            1,
            "foreign owner must not refresh"
        );
        set_session_and_account_cookies(&mut req, &session_token, &account_cookie);
        let response = Box::pin(auth.handle_request(req)).await.unwrap();
        assert_eq!(
            response.status,
            200,
            "{path}: {}",
            String::from_utf8_lossy(&response.body)
        );
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            body.get("accessToken"),
            Some(&json!("rotated-access-token"))
        );
        if path == "/refresh-token" {
            assert_eq!(
                body.get("refreshToken"),
                Some(&json!("rotated-refresh-token"))
            );
        }
        assert!(
            sequence.lock().unwrap().is_empty(),
            "owner refresh uses the old grant exactly once"
        );
        // Read physical SQL independently of the production store's getters.
        for (column, expected) in [
            ("access_token", "rotated-access-token"),
            ("refresh_token", "rotated-refresh-token"),
            ("user_id", user_id.as_str()),
        ] {
            assert_eq!(
                physical
                    .text(
                        &format!("SELECT {column} FROM accounts WHERE id = $1"),
                        &[account.id().as_ref()]
                    )
                    .await
                    .unwrap()
                    .as_deref(),
                Some(expected)
            );
        }
        let original_accounts: Vec<serde_json::Value> =
            serde_json::from_str(before.first().expect("physical snapshot includes accounts"))
                .unwrap();
        let updated_accounts: Vec<serde_json::Value> =
            serde_json::from_str(&physical.table("accounts").await.unwrap()).unwrap();
        assert_eq!(updated_accounts.len(), original_accounts.len());
        let foreign_id = json!(foreign_account.id());
        assert_eq!(
            updated_accounts
                .iter()
                .find(|row| row.get("id") == Some(&foreign_id)),
            original_accounts
                .iter()
                .find(|row| row.get("id") == Some(&foreign_id)),
            "owner refresh must preserve the entire foreign account row"
        );
        assert_eq!(
            physical.tables(&["users", "sessions"]).await.unwrap(),
            before.into_iter().skip(1).collect::<Vec<_>>()
        );
        assert_eq!(
            physical
                .text(
                    "SELECT refresh_token FROM accounts WHERE id = $1",
                    &[foreign_account.id().as_ref()]
                )
                .await
                .unwrap()
                .as_deref(),
            Some("foreign-refresh-token")
        );
        let renewed = response
            .headers
            .get_all("Set-Cookie")
            .find_map(|value| {
                value
                    .split(';')
                    .next()?
                    .strip_prefix("better-auth.account_data=")
            })
            .expect("refresh must renew the account cookie");
        let renewed =
            alibi_core::utils::jwe::decode(TEST_SECRET, "better-auth-account", renewed).unwrap();
        assert_eq!(renewed.get("id"), Some(&json!(account.id())));
        assert_eq!(renewed.get("userId"), Some(&json!(user_id)));
        assert_eq!(
            renewed.get("accessToken"),
            Some(&json!("rotated-access-token"))
        );
        assert_eq!(
            renewed.get("refreshToken"),
            Some(&json!("rotated-refresh-token"))
        );
        drop(auth);
        drop(db);
        B::close(connection).await.unwrap();
    }

    // Upstream reference: packages/better-auth/src/api/routes/account.ts :: accountInfo resolves
    // query.accountId by local account row ID, then fetches provider user info.
    #[tokio::test]
    async fn test_account_info_returns_provider_user_info_for_local_account_id() {
        let mock_url = start_mock_oauth_server("account-info@example.com").await;
        let config = Arc::new(test_config());
        let db = create_test_database().await;

        let (_, session_token, account_id) = setup_user_with_account(
            &db,
            &config,
            "owner@example.com",
            "google",
            Some("stored-access-token".to_owned()),
            Some("stored-refresh-token".to_owned()),
        )
        .await;

        let ctx = AuthContext::new(Arc::clone(&config), Arc::clone(&db));
        let mut oauth_config = OAuthConfig::default();
        oauth_config
            .providers
            .insert("google".to_owned(), make_test_provider(&mock_url));
        let oauth_plugin = OAuthPlugin::with_config(oauth_config);

        let mut req = AuthRequest::new(HttpMethod::Get, "/account-info");
        req.query.insert("accountId".to_owned(), account_id.clone());
        req.headers.insert(
            "cookie".to_owned(),
            format!(
                "better-auth.session_token={}",
                alibi_core::utils::cookie_utils::sign_cookie_value(&session_token, TEST_SECRET)
            ),
        );

        let result = oauth_plugin.on_request(&req, &ctx).await;
        let resp = match result {
            Ok(Some(resp)) => resp,
            other => panic!("account-info should succeed, got {other:?}"),
        };

        assert_eq!(resp.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(
            (*(body).get("user").unwrap_or(&serde_json::Value::Null))
                .get("id")
                .is_none()
        );
        assert_eq!(
            (*(*(body).get("data").unwrap_or(&serde_json::Value::Null))
                .get("sub")
                .unwrap_or(&serde_json::Value::Null)),
            "mock-user-id-123"
        );
        assert_eq!(
            (*(*(body).get("account").unwrap_or(&serde_json::Value::Null))
                .get("id")
                .unwrap_or(&serde_json::Value::Null)),
            account_id
        );
        assert_eq!(
            (*(*(body).get("account").unwrap_or(&serde_json::Value::Null))
                .get("providerId")
                .unwrap_or(&serde_json::Value::Null)),
            "google"
        );
        assert_eq!(
            (*(*(body).get("account").unwrap_or(&serde_json::Value::Null))
                .get("accountId")
                .unwrap_or(&serde_json::Value::Null)),
            "google-account-id"
        );
        assert_eq!(
            (*(*(body).get("user").unwrap_or(&serde_json::Value::Null))
                .get("email")
                .unwrap_or(&serde_json::Value::Null)),
            "account-info@example.com"
        );
        assert_eq!(
            (*(*(body).get("user").unwrap_or(&serde_json::Value::Null))
                .get("name")
                .unwrap_or(&serde_json::Value::Null)),
            "Mock OAuth User"
        );
        assert_eq!(
            (*(*(body).get("user").unwrap_or(&serde_json::Value::Null))
                .get("emailVerified")
                .unwrap_or(&serde_json::Value::Null)),
            true
        );
        assert_eq!(
            (*(*(body).get("data").unwrap_or(&serde_json::Value::Null))
                .get("email")
                .unwrap_or(&serde_json::Value::Null)),
            "account-info@example.com"
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/account.ts :: getAccessToken requires
    // a signed account cookie when useAccountCookie is selected.
    #[tokio::test]
    async fn test_get_access_token_without_cookie_returns_account_not_found() {
        let mock_url = start_mock_oauth_server("missing-cookie@example.com").await;
        let config = Arc::new(test_config());
        let db = create_test_database().await;

        let (_, session_token, _) = setup_user_with_account(
            &db,
            &config,
            "owner@example.com",
            "google",
            Some("stored-access-token".to_owned()),
            Some("stored-refresh-token".to_owned()),
        )
        .await;

        let ctx = AuthContext::new(Arc::clone(&config), Arc::clone(&db));
        let mut oauth_config = OAuthConfig::default();
        oauth_config
            .providers
            .insert("google".to_owned(), make_test_provider(&mock_url));
        let oauth_plugin = OAuthPlugin::with_config(oauth_config);

        let mut req = AuthRequest::new(HttpMethod::Post, "/get-access-token");
        req.headers.insert(
            "cookie".to_owned(),
            format!(
                "better-auth.session_token={}",
                alibi_core::utils::cookie_utils::sign_cookie_value(&session_token, TEST_SECRET)
            ),
        );

        req.body = Some(json!({"useAccountCookie": true}).to_string().into_bytes());
        let result = oauth_plugin.on_request(&req, &ctx).await;
        let resp = match result {
            Ok(Some(resp)) => resp,
            Err(error) => error.to_auth_response(),
            other => panic!("get-access-token should return a 400 response, got {other:?}"),
        };

        assert_eq!(resp.status, 400);
        let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(
            (*(body).get("code").unwrap_or(&serde_json::Value::Null)),
            "ACCOUNT_NOT_FOUND"
        );
        assert_eq!(
            (*(body).get("message").unwrap_or(&serde_json::Value::Null)),
            "Account not found"
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/account.ts :: getAccessToken verifies
    // the selected account cookie belongs to the current session user.
    #[tokio::test]
    async fn test_get_access_token_rejects_cookie_for_the_wrong_user() {
        let mock_url = start_mock_oauth_server("cookie-owner@example.com").await;
        let config = Arc::new(test_config_with_account_cookie());
        let db = create_test_database().await;

        let (cookie_user_id, _, _) = setup_user_with_account(
            &db,
            &config,
            "cookie-owner@example.com",
            "google",
            Some("stored-access-token".to_owned()),
            Some("stored-refresh-token".to_owned()),
        )
        .await;
        let cookie_account = db
            .get_user_accounts(&cookie_user_id)
            .await
            .unwrap()
            .remove(0);

        let other_user = db
            .create_user(
                CreateUser::new()
                    .with_email("other@example.com")
                    .with_name("Other User")
                    .with_email_verified(true),
            )
            .await
            .unwrap();
        let other_session = SessionManager::new(Arc::clone(&config), Arc::clone(&db))
            .create_session(&other_user, None, None)
            .await
            .unwrap();

        let account_cookie = issue_account_cookie(
            &cookie_account,
            &db,
            &config,
            cookie_account.access_token(),
            cookie_account.refresh_token(),
            cookie_account.access_token_expires_at(),
        )
        .await;

        let ctx = AuthContext::new(Arc::clone(&config), Arc::clone(&db));
        let mut oauth_config = OAuthConfig::default();
        oauth_config
            .providers
            .insert("google".to_owned(), make_test_provider(&mock_url));
        let oauth_plugin = OAuthPlugin::with_config(oauth_config);

        let mut req = AuthRequest::new(HttpMethod::Post, "/get-access-token");
        set_session_and_account_cookies(&mut req, other_session.token(), &account_cookie);

        req.body = Some(json!({"useAccountCookie": true}).to_string().into_bytes());
        let result = oauth_plugin.on_request(&req, &ctx).await;
        let resp = match result {
            Ok(Some(resp)) => resp,
            Err(error) => error.to_auth_response(),
            other => panic!("get-access-token should return a 400 response, got {other:?}"),
        };

        assert_eq!(resp.status, 400);
        let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(
            (*(body).get("code").unwrap_or(&serde_json::Value::Null)),
            "ACCOUNT_NOT_FOUND"
        );
        assert_eq!(
            (*(body).get("message").unwrap_or(&serde_json::Value::Null)),
            "Account not found"
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/account.ts :: accountInfo returns a
    // 400 PROVIDER_NOT_CONFIGURED when the account's provider is not configured.
    #[tokio::test]
    async fn test_account_info_returns_provider_not_configured_message() {
        let config = Arc::new(test_config());
        let db = create_test_database().await;

        let (_, session_token, account_id) = setup_user_with_account(
            &db,
            &config,
            "owner@example.com",
            "ghost",
            Some("stored-access-token".to_owned()),
            Some("stored-refresh-token".to_owned()),
        )
        .await;

        let ctx = AuthContext::new(Arc::clone(&config), Arc::clone(&db));
        let oauth_plugin = OAuthPlugin::with_config(OAuthConfig::default());

        let mut req = AuthRequest::new(HttpMethod::Get, "/account-info");
        req.query.insert("accountId".to_owned(), account_id);
        req.headers.insert(
            "cookie".to_owned(),
            format!(
                "better-auth.session_token={}",
                alibi_core::utils::cookie_utils::sign_cookie_value(&session_token, TEST_SECRET)
            ),
        );

        let result = oauth_plugin.on_request(&req, &ctx).await;
        let resp = match result {
            Ok(Some(resp)) => resp,
            Err(error) => error.to_auth_response(),
            other => panic!("account-info should return a 400 response, got {other:?}"),
        };

        assert_eq!(resp.status, 400);
        let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(
            (*(body).get("code").unwrap_or(&serde_json::Value::Null)),
            "PROVIDER_NOT_CONFIGURED"
        );
        assert_eq!(
            (*(body).get("message").unwrap_or(&serde_json::Value::Null)),
            "Account is not associated with a configured social provider."
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/account.ts :: accountInfo returns
    // "Access token not found" when token resolution succeeds but yields no access token.
    #[tokio::test]
    async fn test_account_info_rejects_missing_access_token() {
        let mock_url = start_mock_oauth_server("missing-token@example.com").await;
        let config = Arc::new(test_config());
        let db = create_test_database().await;

        let (_, session_token, account_id) = setup_user_with_account(
            &db,
            &config,
            "owner@example.com",
            "google",
            None,
            Some("stored-refresh-token".to_owned()),
        )
        .await;

        let ctx = AuthContext::new(Arc::clone(&config), Arc::clone(&db));
        let mut oauth_config = OAuthConfig::default();
        oauth_config
            .providers
            .insert("google".to_owned(), make_test_provider(&mock_url));
        let oauth_plugin = OAuthPlugin::with_config(oauth_config);

        let mut req = AuthRequest::new(HttpMethod::Get, "/account-info");
        req.query.insert("accountId".to_owned(), account_id.clone());
        req.headers.insert(
            "cookie".to_owned(),
            format!(
                "better-auth.session_token={}",
                alibi_core::utils::cookie_utils::sign_cookie_value(&session_token, TEST_SECRET)
            ),
        );

        let result = oauth_plugin.on_request(&req, &ctx).await;
        match result {
            Err(error) => assert_eq!(error.to_string(), "Access token not found"),
            Ok(Some(resp)) => {
                assert_eq!(resp.status, 400);
                let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
                assert_eq!(
                    (*(body).get("message").unwrap_or(&serde_json::Value::Null)),
                    "Access token not found"
                );
            }
            Ok(None) => panic!("Expected an account-info error response"),
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Test 2: allow_unlinking_all — unlink handler respects config
    // ─────────────────────────────────────────────────────────────────────────────

    // Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/link-account.test.ts; adapted to the Rust account and OAuth route behavior.
    #[tokio::test]
    async fn test_unlink_last_account_blocked_by_default() {
        let config = Arc::new(test_config()); // allow_unlinking_all = false by default
        let db = create_test_database().await;

        let (_, session_token, account_id) = setup_user_with_account(
            &db,
            &config,
            "unlink@example.com",
            "google",
            Some("access-token".to_owned()),
            None,
        )
        .await;

        let ctx = AuthContext::new(Arc::clone(&config), Arc::clone(&db));
        let plugin = AccountManagementPlugin::new();

        let mut req = AuthRequest::new(HttpMethod::Post, "/unlink-account");
        req.body = Some(json!({"accountId": account_id}).to_string().into_bytes());
        req.headers
            .insert("content-type".to_owned(), "application/json".to_owned());
        req.headers.insert(
            "cookie".to_owned(),
            format!(
                "better-auth.session_token={}",
                alibi_core::utils::cookie_utils::sign_cookie_value(&session_token, TEST_SECRET)
            ),
        );

        let result = plugin.on_request(&req, &ctx).await;

        // Should fail — cannot unlink the last account when allow_unlinking_all is false
        match result {
            Err(e) => {
                let msg = format!("{e:?}");
                assert!(
                    msg.contains("Cannot unlink") || msg.contains("last account"),
                    "Expected 'cannot unlink last account' error, got: {msg}"
                );
            }
            Ok(Some(resp)) => {
                // It might return an error response instead of Err
                assert_ne!(
                    resp.status, 200,
                    "Should not succeed unlinking the last account"
                );
            }
            Ok(None) => panic!("Expected a response"),
        }
    }

    // Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/link-account.test.ts; adapted to the Rust account and OAuth route behavior.
    #[tokio::test]
    async fn test_unlink_last_account_allowed_when_configured() {
        let config = Arc::new(test_config_allow_unlinking_all());
        let db = create_test_database().await;

        let (_, session_token, account_id) = setup_user_with_account(
            &db,
            &config,
            "unlink-ok@example.com",
            "google",
            Some("access-token".to_owned()),
            None,
        )
        .await;

        let ctx = AuthContext::new(Arc::clone(&config), Arc::clone(&db));
        let plugin = AccountManagementPlugin::new();

        let mut req = AuthRequest::new(HttpMethod::Post, "/unlink-account");
        req.body = Some(json!({"accountId": account_id}).to_string().into_bytes());
        req.headers
            .insert("content-type".to_owned(), "application/json".to_owned());
        req.headers.insert(
            "cookie".to_owned(),
            format!(
                "better-auth.session_token={}",
                alibi_core::utils::cookie_utils::sign_cookie_value(&session_token, TEST_SECRET)
            ),
        );

        let result = plugin.on_request(&req, &ctx).await;

        // Should succeed — allow_unlinking_all is true
        match result {
            Ok(Some(resp)) => {
                assert_eq!(resp.status, 200, "Unlinking should succeed");
                let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
                assert_eq!(
                    (*(body).get("status").unwrap_or(&serde_json::Value::Null)),
                    true
                );
            }
            Err(e) => {
                panic!("Unlinking should succeed with allow_unlinking_all=true, got error: {e:?}")
            }
            Ok(None) => panic!("Expected a response"),
        }
    }

    // Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/link-account.test.ts; adapted to the Rust account and OAuth route behavior.
    #[tokio::test]
    async fn test_unlink_non_last_account_always_allowed() {
        // Even with allow_unlinking_all=false, unlinking one of multiple accounts should work
        let config = Arc::new(test_config());
        let db = create_test_database().await;

        let user = db
            .create_user(
                CreateUser::new()
                    .with_email("multi@example.com")
                    .with_name("Multi User")
                    .with_email_verified(true),
            )
            .await
            .unwrap();

        let user_id = user.id().to_string();

        // Create two accounts
        let google_account = db
            .create_account(CreateAccount {
                additional_fields: Default::default(),
                user_id: user_id.clone(),
                account_id: "google-id".to_owned(),
                provider_id: "google".to_owned(),
                access_token: Some("google-token".to_owned()),
                refresh_token: None,
                id_token: None,
                access_token_expires_at: None,
                refresh_token_expires_at: None,
                scope: None,
                password: None,
            })
            .await
            .unwrap();

        db.create_account(CreateAccount {
            additional_fields: Default::default(),
            user_id: user_id.clone(),
            account_id: "github-id".to_owned(),
            provider_id: "github".to_owned(),
            access_token: Some("github-token".to_owned()),
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
            password: None,
        })
        .await
        .unwrap();

        let session_manager = SessionManager::new(Arc::clone(&config), Arc::clone(&db));
        let session = session_manager
            .create_session(&user, None, None)
            .await
            .unwrap();

        let ctx = AuthContext::new(Arc::clone(&config), Arc::clone(&db));
        let plugin = AccountManagementPlugin::new();

        let mut req = AuthRequest::new(HttpMethod::Post, "/unlink-account");
        req.body = Some(
            json!({"accountId": google_account.id()})
                .to_string()
                .into_bytes(),
        );
        req.headers
            .insert("content-type".to_owned(), "application/json".to_owned());
        req.headers.insert(
            "cookie".to_owned(),
            format!(
                "better-auth.session_token={}",
                alibi_core::utils::cookie_utils::sign_cookie_value(session.token(), TEST_SECRET)
            ),
        );

        let result = plugin.on_request(&req, &ctx).await;

        match result {
            Ok(Some(resp)) => {
                assert_eq!(resp.status, 200);
            }
            Err(e) => panic!("Unlinking one of two accounts should succeed: {e:?}"),
            Ok(None) => panic!("Expected a response"),
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Test 3: account_linking.enabled=false — callback rejects linking for existing emails
    // ─────────────────────────────────────────────────────────────────────────────

    // Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/link-account.test.ts; adapted to the Rust account and OAuth route behavior.
    #[tokio::test]
    async fn test_account_linking_disabled_rejects_new_provider() {
        let mock_url = start_mock_oauth_server("existing@example.com").await;

        let config = Arc::new(test_config_linking_disabled());
        let db = create_test_database().await;

        // Create an existing user with a different provider
        let user = db
            .create_user(
                CreateUser::new()
                    .with_email("existing@example.com")
                    .with_name("Existing User")
                    .with_email_verified(true),
            )
            .await
            .unwrap();

        db.create_account(CreateAccount {
            additional_fields: Default::default(),
            user_id: user.id().to_string(),
            account_id: "old-github-id".to_owned(),
            provider_id: "github".to_owned(),
            access_token: Some("old-token".to_owned()),
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
            password: None,
        })
        .await
        .unwrap();

        // Create OAuth config with a "test" provider pointing to our mock server
        let mut oauth_config = OAuthConfig::default();
        oauth_config
            .providers
            .insert("test".to_owned(), make_test_provider(&mock_url));

        // Set up the OAuth state in the verification table
        let state = "test-state-linking-disabled";
        let payload = json!({
            "callbackURL": format!("{}/callback/test", mock_url),
            "codeVerifier": "test-verifier",
            "oauthState": state,
            "expiresAt": (Utc::now() + Duration::minutes(10)).timestamp_millis(),
        });

        db.create_verification(CreateVerification {
            identifier: format!("auth-state:{state}"),
            value: payload.to_string(),
            expires_at: Utc::now() + Duration::minutes(10),
        })
        .await
        .unwrap();

        let ctx = AuthContext::new(Arc::clone(&config), Arc::clone(&db));

        // Simulate a callback request
        let mut req = AuthRequest::new(
            HttpMethod::Get,
            format!("/callback/test?code=test-code&state={state}"),
        );
        req.query.insert("code".to_owned(), "test-code".to_owned());
        req.query.insert("state".to_owned(), state.to_owned());
        req.headers.insert(
            "cookie".into(),
            format!(
                "better-auth.state={}",
                alibi_core::utils::cookie_utils::sign_cookie_value(state, TEST_SECRET)
            ),
        );

        let oauth_plugin = OAuthPlugin::with_config(oauth_config);
        let response = oauth_plugin.on_request(&req, &ctx).await.unwrap().unwrap();
        assert_eq!(response.status, 302);
        let location = url::Url::parse(response.headers.get("location").unwrap()).unwrap();
        assert_eq!(
            location
                .query_pairs()
                .find(|(key, _)| key == "error")
                .map(|(_, value)| value.into_owned()),
            Some("account_not_linked".into()),
            "the callback must reach linking policy, not fail OAuth state validation"
        );
        let accounts = db.get_user_accounts(&user.id()).await.unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts.first().unwrap().provider_id(), "github");
        assert!(db.get_user_sessions(&user.id()).await.unwrap().is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Test 4: handle_link_social + callback token encryption for new users
    // ─────────────────────────────────────────────────────────────────────────────

    // Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/link-account.test.ts; adapted to the Rust account and OAuth route behavior.
    #[tokio::test]
    async fn test_link_social_returns_redirect_url_with_state() {
        let config = Arc::new(test_config_with_encryption());
        let db = create_test_database().await;

        let (_, session_token, _) = setup_user_with_account(
            &db,
            &config,
            "link@example.com",
            "existing-provider",
            Some("existing-token".to_owned()),
            None,
        )
        .await;

        let mut oauth_config = OAuthConfig::default();
        oauth_config.providers.insert(
            "github".to_owned(),
            OAuthProvider {
                client_id: "client".to_owned(),
                additional_client_ids: Vec::new(),
                hosted_domain: None,
                require_email_verification: false,
                client_secret: "secret".to_owned(),
                auth_url: "https://github.com/login/oauth/authorize".to_owned(),
                token_url: "https://github.com/login/oauth/access_token".to_owned(),
                user_info_url: Some("https://api.github.com/user".to_owned()),
                scopes: vec!["user:email".to_owned()],
                authorization: None,
                account_subject: None,
                authorization_params: Vec::new(),
                map_user_info: Some(|_| panic!("This rejection must precede profile mapping")),
                get_user_info: None,
                refresh_access_token: None,
                verify_id_token: None,
                id_token: None,
                disable_id_token_sign_in: false,
                disable_implicit_sign_up: false,
                disable_sign_up: false,
                override_user_info_on_sign_in: false,
            },
        );

        let ctx = AuthContext::new(Arc::clone(&config), Arc::clone(&db));
        let oauth_plugin = OAuthPlugin::with_config(oauth_config);

        let mut req = AuthRequest::new(HttpMethod::Post, "/link-social");
        req.body = Some(json!({"provider": "github"}).to_string().into_bytes());
        req.headers
            .insert("content-type".to_owned(), "application/json".to_owned());
        req.headers.insert(
            "cookie".to_owned(),
            format!(
                "better-auth.session_token={}",
                alibi_core::utils::cookie_utils::sign_cookie_value(&session_token, TEST_SECRET)
            ),
        );

        let result = oauth_plugin.on_request(&req, &ctx).await;

        match result {
            Ok(Some(resp)) => {
                assert_eq!(resp.status, 200);
                let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
                assert!(
                    (*(body).get("url").unwrap_or(&serde_json::Value::Null))
                        .as_str()
                        .is_some(),
                    "Response should contain URL"
                );
                assert_eq!(
                    (*(body).get("redirect").unwrap_or(&serde_json::Value::Null)),
                    true
                );
                let url = (*(body).get("url").unwrap_or(&serde_json::Value::Null))
                    .as_str()
                    .unwrap();
                assert!(url.contains("state="), "URL should contain state param");
                assert!(
                    url.contains("code_challenge="),
                    "URL should contain PKCE challenge"
                );
            }
            Err(e) => panic!("link-social should succeed: {e:?}"),
            Ok(None) => panic!("Expected a response"),
        }
    }

    // Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/link-account.test.ts; adapted to the Rust account and OAuth route behavior.
    #[tokio::test]
    async fn test_callback_with_encryption_encrypts_tokens_for_new_user() {
        let mock_url = start_mock_oauth_server("newuser@example.com").await;

        let config = Arc::new(test_config_with_encryption_skip_state_cookie_check());
        let db = create_test_database().await;

        let mut oauth_config = OAuthConfig::default();
        oauth_config
            .providers
            .insert("test".to_owned(), make_test_provider(&mock_url));

        // Set up the OAuth state for a brand-new user (no link_user_id)
        let state = "encrypt-new-user-state";
        let payload = json!({
            "callbackURL": format!("{}/callback/test", mock_url),
            "codeVerifier": "test-verifier",
            "oauthState": state,
            "expiresAt": (Utc::now() + Duration::minutes(10)).timestamp_millis(),
        });

        db.create_verification(CreateVerification {
            identifier: format!("auth-state:{state}"),
            value: payload.to_string(),
            expires_at: Utc::now() + Duration::minutes(10),
        })
        .await
        .unwrap();

        let ctx = AuthContext::new(Arc::clone(&config), Arc::clone(&db));

        let mut req = AuthRequest::new(
            HttpMethod::Get,
            format!("/callback/test?code=test-code&state={state}"),
        );
        req.query.insert("code".to_owned(), "test-code".to_owned());
        req.query.insert("state".to_owned(), state.to_owned());

        let oauth_plugin = OAuthPlugin::with_config(oauth_config);
        let result = oauth_plugin.on_request(&req, &ctx).await;
        let expected_location = format!("{mock_url}/callback/test");

        match result {
            Ok(Some(resp)) => {
                assert_eq!(resp.status, 302);
                assert_eq!(
                    resp.headers.get("Location").map(String::as_str),
                    Some(expected_location.as_str()),
                );

                // Verify the user was created and tokens are stored encrypted
                let user = db
                    .get_user_by_email("newuser@example.com")
                    .await
                    .unwrap()
                    .expect("User should have been created");

                let accounts = db.get_user_accounts(&user.id()).await.unwrap();
                assert_eq!(accounts.len(), 1);

                let stored_access = (*(accounts)
                    .first()
                    .expect("fixture contains the requested index"))
                .access_token()
                .unwrap();
                // The mock server returns "mock-access-token".
                // With encryption on, the stored value should NOT be the plaintext.
                assert_ne!(
                    stored_access, "mock-access-token",
                    "Access token should be encrypted in DB"
                );

                // Verify it can be decrypted back to the original mock value
                let decrypted = decrypt_token(stored_access, TEST_SECRET).unwrap();
                assert_eq!(decrypted, "mock-access-token");

                // Also verify refresh token is encrypted
                if let Some(stored_refresh) = (*(accounts)
                    .first()
                    .expect("fixture contains the requested index"))
                .refresh_token()
                {
                    assert_ne!(
                        stored_refresh, "mock-refresh-token",
                        "Refresh token should be encrypted in DB"
                    );
                    let decrypted_refresh = decrypt_token(stored_refresh, TEST_SECRET).unwrap();
                    assert_eq!(decrypted_refresh, "mock-refresh-token");
                }
            }
            Err(e) => panic!("Callback should succeed for new user: {e:?}"),
            Ok(None) => panic!("Expected a response"),
        }
    }

    // Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/link-account.test.ts; adapted to the Rust account and OAuth route behavior.
    #[tokio::test]
    async fn test_get_access_token_preserves_source_plaintext_import_when_encryption_is_enabled() {
        let config = Arc::new(test_config_with_encryption());
        let db = create_test_database().await;

        let (user_id, session_token, account_id) = setup_user_with_account(
            &db,
            &config,
            "plaintext-access@example.com",
            "google",
            Some("plain-access-token".to_owned()),
            Some("plain-refresh-token".to_owned()),
        )
        .await;

        let before = serde_json::to_value(db.get_user_accounts(&user_id).await.unwrap()).unwrap();
        let ctx = AuthContext::new(Arc::clone(&config), Arc::clone(&db));
        let mut oauth_config = OAuthConfig::default();
        oauth_config.providers.insert(
            "google".to_owned(),
            make_test_provider("http://localhost:65535"),
        );
        let oauth_plugin = OAuthPlugin::with_config(oauth_config);

        let mut req = AuthRequest::new(HttpMethod::Post, "/get-access-token");
        req.body = Some(json!({"accountId": account_id}).to_string().into_bytes());
        req.headers
            .insert("content-type".to_owned(), "application/json".to_owned());
        req.headers.insert(
            "cookie".to_owned(),
            format!(
                "better-auth.session_token={}",
                alibi_core::utils::cookie_utils::sign_cookie_value(&session_token, TEST_SECRET)
            ),
        );

        let result = oauth_plugin.on_request(&req, &ctx).await;
        let response = result.unwrap().unwrap();
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            (*(body)
                .get("accessToken")
                .unwrap_or(&serde_json::Value::Null)),
            "plain-access-token"
        );
        assert_eq!(
            serde_json::to_value(db.get_user_accounts(&user_id).await.unwrap()).unwrap(),
            before
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/account.test.ts :: describe("account") and packages/better-auth/src/oauth2/link-account.test.ts; adapted to the Rust account and OAuth route behavior.
    #[tokio::test]
    async fn test_refresh_token_passes_plaintext_import_to_custom_provider_and_encrypts_rotation() {
        let config = Arc::new(test_config_with_encryption());
        let db = create_test_database().await;

        let (user_id, session_token, account_id) = setup_user_with_account(
            &db,
            &config,
            "plaintext-refresh@example.com",
            "google",
            Some("plain-access-token".to_owned()),
            Some("plain-refresh-token".to_owned()),
        )
        .await;

        let ctx = AuthContext::new(Arc::clone(&config), Arc::clone(&db));
        let mut oauth_config = OAuthConfig::default();
        let sequence = Arc::new(std::sync::Mutex::new(vec![(
            "plain-refresh-token".to_owned(),
            OAuthTokenSet {
                access_token: Some("new-access-token".to_owned()),
                refresh_token: Some("new-refresh-token".to_owned()),
                id_token: Some("literal-provider-id-token".to_owned()),
                ..Default::default()
            },
        )]));
        let mut provider = make_test_provider("http://localhost:65535");
        provider.refresh_access_token = Some(Arc::new(RotatingRefreshHandler {
            sequence: Arc::clone(&sequence),
        }));
        oauth_config.providers.insert("google".to_owned(), provider);
        let oauth_plugin = OAuthPlugin::with_config(oauth_config);

        let mut req = AuthRequest::new(HttpMethod::Post, "/refresh-token");
        req.body = Some(json!({"accountId": account_id}).to_string().into_bytes());
        req.headers
            .insert("content-type".to_owned(), "application/json".to_owned());
        req.headers.insert(
            "cookie".to_owned(),
            format!(
                "better-auth.session_token={}",
                alibi_core::utils::cookie_utils::sign_cookie_value(&session_token, TEST_SECRET)
            ),
        );

        let result = oauth_plugin.on_request(&req, &ctx).await;
        let response = result.unwrap().unwrap();
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            (*(body)
                .get("accessToken")
                .unwrap_or(&serde_json::Value::Null)),
            "new-access-token"
        );
        assert_eq!(
            (*(body)
                .get("refreshToken")
                .unwrap_or(&serde_json::Value::Null)),
            "new-refresh-token"
        );
        assert_eq!(
            (*(body).get("idToken").unwrap_or(&serde_json::Value::Null)),
            "literal-provider-id-token"
        );
        assert!(sequence.lock().unwrap().is_empty());
        let account = db.get_user_accounts(&user_id).await.unwrap().remove(0);
        assert_eq!(account.id(), account_id);
        assert_eq!(
            decrypt_token(account.access_token().unwrap(), TEST_SECRET).unwrap(),
            "new-access-token"
        );
        assert_eq!(
            decrypt_token(account.refresh_token().unwrap(), TEST_SECRET).unwrap(),
            "new-refresh-token"
        );
        assert_eq!(account.id_token(), Some("literal-provider-id-token"));
    }
}
