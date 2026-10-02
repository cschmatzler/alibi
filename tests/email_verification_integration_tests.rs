#![cfg(test)]
//! Awaited notification policy and direct delivery at the HTTP boundary.
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]

#[cfg(test)]
#[path = "email_verification_integration_tests/tests.rs"]
mod tests;

use async_trait::async_trait;
use better_auth::plugins::user_management::{SendChangeEmailConfirmation, UserInfo};
use better_auth::plugins::{
    EmailPasswordPlugin, EmailVerificationConfig, EmailVerificationPlugin, SendVerificationEmail,
    UserManagementPlugin,
};
use better_auth::{AuthBuilder, AuthConfig, BetterAuth};
use better_auth_core::wire::UserView;
use better_auth_core::{
    AuthAccount, AuthError, AuthRequest, AuthResponse, AuthResult, AuthUser, HttpMethod,
};
use better_auth_seaorm::{Database, SeaOrmStore};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

const ORIGIN: &str = "http://verification.fixture.test";

const EMAIL: &str = "mixedcase@verification.fixture.test";

const PASSWORD: &str = "notification-contract-password123";

#[derive(Default)]
struct Sender {
    calls: Mutex<Vec<(UserView, String)>>,
    fail: AtomicBool,
}

#[async_trait]
impl SendVerificationEmail for Sender {
    async fn send(&self, user: &UserView, _url: &str, token: &str) -> AuthResult<()> {
        self.calls
            .lock()
            .unwrap()
            .push((user.clone(), token.to_owned()));
        if self.fail.load(Ordering::SeqCst) {
            Err(AuthError::bad_request("fixture delivery failed"))
        } else {
            Ok(())
        }
    }
}

#[derive(Default)]
struct ChangeProofSender {
    calls: Mutex<Vec<(String, String, String)>>,
}

#[async_trait]
impl SendChangeEmailConfirmation for ChangeProofSender {
    async fn send(
        &self,
        user: &UserInfo,
        _new_email: &str,
        url: &str,
        token: &str,
    ) -> AuthResult<()> {
        self.calls
            .lock()
            .unwrap()
            .push((user.id.clone(), url.to_owned(), token.to_owned()));
        Ok(())
    }
}

async fn auth(
    required: bool,
    send_on_signup: Option<bool>,
    fail: bool,
    policy: better_auth::AwaitedNotificationErrorPolicy,
) -> (BetterAuth<Schema>, Arc<Sender>) {
    let mut config =
        AuthConfig::new("verification-fixture-secret-minimum-32-characters").base_url(ORIGIN);
    if policy == better_auth::AwaitedNotificationErrorPolicy::LogAndContinue {
        config = config.awaited_notification_errors(policy);
    }
    let db = Database::connect("sqlite::memory:").await.unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&db)
        .await
        .unwrap();
    let sender = Arc::new(Sender {
        fail: AtomicBool::new(fail),
        ..Default::default()
    });
    let auth = AuthBuilder::new(config.clone())
        .store(SeaOrmStore::<Schema>::new(config, db))
        .plugin(
            EmailPasswordPlugin::new()
                .enable_username(false)
                .require_email_verification(required),
        )
        // Registering the plugins independently exercises initialized configuration discovery.
        .plugin(EmailVerificationPlugin::with_config(
            EmailVerificationConfig {
                send_on_sign_up: send_on_signup,
                send_on_sign_in: true,
                send_verification_email: Some(Arc::<Sender>::clone(&sender)),
                ..Default::default()
            },
        ))
        .build()
        .await
        .unwrap();
    (auth, sender)
}

async fn post(auth: &BetterAuth<Schema>, path: &str, body: Value) -> (AuthResponse, Value) {
    post_with_cookie(auth, path, body, None).await
}

async fn post_with_cookie(
    auth: &BetterAuth<Schema>,
    path: &str,
    body: Value,
    cookie: Option<&str>,
) -> (AuthResponse, Value) {
    let mut req = AuthRequest::new(
        HttpMethod::Post,
        format!("{}{path}", auth.config().base_path),
    );
    drop(
        req.headers
            .insert("content-type".into(), "application/json".into()),
    );
    drop(req.headers.insert("origin".into(), ORIGIN.into()));
    if let Some(cookie) = cookie {
        drop(req.headers.insert("cookie".into(), cookie.into()));
    }
    req.body = Some(serde_json::to_vec(&body).unwrap());
    let response = auth.handle_request(req).await.unwrap();
    let payload = serde_json::from_slice(&response.body).unwrap();
    (response, payload)
}

fn signup() -> Value {
    json!({"email":"MixedCase@verification.fixture.test","password":PASSWORD,"name":"Verification Contract"})
}
