//! The pinned runtime treats notification failures differently from direct delivery failures.
#![expect(
    clippy::unwrap_used,
    reason = "integration setup and endpoint results must succeed"
)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use better_auth::plugins::{
    EmailPasswordPlugin, EmailVerificationConfig, EmailVerificationPlugin, SendVerificationEmail,
};
use better_auth::{AuthBuilder, AuthConfig, BetterAuth};
use better_auth_core::wire::UserView;
use better_auth_core::{
    AuthAccount, AuthError, AuthRequest, AuthResponse, AuthResult, AuthUser, HttpMethod,
};
use better_auth_seaorm::{Database, SeaOrmStore};
use serde_json::{Value, json};

type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
const ORIGIN: &str = "http://verification.fixture.test";
const EMAIL: &str = "mixedcase@verification.fixture.test";
const PASSWORD: &str = "notification-contract-password123";

#[derive(Default)]
struct Sender {
    calls: Mutex<Vec<(UserView, String)>>,
    fail: bool,
}

#[async_trait]
impl SendVerificationEmail for Sender {
    async fn send(&self, user: &UserView, _url: &str, token: &str) -> AuthResult<()> {
        self.calls
            .lock()
            .unwrap()
            .push((user.clone(), token.to_string()));
        if self.fail {
            Err(AuthError::bad_request("fixture delivery failed"))
        } else {
            Ok(())
        }
    }
}

async fn auth(
    required: bool,
    send_on_signup: Option<bool>,
    fail: bool,
) -> (BetterAuth<Schema>, Arc<Sender>) {
    let config =
        AuthConfig::new("verification-fixture-secret-minimum-32-characters").base_url(ORIGIN);
    let db = Database::connect("sqlite::memory:").await.unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&db)
        .await
        .unwrap();
    let sender = Arc::new(Sender {
        fail,
        ..Default::default()
    });
    let auth = AuthBuilder::new(config.clone())
        .store(SeaOrmStore::<Schema>::new(config, db))
        .plugin(EmailPasswordPlugin::new().require_email_verification(required))
        // Registering the plugins independently exercises initialized configuration discovery.
        .plugin(EmailVerificationPlugin::with_config(
            EmailVerificationConfig {
                send_on_sign_up: send_on_signup,
                send_on_sign_in: true,
                send_verification_email: Some(sender.clone()),
                ..Default::default()
            },
        ))
        .build()
        .await
        .unwrap();
    (auth, sender)
}

async fn post(auth: &BetterAuth<Schema>, path: &str, body: Value) -> (AuthResponse, Value) {
    let mut req = AuthRequest::new(HttpMethod::Post, format!("/api/auth{path}"));
    _ = req
        .headers
        .insert("content-type".into(), "application/json".into());
    _ = req.headers.insert("origin".into(), ORIGIN.into());
    req.body = Some(serde_json::to_vec(&body).unwrap());
    let response = auth.handle_request(req).await.unwrap();
    let payload = serde_json::from_slice(&response.body).unwrap();
    (response, payload)
}

fn signup() -> Value {
    json!({"email":"MixedCase@verification.fixture.test","password":PASSWORD,"name":"Verification Contract"})
}

// Pinned sign-up uses sendOnSignUp ?? requireEmailVerification. This must
// govern real delivery and session issuance, even with independently installed plugins.
#[tokio::test]
async fn signup_configuration_controls_delivery_without_bypassing_required_verification() {
    for (required, send_on_signup, delivered, signed_in) in [
        (true, None, true, false),
        (true, Some(false), false, false),
        (false, Some(true), true, true),
    ] {
        let (auth, sender) = auth(required, send_on_signup, false).await;
        let (response, payload) = post(&auth, "/sign-up/email", signup()).await;
        assert_eq!(response.status, 200, "{payload}");
        assert_eq!(payload.pointer("/user/email"), Some(&json!(EMAIL)));
        assert_eq!(payload.pointer("/user/emailVerified"), Some(&json!(false)));
        let user = auth
            .store()
            .get_user_by_email(EMAIL)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            payload.pointer("/user/id").and_then(Value::as_str),
            Some(user.id().as_ref())
        );
        let accounts = auth.store().get_user_accounts(&user.id()).await.unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts.first().unwrap().provider_id(), "credential");
        assert_eq!(accounts.first().unwrap().user_id(), user.id());
        let sessions = auth.store().get_user_sessions(&user.id()).await.unwrap();
        assert_eq!(sessions.len(), usize::from(signed_in));
        assert_eq!(
            payload.get("token").is_some_and(Value::is_string),
            signed_in
        );
        let calls = sender.calls.lock().unwrap();
        assert_eq!(calls.len(), usize::from(delivered));
        if let Some((recipient, _)) = calls.first() {
            assert_eq!(recipient.id, user.id());
            assert_eq!(recipient.email.as_deref(), Some(EMAIL));
        }
    }
}

// Upstream runInBackgroundOrAwait logs callback errors at signup/signin, while
// sendVerificationEmailFn directly awaits and propagates the same callback error.
#[tokio::test]
async fn notification_failure_commits_signup_but_direct_delivery_reports_the_error() {
    let (auth, sender) = auth(true, None, true).await;
    let (registered, signup_body) = post(&auth, "/sign-up/email", signup()).await;
    assert_eq!(registered.status, 200, "{signup_body}");
    assert_eq!(signup_body.get("token"), Some(&Value::Null));
    let user = auth
        .store()
        .get_user_by_email(EMAIL)
        .await
        .unwrap()
        .unwrap();
    assert!(!user.email_verified());
    assert_eq!(
        auth.store()
            .get_user_accounts(&user.id())
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        auth.store()
            .get_user_sessions(&user.id())
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(sender.calls.lock().unwrap().len(), 1);

    let (denied, denied_body) = post(
        &auth,
        "/sign-in/email",
        json!({"email":EMAIL,"password":PASSWORD}),
    )
    .await;
    assert_eq!(denied.status, 403, "{denied_body}");
    assert_eq!(denied_body.get("code"), Some(&json!("EMAIL_NOT_VERIFIED")));
    assert_eq!(sender.calls.lock().unwrap().len(), 2);
    assert!(
        auth.store()
            .get_user_sessions(&user.id())
            .await
            .unwrap()
            .is_empty()
    );

    let (direct, direct_body) =
        post(&auth, "/send-verification-email", json!({"email":EMAIL})).await;
    assert_eq!(direct.status, 400, "{direct_body}");
    assert_eq!(
        direct_body.get("message"),
        Some(&json!("fixture delivery failed"))
    );
    assert_eq!(sender.calls.lock().unwrap().len(), 3);
    assert!(
        !auth
            .store()
            .get_user_by_id(&user.id())
            .await
            .unwrap()
            .unwrap()
            .email_verified()
    );

    let token = sender.calls.lock().unwrap().first().unwrap().1.clone();
    let mut proof = AuthRequest::new(HttpMethod::Get, "/api/auth/verify-email");
    _ = proof.query.insert("token".into(), token);
    let verified = auth.handle_request(proof).await.unwrap();
    assert_eq!(verified.status, 200);
    let verified_body: Value = serde_json::from_slice(&verified.body).unwrap();
    assert_eq!(verified_body.get("user"), Some(&Value::Null));
    assert!(
        auth.store()
            .get_user_by_id(&user.id())
            .await
            .unwrap()
            .unwrap()
            .email_verified()
    );

    let (signed_in, signed_in_body) = post(
        &auth,
        "/sign-in/email",
        json!({"email":EMAIL,"password":PASSWORD}),
    )
    .await;
    assert_eq!(signed_in.status, 200, "{signed_in_body}");
    let sessions = auth.store().get_user_sessions(&user.id()).await.unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(
        signed_in_body.pointer("/user/id").and_then(Value::as_str),
        Some(user.id().as_ref())
    );
    assert_eq!(sender.calls.lock().unwrap().len(), 3);
}
