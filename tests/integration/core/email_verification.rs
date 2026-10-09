//! Awaited notification policy and direct delivery at the HTTP boundary.
#![allow(
    clippy::panic_in_result_fn,
    reason = "shared integration owners propagate fixture failures and assert wire contracts"
)]

use crate::storage::{Backend, Db, TestResult, backend_tests, postgres_tests};
use alibi::plugins::user_management::{SendChangeEmailConfirmation, UserInfo};
use alibi::plugins::{
    EmailPasswordPlugin, EmailVerificationConfig, EmailVerificationPlugin, SendVerificationEmail,
    UserManagementPlugin,
};
use alibi::wire::UserView;
use alibi::{AuthAccount, AuthError, AuthRequest, AuthResponse, AuthResult, AuthUser, HttpMethod};
use alibi::{AuthBuilder, AuthConfig, BetterAuth};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

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

async fn auth<B: Backend>(
    db: Db,
    required: bool,
    send_on_signup: Option<bool>,
    fail: bool,
    policy: alibi::AwaitedNotificationErrorPolicy,
) -> (BetterAuth<B::Schema>, Arc<Sender>, Db) {
    let mut config =
        AuthConfig::new("verification-fixture-secret-minimum-32-characters").base_url(ORIGIN);
    if policy == alibi::AwaitedNotificationErrorPolicy::LogAndContinue {
        config = config.awaited_notification_errors(policy);
    }
    let (connection, _) = db
        .migrated::<B>("verification-fixture-secret-minimum-32-characters")
        .await
        .unwrap();
    let sender = Arc::new(Sender {
        fail: AtomicBool::new(fail),
        ..Default::default()
    });
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
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
    (auth, sender, db)
}

async fn post<S: alibi::AuthSchema>(
    auth: &BetterAuth<S>,
    path: &str,
    body: Value,
) -> (AuthResponse, Value) {
    Box::pin(post_with_cookie(auth, path, body, None)).await
}

async fn post_with_cookie<S: alibi::AuthSchema>(
    auth: &BetterAuth<S>,
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
    let response = Box::pin(auth.handle_request(req)).await.unwrap();
    let payload = serde_json::from_slice(&response.body).unwrap();
    (response, payload)
}

fn signup() -> Value {
    json!({"email":"MixedCase@verification.fixture.test","password":PASSWORD,"name":"Verification Contract"})
}

#[cfg(test)]
mod tests {
    use super::*;
    backend_tests!(
        authenticated_verification_delivery_compares_normalized_mailboxes,
        username_disabled_signup_ignores_additional_input_and_excludes_username_routes,
        signup_configuration_controls_delivery_without_bypassing_required_verification,
        notification_error_policy_controls_signup_commit_and_preserves_direct_delivery_errors,
        change_email_delivery_uses_configured_verification_expiry_and_base_path
    );
    postgres_tests!(
        authenticated_verification_delivery_compares_normalized_mailboxes,
        username_disabled_signup_ignores_additional_input_and_excludes_username_routes,
        signup_configuration_controls_delivery_without_bypassing_required_verification,
        notification_error_policy_controls_signup_commit_and_preserves_direct_delivery_errors,
        change_email_delivery_uses_configured_verification_expiry_and_base_path
    );

    // The session's normalized mailbox matches a case-varied delivery request,
    // while a genuinely different mailbox must not receive its proof.
    async fn authenticated_verification_delivery_compares_normalized_mailboxes<B: Backend>(
        db: Db,
    ) -> TestResult {
        let (auth, sender, _db) = auth::<B>(
            db.fresh().await?,
            false,
            Some(false),
            false,
            alibi::AwaitedNotificationErrorPolicy::Propagate,
        )
        .await;
        let (registered, body) = post(&auth, "/sign-up/email", signup()).await;
        assert_eq!(registered.status, 200, "{body}");
        let cookie = registered
            .headers
            .get("set-cookie")
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let (sent, sent_body) = post_with_cookie(
            &auth,
            "/send-verification-email",
            json!({"email":EMAIL.to_uppercase()}),
            Some(cookie),
        )
        .await;
        assert_eq!(sent.status, 200, "{sent_body}");
        assert_eq!(sent_body, json!({"status":true}));
        assert_eq!(sender.calls.lock().unwrap().len(), 1);
        let (foreign, foreign_body) = post_with_cookie(
            &auth,
            "/send-verification-email",
            json!({"email":"different@verification.fixture.test"}),
            Some(cookie),
        )
        .await;
        assert_eq!(foreign.status, 400, "{foreign_body}");
        assert_eq!(foreign_body.get("message"), Some(&json!("Email mismatch")));
        assert_eq!(sender.calls.lock().unwrap().len(), 1);
        let calls = sender.calls.lock().unwrap();
        assert_eq!(calls.first().unwrap().0.email.as_deref(), Some(EMAIL));
        assert_eq!(
            body.pointer("/user/id").and_then(Value::as_str),
            Some(calls.first().unwrap().0.id.as_str())
        );
        Ok(())
    }

    // Disabled username registration ignores additional username inputs as the
    // pinned core schema does, and cannot dispatch either username endpoint.
    async fn username_disabled_signup_ignores_additional_input_and_excludes_username_routes<
        B: Backend,
    >(
        db: Db,
    ) -> TestResult {
        let (auth, sender, _db) = auth::<B>(
            db.fresh().await?,
            false,
            Some(false),
            false,
            alibi::AwaitedNotificationErrorPolicy::Propagate,
        )
        .await;
        for (email, username, display) in [
            (
                "username-disabled-short@verification.fixture.test",
                json!("ab"),
                json!("invalid display !"),
            ),
            (
                "username-disabled-type@verification.fixture.test",
                json!(7),
                json!({"unregistered":true}),
            ),
        ] {
            let (response, body) = post(&auth, "/sign-up/email", json!({"email":email,"password":PASSWORD,"name":"Core Signup","username":username,"displayUsername":display})).await;
            assert_eq!(response.status, 200, "{body}");
            let user = auth
                .store()
                .get_user_by_email(email)
                .await
                .unwrap()
                .unwrap();
            assert!(user.username().is_none());
            assert!(user.display_username().is_none());
            assert_eq!(
                auth.store()
                    .get_user_accounts(&user.id())
                    .await
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(
                auth.store()
                    .get_user_sessions(&user.id())
                    .await
                    .unwrap()
                    .len(),
                1
            );
        }
        assert!(sender.calls.lock().unwrap().is_empty());
        for path in ["/sign-in/username", "/is-username-available"] {
            assert!(
                !auth
                    .routes()
                    .iter()
                    .any(|(registered, _)| registered == path)
            );
            let req = AuthRequest::new(HttpMethod::Post, format!("/api/auth{path}"));
            let response = Box::pin(auth.handle_request(req)).await.unwrap();
            assert_eq!(response.status, 404);
            assert_eq!(response.body.len(), 0);
        }
        Ok(())
    }

    // Pinned sign-up uses sendOnSignUp ?? requireEmailVerification. This must
    // govern real delivery and session issuance, even with independently installed plugins.
    async fn signup_configuration_controls_delivery_without_bypassing_required_verification<
        B: Backend,
    >(
        db: Db,
    ) -> TestResult {
        for (required, send_on_signup, delivered, signed_in) in [
            (true, None, true, false),
            (true, Some(false), false, false),
            (false, Some(true), true, true),
        ] {
            let (auth, sender, _db) = auth::<B>(
                db.fresh().await?,
                required,
                send_on_signup,
                false,
                alibi::AwaitedNotificationErrorPolicy::Propagate,
            )
            .await;
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
        Ok(())
    }

    // An awaited default failure rolls back uncommitted signup writes. Opt-in logging
    // completes signup and retains its proof. Both policies retain committed users
    // after sign-in notification errors and report direct delivery failure.
    async fn notification_error_policy_controls_signup_commit_and_preserves_direct_delivery_errors<
        B: Backend,
    >(
        db: Db,
    ) -> TestResult {
        for policy in [
            alibi::AwaitedNotificationErrorPolicy::Propagate,
            alibi::AwaitedNotificationErrorPolicy::LogAndContinue,
        ] {
            let (auth, sender, _db) = auth::<B>(db.fresh().await?, true, None, true, policy).await;
            let (registered, signup_body) = post(&auth, "/sign-up/email", signup()).await;
            if policy == alibi::AwaitedNotificationErrorPolicy::Propagate {
                assert_eq!(registered.status, 400, "{signup_body}");
                assert_eq!(
                    signup_body.get("message"),
                    Some(&json!("fixture delivery failed"))
                );
            } else {
                assert_eq!(registered.status, 200, "{signup_body}");
                assert_eq!(signup_body.get("token"), Some(&Value::Null));
            }
            if policy == alibi::AwaitedNotificationErrorPolicy::Propagate {
                assert!(
                    auth.store()
                        .get_user_by_email(EMAIL)
                        .await
                        .unwrap()
                        .is_none()
                );
                let delivered_user = sender.calls.lock().unwrap().first().unwrap().0.id.clone();
                assert!(
                    auth.store()
                        .get_user_by_id(&delivered_user)
                        .await
                        .unwrap()
                        .is_none()
                );
                assert!(
                    auth.store()
                        .get_user_accounts(&delivered_user)
                        .await
                        .unwrap()
                        .is_empty()
                );
                assert!(
                    auth.store()
                        .get_user_sessions(&delivered_user)
                        .await
                        .unwrap()
                        .is_empty()
                );
                assert_eq!(sender.calls.lock().unwrap().len(), 1);
                sender.fail.store(false, Ordering::SeqCst);
                let (retry, retry_body) = post(&auth, "/sign-up/email", signup()).await;
                assert_eq!(retry.status, 200, "{retry_body}");
                sender.fail.store(true, Ordering::SeqCst);
            }
            let signup_deliveries = if policy == alibi::AwaitedNotificationErrorPolicy::Propagate {
                2
            } else {
                1
            };
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
            assert_eq!(
                auth.store()
                    .get_user_sessions(&user.id())
                    .await
                    .unwrap()
                    .len(),
                0
            );
            let token = {
                let calls = sender.calls.lock().unwrap();
                assert_eq!(calls.len(), signup_deliveries);
                calls.last().expect("signup must deliver a proof").1.clone()
            };

            let (denied, denied_body) = post(
                &auth,
                "/sign-in/email",
                json!({"email":EMAIL,"password":PASSWORD}),
            )
            .await;
            if policy == alibi::AwaitedNotificationErrorPolicy::Propagate {
                assert_eq!(denied.status, 400, "{denied_body}");
                assert_eq!(
                    denied_body.get("message"),
                    Some(&json!("fixture delivery failed"))
                );
            } else {
                assert_eq!(denied.status, 403, "{denied_body}");
                assert_eq!(denied_body.get("code"), Some(&json!("EMAIL_NOT_VERIFIED")));
            }
            assert_eq!(sender.calls.lock().unwrap().len(), signup_deliveries + 1);
            assert_eq!(
                auth.store()
                    .get_user_sessions(&user.id())
                    .await
                    .unwrap()
                    .len(),
                0
            );

            let (direct, direct_body) =
                post(&auth, "/send-verification-email", json!({"email":EMAIL})).await;
            assert_eq!(direct.status, 400, "{direct_body}");
            assert_eq!(
                direct_body.get("message"),
                Some(&json!("fixture delivery failed"))
            );
            assert_eq!(sender.calls.lock().unwrap().len(), signup_deliveries + 2);
            assert!(
                !auth
                    .store()
                    .get_user_by_id(&user.id())
                    .await
                    .unwrap()
                    .unwrap()
                    .email_verified()
            );

            let mut proof = AuthRequest::new(HttpMethod::Get, "/api/auth/verify-email");
            drop(proof.query.insert("token".into(), token));
            let verified = Box::pin(auth.handle_request(proof)).await.unwrap();
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
            assert_eq!(sender.calls.lock().unwrap().len(), signup_deliveries + 2);
        }
        Ok(())
    }

    // Modern email-change proofs use initialized email-verification expiry in both
    // delivery stages, including when the auth instance has a custom base path.
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn change_email_delivery_uses_configured_verification_expiry_and_base_path<B: Backend>(
        db: Db,
    ) -> TestResult {
        for (expiry, path, expected_seconds) in [
            (chrono::Duration::hours(1), "/api/auth", 3600),
            (chrono::Duration::seconds(90), "/nested/auth", 90),
        ] {
            let config =
                AuthConfig::new("verification-change-fixture-secret-minimum-32-characters")
                    .base_url(ORIGIN)
                    .base_path(path);
            let case_db = db.fresh().await?;
            let (connection, _) = case_db
                .migrated::<B>("verification-change-fixture-secret-minimum-32-characters")
                .await?;
            let confirmation = Arc::new(ChangeProofSender::default());
            let follow_up = Arc::new(Sender::default());
            let auth = AuthBuilder::new(config.clone())
                .store(B::store(Arc::new(config), &connection))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(EmailVerificationPlugin::with_config(
                    EmailVerificationConfig {
                        verification_token_expiry: expiry,
                        send_on_sign_up: Some(false),
                        send_verification_email: Some(Arc::<Sender>::clone(&follow_up)),
                        ..Default::default()
                    },
                ))
                .plugin(
                    UserManagementPlugin::new()
                        .change_email_enabled(true)
                        .send_change_email_confirmation(Arc::<ChangeProofSender>::clone(
                            &confirmation,
                        )),
                )
                .build()
                .await
                .unwrap();
            let (registered, user) = post(&auth, "/sign-up/email", signup()).await;
            assert_eq!(registered.status, 200, "{user}");
            let id = user.pointer("/user/id").and_then(Value::as_str).unwrap();
            drop(
                auth.store()
                    .update_user(
                        id,
                        alibi::UpdateUser {
                            email_verified: Some(true),
                            ..Default::default()
                        },
                    )
                    .await
                    .unwrap(),
            );
            let cookie = registered
                .headers
                .get("set-cookie")
                .unwrap()
                .split(';')
                .next()
                .unwrap();
            let target = "changed@verification.fixture.test";
            let callback = "/complete?flow=change#done";
            let (changed, body) = post_with_cookie(
                &auth,
                "/change-email",
                json!({"newEmail":target,"callbackURL":callback}),
                Some(cookie),
            )
            .await;
            assert_eq!(changed.status, 200, "{body}");
            let deliveries = confirmation.calls.lock().unwrap().clone();
            assert_eq!(deliveries.len(), 1);
            let (owner, url, token) = deliveries.first().unwrap();
            assert_eq!(owner, id);
            let claims = jsonwebtoken::decode::<Value>(
                token,
                &jsonwebtoken::DecodingKey::from_secret(auth.config().secret.as_bytes()),
                &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256),
            )
            .unwrap()
            .claims;
            assert_eq!(
                claims.get("exp").and_then(Value::as_i64).unwrap()
                    - claims.get("iat").and_then(Value::as_i64).unwrap(),
                expected_seconds
            );
            assert_eq!(claims.get("email").and_then(Value::as_str), Some(EMAIL));
            assert_eq!(claims.get("updateTo").and_then(Value::as_str), Some(target));
            assert_eq!(
                claims.get("requestType").and_then(Value::as_str),
                Some("change-email-confirmation")
            );
            let delivered = reqwest::Url::parse(url).unwrap();
            assert_eq!(delivered.path(), format!("{path}/verify-email"));
            let query: std::collections::HashMap<_, _> =
                delivered.query_pairs().into_owned().collect();
            assert_eq!(query.get("token"), Some(token));
            assert_eq!(query.get("callbackURL").map(String::as_str), Some(callback));
            assert_eq!(
                auth.store()
                    .get_user_by_id(id)
                    .await
                    .unwrap()
                    .unwrap()
                    .email(),
                Some(EMAIL)
            );
            let mut verify = AuthRequest::new(HttpMethod::Get, delivered.path());
            verify.query = query;
            drop(verify.headers.insert("cookie".into(), cookie.into()));
            let confirmed = Box::pin(auth.handle_request(verify)).await.unwrap();
            assert_eq!(confirmed.status, 302);
            let calls = follow_up.calls.lock().unwrap().clone();
            assert_eq!(calls.len(), 1);
            let (follow_up_user, follow_up_token) = calls.first().unwrap();
            assert_eq!(follow_up_user.id, id);
            assert_eq!(follow_up_user.email.as_deref(), Some(target));
            let follow_up_claims = jsonwebtoken::decode::<Value>(
                follow_up_token,
                &jsonwebtoken::DecodingKey::from_secret(auth.config().secret.as_bytes()),
                &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256),
            )
            .unwrap()
            .claims;
            assert_eq!(
                follow_up_claims.get("exp").and_then(Value::as_i64).unwrap()
                    - follow_up_claims.get("iat").and_then(Value::as_i64).unwrap(),
                expected_seconds
            );
            let mut finish = AuthRequest::new(HttpMethod::Get, format!("{path}/verify-email"));
            drop(finish.query.insert("token".into(), follow_up_token.clone()));
            drop(finish.headers.insert("cookie".into(), cookie.into()));
            assert_eq!(
                Box::pin(auth.handle_request(finish)).await.unwrap().status,
                200
            );
            let persisted = auth.store().get_user_by_id(id).await.unwrap().unwrap();
            assert_eq!(persisted.email(), Some(target));
            assert!(persisted.email_verified());
            assert_eq!(auth.store().get_user_accounts(id).await.unwrap().len(), 1);
            assert_eq!(auth.store().get_user_sessions(id).await.unwrap().len(), 1);
        }
        Ok(())
    }
}
