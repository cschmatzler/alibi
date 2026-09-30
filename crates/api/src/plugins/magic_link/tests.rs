#![expect(
    clippy::unwrap_used,
    reason = "test fixtures require successful setup and decoding"
)]

use super::*;
use crate::plugins::test_helpers;
use better_auth_core::{
    AuthPlugin, AuthSession, AuthUser, AuthVerification, CreateUser, HttpMethod,
};
use std::sync::Mutex;

#[derive(Default)]
struct Outbox(Mutex<Vec<MagicLinkDelivery>>);

#[async_trait]
impl SendMagicLink for Outbox {
    async fn send(&self, delivery: &MagicLinkDelivery) -> AuthResult<()> {
        self.0.lock().unwrap().push(delivery.clone());
        Ok(())
    }
}

fn configured() -> (MagicLinkPlugin, Arc<Outbox>) {
    let outbox = Arc::new(Outbox::default());
    (
        MagicLinkPlugin::new(MagicLinkConfig {
            send_magic_link: Some(outbox.clone()),
            ..Default::default()
        }),
        outbox,
    )
}

fn verify_request(token: &str) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Get, "/magic-link/verify");
    let _ = req.query.insert("token".into(), token.into());
    req
}

// Upstream: magicLink signInMagicLink persists before delivery, then consumes
// once; no callback gives the complete real user/session response.
#[tokio::test]
async fn delivered_link_authenticates_its_mailbox_once_and_persists_session() {
    let ctx = test_helpers::create_test_context().await;
    let (plugin, outbox) = configured();
    let req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/sign-in/magic-link",
        None,
        Some(json!({"email":"owner@example.com","name":"Owner","metadata":{"campaign":"welcome"}})),
    );
    assert_eq!(
        plugin.on_request(&req, &ctx).await.unwrap().unwrap().status,
        200
    );
    let delivery = outbox.0.lock().unwrap().last().unwrap().clone();
    let url = Url::parse(&delivery.url).unwrap();
    assert_eq!(url.path(), "/api/auth/magic-link/verify");
    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "callbackURL")
            .map(|(_, value)| value.into_owned()),
        Some("/".into())
    );
    assert_eq!(delivery.metadata, Some(json!({"campaign":"welcome"})));
    let stored = ctx
        .database
        .get_latest_verification_by_identifier(&delivery.token)
        .await
        .unwrap()
        .unwrap();
    assert!(
        (stored.expires_at() - Utc::now() - Duration::seconds(300))
            .num_seconds()
            .abs()
            <= 1
    );
    let req = verify_request(&delivery.token);
    let response = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(response.status, 200);
    let payload: Value = serde_json::from_slice(&response.body).unwrap();
    let token = payload.get("token").and_then(Value::as_str).unwrap();
    let user = ctx
        .database
        .get_user_by_email("owner@example.com")
        .await
        .unwrap()
        .unwrap();
    assert!(user.email_verified());
    assert_eq!(
        ctx.database
            .get_session(token)
            .await
            .unwrap()
            .unwrap()
            .user_id(),
        user.id()
    );
    assert!(payload.get("session").is_some());
    assert!(
        ctx.database
            .get_latest_verification_by_identifier(&delivery.token)
            .await
            .unwrap()
            .is_none()
    );
    let replay = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(replay.status, 302);
    assert!(
        replay
            .headers
            .get("location")
            .unwrap()
            .contains("error=INVALID_TOKEN")
    );
}

// Upstream: callbackURL/newUserCallbackURL choose different destinations;
// untrusted redirects are rejected before single-use consumption.
#[tokio::test]
async fn callback_authorization_does_not_burn_token_and_new_user_redirects() {
    let ctx = test_helpers::create_test_context().await;
    let (plugin, outbox) = configured();
    let req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/sign-in/magic-link",
        None,
        Some(json!({"email":"new@example.com"})),
    );
    let _ = plugin.on_request(&req, &ctx).await.unwrap();
    let delivery = outbox.0.lock().unwrap().last().unwrap().clone();
    let mut req = verify_request(&delivery.token);
    let _ = req
        .query
        .insert("callbackURL".into(), "https://evil.example/steal".into());
    assert_eq!(
        plugin
            .on_request(&req, &ctx)
            .await
            .unwrap_err()
            .status_code(),
        403
    );
    assert!(
        ctx.database
            .get_latest_verification_by_identifier(&delivery.token)
            .await
            .unwrap()
            .is_some()
    );
    let _ = req.query.insert("callbackURL".into(), "/existing".into());
    let _ = req
        .query
        .insert("newUserCallbackURL".into(), "/welcome?source=magic".into());
    let response = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(response.status, 302);
    assert_eq!(
        response.headers.get("location"),
        Some(&"http://localhost:3000/welcome?source=magic".into())
    );
    assert!(response.headers.contains_key("set-cookie"));
}

// Upstream: disabled signup still issues/delivers, but consumes and redirects
// with new_user_signup_disabled when the token identifies a new user.
#[tokio::test]
async fn disabled_signup_consumes_token_without_creating_user() {
    let ctx = test_helpers::create_test_context().await;
    let (mut plugin, outbox) = configured();
    plugin.config.disable_sign_up = true;
    let req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/sign-in/magic-link",
        None,
        Some(json!({"email":"disabled@example.com"})),
    );
    let _ = plugin.on_request(&req, &ctx).await.unwrap();
    let delivery = outbox.0.lock().unwrap().last().unwrap().clone();
    let response = plugin
        .on_request(&verify_request(&delivery.token), &ctx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status, 302);
    assert!(
        response
            .headers
            .get("location")
            .unwrap()
            .contains("new_user_signup_disabled")
    );
    assert!(
        ctx.database
            .get_user_by_email("disabled@example.com")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        ctx.database
            .get_latest_verification_by_identifier(&delivery.token)
            .await
            .unwrap()
            .is_none()
    );
}

// Upstream: hashed storage derives the lookup key, and verification after
// expiry invalidates the record without minting a user/session.
#[tokio::test]
async fn hashed_expired_token_is_removed_and_cannot_create_session() {
    let ctx = test_helpers::create_test_context().await;
    let (mut plugin, outbox) = configured();
    plugin.config.storage = MagicLinkTokenStorage::Hashed;
    plugin.config.expires_in = Duration::seconds(-1);
    let req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/sign-in/magic-link",
        None,
        Some(json!({"email":"expired@example.com"})),
    );
    let _ = plugin.on_request(&req, &ctx).await.unwrap();
    let delivery = outbox.0.lock().unwrap().last().unwrap().clone();
    assert!(
        ctx.database
            .get_latest_verification_by_identifier(&delivery.token)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        ctx.database
            .get_latest_verification_by_identifier(&hash_token(&delivery.token))
            .await
            .unwrap()
            .is_some()
    );
    let response = plugin
        .on_request(&verify_request(&delivery.token), &ctx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status, 302);
    assert!(
        response
            .headers
            .get("location")
            .unwrap()
            .contains("INVALID_TOKEN")
    );
    assert!(
        ctx.database
            .get_user_by_email("expired@example.com")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        ctx.database
            .get_latest_verification_by_identifier(&hash_token(&delivery.token))
            .await
            .unwrap()
            .is_none()
    );
}

// Upstream: a magic-link proof removes unproven standing sessions before login.
#[tokio::test]
async fn existing_unverified_user_keeps_identity_but_loses_previous_session() {
    let ctx = test_helpers::create_test_context().await;
    let user = ctx
        .database
        .create_user(CreateUser::new().with_email("promote@example.com"))
        .await
        .unwrap();
    let previous = ctx
        .session_manager()
        .create_session(&user, None, None)
        .await
        .unwrap();
    let (plugin, outbox) = configured();
    let req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/sign-in/magic-link",
        None,
        Some(json!({"email":"promote@example.com"})),
    );
    let _ = plugin.on_request(&req, &ctx).await.unwrap();
    let delivery = outbox.0.lock().unwrap().last().unwrap().clone();
    assert_eq!(
        plugin
            .on_request(&verify_request(&delivery.token), &ctx)
            .await
            .unwrap()
            .unwrap()
            .status,
        200
    );
    let promoted = ctx
        .database
        .get_user_by_email("promote@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(promoted.id(), user.id());
    assert!(promoted.email_verified());
    assert!(
        ctx.database
            .get_session(previous.token())
            .await
            .unwrap()
            .is_none()
    );
}

struct FixedToken;
#[async_trait]
impl MagicLinkTokenGenerator for FixedToken {
    async fn generate(&self, _: &str) -> AuthResult<String> {
        Ok("application-issued-link-token".into())
    }
}
struct PrefixHasher;
#[async_trait]
impl MagicLinkTokenHasher for PrefixHasher {
    async fn hash(&self, token: &str) -> AuthResult<String> {
        Ok(format!("application-hash:{}", hash_token(token)))
    }
}

// Upstream: custom token generation and storage compose, and concurrent calls
// consume a shared token once even when both callers know the actual secret.
#[tokio::test]
async fn custom_generation_hashing_and_concurrent_consumption_preserve_owned_session() {
    let ctx = test_helpers::create_test_context().await;
    let (mut plugin, outbox) = configured();
    plugin.config.generate_token = Some(Arc::new(FixedToken));
    plugin.config.storage = MagicLinkTokenStorage::Custom(Arc::new(PrefixHasher));
    let req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/sign-in/magic-link",
        None,
        Some(json!({"email":"custom@example.com"})),
    );
    let _ = plugin.on_request(&req, &ctx).await.unwrap();
    let token = outbox.0.lock().unwrap().last().unwrap().token.clone();
    assert_eq!(token, "application-issued-link-token");
    assert!(
        ctx.database
            .get_latest_verification_by_identifier(&token)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        ctx.database
            .get_latest_verification_by_identifier(&format!(
                "application-hash:{}",
                hash_token(&token)
            ))
            .await
            .unwrap()
            .is_some()
    );
    let req = verify_request(&token);
    let (first, second) =
        tokio::join!(plugin.on_request(&req, &ctx), plugin.on_request(&req, &ctx));
    let mut statuses = [
        first.unwrap().unwrap().status,
        second.unwrap().unwrap().status,
    ];
    statuses.sort();
    assert_eq!(statuses, [200, 302]);
    let user = ctx
        .database
        .get_user_by_email("custom@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        ctx.database
            .get_user_sessions(&user.id())
            .await
            .unwrap()
            .len(),
        1
    );
}

// Golden Zod vectors and all originCheck closures are evaluated before the
// challenge is touched, including error/new-user callbacks.
#[tokio::test]
async fn validation_and_every_callback_guard_leave_the_challenge_untouched() {
    let ctx = test_helpers::create_test_context().await;
    let (plugin, outbox) = configured();
    let req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/sign-in/magic-link",
        None,
        Some(json!({"email":"ok@example.com","name":null,"metadata":[]})),
    );
    let response = plugin.on_request(&req, &ctx).await.unwrap().unwrap();
    assert_eq!(response.status, 400);
    let payload: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(
        payload,
        json!({"code":"VALIDATION_ERROR","message":"[body.name] Invalid input: expected string, received null; [body.metadata] Invalid input: expected record, received array"})
    );
    assert!(outbox.0.lock().unwrap().is_empty());
    let req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/sign-in/magic-link",
        None,
        Some(json!({"email":"ok@example.com"})),
    );
    let _ = plugin.on_request(&req, &ctx).await.unwrap();
    let token = outbox.0.lock().unwrap().last().unwrap().token.clone();
    for field in ["callbackURL", "newUserCallbackURL", "errorCallbackURL"] {
        let mut req = verify_request(&token);
        let _ = req
            .query
            .insert(field.into(), "https://foreign.example/steal".into());
        let error = plugin.on_request(&req, &ctx).await.unwrap_err();
        let (_, code, message) = error.error_payload();
        assert_eq!(code.as_deref(), Some("INVALID_CALLBACK_URL"));
        assert_eq!(message, "Invalid callbackURL");
        assert!(
            ctx.database
                .get_latest_verification_by_identifier(&token)
                .await
                .unwrap()
                .is_some()
        );
    }
    let missing = AuthRequest::new(HttpMethod::Get, "/magic-link/verify");
    assert_eq!(
        plugin
            .on_request(&missing, &ctx)
            .await
            .unwrap_err()
            .error_payload()
            .1
            .as_deref(),
        Some("VALIDATION_ERROR")
    );
}

struct FailedDelivery;
#[async_trait]
impl SendMagicLink for FailedDelivery {
    async fn send(&self, _: &MagicLinkDelivery) -> AuthResult<()> {
        Err(AuthError::internal("deterministic sender outage"))
    }
}

// Upstream: delivery fails after persistence; an already issued token retains
// its deadline and is usable after the application restores the sender.
#[tokio::test]
async fn sender_failure_keeps_token_and_error_redirect_preserves_query_state() {
    let ctx = test_helpers::create_test_context().await;
    let (mut plugin, _) = configured();
    plugin.config.generate_token = Some(Arc::new(FixedToken));
    plugin.config.send_magic_link = Some(Arc::new(FailedDelivery));
    let req = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/sign-in/magic-link",
        None,
        Some(json!({"email":"outage@example.com"})),
    );
    assert_eq!(
        plugin
            .on_request(&req, &ctx)
            .await
            .unwrap_err()
            .status_code(),
        500
    );
    assert!(
        ctx.database
            .get_latest_verification_by_identifier("application-issued-link-token")
            .await
            .unwrap()
            .is_some()
    );
    let req = verify_request("application-issued-link-token");
    assert_eq!(
        plugin.on_request(&req, &ctx).await.unwrap().unwrap().status,
        200
    );
    let mut replay = req;
    let _ = replay.query.insert(
        "errorCallbackURL".into(),
        "/error?source=magic&error=old&error_description=preserved".into(),
    );
    let response = plugin.on_request(&replay, &ctx).await.unwrap().unwrap();
    let url = Url::parse(response.headers.get("location").unwrap()).unwrap();
    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "error_description")
            .map(|(_, value)| value.into_owned()),
        Some("preserved".into())
    );
    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "error")
            .map(|(_, value)| value.into_owned()),
        Some("INVALID_TOKEN".into())
    );
}
