#![allow(
    clippy::unwrap_used,
    reason = "asserted one-time-token contracts against real SQLite"
)]

use super::*;
use crate::plugins::test_helpers;
use better_auth_core::CreateUser;

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

async fn setup() -> (AuthContext<TestSchema>, OneTimeTokenSession) {
    let ctx = test_helpers::create_test_context().await;
    let (user, session) = test_helpers::create_user_and_session(
        &ctx,
        CreateUser::new().with_email("one-time-token@fixture.test"),
        Duration::days(1),
    )
    .await;
    (ctx, OneTimeTokenSession { user, session })
}

fn signed_request(
    path: &str,
    session: &OneTimeTokenSession,
    ctx: &AuthContext<impl AuthSchema>,
) -> AuthRequest {
    let mut req = test_helpers::create_auth_request_no_query(HttpMethod::Get, path, None, None);
    req.headers.insert(
        "cookie".to_owned(),
        better_auth_core::utils::cookie_utils::create_session_cookie(
            &session.session.token,
            &ctx.config,
        )
        .split(';')
        .next()
        .unwrap()
        .to_owned(),
    );
    req
}

#[tokio::test]
async fn default_tokens_are_persisted_consumed_once_and_reuse_the_original_session() {
    let (ctx, session) = setup().await;
    let plugin = OneTimeTokenPlugin::new();
    let token = plugin
        .generate_for_session(&session, None, &ctx)
        .await
        .unwrap();
    assert_eq!(token.chars().count(), 32);
    let identifier = format!("one-time-token:{token}");
    let stored = ctx
        .database
        .get_latest_verification_by_identifier(&identifier)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.value, session.session.token);
    assert!((stored.expires_at - Utc::now()).num_seconds() >= 179);
    let verified = plugin.verify_token(&token, &ctx).await.unwrap();
    assert_eq!(verified.session.token, session.session.token);
    assert_eq!(verified.user.id, session.user.id);
    assert!(
        ctx.database
            .get_latest_verification_by_identifier(&identifier)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        matches!(plugin.verify_token(&token, &ctx).await, Err(AuthError::BadRequest(message)) if message == "Invalid token")
    );
    assert_eq!(
        ctx.database
            .get_user_sessions(&session.user.id)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn expired_latest_generation_invalidates_older_live_token_and_revoked_session_consumes_the_token()
 {
    let (ctx, session) = setup().await;
    let plugin = OneTimeTokenPlugin::new();
    let identifier = "one-time-token:duplicate";
    ctx.database
        .create_verification(CreateVerification {
            identifier: identifier.to_owned(),
            value: session.session.token.clone(),
            expires_at: Utc::now() + Duration::minutes(3),
        })
        .await
        .unwrap();
    ctx.database
        .create_verification(CreateVerification {
            identifier: identifier.to_owned(),
            value: session.session.token.clone(),
            expires_at: Utc::now() - Duration::seconds(1),
        })
        .await
        .unwrap();
    assert!(
        matches!(plugin.verify_token("duplicate", &ctx).await, Err(AuthError::BadRequest(message)) if message == "Invalid token")
    );
    assert!(
        ctx.database
            .get_latest_verification_by_identifier(identifier)
            .await
            .unwrap()
            .is_none()
    );
    let token = plugin
        .generate_for_session(&session, None, &ctx)
        .await
        .unwrap();
    ctx.database
        .delete_session(&session.session.token)
        .await
        .unwrap();
    assert!(
        matches!(plugin.verify_token(&token, &ctx).await, Err(AuthError::BadRequest(message)) if message == "Session not found")
    );
    assert!(
        matches!(plugin.verify_token(&token, &ctx).await, Err(AuthError::BadRequest(message)) if message == "Invalid token")
    );
}

#[tokio::test]
async fn concurrent_token_redemption_has_exactly_one_winner() {
    let (ctx, session) = setup().await;
    let plugin = OneTimeTokenPlugin::new();
    let token = plugin
        .generate_for_session(&session, None, &ctx)
        .await
        .unwrap();
    let (first, second) = tokio::join!(
        plugin.verify_token(&token, &ctx),
        plugin.verify_token(&token, &ctx)
    );
    assert_ne!(first.is_ok(), second.is_ok());
    let verified = first.or(second).unwrap();
    assert_eq!(verified.session.token, session.session.token);
    assert_eq!(
        ctx.database
            .get_user_sessions(&session.user.id)
            .await
            .unwrap()
            .len(),
        1
    );
}

struct CustomHasher;
#[async_trait]
impl HashOneTimeToken for CustomHasher {
    async fn hash(&self, token: &str) -> AuthResult<String> {
        Ok(format!("custom:{token}"))
    }
}
struct CustomGenerator;
#[async_trait]
impl GenerateOneTimeToken for CustomGenerator {
    async fn generate(
        &self,
        session: &OneTimeTokenSession,
        request: Option<&AuthRequest>,
    ) -> AuthResult<String> {
        assert_eq!(request.map(AuthRequest::path), None);
        assert!(!session.user.id.is_empty());
        Ok("custom-generated-token".to_owned())
    }
}

#[tokio::test]
async fn hashed_and_custom_storage_share_consistent_issue_and_consume_paths() {
    let (ctx, session) = setup().await;
    for storage in [
        OneTimeTokenStorage::Hashed,
        OneTimeTokenStorage::Custom(Arc::new(CustomHasher)),
    ] {
        let plugin = OneTimeTokenPlugin::with_config(OneTimeTokenConfig {
            storage,
            generator: Some(Arc::new(CustomGenerator)),
            ..Default::default()
        });
        let token = plugin
            .generate_for_session(&session, None, &ctx)
            .await
            .unwrap();
        let stored = plugin.stored_token(&token).await.unwrap();
        assert_ne!(token, stored);
        assert!(
            ctx.database
                .get_latest_verification_by_identifier(&format!("one-time-token:{token}"))
                .await
                .unwrap()
                .is_none()
        );
        let row = ctx
            .database
            .get_latest_verification_by_identifier(&format!("one-time-token:{stored}"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.value, session.session.token);
        assert_eq!(
            plugin
                .verify_token(&token, &ctx)
                .await
                .unwrap()
                .session
                .token,
            session.session.token
        );
    }
}

#[tokio::test]
async fn http_transfer_cookie_headers_and_server_only_configuration_are_observable() {
    let (ctx, session) = setup().await;
    let plugin = OneTimeTokenPlugin::with_config(OneTimeTokenConfig {
        disable_client_request: true,
        set_ott_header_on_new_session: true,
        ..Default::default()
    });
    let req = signed_request("/one-time-token/generate", &session, &ctx);
    assert_eq!(plugin.generate(&req, &ctx).await.unwrap().status, 400);
    let token = plugin
        .generate_for_session(&session, None, &ctx)
        .await
        .unwrap();
    let verify = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/one-time-token/verify",
        None,
        Some(json!({ "token": token })),
    );
    let response = plugin.verify(&verify, &ctx).await.unwrap();
    assert_eq!(response.status, 200);
    let cookie = response.headers.get("set-cookie").unwrap();
    let cookie = cookie::Cookie::parse(cookie.clone()).unwrap();
    assert_eq!(
        verify_cookie_value(cookie.value(), &ctx.config.secret).as_deref(),
        Some(session.session.token.as_str())
    );
    for (preference, persistent) in [
        (None, true),
        (Some(""), true),
        (Some("false"), false),
        (Some("true"), false),
    ] {
        let token = plugin
            .generate_for_session(&session, None, &ctx)
            .await
            .unwrap();
        let mut verify = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/one-time-token/verify",
            None,
            Some(json!({ "token": token })),
        );
        if let Some(value) = preference {
            verify.headers.insert(
                "cookie".to_owned(),
                format!(
                    "{}={}",
                    related_cookie_name(&ctx.config, "dont_remember"),
                    sign_cookie_value(value, &ctx.config.secret)
                ),
            );
        }
        let verified = plugin.verify(&verify, &ctx).await.unwrap();
        assert_eq!(verified.status, 200);
        let cookies = verified
            .headers
            .get_all("set-cookie")
            .map(|header| cookie::Cookie::parse(header.clone()).unwrap())
            .collect::<Vec<_>>();
        let session_cookie = cookies
            .iter()
            .find(|cookie| cookie.name() == ctx.config.session.cookie_name)
            .unwrap();
        assert_eq!(
            cookies
                .iter()
                .any(|cookie| cookie.name() == related_cookie_name(&ctx.config, "dont_remember")),
            !persistent
        );
        assert_eq!(
            session_cookie.max_age().map(|age| age.whole_seconds()),
            persistent.then_some(ctx.config.session.expires_in.num_seconds()),
            "receiving preference {preference:?}"
        );
        assert_eq!(
            verify_cookie_value(session_cookie.value(), &ctx.config.secret).as_deref(),
            Some(session.session.token.as_str())
        );
    }
    let mut response = response;
    response.headers.insert(
        "access-control-expose-headers",
        " existing, ,existing, set-ott, set-ott, Existing ",
    );
    let hooked = plugin.after_request(&verify, &ctx, response).await.unwrap();
    assert_eq!(
        hooked.headers.get("access-control-expose-headers").unwrap(),
        "existing, set-ott, Existing"
    );
    let delivered = plugin
        .verify_token(hooked.headers.get("set-ott").unwrap(), &ctx)
        .await
        .unwrap();
    assert_eq!(delivered.session.token, session.session.token);
    assert_eq!(delivered.user.id, session.user.id);
    let no_cookie = OneTimeTokenPlugin::with_config(OneTimeTokenConfig {
        disable_set_session_cookie: true,
        ..Default::default()
    });
    let token = no_cookie
        .generate_for_session(&session, None, &ctx)
        .await
        .unwrap();
    let verify = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/one-time-token/verify",
        None,
        Some(json!({ "token": token })),
    );
    assert!(
        no_cookie
            .verify(&verify, &ctx)
            .await
            .unwrap()
            .headers
            .get("set-cookie")
            .is_none()
    );
}
