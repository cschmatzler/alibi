use super::*;

// The session's normalized mailbox matches a case-varied delivery request,
// while a genuinely different mailbox must not receive its proof.
#[tokio::test]
async fn authenticated_verification_delivery_compares_normalized_mailboxes() {
    let (auth, sender) = auth(false, Some(false), false).await;
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
}

// Disabled username registration ignores additional username inputs as the
// pinned core schema does, and cannot dispatch either username endpoint.
#[tokio::test]
async fn username_disabled_signup_ignores_additional_input_and_excludes_username_routes() {
    let (auth, sender) = auth(false, Some(false), false).await;
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
        let response = auth.handle_request(req).await.unwrap();
        assert_eq!(response.status, 404);
        assert_eq!(response.body.len(), 0);
    }
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
    assert_eq!(
        auth.store()
            .get_user_sessions(&user.id())
            .await
            .unwrap()
            .len(),
        0
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
    drop(proof.query.insert("token".into(), token));
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

// Modern email-change proofs use initialized email-verification expiry in both
// delivery stages, including when the auth instance has a custom base path.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn change_email_delivery_uses_configured_verification_expiry_and_base_path() {
    for (expiry, path, expected_seconds) in [
        (chrono::Duration::hours(1), "/api/auth", 3600),
        (chrono::Duration::seconds(90), "/nested/auth", 90),
    ] {
        let config = AuthConfig::new("verification-change-fixture-secret-minimum-32-characters")
            .base_url(ORIGIN)
            .base_path(path);
        let database = Database::connect("sqlite::memory:").await.unwrap();
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
            .await
            .unwrap();
        let confirmation = Arc::new(ChangeProofSender::default());
        let follow_up = Arc::new(Sender::default());
        let auth = AuthBuilder::new(config.clone())
            .store(SeaOrmStore::<Schema>::new(config, database))
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
                    .send_change_email_confirmation(Arc::<ChangeProofSender>::clone(&confirmation)),
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
                    better_auth_core::UpdateUser {
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
        let query: std::collections::HashMap<_, _> = delivered.query_pairs().into_owned().collect();
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
        let confirmed = auth.handle_request(verify).await.unwrap();
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
        assert_eq!(auth.handle_request(finish).await.unwrap().status, 200);
        let persisted = auth.store().get_user_by_id(id).await.unwrap().unwrap();
        assert_eq!(persisted.email(), Some(target));
        assert!(persisted.email_verified());
        assert_eq!(auth.store().get_user_accounts(id).await.unwrap().len(), 1);
        assert_eq!(auth.store().get_user_sessions(id).await.unwrap().len(), 1);
    }
}
