//! Logical OTP sign-in distinguishes returning identities from signup-only input.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::email_otp::{EmailOtpConfig, EmailOtpPlugin, EmailOtpType};

backend_tests!(server_email_otp_sign_in_preserves_owner_and_creation_authority);
async fn server_email_otp_sign_in_preserves_owner_and_creation_authority<B: Backend>(
    parent: Db,
) -> TestResult {
    for disabled in [false, true] {
        let db = parent.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let config = AuthConfig::new(SECRET).base_url(ORIGIN);
        let auth = Box::pin(
            AuthBuilder::new(config.clone())
                .store(B::store(Arc::new(config), &connection))
                .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
                .plugin(super::auth_probe::fast_password().enable_username(!disabled))
                .plugin(SessionManagementPlugin::new())
                .plugin(EmailOtpPlugin::new(EmailOtpConfig {
                    disable_sign_up: disabled,
                    ..Default::default()
                }))
                .build(),
        )
        .await?;
        let email = "server-otp-login-owner@example.test";
        let owner = Box::pin(signup(&auth, email)).await;
        let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
        let foreign = Box::pin(signup(&auth, "server-otp-login-foreign@example.test")).await;
        let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
        let verification = Box::pin(auth.dispatch_endpoint(
            EmailOtpPlugin::create_verification_otp_endpoint(
                email,
                EmailOtpType::EmailVerification,
            ),
            EndpointOptions::default(),
        ))
        .await?
        .decode()?;
        let verified = Box::pin(auth.dispatch_endpoint(
            EmailOtpPlugin::verify_email_otp_endpoint(email, verification),
            EndpointOptions::default(),
        ))
        .await?;
        let expected_user = serde_json::to_value(verified.value().get("user").unwrap())?;
        let identities = db.tables(&["users", "accounts"]).await?;
        let sessions = db.table("sessions").await?;
        let otp = Box::pin(auth.dispatch_endpoint(
            EmailOtpPlugin::create_verification_otp_endpoint(email, EmailOtpType::SignIn),
            EndpointOptions::default(),
        ))
        .await?
        .decode()?;
        let proof = db.table("verifications").await?;
        let endpoint = |body: &Value| {
            ServerEndpoint::<Value>::new("email-otp", "signInEmailOTP").with_body(body)
        };
        let invalid = Box::pin(auth.dispatch_endpoint(
            endpoint(&json!({"email":email,"otp":42}))?,
            EndpointOptions::default(),
        ))
        .await
        .unwrap_err();
        assert_eq!(invalid.error.status_code(), 400);
        assert_eq!(
            invalid.error.error_payload().1.as_deref(),
            Some("VALIDATION_ERROR")
        );
        assert_eq!(db.table("verifications").await?, proof);
        let wrong = Box::pin(auth.dispatch_endpoint(
            endpoint(&json!({"email":email,"otp":"wrong"}))?,
            EndpointOptions::default(),
        ))
        .await
        .unwrap_err();
        assert_eq!(
            wrong.error.error_payload().1.as_deref(),
            Some("INVALID_OTP")
        );
        use alibi::AuthVerification;
        let key = format!("sign-in-otp-{email}");
        assert_eq!(
            auth.store()
                .get_verification_by_identifier(&key)
                .await?
                .unwrap()
                .value(),
            format!("{otp}:1")
        );
        let output=Box::pin(auth.dispatch_endpoint(endpoint(&json!({"email":email.to_uppercase(),"otp":otp,"username":5,"displayUsername":{"unexpected":true},"name":"Ignored New Name","image":"https://ignored.example/image.png","userId":foreign_id}))?,EndpointOptions {
            headers:Some([("user-agent".into(),"server-email-otp-sign-in".into()),("x-forwarded-for".into(),"198.51.100.32".into())].into_iter().collect()), ..Default::default()
        })).await?;
        let value = output.decode()?;
        assert_eq!(value["user"], expected_user);
        let token = value["token"].as_str().unwrap();
        let session = auth.store().get_session(token).await?.unwrap();
        use alibi::AuthSession;
        assert_eq!(session.user_id(), owner_id);
        assert_eq!(session.user_agent(), Some("server-email-otp-sign-in"));
        assert_eq!(session.ip_address(), Some("198.51.100.32"));
        Box::pin(authenticated(
            &auth,
            &cookies(&output.into_response()?),
            email,
        ))
        .await;
        assert_eq!(db.tables(&["users", "accounts"]).await?, identities);
        assert_eq!(db.count("sessions").await?, 3);
        let existing: Vec<Value> = serde_json::from_str(&sessions)?;
        let current: Vec<Value> = serde_json::from_str(&db.table("sessions").await?)?;
        assert!(existing.iter().all(|row| current.contains(row)));
        Box::pin(authenticated(&auth, &cookies(&owner), email)).await;
        Box::pin(authenticated(
            &auth,
            &cookies(&foreign),
            "server-otp-login-foreign@example.test",
        ))
        .await;
        let completed = db
            .tables(&["users", "accounts", "sessions", "verifications"])
            .await?;
        let replay = Box::pin(auth.dispatch_endpoint(
            endpoint(&json!({"email":email,"otp":otp}))?,
            EndpointOptions::default(),
        ))
        .await
        .unwrap_err();
        assert_eq!(
            replay.error.error_payload().1.as_deref(),
            Some("INVALID_OTP")
        );
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "verifications"])
                .await?,
            completed
        );
        let guest = "server-otp-login-guest@example.test";
        let guest_otp = Box::pin(auth.dispatch_endpoint(
            EmailOtpPlugin::create_verification_otp_endpoint(guest, EmailOtpType::SignIn),
            EndpointOptions::default(),
        ))
        .await?
        .decode()?;
        let created=Box::pin(auth.dispatch_endpoint(EmailOtpPlugin::sign_in_email_otp_endpoint(&serde_json::from_value(json!({"email":guest,"otp":guest_otp,"name":"Fresh OTP","image":"https://images.example/otp.png","username":"fresh_otp","displayUsername":"Fresh OTP"}))?)?,EndpointOptions::default())).await;
        if disabled {
            let error = created.unwrap_err();
            assert_eq!(error.error.status_code(), 400);
            assert_eq!(
                error.error.error_payload().1.as_deref(),
                Some("INVALID_OTP")
            );
            assert_eq!(
                db.tables(&["users", "accounts", "sessions", "verifications"])
                    .await?,
                completed
            );
        } else {
            let output = created?;
            let value = output.decode()?;
            assert_eq!(value.user.email.as_deref(), Some(guest));
            assert_eq!(value.user.name.as_deref(), Some("Fresh OTP"));
            assert!(value.user.email_verified);
            assert_eq!(value.user.username.as_deref(), Some("fresh_otp"));
            Box::pin(authenticated(
                &auth,
                &cookies(&output.into_response()?),
                guest,
            ))
            .await;
            assert_eq!(db.count("users").await?, 3);
            assert_eq!(db.count("accounts").await?, 2);
            assert_eq!(db.count("sessions").await?, 4);
            assert_eq!(db.count("verifications").await?, 0);
        }
        B::close(connection).await?;
    }
    Ok(())
}
