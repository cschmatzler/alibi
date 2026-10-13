//! Server mailbox verification consumes its scoped proof before optional session publication.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::EmailVerificationPlugin;
use alibi::plugins::email_otp::{EmailOtpConfig, EmailOtpPlugin, EmailOtpType};

backend_tests!(server_email_otp_verification_consumes_proofs_and_respects_auto_sign_in);
async fn server_email_otp_verification_consumes_proofs_and_respects_auto_sign_in<B: Backend>(
    parent: Db,
) -> TestResult {
    for auto in [false, true] {
        let db = parent.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let auth = Box::pin(
            super::auth_probe::fast_builder::<B>(&connection)
                .plugin(EmailVerificationPlugin::new().auto_sign_in_after_verification(auto))
                .plugin(EmailOtpPlugin::new(EmailOtpConfig::default()))
                .build(),
        )
        .await?;
        let email = "server-verify-owner@example.test";
        let owner = Box::pin(signup(&auth, email)).await;
        let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
        assert_eq!(body(&owner)["user"]["emailVerified"], false);
        let foreign = Box::pin(signup(&auth, "server-verify-foreign@example.test")).await;
        let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
        let identities = db.tables(&["user", "account", "session"]).await?;
        let otp = Box::pin(auth.dispatch_endpoint(
            EmailOtpPlugin::create_verification_otp_endpoint(
                email,
                EmailOtpType::EmailVerification,
            ),
            EndpointOptions::default(),
        ))
        .await?
        .decode()?;
        let key = format!("email-verification-otp-{email}");
        let proof = db.table("verification").await?;
        let endpoint = |input: &Value| {
            ServerEndpoint::<Value>::new("email-otp", "verifyEmailOTP").with_body(input)
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
        assert_eq!(db.table("verification").await?, proof);
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
        assert_eq!(
            auth.store()
                .get_verification_by_identifier(&key)
                .await?
                .unwrap()
                .value(),
            format!("{otp}:1")
        );
        assert_eq!(
            db.tables(&["user", "account", "session"]).await?,
            identities
        );
        let output = Box::pin(
            auth.dispatch_endpoint(
                EmailOtpPlugin::verify_email_otp_endpoint(email.to_uppercase(), otp.clone())
                    .with_body(
                        &json!({"email":email.to_uppercase(),"otp":otp,"userId":foreign_id}),
                    )?,
                EndpointOptions {
                    headers: Some(
                        [
                            ("user-agent".into(), "server-email-otp-sdk".into()),
                            ("x-forwarded-for".into(), "198.51.100.31".into()),
                        ]
                        .into_iter()
                        .collect(),
                    ),
                    ..Default::default()
                },
            ),
        )
        .await?;
        let value = output.decode()?;
        assert!(value.status);
        assert_eq!(value.user.id, owner_id);
        assert!(value.user.email_verified);
        assert!(
            auth.store()
                .get_verification_by_identifier(&key)
                .await?
                .is_none()
        );
        assert_eq!(db.count("session").await?, if auto { 3 } else { 2 });
        if auto {
            let token = value.token.as_deref().unwrap();
            let session = auth.store().get_session(token).await?.unwrap();
            use alibi::AuthSession;
            assert_eq!(session.user_id(), owner_id);
            assert_eq!(session.user_agent(), Some("server-email-otp-sdk"));
            assert_eq!(session.ip_address(), Some("198.51.100.31"));
            let response = output.into_response()?;
            Box::pin(authenticated(&auth, &cookies(&response), email)).await;
        } else {
            assert!(value.token.is_none());
            assert!(output.headers().get_all("set-cookie").next().is_none());
            let anonymous = Box::pin(call(&auth, request("/get-session", None, ""), 200)).await;
            assert_eq!(body(&anonymous), Value::Null);
        }
        Box::pin(authenticated(&auth, &cookies(&owner), email)).await;
        Box::pin(authenticated(
            &auth,
            &cookies(&foreign),
            "server-verify-foreign@example.test",
        ))
        .await;
        let completed = db
            .tables(&["user", "account", "session", "verification"])
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
            db.tables(&["user", "account", "session", "verification"])
                .await?,
            completed
        );
        let guest = "server-verify-absent@example.test";
        let guest_otp = Box::pin(auth.dispatch_endpoint(
            EmailOtpPlugin::create_verification_otp_endpoint(
                guest,
                EmailOtpType::EmailVerification,
            ),
            EndpointOptions::default(),
        ))
        .await?
        .decode()?;
        let missing = Box::pin(auth.dispatch_endpoint(
            endpoint(&json!({"email":guest,"otp":guest_otp}))?,
            EndpointOptions::default(),
        ))
        .await
        .unwrap_err();
        assert_eq!(missing.error.status_code(), 400);
        assert_eq!(
            missing.error.error_payload().1.as_deref(),
            Some("USER_NOT_FOUND")
        );
        assert_eq!(
            db.tables(&["user", "account", "session", "verification"])
                .await?,
            completed
        );
        B::close(connection).await?;
    }
    Ok(())
}
