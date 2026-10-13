//! OTP reset validates password policy before consuming proof and retains established sessions.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::email_otp::{EmailOtpConfig, EmailOtpPlugin, EmailOtpType};

backend_tests!(server_email_otp_password_reset_replaces_credentials_without_reissuing_authority);
async fn server_email_otp_password_reset_replaces_credentials_without_reissuing_authority<
    B: Backend,
>(
    parent: Db,
) -> TestResult {
    for credential in [true, false] {
        let db = parent.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let auth = Box::pin(
            super::auth_probe::fast_builder::<B>(&connection)
                .plugin(EmailOtpPlugin::new(EmailOtpConfig::default()))
                .build(),
        )
        .await?;
        let email = "server-reset-owner@example.test";
        let owner = if credential {
            Box::pin(signup(&auth, email)).await
        } else {
            let otp = Box::pin(auth.dispatch_endpoint(
                EmailOtpPlugin::create_verification_otp_endpoint(email, EmailOtpType::SignIn),
                EndpointOptions::default(),
            ))
            .await?
            .decode()?;
            Box::pin(
                auth.dispatch_endpoint(
                    ServerEndpoint::<Value>::new("email-otp", "signInEmailOTP")
                        .with_body(&json!({"email":email,"otp":otp,"name":"OTP Owner"}))?,
                    EndpointOptions::default(),
                ),
            )
            .await?
            .into_response()?
        };
        let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
        let foreign = Box::pin(signup(&auth, "server-reset-foreign@example.test")).await;
        let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
        let sessions = db.table("session").await?;
        let foreign_before = auth.store().get_user_by_id(&foreign_id).await?.unwrap();
        let otp = Box::pin(auth.dispatch_endpoint(
            EmailOtpPlugin::create_verification_otp_endpoint(email, EmailOtpType::ForgetPassword),
            EndpointOptions::default(),
        ))
        .await?
        .decode()?;
        let proof = db.table("verification").await?;
        let identities = db.tables(&["user", "account", "session"]).await?;
        let endpoint = |body: &Value| {
            ServerEndpoint::<Value>::new("email-otp", "resetPasswordEmailOTP").with_body(body)
        };
        for (input, code) in [
            (
                json!({"email":email,"otp":otp,"password":42}),
                "VALIDATION_ERROR",
            ),
            (
                json!({"email":email,"otp":otp,"password":"short"}),
                "PASSWORD_TOO_SHORT",
            ),
        ] {
            let error =
                Box::pin(auth.dispatch_endpoint(endpoint(&input)?, EndpointOptions::default()))
                    .await
                    .unwrap_err();
            assert_eq!(error.error.status_code(), 400);
            assert_eq!(error.error.error_payload().1.as_deref(), Some(code));
            assert_eq!(db.table("verification").await?, proof);
            assert_eq!(
                db.tables(&["user", "account", "session"]).await?,
                identities
            );
        }
        let wrong = Box::pin(auth.dispatch_endpoint(
            endpoint(&json!({"email":email,"otp":"wrong","password":"replacement-password123"}))?,
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
                .get_verification_by_identifier(&format!("forget-password-otp-{email}"))
                .await?
                .unwrap()
                .value(),
            format!("{otp}:1")
        );
        let output=Box::pin(auth.dispatch_endpoint(EmailOtpPlugin::reset_password_email_otp_endpoint(&alibi::plugins::email_otp::EmailOtpPasswordResetInput {email:email.to_uppercase(),otp:otp.clone(),password:"replacement-password123".into()})?.with_body(&json!({"email":email.to_uppercase(),"otp":otp,"password":"replacement-password123","userId":foreign_id}))?,EndpointOptions::default())).await?;
        assert!(output.decode()?.success);
        assert!(output.headers().get_all("set-cookie").next().is_none());
        assert_eq!(db.count("verification").await?, 0);
        assert_eq!(db.table("session").await?, sessions);
        use alibi::AuthUser;
        let updated = auth.store().get_user_by_id(&owner_id).await?.unwrap();
        assert!(updated.email_verified());
        assert_eq!(
            serde_json::to_value(auth.store().get_user_by_id(&foreign_id).await?.unwrap())?,
            serde_json::to_value(foreign_before)?
        );
        assert_eq!(db.count("account").await?, 2);
        Box::pin(authenticated(&auth, &cookies(&owner), email)).await;
        Box::pin(authenticated(
            &auth,
            &cookies(&foreign),
            "server-reset-foreign@example.test",
        ))
        .await;
        let completed = db
            .tables(&["user", "account", "session", "verification"])
            .await?;
        let replay = Box::pin(auth.dispatch_endpoint(
            endpoint(&json!({"email":email,"otp":otp,"password":"must-not-commit123"}))?,
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
        if credential {
            let denied = Box::pin(call(
                &auth,
                request(
                    "/sign-in/email",
                    Some(json!({"email":email,"password":PASSWORD})),
                    "",
                ),
                401,
            ))
            .await;
            assert_eq!(body(&denied)["code"], "INVALID_EMAIL_OR_PASSWORD");
        }
        let accepted = Box::pin(call(
            &auth,
            request(
                "/sign-in/email",
                Some(json!({"email":email,"password":"replacement-password123"})),
                "",
            ),
            200,
        ))
        .await;
        assert_eq!(body(&accepted)["user"]["id"], owner_id);
        B::close(connection).await?;
    }
    Ok(())
}
