//! Server OTP checks retain live proofs while enforcing scope, user existence and attempts.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::email_otp::{EmailOtpConfig, EmailOtpPlugin, EmailOtpStorage, EmailOtpType};

backend_tests!(server_email_otp_checks_preserve_live_proofs_and_retire_exhausted_attempts);
async fn server_email_otp_checks_preserve_live_proofs_and_retire_exhausted_attempts<B: Backend>(
    parent: Db,
) -> TestResult {
    for storage in [EmailOtpStorage::Plain, EmailOtpStorage::Hashed] {
        let db = parent.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let auth = Box::pin(
            super::auth_probe::fast_builder::<B>(&connection)
                .plugin(EmailOtpPlugin::new(EmailOtpConfig {
                    storage: storage.clone(),
                    ..Default::default()
                }))
                .build(),
        )
        .await?;
        let email = "server-check-owner@example.test";
        let _ = Box::pin(signup(&auth, email)).await;
        let identities = db.tables(&["user", "account", "session"]).await?;
        let endpoint = |input: &Value| {
            ServerEndpoint::<Value>::new("email-otp", "checkVerificationOTP").with_body(input)
        };
        for kind in [
            EmailOtpType::EmailVerification,
            EmailOtpType::SignIn,
            EmailOtpType::ForgetPassword,
            EmailOtpType::ChangeEmail,
        ] {
            let otp = Box::pin(auth.dispatch_endpoint(
                EmailOtpPlugin::create_verification_otp_endpoint(email, kind),
                EndpointOptions::default(),
            ))
            .await?
            .decode()?;
            let key = format!("{}-otp-{email}", kind.as_str());
            let proof = db.table("verification").await?;
            let malformed = Box::pin(auth.dispatch_endpoint(
                endpoint(&json!({"email":email,"type":kind.as_str(),"otp":42}))?,
                EndpointOptions::default(),
            ))
            .await
            .unwrap_err();
            assert_eq!(malformed.error.status_code(), 400);
            assert_eq!(
                malformed.error.error_payload().1.as_deref(),
                Some("VALIDATION_ERROR")
            );
            assert_eq!(db.table("verification").await?, proof);
            let success=Box::pin(auth.dispatch_endpoint(EmailOtpPlugin::check_verification_otp_endpoint(email.to_uppercase(),kind,otp.clone()).with_body(&json!({"email":email.to_uppercase(),"type":kind.as_str(),"otp":otp,"ignored":true}))?,EndpointOptions::default())).await?;
            assert!(success.decode()?.success);
            assert!(success.headers().get_all("set-cookie").next().is_none());
            assert_eq!(db.table("verification").await?, proof);
            for attempt in 1..=3 {
                let wrong = Box::pin(auth.dispatch_endpoint(
                    endpoint(&json!({"email":email,"type":kind.as_str(),"otp":"wrong"}))?,
                    EndpointOptions::default(),
                ))
                .await
                .unwrap_err();
                assert_eq!(wrong.error.status_code(), 400);
                assert_eq!(
                    wrong.error.error_payload().1.as_deref(),
                    Some("INVALID_OTP")
                );
                use alibi::AuthVerification;
                let stored = auth
                    .store()
                    .get_verification_by_identifier(&key)
                    .await?
                    .unwrap();
                assert!(stored.value().ends_with(&format!(":{attempt}")));
                if matches!(storage, EmailOtpStorage::Plain) {
                    assert_eq!(stored.value(), format!("{otp}:{attempt}"));
                }
            }
            let exhausted = Box::pin(auth.dispatch_endpoint(
                endpoint(&json!({"email":email,"type":kind.as_str(),"otp":otp}))?,
                EndpointOptions::default(),
            ))
            .await
            .unwrap_err();
            assert_eq!(exhausted.error.status_code(), 403);
            assert_eq!(
                exhausted.error.error_payload().1.as_deref(),
                Some("TOO_MANY_ATTEMPTS")
            );
            assert!(
                auth.store()
                    .get_verification_by_identifier(&key)
                    .await?
                    .is_none()
            );
            assert_eq!(
                db.tables(&["user", "account", "session"]).await?,
                identities
            );
        }
        let guest = "server-check-absent@example.test";
        let otp = Box::pin(auth.dispatch_endpoint(
            EmailOtpPlugin::create_verification_otp_endpoint(guest, EmailOtpType::SignIn),
            EndpointOptions::default(),
        ))
        .await?
        .decode()?;
        let proof = db.table("verification").await?;
        let missing = Box::pin(auth.dispatch_endpoint(
            endpoint(&json!({"email":guest,"type":"sign-in","otp":otp}))?,
            EndpointOptions::default(),
        ))
        .await
        .unwrap_err();
        assert_eq!(missing.error.status_code(), 400);
        assert_eq!(
            missing.error.error_payload().1.as_deref(),
            Some("USER_NOT_FOUND")
        );
        assert_eq!(db.table("verification").await?, proof);
        let key = format!("sign-in-otp-{guest}");
        let _ = auth
            .context()
            .verifications()
            .update(
                &key,
                alibi::UpdateVerification {
                    expires_at: Some(chrono::Utc::now() - chrono::Duration::hours(1)),
                    ..Default::default()
                },
            )
            .await?;
        let expired = Box::pin(auth.dispatch_endpoint(
            endpoint(&json!({"email":guest,"type":"sign-in","otp":otp}))?,
            EndpointOptions::default(),
        ))
        .await
        .unwrap_err();
        assert_eq!(expired.error.status_code(), 400);
        assert_eq!(
            expired.error.error_payload().1.as_deref(),
            Some("OTP_EXPIRED")
        );
        assert!(
            auth.store()
                .get_verification_by_identifier(&key)
                .await?
                .is_none()
        );
        let replay = Box::pin(auth.dispatch_endpoint(
            endpoint(&json!({"email":guest,"type":"sign-in","otp":otp}))?,
            EndpointOptions::default(),
        ))
        .await
        .unwrap_err();
        assert_eq!(
            replay.error.error_payload().1.as_deref(),
            Some("INVALID_OTP")
        );
        assert_eq!(
            db.tables(&["user", "account", "session"]).await?,
            identities
        );
        B::close(connection).await?;
    }
    Ok(())
}
