//! Pending factor authority, authenticator interoperability and trusted-device rotation.
use super::*;
use alibi::plugins::TwoFactorPlugin;
use alibi::plugins::two_factor::{SendTwoFactorOtp, TwoFactorConfig};
use alibi::{AuthResult, UserView};
use async_trait::async_trait;

#[derive(Default)]
struct FactorMailbox(Mutex<Vec<(String, String)>>);
#[async_trait]
impl SendTwoFactorOtp for FactorMailbox {
    async fn send(&self, user: &UserView, code: &str) -> AuthResult<()> {
        self.0.lock().unwrap().push((user.id.clone(), code.into()));
        Ok(())
    }
}
use alibi::endpoint::EndpointOptions;

backend_tests!(
    totp_enrollment_pending_login_and_trusted_device_rotation,
    renamed_factor_table_owns_the_complete_factor_lifecycle
);
postgres_tests!(totp_enrollment_pending_login_and_trusted_device_rotation);

async fn signin<S: AuthSchema>(auth: &Alibi<S>, cookie: &str) -> AuthResponse {
    call(
        auth,
        request(
            "/sign-in/email",
            Some(json!({
                "email":"factor@example.test", "password":PASSWORD
            })),
            cookie,
        ),
        200,
    )
    .await
}

async fn totp_enrollment_pending_login_and_trusted_device_rotation<B: Backend>(
    db: Db,
) -> TestResult {
    Box::pin(async move {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mailbox = Arc::new(FactorMailbox::default());
    let auth = builder::<B>(&connection)
        .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
            send_otp: Some(mailbox.clone()),
            account_lockout: alibi::plugins::two_factor::AccountLockoutConfig {
                max_failed_attempts: 3.0,
                ..Default::default()
            },
            ..Default::default()
        }))
        .build()
        .await?;
    // RFC 6238's ASCII secret, encoded independently for the authenticator.
    let server_authenticator = totp_rs::Totp::from_url(
        "otpauth://totp/Server?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=6&period=30",
    )?;
    let server_code = Box::pin(auth
        .dispatch_endpoint(
            TwoFactorPlugin::generate_totp_endpoint("12345678901234567890"),
            EndpointOptions::default(),
        ))
        .await?
        .decode()?
        .code;
    assert!(server_authenticator.check_current(&server_code).is_some());
    let owner = signup(&auth, "factor@example.test").await;
    let user = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let before = db
        .tables(&["user", "account", "session", "twoFactor"])
        .await?;
    for (input, cookie, status, code) in [
        (json!({}), Some(cookies(&owner)), 400, "VALIDATION_ERROR"),
        (
            json!({"password":42}),
            Some(cookies(&owner)),
            400,
            "VALIDATION_ERROR",
        ),
        (
            json!({"password":PASSWORD,"method":"invalid"}),
            Some(cookies(&owner)),
            400,
            "VALIDATION_ERROR",
        ),
        (
            json!({"password":PASSWORD,"issuer":null}),
            Some(cookies(&owner)),
            400,
            "VALIDATION_ERROR",
        ),
        (json!({"password":PASSWORD}), None, 401, "UNAUTHORIZED"),
        (
            json!({"password":"wrong-password"}),
            Some(cookies(&owner)),
            400,
            "INVALID_PASSWORD",
        ),
    ] {
        let error = Box::pin(
            auth.dispatch_endpoint(
                alibi::endpoint::ServerEndpoint::<Value>::new("two-factor", "enableTwoFactor")
                    .with_body(&input)?,
                EndpointOptions {
                    headers: cookie.map(|cookie| [("cookie".into(), cookie)].into_iter().collect()),
                    ..Default::default()
                },
            ),
        )
        .await
        .unwrap_err();
        assert_eq!(error.error.status_code(), status);
        assert_eq!(error.error.error_payload().1.as_deref(), Some(code));
        assert_eq!(
            db.tables(&["user", "account", "session", "twoFactor"])
                .await?,
            before
        );
    }
    let enrollment = Box::pin(auth.dispatch_endpoint(
        TwoFactorPlugin::enable_two_factor_endpoint(alibi::plugins::two_factor::EnableTwoFactorInput {
                password:Some(PASSWORD.into()), issuer:Some("Server enrollment".into()), ..Default::default()
            }).with_body(&json!({"password":PASSWORD,"issuer":"Server enrollment","userId":"untrusted-selector"}))?,
        EndpointOptions {headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()}
    )).await?;
    assert!(matches!(
        enrollment.decode()?,
        alibi::plugins::two_factor::TwoFactorEnabled::Totp { .. }
    ));
    let enrollment = enrollment.into_response()?;
    let enrollment_body = body(&enrollment);
    assert_eq!(enrollment_body["method"], "totp");
    assert_eq!(
        url::Url::parse(enrollment_body["totpURI"].as_str().unwrap())?
            .query_pairs()
            .find(|(name, _)| name == "issuer")
            .unwrap()
            .1,
        "Server enrollment"
    );
    assert_eq!(enrollment_body["backupCodes"].as_array().unwrap().len(), 10);
    let after = db
        .tables(&["user", "account", "session", "twoFactor"])
        .await?;
    assert_eq!(&after[..3], &before[..3]);
    // A separate authenticator implementation consumes the actual otpauth URI.
    // Do not ask the production plugin to manufacture its own expected code.
    let authenticator = totp_rs::Totp::from_url(enrollment_body["totpURI"].as_str().unwrap())?;
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM \"user\" WHERE id = $1 AND \"twoFactorEnabled\" = true",
            &[&user]
        )
        .await?,
        0
    );
    let activated = Box::pin(auth.dispatch_endpoint(
        TwoFactorPlugin::verify_totp_endpoint(alibi::plugins::two_factor::VerifyTotpInput{code:authenticator.generate_current().to_string(),trust_device:None}),
        EndpointOptions {headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()}
    )).await?.into_response()?;
    let active_cookie = cookies(&activated);
    authenticated(&auth, &active_cookie, "factor@example.test").await;
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM \"user\" WHERE id = $1 AND \"twoFactorEnabled\" = true",
            &[&user]
        )
        .await?,
        1
    );
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM \"twoFactor\" WHERE \"userId\" = $1 AND \"verified\" = true",
            &[&user]
        )
        .await?,
        1
    );

    let remaining = Box::pin(async {
    Box::pin(async {
    let stable = db.tables(&["user", "account", "session", "twoFactor", "verification"]).await?;
    for (input, cookie, status, code) in [
        (json!({}), Some(active_cookie.clone()), 400, "VALIDATION_ERROR"),
        (json!({"password":42}), Some(active_cookie.clone()), 400, "VALIDATION_ERROR"),
        (json!({"password":"incorrect"}), Some(active_cookie.clone()), 400, "INVALID_PASSWORD"),
        (json!({"password":PASSWORD}), None, 401, "UNAUTHORIZED"),
    ] {
        let error = Box::pin(auth.dispatch_endpoint(
            alibi::endpoint::ServerEndpoint::<Value>::new("two-factor", "generateBackupCodes").with_body(&input)?,
            EndpointOptions {headers:cookie.map(|cookie| [("cookie".into(),cookie)].into_iter().collect()), ..Default::default()},
        )).await.unwrap_err();
        assert_eq!(error.error.status_code(), status);
        assert_eq!(error.error.error_payload().1.as_deref(), Some(code));
        assert_eq!(db.tables(&["user", "account", "session", "twoFactor", "verification"]).await?,stable);
    }
    Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }).await?;
    let regenerated = Box::pin(auth.dispatch_endpoint(
        TwoFactorPlugin::generate_backup_codes_endpoint(alibi::plugins::two_factor::GenerateBackupCodesInput { password:Some(PASSWORD.into()) })
            .with_body(&json!({"password":PASSWORD,"userId":"untrusted-selector"}))?,
        EndpointOptions {headers:Some([("cookie".into(),active_cookie.clone())].into_iter().collect()),..Default::default()},
    )).await?.into_response()?;
    assert_eq!(body(&regenerated)["status"], true);
    assert_eq!(body(&regenerated)["backupCodes"].as_array().unwrap().len(),10);
    let backup_view = Box::pin(auth
        .dispatch_endpoint(
            TwoFactorPlugin::view_backup_codes_endpoint(&user),
            EndpointOptions::default(),
        ))
        .await?
        .decode()?;
    assert!(backup_view.status);
    assert_eq!(backup_view.backup_codes, body(&regenerated)["backupCodes"]);
    let old_code = &enrollment_body["backupCodes"][0];
    let new_code = body(&regenerated)["backupCodes"][0]
        .as_str()
        .unwrap()
        .to_owned();
    let _ = call(
        &auth,
        request(
            "/two-factor/verify-backup-code",
            Some(json!({"code":old_code})),
            &active_cookie,
        ),
        401,
    )
    .await;
    let _ = call(
        &auth,
        request(
            "/two-factor/verify-backup-code",
            Some(json!({"code":new_code})),
            &active_cookie,
        ),
        200,
    )
    .await;

    let remaining = Box::pin(auth
        .dispatch_endpoint(
            TwoFactorPlugin::view_backup_codes_endpoint(&user),
            EndpointOptions::default(),
        ))
        .await?
        .decode()?
        .backup_codes;
    assert!(!remaining.as_array().unwrap().contains(&json!(new_code)));
    assert_eq!(
        remaining.as_array().unwrap().len() + 1,
        backup_view.backup_codes.as_array().unwrap().len()
    );

        Ok::<Value, Box<dyn std::error::Error + Send + Sync>>(remaining)
    }).await?;

    let before_pending = db.table("session").await?;
    let pending = signin(&auth, "").await;
    assert_eq!(body(&pending)["twoFactorRedirect"], true);
    assert!(body(&pending).get("token").is_none());
    assert_eq!(db.table("session").await?, before_pending);
    let pending_cookie = cookies(&pending);
    assert_eq!(
        body(&call(&auth, request("/get-session", None, &pending_cookie), 200).await),
        Value::Null
    );
    let now = chrono::Utc::now().timestamp() as u64;
    let invalid_code = (0..1_000_000)
        .map(|code| format!("{code:06}"))
        .find(|code| {
            (-2_i64..=2).all(|window| {
                authenticator
                    .generate((now as i64 + window * 30) as u64)
                    .to_string()
                    != *code
            })
        })
        .unwrap();
    let denied = Box::pin(auth.dispatch_endpoint(
        TwoFactorPlugin::verify_totp_endpoint(alibi::plugins::two_factor::VerifyTotpInput{code:invalid_code.clone(),trust_device:None}),
        EndpointOptions{headers:Some([("cookie".into(),pending_cookie.clone())].into_iter().collect()),..Default::default()}
    )).await.unwrap_err();
    assert_eq!(denied.error.status_code(),401);
    assert_eq!(denied.error.error_payload().1.as_deref(),Some("INVALID_CODE"));
    assert_eq!(db.table("session").await?, before_pending);
    let completed = Box::pin(auth.dispatch_endpoint(
        TwoFactorPlugin::verify_totp_endpoint(alibi::plugins::two_factor::VerifyTotpInput{code:authenticator.generate_current().to_string(),trust_device:Some(true)}),
        EndpointOptions {headers:Some([("cookie".into(),pending_cookie.clone())].into_iter().collect()),..Default::default()}
    )).await?.into_response()?;
    authenticated(&auth, &cookies(&completed), "factor@example.test").await;
    let trust = cookies(&completed)
        .split("; ")
        .find(|cookie| cookie.starts_with("better-auth.trust_device="))
        .unwrap()
        .to_owned();
    let sessions = db.table("session").await?;
    let before_replay = db.tables(&["user","account","session","twoFactor","verification"]).await?;
    let replay = Box::pin(auth.dispatch_endpoint(
        TwoFactorPlugin::verify_totp_endpoint(alibi::plugins::two_factor::VerifyTotpInput{code:authenticator.generate_current().to_string(),trust_device:None}),
        EndpointOptions{headers:Some([("cookie".into(),pending_cookie.clone())].into_iter().collect()),..Default::default()}
    )).await.unwrap_err();
    assert_eq!(replay.error.status_code(),401);
    assert_eq!(replay.error.error_payload().1.as_deref(),Some("INVALID_TWO_FACTOR_COOKIE"));
    assert_eq!(db.tables(&["user","account","session","twoFactor","verification"]).await?,before_replay);
    assert_eq!(db.table("session").await?,sessions);

    let trusted = signin(&auth, &trust).await;
    assert!(body(&trusted)["token"].as_str().is_some());
    assert!(body(&trusted).get("twoFactorRedirect").is_none());
    authenticated(&auth, &cookies(&trusted), "factor@example.test").await;
    let old_trust = signin(&auth, &trust).await;
    assert_eq!(
        body(&old_trust)["twoFactorRedirect"],
        true,
        "trusted-device proofs rotate once used"
    );
    let before_uri = db.tables(&["user","account","session","twoFactor","verification"]).await?;
    for (input,cookie,status,code) in [
        (json!({}),Some(cookies(&trusted)),400,"VALIDATION_ERROR"),
        (json!({"password":42}),Some(cookies(&trusted)),400,"VALIDATION_ERROR"),
        (json!({"password":null}),Some(cookies(&trusted)),400,"VALIDATION_ERROR"),
        (json!({"password":PASSWORD}),None,401,"UNAUTHORIZED"),
        (json!({"password":"wrong-password"}),Some(cookies(&trusted)),400,"INVALID_PASSWORD"),
    ] {
        let error = Box::pin(auth.dispatch_endpoint(alibi::endpoint::ServerEndpoint::<Value>::new("two-factor","getTOTPURI").with_body(&input)?,EndpointOptions {headers:cookie.map(|cookie|[("cookie".into(),cookie)].into_iter().collect()),..Default::default()})).await.unwrap_err();
        assert_eq!(error.error.status_code(),status);
        assert_eq!(error.error.error_payload().1.as_deref(),Some(code));
        assert_eq!(db.tables(&["user","account","session","twoFactor","verification"]).await?,before_uri);
    }
    let uri = Box::pin(auth.dispatch_endpoint(
        TwoFactorPlugin::get_totp_uri_endpoint(alibi::plugins::two_factor::GetTotpUriInput{password:Some(PASSWORD.into())})
            .with_body(&json!({"password":PASSWORD,"userId":"untrusted-selector"}))?,
        EndpointOptions{headers:Some([("cookie".into(),cookies(&trusted))].into_iter().collect()),..Default::default()}
    )).await?;
    assert!(!uri.decode()?.totp_uri.is_empty());
    let uri = uri.into_response()?;
    assert_eq!(db.tables(&["user","account","session","twoFactor","verification"]).await?,before_uri);
    let recovered = totp_rs::Totp::from_url(body(&uri)["totpURI"].as_str().unwrap())?;
    assert!(
        recovered
            .check_current(&authenticator.generate_current().to_string())
            .is_some()
    );
    let factors = db.table("twoFactor").await?;
    let _ = call(
        &auth,
        request(
            "/two-factor/get-totp-uri",
            Some(json!({"password":"wrong-password"})),
            &cookies(&trusted),
        ),
        400,
    )
    .await;
    assert_eq!(db.table("twoFactor").await?, factors);
    // OTP and backup codes must complete actual password-authenticated pending
    // logins, consume their proofs, and publish a session the browser can use.
    let pending_otp = cookies(&old_trust);
    let sessions = db.table("session").await?;
    let _ = call(
        &auth,
        request("/two-factor/send-otp", Some(json!({})), &pending_otp),
        200,
    )
    .await;
    let (delivered_user, code) = mailbox.0.lock().unwrap().pop().unwrap();
    assert_eq!(delivered_user, user);
    assert_eq!(db.table("session").await?, sessions);
    let wrong = if code == "000000" { "000001" } else { "000000" };
    let invalid = call(
        &auth,
        request(
            "/two-factor/verify-otp",
            Some(json!({"code":wrong})),
            &pending_otp,
        ),
        401,
    )
    .await;
    assert_eq!(body(&invalid)["message"], "Invalid code");
    assert_eq!(db.table("session").await?, sessions);
    let completed = call(
        &auth,
        request(
            "/two-factor/verify-otp",
            Some(json!({"code":code})),
            &pending_otp,
        ),
        200,
    )
    .await;
    authenticated(&auth, &cookies(&completed), "factor@example.test").await;
    let sessions = db.table("session").await?;
    let _ = call(
        &auth,
        request(
            "/two-factor/verify-otp",
            Some(json!({"code":code})),
            &pending_otp,
        ),
        401,
    )
    .await;
    assert_eq!(db.table("session").await?, sessions);
    let pending_backup = signin(&auth, "").await;
    let backup = remaining.as_array().unwrap()[0].as_str().unwrap();
    let completed = call(
        &auth,
        request(
            "/two-factor/verify-backup-code",
            Some(json!({"code":backup})),
            &cookies(&pending_backup),
        ),
        200,
    )
    .await;
    authenticated(&auth, &cookies(&completed), "factor@example.test").await;
    let next_pending = signin(&auth, "").await;
    let sessions = db.table("session").await?;
    let _ = call(
        &auth,
        request(
            "/two-factor/verify-backup-code",
            Some(json!({"code":backup})),
            &cookies(&next_pending),
        ),
        401,
    )
    .await;
    assert_eq!(db.table("session").await?, sessions);
    // The previous backup-code replay is one failed pending attempt. Two more
    // failures across fresh challenges lock the ACCOUNT, not just one cookie.
    for expected in [2.0, 3.0] {
        let challenge = signin(&auth, "").await;
        let _ = call(
            &auth,
            request(
                "/two-factor/verify-totp",
                Some(json!({"code":invalid_code})),
                &cookies(&challenge),
            ),
            401,
        )
        .await;
        let factor = auth
            .store()
            .get_two_factor_by_user_id(&user)
            .await?
            .unwrap();
        assert_eq!(factor.failed_verification_count, Some(expected));
        assert_eq!(factor.locked_until.is_some(), expected == 3.0);
        assert_eq!(db.table("session").await?, sessions);
    }
    let locked = signin(&auth, "").await;
    let denied = call(
        &auth,
        request(
            "/two-factor/verify-totp",
            Some(json!({"code":authenticator.generate_current().to_string()})),
            &cookies(&locked),
        ),
        429,
    )
    .await;
    assert_eq!(body(&denied)["code"], "ACCOUNT_TEMPORARILY_LOCKED");
    assert_eq!(db.table("session").await?, sessions);
    let factor = auth
        .store()
        .get_two_factor_by_user_id(&user)
        .await?
        .unwrap();
    // Seed elapsed time through the public store, without a real sleep or
    // production-only clock seam. The handler must clear this expired lock.
    drop(
        auth.store()
            .set_two_factor_lock_if_count_at_least(
                &factor.id,
                3.0,
                chrono::Utc::now() - chrono::Duration::seconds(1),
            )
            .await?,
    );
    let recovered = call(
        &auth,
        request(
            "/two-factor/verify-totp",
            Some(json!({"code":authenticator.generate_current().to_string()})),
            &cookies(&locked),
        ),
        200,
    )
    .await;
    authenticated(&auth, &cookies(&recovered), "factor@example.test").await;
    let factor = auth
        .store()
        .get_two_factor_by_user_id(&user)
        .await?
        .unwrap();
    assert_eq!(factor.failed_verification_count, Some(0.0));
    assert!(factor.locked_until.is_none());
    // Disabling account-level lockout does not disable the per-challenge cap.
    let no_lockout = builder::<B>(&connection)
        .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
            account_lockout: alibi::plugins::two_factor::AccountLockoutConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        }))
        .build()
        .await?;
    let exhausted = signin(&no_lockout, "").await;
    let sessions = db.table("session").await?;
    for _ in 0..5 {
        let _ = call(
            &no_lockout,
            request(
                "/two-factor/verify-totp",
                Some(json!({"code":invalid_code})),
                &cookies(&exhausted),
            ),
            401,
        )
        .await;
        assert_eq!(db.table("session").await?, sessions);
    }
    let rejected = call(
        &no_lockout,
        request(
            "/two-factor/verify-totp",
            Some(json!({"code":authenticator.generate_current().to_string()})),
            &cookies(&exhausted),
        ),
        400,
    )
    .await;
    assert_eq!(
        body(&rejected)["code"],
        "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE"
    );
    assert_eq!(db.table("session").await?, sessions);
    let _ = call(
        &no_lockout,
        request(
            "/two-factor/verify-totp",
            Some(json!({"code":authenticator.generate_current().to_string()})),
            &cookies(&exhausted),
        ),
        401,
    )
    .await;
    assert_eq!(db.table("session").await?, sessions);
    let preference = call(&auth,request("/sign-in/email",Some(json!({"email":"factor@example.test","password":PASSWORD,"rememberMe":false})),""),200).await;
    let remember_cookie = cookies(&preference).split("; ").find(|cookie|cookie.starts_with("better-auth.dont_remember=")).unwrap().to_owned();
    let disable_cookie = format!("{}; {remember_cookie}",cookies(&trusted));
    let foreign = call(&auth,request("/sign-up/email",Some(json!({"email":"disable-foreign@example.test","password":"foreign-password123","name":"Foreign owner"})),""),200).await;
    let before_disable = db.tables(&["user","account","session","twoFactor","verification"]).await?;
    let trust_id = db.text("SELECT \"identifier\" FROM \"verification\" WHERE \"identifier\" LIKE 'trust-device-%' AND \"value\"=$1",&[&user]).await?.unwrap();
    let old_token = body(&trusted)["token"].as_str().unwrap().to_owned();
    for (input,cookie,status,code) in [
        (json!({}),Some(disable_cookie.clone()),400,"VALIDATION_ERROR"),
        (json!({"password":42}),Some(disable_cookie.clone()),400,"VALIDATION_ERROR"),
        (json!({"password":null}),Some(disable_cookie.clone()),400,"VALIDATION_ERROR"),
        (json!({"password":PASSWORD}),None,401,"UNAUTHORIZED"),
        (json!({"password":"incorrect-password"}),Some(disable_cookie.clone()),400,"INVALID_PASSWORD"),
        (json!({"password":PASSWORD,"userId":user}),Some(cookies(&foreign)),400,"INVALID_PASSWORD"),
    ] {
        let error = Box::pin(auth.dispatch_endpoint(
            alibi::endpoint::ServerEndpoint::<Value>::new("two-factor","disableTwoFactor").with_body(&input)?,
            EndpointOptions{headers:cookie.map(|cookie|[("cookie".into(),cookie)].into_iter().collect()),..Default::default()}
        )).await.unwrap_err();
        assert_eq!(error.error.status_code(),status);
        assert_eq!(error.error.error_payload().1.as_deref(),Some(code));
        assert_eq!(db.tables(&["user","account","session","twoFactor","verification"]).await?,before_disable);
    }
    let disabled = Box::pin(auth.dispatch_endpoint(
        TwoFactorPlugin::disable_two_factor_endpoint(alibi::plugins::two_factor::DisableTwoFactorInput { password:Some(PASSWORD.into()) })
            .with_body(&json!({"password":PASSWORD,"userId":"untrusted-selector"}))?,
        EndpointOptions {headers:Some([("cookie".into(),disable_cookie.clone())].into_iter().collect()),..Default::default()}
    )).await?;
    assert!(disabled.decode()?.status);
    let disabled = disabled.into_response()?;
    let session_cookie = disabled.headers.get_all("set-cookie").find(|cookie|cookie.starts_with("better-auth.session_token=")).unwrap();
    assert!(!session_cookie.to_ascii_lowercase().contains("max-age"));
    assert_eq!(body(&disabled)["status"], true);
    authenticated(&auth,&cookies(&disabled),"factor@example.test").await;
    assert_eq!(db.count_where("SELECT COUNT(*) FROM \"session\" WHERE \"token\"=$1",&[&old_token]).await?,0);
    assert_eq!(db.count_where("SELECT COUNT(*) FROM \"verification\" WHERE \"identifier\"=$1",&[&trust_id]).await?,0);
    let after_disable = db.tables(&["user","account","session","twoFactor","verification"]).await?;
    let replay = Box::pin(auth.dispatch_endpoint(
        TwoFactorPlugin::disable_two_factor_endpoint(alibi::plugins::two_factor::DisableTwoFactorInput {password:Some(PASSWORD.into())}),
        EndpointOptions{headers:Some([("cookie".into(),cookies(&trusted))].into_iter().collect()),..Default::default()}
    )).await.unwrap_err();
    assert_eq!(replay.error.status_code(),401);
    assert_eq!(replay.error.error_payload().1.as_deref(),Some("UNAUTHORIZED"));
    assert_eq!(db.tables(&["user","account","session","twoFactor","verification"]).await?,after_disable);
    assert_eq!(db.count("twoFactor").await?, 0);
    let password_only = signin(&auth, "").await;
    authenticated(&auth, &cookies(&password_only), "factor@example.test").await;
    let enabled = call(
        &auth,
        request(
            "/two-factor/enable",
            Some(json!({"method":"otp","password":PASSWORD})),
            &cookies(&password_only),
        ),
        200,
    )
    .await;
    authenticated(&auth, &cookies(&enabled), "factor@example.test").await;
    assert!(
        body(
            &call(
                &auth,
                request("/get-session", None, &cookies(&password_only)),
                200
            )
            .await
        )
        .is_null()
    );
    assert_eq!(
        db.count("twoFactor").await?,
        0,
        "OTP-only enrollment creates no TOTP secret"
    );
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM \"user\" WHERE id=$1 AND \"twoFactorEnabled\"=true",
            &[&user]
        )
        .await?,
        1
    );
    let pending = signin(&auth, "").await;
    assert_eq!(body(&pending)["twoFactorRedirect"], true);
    let _ = call(
        &auth,
        request("/two-factor/send-otp", Some(json!({})), &cookies(&pending)),
        200,
    )
    .await;
    let (recipient, code) = mailbox.0.lock().unwrap().pop().unwrap();
    assert_eq!(recipient, user);
    let completed = call(
        &auth,
        request(
            "/two-factor/verify-otp",
            Some(json!({"code":code})),
            &cookies(&pending),
        ),
        200,
    )
    .await;
    authenticated(&auth, &cookies(&completed), "factor@example.test").await;
    B::close(connection).await
    }).await
}

async fn renamed_factor_table_owns_the_complete_factor_lifecycle<B: Backend>(db: Db) -> TestResult {
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.advanced.database.two_factor = Some(alibi::config::TwoFactorDatabaseConfig {
        table_name: "application_second_factor".into(),
        columns: [
            ("secret", "application_secret"),
            ("backup_codes", "application_backups"),
            ("user_id", "application_owner"),
        ]
        .into_iter()
        .map(|(name, column)| (name.into(), column.into()))
        .collect(),
    });
    let connection = B::connect(&db.url, None).await?;
    let store = B::store(Arc::new(config.clone()), &connection);
    alibi::store::SchemaMigrator::migrate(&store).await?;
    let mailbox = Arc::new(FactorMailbox::default());
    let auth = AuthBuilder::new(config)
        .store(store)
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
            send_otp: Some(mailbox.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let rows = async |user: &str| {
        db.count_where(
            "SELECT COUNT(*) FROM application_second_factor WHERE application_owner = $1 AND application_secret <> '' AND application_backups <> ''",
            &[user],
        )
        .await
        .unwrap()
    };
    let owner = signup(&auth, "factor@example.test").await;
    let user = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let session = cookies(&owner);
    let enrollment = body(
        &call(
            &auth,
            request(
                "/two-factor/enable",
                Some(json!({"password": PASSWORD})),
                &session,
            ),
            200,
        )
        .await,
    );
    assert_eq!(rows(&user).await, 1);
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM sqlite_master WHERE \"name\" = 'two_factor'",
            &[]
        )
        .await
        .unwrap_or(0),
        0
    );
    let authenticator = totp_rs::Totp::from_url(enrollment["totpURI"].as_str().unwrap())?;
    let activated = call(
        &auth,
        request(
            "/two-factor/verify-totp",
            Some(json!({"code": authenticator.generate_current().to_string()})),
            &session,
        ),
        200,
    )
    .await;
    let session = cookies(&activated);

    let pending = signin(&auth, "").await;
    assert_eq!(body(&pending)["twoFactorRedirect"], true);
    let pending_cookie = cookies(&pending);
    _ = call(
        &auth,
        request("/two-factor/send-otp", Some(json!({})), &pending_cookie),
        200,
    )
    .await;
    let otp = mailbox.0.lock().unwrap().last().unwrap().1.clone();
    _ = call(
        &auth,
        request(
            "/two-factor/verify-otp",
            Some(json!({"code": otp})),
            &pending_cookie,
        ),
        200,
    )
    .await;

    let pending = signin(&auth, "").await;
    let backup = call(
        &auth,
        request(
            "/two-factor/verify-backup-code",
            Some(json!({"code": enrollment["backupCodes"][0], "trustDevice": true})),
            &cookies(&pending),
        ),
        200,
    )
    .await;
    let trusted = signin(&auth, &cookies(&backup)).await;
    assert!(body(&trusted).get("twoFactorRedirect").is_none());
    _ = call(
        &auth,
        request(
            "/two-factor/disable",
            Some(json!({"password": PASSWORD})),
            &session,
        ),
        200,
    )
    .await;
    assert_eq!(rows(&user).await, 0);
    B::close(connection).await
}
