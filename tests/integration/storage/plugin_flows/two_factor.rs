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
    let server_code = auth
        .dispatch_endpoint(
            TwoFactorPlugin::generate_totp_endpoint("12345678901234567890"),
            EndpointOptions::default(),
        )
        .await?
        .decode()?
        .code;
    assert!(server_authenticator.check_current(&server_code).is_some());
    let owner = signup(&auth, "factor@example.test").await;
    let user = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let enrollment = call(
        &auth,
        request(
            "/two-factor/enable",
            Some(json!({"password":PASSWORD})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    let enrollment_body = body(&enrollment);
    // A separate authenticator implementation consumes the actual otpauth URI.
    // Do not ask the production plugin to manufacture its own expected code.
    let authenticator = totp_rs::Totp::from_url(enrollment_body["totpURI"].as_str().unwrap())?;
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM users WHERE id = $1 AND two_factor_enabled = true",
            &[&user]
        )
        .await?,
        0
    );
    let activated = call(
        &auth,
        request(
            "/two-factor/verify-totp",
            Some(json!({"code":authenticator.generate_current().to_string()})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    let active_cookie = cookies(&activated);
    authenticated(&auth, &active_cookie, "factor@example.test").await;
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM users WHERE id = $1 AND two_factor_enabled = true",
            &[&user]
        )
        .await?,
        1
    );
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM two_factor WHERE user_id = $1 AND verified = true",
            &[&user]
        )
        .await?,
        1
    );

    let regenerated = call(
        &auth,
        request(
            "/two-factor/generate-backup-codes",
            Some(json!({"password":PASSWORD})),
            &active_cookie,
        ),
        200,
    )
    .await;
    let backup_view = auth
        .dispatch_endpoint(
            TwoFactorPlugin::view_backup_codes_endpoint(&user),
            EndpointOptions::default(),
        )
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

    let remaining = auth
        .dispatch_endpoint(
            TwoFactorPlugin::view_backup_codes_endpoint(&user),
            EndpointOptions::default(),
        )
        .await?
        .decode()?
        .backup_codes;
    assert!(!remaining.as_array().unwrap().contains(&json!(new_code)));
    assert_eq!(
        remaining.as_array().unwrap().len() + 1,
        backup_view.backup_codes.as_array().unwrap().len()
    );

    let before_pending = db.table("sessions").await?;
    let pending = signin(&auth, "").await;
    assert_eq!(body(&pending)["twoFactorRedirect"], true);
    assert!(body(&pending).get("token").is_none());
    assert_eq!(db.table("sessions").await?, before_pending);
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
    let denied = call(
        &auth,
        request(
            "/two-factor/verify-totp",
            Some(json!({"code":invalid_code})),
            &pending_cookie,
        ),
        401,
    )
    .await;
    assert_eq!(body(&denied)["message"], "Invalid code");
    assert_eq!(db.table("sessions").await?, before_pending);
    let completed = call(
        &auth,
        request(
            "/two-factor/verify-totp",
            Some(json!({"code":authenticator.generate_current().to_string(),"trustDevice":true})),
            &pending_cookie,
        ),
        200,
    )
    .await;
    authenticated(&auth, &cookies(&completed), "factor@example.test").await;
    let trust = cookies(&completed)
        .split("; ")
        .find(|cookie| cookie.starts_with("better-auth.trust_device="))
        .unwrap()
        .to_owned();
    let sessions = db.table("sessions").await?;
    let _ = call(
        &auth,
        request(
            "/two-factor/verify-totp",
            Some(json!({"code":authenticator.generate_current().to_string()})),
            &pending_cookie,
        ),
        401,
    )
    .await;
    assert_eq!(db.table("sessions").await?, sessions);

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
    let uri = call(
        &auth,
        request(
            "/two-factor/get-totp-uri",
            Some(json!({"password":PASSWORD})),
            &cookies(&trusted),
        ),
        200,
    )
    .await;
    let recovered = totp_rs::Totp::from_url(body(&uri)["totpURI"].as_str().unwrap())?;
    assert!(
        recovered
            .check_current(&authenticator.generate_current().to_string())
            .is_some()
    );
    let factors = db.table("two_factor").await?;
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
    assert_eq!(db.table("two_factor").await?, factors);
    // OTP and backup codes must complete actual password-authenticated pending
    // logins, consume their proofs, and publish a session the browser can use.
    let pending_otp = cookies(&old_trust);
    let sessions = db.table("sessions").await?;
    let _ = call(
        &auth,
        request("/two-factor/send-otp", Some(json!({})), &pending_otp),
        200,
    )
    .await;
    let (delivered_user, code) = mailbox.0.lock().unwrap().pop().unwrap();
    assert_eq!(delivered_user, user);
    assert_eq!(db.table("sessions").await?, sessions);
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
    assert_eq!(db.table("sessions").await?, sessions);
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
    let sessions = db.table("sessions").await?;
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
    assert_eq!(db.table("sessions").await?, sessions);
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
    let sessions = db.table("sessions").await?;
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
    assert_eq!(db.table("sessions").await?, sessions);
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
        assert_eq!(db.table("sessions").await?, sessions);
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
    assert_eq!(db.table("sessions").await?, sessions);
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
    let sessions = db.table("sessions").await?;
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
        assert_eq!(db.table("sessions").await?, sessions);
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
    assert_eq!(db.table("sessions").await?, sessions);
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
    assert_eq!(db.table("sessions").await?, sessions);
    let disabled = call(
        &auth,
        request(
            "/two-factor/disable",
            Some(json!({"password":PASSWORD})),
            &cookies(&trusted),
        ),
        200,
    )
    .await;
    assert_eq!(body(&disabled)["status"], true);
    assert_eq!(db.count("two_factor").await?, 0);
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
        db.count("two_factor").await?,
        0,
        "OTP-only enrollment creates no TOTP secret"
    );
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM users WHERE id=$1 AND two_factor_enabled=true",
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
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'two_factor'",
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
