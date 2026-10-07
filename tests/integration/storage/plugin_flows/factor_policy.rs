//! Application OTP representations and per-operation passwordless authority.
use super::passwordless::Mailbox;
use super::*;
use alibi::plugins::email_otp::{EmailOtpConfig, EmailOtpDelivery};
use alibi::plugins::two_factor::{
    SendTwoFactorOtp, TwoFactorConfig, TwoFactorOtpCipher, TwoFactorOtpStorage,
};
use alibi::plugins::{EmailOtpPlugin, TwoFactorPlugin};
use alibi_core::{AuthError, AuthResult, UserView};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

backend_tests!(
    factor_storage_callbacks_preserve_consumption_and_totp_disable,
    passwordless_factor_policy_requires_absent_credential_and_honors_route_overrides
);
postgres_tests!(
    factor_storage_callbacks_preserve_consumption_and_totp_disable,
    passwordless_factor_policy_requires_absent_credential_and_honors_route_overrides
);

#[derive(Default)]
struct ApplicationFactor {
    failure: Mutex<&'static str>,
    delivered: Mutex<Vec<(String, String)>>,
}
#[async_trait]
impl TwoFactorOtpCipher for ApplicationFactor {
    async fn encrypt(&self, otp: &str) -> AuthResult<String> {
        if *self.failure.lock().unwrap() == "encrypt" {
            return Err(AuthError::internal("private encryption failure"));
        }
        Ok(format!("application-{}", URL_SAFE_NO_PAD.encode(otp)))
    }
    async fn decrypt(&self, stored: &str) -> AuthResult<String> {
        if *self.failure.lock().unwrap() == "decrypt" {
            return Err(AuthError::internal("private decryption failure"));
        }
        Ok(String::from_utf8(
            URL_SAFE_NO_PAD
                .decode(stored.strip_prefix("application-").unwrap())
                .unwrap(),
        )
        .unwrap())
    }
}
#[async_trait]
impl SendTwoFactorOtp for ApplicationFactor {
    async fn send(&self, user: &UserView, code: &str) -> AuthResult<()> {
        self.delivered
            .lock()
            .unwrap()
            .push((user.id.clone(), code.to_owned()));
        Ok(())
    }
}
async fn factor_storage_callbacks_preserve_consumption_and_totp_disable<B: Backend>(
    parent: Db,
) -> TestResult {
    for kind in ["hash", "encrypted", "custom"] {
        let db = parent.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let application = Arc::new(ApplicationFactor::default());
        let storage = match kind {
            "hash" => TwoFactorOtpStorage::Hashed,
            "encrypted" => TwoFactorOtpStorage::Encrypted,
            _ => TwoFactorOtpStorage::CustomCipher(application.clone()),
        };
        let auth = builder::<B>(&connection)
            .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
                totp_disabled: true,
                send_otp: Some(application.clone()),
                otp_storage: storage,
                ..Default::default()
            }))
            .build()
            .await?;
        let owner = signup(&auth, "otp-factor@example.test").await;
        let cookie = cookies(&owner);
        let original = db.tables(&["users", "sessions", "two_factor"]).await?;
        for (route, input) in [
            ("/two-factor/enable", json!({"password":PASSWORD})),
            ("/two-factor/get-totp-uri", json!({"password":PASSWORD})),
            ("/two-factor/verify-totp", json!({"code":"123456"})),
        ] {
            let denied = call(&auth, request(route, Some(input), &cookie), 400).await;
            assert_eq!(body(&denied)["code"], "TOTP_NOT_CONFIGURED");
            assert_eq!(
                db.tables(&["users", "sessions", "two_factor"]).await?,
                original
            );
        }
        let generated = auth
            .dispatch_endpoint(
                TwoFactorPlugin::generate_totp_endpoint("12345678901234567890"),
                alibi_core::endpoint::EndpointOptions::default(),
            )
            .await;
        assert_eq!(generated.unwrap_err().error.status_code(), 400);
        let enabled = call(
            &auth,
            request(
                "/two-factor/enable",
                Some(json!({"password":PASSWORD,"method":"otp"})),
                &cookie,
            ),
            200,
        )
        .await;
        assert_eq!(db.count("two_factor").await?, 0);
        authenticated(&auth, &cookies(&enabled), "otp-factor@example.test").await;
        let pending = call(
            &auth,
            request(
                "/sign-in/email",
                Some(json!({"email":"otp-factor@example.test","password":PASSWORD})),
                "",
            ),
            200,
        )
        .await;
        assert_eq!(body(&pending)["twoFactorMethods"], json!(["otp"]));
        let cookie = cookies(&pending);
        let sessions = db.table("sessions").await?;
        let pending_rows = db.table("verifications").await?;
        if kind == "custom" {
            *application.failure.lock().unwrap() = "encrypt";
            let _ = call(
                &auth,
                request("/two-factor/send-otp", Some(json!({})), &cookie),
                500,
            )
            .await;
            assert_eq!(db.table("verifications").await?, pending_rows);
            assert!(application.delivered.lock().unwrap().is_empty());
            *application.failure.lock().unwrap() = "";
        }
        let _ = call(
            &auth,
            request("/two-factor/send-otp", Some(json!({})), &cookie),
            200,
        )
        .await;
        let (recipient, code) = application.delivered.lock().unwrap().pop().unwrap();
        assert_eq!(recipient, body(&owner)["user"]["id"]);
        let persisted = db
            .text(
                "SELECT value FROM verifications WHERE identifier LIKE '2fa-otp-%'",
                &[],
            )
            .await?
            .unwrap();
        assert_ne!(persisted.split(':').next(), Some(code.as_str()));
        if kind == "custom" {
            assert_eq!(
                persisted,
                format!("application-{}:0", URL_SAFE_NO_PAD.encode(&code))
            );
            *application.failure.lock().unwrap() = "decrypt";
            let _ = call(
                &auth,
                request(
                    "/two-factor/verify-otp",
                    Some(json!({"code":code})),
                    &cookie,
                ),
                500,
            )
            .await;
            assert_eq!(db.table("sessions").await?, sessions);
            assert_eq!(db.table("verifications").await?, pending_rows);
            *application.failure.lock().unwrap() = "";
            let _ = call(
                &auth,
                request("/two-factor/send-otp", Some(json!({})), &cookie),
                200,
            )
            .await;
        } else {
            application
                .delivered
                .lock()
                .unwrap()
                .push((recipient, code));
        }
        let (_, code) = application.delivered.lock().unwrap().pop().unwrap();
        let completed = call(
            &auth,
            request(
                "/two-factor/verify-otp",
                Some(json!({"code":code})),
                &cookie,
            ),
            200,
        )
        .await;
        authenticated(&auth, &cookies(&completed), "otp-factor@example.test").await;
        assert_eq!(db.count("verifications").await?, 1);
        assert_eq!(db.count_where("SELECT COUNT(*) FROM verifications WHERE identifier LIKE '2fa-attempts-%' AND value='0'", &[]).await?, 1);
        assert_eq!(db.count("sessions").await?, 2);
        B::close(connection).await?;
    }
    Ok(())
}
async fn passwordless_factor_policy_requires_absent_credential_and_honors_route_overrides<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mailbox = Arc::new(Mailbox::<EmailOtpDelivery>::default());
    let initial = builder::<B>(&connection)
        .plugin(EmailOtpPlugin::new(EmailOtpConfig {
            send_verification_otp: Some(mailbox.clone()),
            ..Default::default()
        }))
        .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
            allow_passwordless: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let _ = call(
        &initial,
        request(
            "/email-otp/send-verification-otp",
            Some(json!({"email":"passwordless-factor@example.test","type":"sign-in"})),
            "",
        ),
        200,
    )
    .await;
    let delivery = mailbox.take();
    let owner = call(
        &initial,
        request(
            "/sign-in/email-otp",
            Some(json!({"email":delivery.email,"otp":delivery.otp})),
            "",
        ),
        200,
    )
    .await;
    let cookie = cookies(&owner);
    assert_eq!(db.count("accounts").await?, 0);
    let enabled = call(
        &initial,
        request("/two-factor/enable", Some(json!({})), &cookie),
        200,
    )
    .await;
    assert!(
        body(&enabled)["totpURI"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://")
    );
    let authenticator = totp_rs::Totp::from_url(body(&enabled)["totpURI"].as_str().unwrap())?;
    let activated = call(
        &initial,
        request(
            "/two-factor/verify-totp",
            Some(json!({"code":authenticator.generate_current().to_string()})),
            &cookie,
        ),
        200,
    )
    .await;
    let cookie = cookies(&activated);
    authenticated(&initial, &cookie, "passwordless-factor@example.test").await;
    let credential = signup(&initial, "credential-factor@example.test").await;
    let unchanged = db.tables(&["users", "sessions", "two_factor"]).await?;
    let _ = call(
        &initial,
        request("/two-factor/enable", Some(json!({})), &cookies(&credential)),
        400,
    )
    .await;
    assert_eq!(
        db.tables(&["users", "sessions", "two_factor"]).await?,
        unchanged
    );
    for (global, override_value, expected) in [
        (false, None, 400),
        (true, None, 200),
        (true, Some(false), 400),
        (false, Some(true), 200),
    ] {
        let auth = builder::<B>(&connection)
            .plugin(TwoFactorPlugin::with_config(TwoFactorConfig {
                allow_passwordless: global,
                totp_allow_passwordless: override_value,
                backup_allow_passwordless: override_value,
                ..Default::default()
            }))
            .build()
            .await?;
        for route in [
            "/two-factor/get-totp-uri",
            "/two-factor/generate-backup-codes",
        ] {
            let before = db.tables(&["users", "sessions", "two_factor"]).await?;
            let response = call(&auth, request(route, Some(json!({})), &cookie), expected).await;
            if expected == 400 {
                assert_eq!(
                    db.tables(&["users", "sessions", "two_factor"]).await?,
                    before
                );
            } else if route.ends_with("get-totp-uri") {
                assert_eq!(body(&response)["totpURI"], body(&enabled)["totpURI"]);
            } else {
                assert_eq!(body(&response)["backupCodes"].as_array().unwrap().len(), 10);
                assert_ne!(db.table("two_factor").await?, before[2]);
            }
        }
    }
    let disabled = call(
        &initial,
        request("/two-factor/disable", Some(json!({})), &cookie),
        200,
    )
    .await;
    authenticated(
        &initial,
        &cookies(&disabled),
        "passwordless-factor@example.test",
    )
    .await;
    assert_eq!(db.count("two_factor").await?, 0);
    B::close(connection).await
}
