//! Phone-number request validation, proof budgets, provider verification and reset effects.
use super::auth_probe::{Probe, fast_builder};
use super::*;
use alibi::plugins::PasswordManagementPlugin;
use alibi::plugins::password_management::PasswordManagementConfig;
use alibi::plugins::phone_number::{
    PhoneNumberConfig, PhoneNumberPlugin, PhoneNumberValidator, PhoneNumberVerification,
    PhoneOtpDelivery, PhoneOtpVerifier, PhoneSignupIdentity, PhoneVerificationHook, SendPhoneOtp,
};
use alibi::{AuthError, AuthResult, CallbackContext};
use async_trait::async_trait;

backend_tests!(
    phone_number_request_and_proof_matrix,
    phone_number_provider_and_sender_failures,
    phone_number_password_reset_effects,
    phone_number_signup_and_update_inputs,
    phone_signin_distinguishes_missing_null_and_empty_credentials
);

#[derive(Default)]
struct Outbox {
    sent: Mutex<Vec<PhoneOtpDelivery>>,
    failure: Mutex<Option<&'static str>>,
}
impl Outbox {
    fn last(&self) -> PhoneOtpDelivery {
        self.sent.lock().unwrap().last().cloned().unwrap()
    }
}
#[async_trait]
impl SendPhoneOtp for Outbox {
    async fn send(&self, delivery: &PhoneOtpDelivery, _: &CallbackContext) -> AuthResult<()> {
        self.sent.lock().unwrap().push(delivery.clone());
        match *self.failure.lock().unwrap() {
            Some("internal") => Err(AuthError::internal("gateway down")),
            Some("api") => Err(AuthError::forbidden("gateway refused")),
            _ => Ok(()),
        }
    }
}

struct Validator;
#[async_trait]
impl PhoneNumberValidator for Validator {
    async fn is_valid(&self, phone_number: &str) -> AuthResult<bool> {
        match phone_number {
            "+000" => Ok(false),
            "+err" => Err(AuthError::internal("validator offline")),
            _ => Ok(true),
        }
    }
}

struct Identity;
impl PhoneSignupIdentity for Identity {
    fn temporary_email(&self, phone_number: &str) -> String {
        format!(
            "{}@phone.example.test",
            phone_number.trim_start_matches('+')
        )
    }
    fn temporary_name(&self, phone_number: &str) -> Option<String> {
        (phone_number != "+15550000003").then(|| format!("Phone {phone_number}"))
    }
}

struct Hook;
#[async_trait]
impl PhoneVerificationHook for Hook {
    async fn verified(
        &self,
        result: &PhoneNumberVerification,
        _: &CallbackContext,
    ) -> AuthResult<()> {
        if result.phone_number.ends_with('9') {
            return Err(AuthError::forbidden("hook rejected"));
        }
        Ok(())
    }
}

struct Provider(&'static str);
#[async_trait]
impl PhoneOtpVerifier for Provider {
    async fn verify(&self, delivery: &PhoneOtpDelivery, _: &CallbackContext) -> AuthResult<bool> {
        match self.0 {
            "accept" => Ok(delivery.code == "424242"),
            "api" => Err(AuthError::forbidden("provider denied")),
            _ => Err(AuthError::internal("provider offline")),
        }
    }
}

fn verify_body(number: &str, code: &str, extra: &Value) -> String {
    let mut input = json!({"phoneNumber":number,"code":code});
    input
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    input.to_string()
}

async fn send_code<S: AuthSchema>(
    probe: &mut Probe<'_, S>,
    outbox: &Outbox,
    number: &str,
) -> String {
    let _ = probe
        .post(
            &format!("send {number}"),
            "/phone-number/send-otp",
            &json!({"phoneNumber":number}).to_string(),
            "",
        )
        .await;
    outbox.last().code
}

async fn phone_number_request_and_proof_matrix<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let outbox = Arc::new(Outbox::default());
    let auth = fast_builder::<B>(&connection)
        .plugin(PhoneNumberPlugin::new(PhoneNumberConfig {
            send_otp: Some(outbox.clone()),
            send_password_reset_otp: Some(outbox.clone()),
            phone_number_validator: Some(Arc::new(Validator)),
            sign_up_on_verification: Some(Arc::new(Identity)),
            callback_on_verification: Some(Arc::new(Hook)),
            require_verification: true,
            allowed_attempts: 2.0,
            ..Default::default()
        }))
        .build()
        .await?;
    let mut probe = Probe::new(&auth);
    for path in [
        "/sign-in/phone-number",
        "/phone-number/send-otp",
        "/phone-number/verify",
        "/phone-number/request-password-reset",
        "/phone-number/reset-password",
    ] {
        for text in [
            "[]",
            "null",
            "{}",
            r#"{"phoneNumber":5,"password":5,"code":5,"otp":5,"newPassword":5}"#,
            r#"{"phoneNumber":"+000","password":"a-native-password-123","code":"1","otp":"1","newPassword":"a-native-password-123"}"#,
            r#"{"phoneNumber":"+err","password":"a-native-password-123","code":"1"}"#,
        ] {
            let _ = probe.post(&format!("{path} {text}"), path, text, "").await;
        }
    }
    let phone = "+15550000001";
    let verify = "/phone-number/verify";
    let _ = probe
        .post(
            "verify before send",
            verify,
            &verify_body(phone, "1", &json!({})),
            "",
        )
        .await;
    let _ = send_code(&mut probe, &outbox, phone).await;
    for wrong in ["wrong-1", "wrong-2", "wrong-3"] {
        let _ = probe
            .post(wrong, verify, &verify_body(phone, wrong, &json!({})), "")
            .await;
    }
    let code = send_code(&mut probe, &outbox, phone).await;
    let _ = probe
        .post(
            "verified input rejected",
            verify,
            &verify_body(phone, &code, &json!({"phoneNumberVerified":true})),
            "",
        )
        .await;
    let code = send_code(&mut probe, &outbox, phone).await;
    db.set_timestamp(
        "verifications",
        "expires_at",
        ("identifier", phone),
        chrono::Utc::now() - chrono::Duration::seconds(5),
    )
    .await?;
    let _ = probe
        .post(
            "expired",
            verify,
            &verify_body(phone, &code, &json!({})),
            "",
        )
        .await;
    let code = send_code(&mut probe, &outbox, phone).await;
    let _ = probe
        .post(
            "creates user without session",
            verify,
            &verify_body(phone, &code, &json!({"disableSession":true})),
            "",
        )
        .await;
    assert_eq!(db.count("users").await?, 1);
    assert_eq!(db.count("sessions").await?, 0);
    let code = send_code(&mut probe, &outbox, phone).await;
    let _ = probe
        .post(
            "existing user",
            verify,
            &verify_body(phone, &code, &json!({})),
            "",
        )
        .await;
    let hooked = "+15550000009";
    let code = send_code(&mut probe, &outbox, hooked).await;
    let _ = probe
        .post(
            "callback rejects",
            verify,
            &verify_body(hooked, &code, &json!({})),
            "",
        )
        .await;
    let nameless = "+15550000003";
    let code = send_code(&mut probe, &outbox, nameless).await;
    let _ = probe
        .post(
            "nameless signup",
            verify,
            &verify_body(
                nameless,
                &code,
                &json!({"username":"ignored","image":"https://img.example.test/a.png"}),
            ),
            "",
        )
        .await;
    for (label, number, password) in [
        ("unknown phone", "+15559999999", PASSWORD.to_owned()),
        ("long password", phone, "p".repeat(200)),
        ("unverified phone", phone, PASSWORD.to_owned()),
    ] {
        let _ = probe
            .post(
                &format!("sign in {label}"),
                "/sign-in/phone-number",
                &json!({"phoneNumber":number,"password":password}).to_string(),
                "",
            )
            .await;
    }
    _ = db
        .execute("UPDATE users SET phone_number_verified = false", &[])
        .await?;
    let _ = probe
        .post(
            "sign in without credential",
            "/sign-in/phone-number",
            &json!({"phoneNumber":phone,"password":PASSWORD}).to_string(),
            "",
        )
        .await;
    probe
        .trace
        .value("deliveries", json!(outbox.sent.lock().unwrap().len()));
    probe.trace.assert("phone-number/request-and-proof-matrix");
    B::close(connection).await
}

async fn phone_number_provider_and_sender_failures<B: Backend>(db: Db) -> TestResult {
    let mut trace = crate::snapshot::Trace::default();
    for mode in [
        "no sender",
        "internal sender",
        "api sender",
        "provider accepts",
        "provider api error",
        "provider internal error",
        "invalid expiry",
        "sign-up unavailable",
    ] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let outbox = Arc::new(Outbox::default());
        *outbox.failure.lock().unwrap() = match mode {
            "internal sender" => Some("internal"),
            "api sender" => Some("api"),
            _ => None,
        };
        let provider = Arc::new(Provider(match mode {
            "provider api error" => "api",
            "provider internal error" => "internal",
            _ => "accept",
        }));
        let config = PhoneNumberConfig {
            send_otp: (mode != "no sender").then(|| outbox.clone() as _),
            verify_otp: mode.starts_with("provider").then(|| provider.clone() as _),
            sign_up_on_verification: (mode != "sign-up unavailable")
                .then(|| Arc::new(Identity) as _),
            expires_in: if mode == "invalid expiry" {
                f64::INFINITY
            } else {
                300.0
            },
            ..Default::default()
        };
        let auth = fast_builder::<B>(&connection)
            .plugin(PhoneNumberPlugin::new(config))
            .build()
            .await?;
        let mut probe = Probe::new(&auth);
        probe.trace = trace;
        probe.prefix = format!("{mode}: ");
        let phone = "+15550000002";
        let _ = probe
            .post(
                "send",
                "/phone-number/send-otp",
                &json!({"phoneNumber":phone}).to_string(),
                "",
            )
            .await;
        let code = if mode.starts_with("provider") {
            "424242".to_owned()
        } else {
            outbox
                .sent
                .lock()
                .unwrap()
                .last()
                .map_or_else(|| "000000".into(), |sent| sent.code.clone())
        };
        for (label, attempt) in [
            ("issued", code.as_str()),
            ("provider", "424242"),
            ("wrong", "000000"),
        ] {
            let _ = probe
                .post(
                    &format!("verify {label}"),
                    "/phone-number/verify",
                    &verify_body(phone, attempt, &json!({})),
                    "",
                )
                .await;
        }
        probe
            .trace
            .value(&format!("{mode}: users"), json!(db.count("users").await?));
        trace = probe.trace;
        B::close(connection).await?;
    }
    trace.assert("phone-number/provider-and-sender-failures");
    Ok(())
}

type ResetFuture = std::pin::Pin<Box<dyn std::future::Future<Output = AuthResult<()>> + Send>>;

async fn latest_reset_code(db: &Db, phone: &str) -> TestResult<String> {
    Ok(db
        .text(
            "SELECT value FROM verifications WHERE identifier = $1",
            &[&format!("{phone}-request-password-reset")],
        )
        .await?
        .unwrap()
        .split(':')
        .next()
        .unwrap()
        .to_owned())
}

async fn phone_number_password_reset_effects<B: Backend>(db: Db) -> TestResult {
    let mut trace = crate::snapshot::Trace::default();
    for mode in ["plain", "callback", "revoke", "callback fails"] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let outbox = Arc::new(Outbox::default());
        let calls = Arc::new(Mutex::new(0_usize));
        let seen = calls.clone();
        let failing = mode == "callback fails";
        let auth = fast_builder::<B>(&connection)
            .plugin(PhoneNumberPlugin::new(PhoneNumberConfig {
                send_otp: Some(outbox.clone()),
                send_password_reset_otp: (mode != "plain").then(|| outbox.clone() as _),
                sign_up_on_verification: Some(Arc::new(Identity)),
                ..Default::default()
            }))
            .plugin(PasswordManagementPlugin::with_config(
                PasswordManagementConfig {
                    revoke_sessions_on_password_reset: mode == "revoke",
                    on_password_reset: mode.starts_with("callback").then(|| {
                        Arc::new(move |_: Value| -> ResetFuture {
                            *seen.lock().unwrap() += 1;
                            Box::pin(async move {
                                if failing {
                                    Err(AuthError::forbidden("reset hook refused"))
                                } else {
                                    Ok(())
                                }
                            })
                        }) as _
                    }),
                    ..Default::default()
                },
            ))
            .build()
            .await?;
        let mut probe = Probe::new(&auth);
        probe.trace = trace;
        probe.prefix = format!("{mode}: ");
        let phone = "+15550000004";
        let code = send_code(&mut probe, &outbox, phone).await;
        let created = probe
            .post(
                "verify",
                "/phone-number/verify",
                &verify_body(phone, &code, &json!({})),
                "",
            )
            .await;
        let session = cookies(&created);
        let _ = probe
            .post(
                "request unknown phone",
                "/phone-number/request-password-reset",
                r#"{"phoneNumber":"+15551111111"}"#,
                "",
            )
            .await;
        let _ = probe
            .post(
                "reset unknown phone",
                "/phone-number/reset-password",
                r#"{"phoneNumber":"+15551111111","otp":"1","newPassword":"a-native-password-123"}"#,
                "",
            )
            .await;
        for (label, password) in [("too short", "short"), ("accepted", "a-brand-new-password")] {
            let _ = probe
                .post(
                    "request",
                    "/phone-number/request-password-reset",
                    &json!({"phoneNumber":phone}).to_string(),
                    "",
                )
                .await;
            let otp = if mode == "plain" {
                latest_reset_code(&db, phone).await?
            } else {
                outbox.last().code
            };
            let _ = probe
                .post(
                    label,
                    "/phone-number/reset-password",
                    &json!({"phoneNumber":phone,"otp":otp,"newPassword":password}).to_string(),
                    "",
                )
                .await;
        }
        let credentials = db
            .count_where(
                "SELECT COUNT(*) FROM accounts WHERE provider_id = 'credential'",
                &[],
            )
            .await?;
        let hook_calls = *calls.lock().unwrap();
        let old_session = body(&call(&auth, request("/get-session", None, &session), 200).await);
        probe.trace.value(
            "effects",
            json!({"credentials": credentials, "hook calls": hook_calls, "old session cleared": old_session.is_null()}),
        );
        let _ = probe
            .post(
                "sign in with new password",
                "/sign-in/phone-number",
                &json!({"phoneNumber":phone,"password":"a-brand-new-password"}).to_string(),
                "",
            )
            .await;
        trace = probe.trace;
        B::close(connection).await?;
    }
    trace.assert("phone-number/password-reset-effects");
    Ok(())
}

async fn phone_number_signup_and_update_inputs<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = fast_builder::<B>(&connection)
        .plugin(PhoneNumberPlugin::new(PhoneNumberConfig::default()))
        .plugin(alibi::plugins::UserManagementPlugin::new())
        .build()
        .await?;
    let mut probe = Probe::new(&auth);
    let inputs = [
        r#""+15550001""#,
        "true",
        "false",
        "12345",
        "1.5",
        "1e400",
        "-0",
        "[]",
        r#"{"number":1}"#,
        "null",
    ];
    for (index, phone) in inputs.into_iter().enumerate() {
        let _ = probe
            .post(
                &format!("signup phone {phone}"),
                "/sign-up/email",
                &format!(
                    r#"{{"email":"p{index}@example.test","password":"{PASSWORD}","name":"P","phoneNumber":{phone}}}"#
                ),
                "",
            )
            .await;
    }
    for (index, verified) in ["true", "1", r#""yes""#, "[]", "false", "0", r#""""#, "null"]
        .into_iter()
        .enumerate()
    {
        let _ = probe
            .post(
                &format!("signup verified {verified}"),
                "/sign-up/email",
                &format!(
                    r#"{{"email":"v{index}@example.test","password":"{PASSWORD}","name":"P","phoneNumberVerified":{verified}}}"#
                ),
                "",
            )
            .await;
    }
    let owner = cookies(&signup(&auth, "updater@example.test").await);
    for text in [
        r#"{"phoneNumber":"+15557777777"}"#,
        r#"{"phoneNumber":null}"#,
        r#"{"phoneNumber":0}"#,
        r#"{"name":"Plain update"}"#,
    ] {
        let _ = probe
            .post(&format!("update {text}"), "/update-user", text, &owner)
            .await;
    }
    probe.trace.value("rows", json!(db.count("users").await?));
    probe.trace.assert("phone-number/signup-and-update-inputs");
    B::close(connection).await
}

async fn phone_signin_distinguishes_missing_null_and_empty_credentials<B: Backend>(
    parent: Db,
) -> TestResult {
    for state in ["missing", "null", "empty"] {
        let db = parent.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let auth = fast_builder::<B>(&connection)
            .plugin(PhoneNumberPlugin::new(PhoneNumberConfig::default()))
            .build()
            .await?;
        let owner=call(&auth,request("/sign-up/email",Some(json!({"email":"phone-owner@example.test","password":PASSWORD,"name":"Phone Owner","phoneNumber":"+15550000101"})),""),200).await;
        let id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
        _ = call(
            &auth,
            request(
                "/sign-in/phone-number",
                Some(json!({"phoneNumber":"+15550000101","password":PASSWORD})),
                "",
            ),
            200,
        )
        .await;
        let sql = match state {
            "missing" => "DELETE FROM accounts WHERE user_id=$1",
            "null" => "UPDATE accounts SET password=NULL WHERE user_id=$1",
            _ => "UPDATE accounts SET password='' WHERE user_id=$1",
        };
        _ = db.execute(sql, &[&id]).await?;
        let before = db
            .tables(&["users", "accounts", "sessions", "verifications"])
            .await?;
        let denied = call(
            &auth,
            request(
                "/sign-in/phone-number",
                Some(json!({"phoneNumber":"+15550000101","password":PASSWORD})),
                "",
            ),
            401,
        )
        .await;
        assert_eq!(
            body(&denied)["code"],
            if state == "missing" {
                "INVALID_PHONE_NUMBER_OR_PASSWORD"
            } else {
                "UNEXPECTED_ERROR"
            }
        );
        assert!(!denied.headers.contains_key("set-cookie"));
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "verifications"])
                .await?,
            before
        );
        authenticated(&auth, &cookies(&owner), "phone-owner@example.test").await;
        B::close(connection).await?;
    }
    Ok(())
}
