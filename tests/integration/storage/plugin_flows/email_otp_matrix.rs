//! Email OTP issuance limits, request validation, reset and change-email policy.
use super::auth_probe::{fast_builder, raw};
use super::*;
use crate::snapshot::Trace;
use alibi::plugins::email_otp::{
    EmailOtpConfig, EmailOtpDelivery, EmailOtpPlugin, OtpResendStrategy,
};
use alibi::plugins::{EmailVerificationConfig, EmailVerificationPlugin};
use alibi::{AuthError, AuthResult, CallbackContext};

backend_tests!(
    email_otp_issuance_and_request_validation,
    email_otp_change_email_policy,
    email_otp_hooks_and_reset_edges
);

#[derive(Default)]
struct Mailbox(Mutex<Vec<EmailOtpDelivery>>);
impl Mailbox {
    fn take(&self) -> EmailOtpDelivery {
        self.0.lock().unwrap().pop().unwrap()
    }
    fn drain(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap()
            .drain(..)
            .map(|sent| sent.otp)
            .collect()
    }
}
#[async_trait::async_trait]
impl alibi::plugins::email_otp::SendEmailOtp for Mailbox {
    async fn send(&self, delivery: &EmailOtpDelivery, _: &CallbackContext) -> AuthResult<()> {
        self.0.lock().unwrap().push(delivery.clone());
        Ok(())
    }
}

fn plugin(mailbox: &Arc<Mailbox>, config: EmailOtpConfig) -> EmailOtpPlugin {
    EmailOtpPlugin::new(EmailOtpConfig {
        send_verification_otp: Some(mailbox.clone()),
        ..config
    })
}

async fn email_otp_issuance_and_request_validation<B: Backend>(db: Db) -> TestResult {
    let mut trace = Trace::default();
    let paths = [
        "/email-otp/send-verification-otp",
        "/email-otp/check-verification-otp",
        "/email-otp/verify-email",
        "/sign-in/email-otp",
        "/email-otp/request-password-reset",
        "/forget-password/email-otp",
        "/email-otp/reset-password",
        "/email-otp/request-email-change",
        "/email-otp/change-email",
    ];
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mailbox = Arc::new(Mailbox::default());
    let auth = fast_builder::<B>(&connection)
        .plugin(plugin(
            &mailbox,
            EmailOtpConfig {
                change_email_enabled: true,
                ..Default::default()
            },
        ))
        .build()
        .await?;
    let owner = cookies(&signup(&auth, "owner@example.test").await);
    for path in paths {
        for text in [
            "[]",
            "null",
            "{}",
            r#"{"email":5,"otp":5,"type":5,"newEmail":5,"password":5}"#,
            r#"{"email":"not-an-email","otp":"123456","type":"sign-in","newEmail":"x","password":"a-native-password-123"}"#,
            r#"{"email":"nobody@example.test","otp":"123456","type":"sign-in","newEmail":"other@example.test","password":"a-native-password-123"}"#,
            r#"{"email":"owner@example.test","otp":"123456","type":"change-email","newEmail":"owner@example.test","password":"short"}"#,
        ] {
            for (who, cookie) in [("anonymous", ""), ("owner", owner.as_str())] {
                trace.response(
                    &format!("{path} {who} {text}"),
                    &Box::pin(auth.handle_request(raw(path, text, cookie))).await?,
                );
            }
        }
    }
    B::close(connection).await?;

    for (mode, config) in [
        (
            "reuse",
            EmailOtpConfig {
                resend_strategy: OtpResendStrategy::Reuse,
                ..Default::default()
            },
        ),
        (
            "invalid expiry",
            EmailOtpConfig {
                expires_in: f64::INFINITY,
                ..Default::default()
            },
        ),
        (
            "nonpositive length",
            EmailOtpConfig {
                otp_length: 0.0,
                ..Default::default()
            },
        ),
        (
            "zero attempts",
            EmailOtpConfig {
                allowed_attempts: 0.0,
                ..Default::default()
            },
        ),
        (
            "sign-up disabled",
            EmailOtpConfig {
                disable_sign_up: true,
                ..Default::default()
            },
        ),
    ] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let mailbox = Arc::new(Mailbox::default());
        let auth = fast_builder::<B>(&connection)
            .plugin(plugin(&mailbox, config))
            .build()
            .await?;
        let send = r#"{"email":"Fresh@Example.test","type":"sign-in"}"#;
        for label in ["first", "second"] {
            trace.response(
                &format!("{mode}: send {label}"),
                &Box::pin(auth.handle_request(raw("/email-otp/send-verification-otp", send, "")))
                    .await?,
            );
        }
        let delivered = mailbox.drain();
        trace.value(&format!("{mode}: deliveries"), json!(delivered.len()));
        if mode == "reuse" {
            assert_eq!(delivered.len(), 2);
            assert_eq!(delivered[0], delivered[1]);
        }
        trace.value(
            &format!("{mode}: verifications"),
            json!(db.count("verifications").await?),
        );
        if let Some(otp) = delivered.first() {
            for wrong in ["wrong-1", "wrong-2", "wrong-3", "wrong-4"] {
                trace.response(
                    &format!("{mode}: sign in {wrong}"),
                    &Box::pin(auth.handle_request(raw(
                        "/sign-in/email-otp",
                        &json!({"email":"fresh@example.test","otp":wrong}).to_string(),
                        "",
                    )))
                    .await?,
                );
            }
            trace.response(
                &format!("{mode}: sign in after budget"),
                &Box::pin(auth.handle_request(raw(
                    "/sign-in/email-otp",
                    &json!({"email":"fresh@example.test","otp":otp}).to_string(),
                    "",
                )))
                .await?,
            );
        }
        B::close(connection).await?;
    }
    trace.assert("email-otp/issuance-and-validation");
    Ok(())
}

async fn email_otp_change_email_policy<B: Backend>(db: Db) -> TestResult {
    let mut trace = Trace::default();
    for mode in ["disabled", "enabled", "verify-current"] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let mailbox = Arc::new(Mailbox::default());
        let auth = fast_builder::<B>(&connection)
            .plugin(plugin(
                &mailbox,
                EmailOtpConfig {
                    change_email_enabled: mode != "disabled",
                    verify_current_email: mode == "verify-current",
                    ..Default::default()
                },
            ))
            .build()
            .await?;
        let owner = cookies(&signup(&auth, "owner@example.test").await);
        let _ = signup(&auth, "taken@example.test").await;
        let mut send = async |label: &str, path: &str, input: Value| {
            let response = Box::pin(auth.handle_request(raw(path, &input.to_string(), &owner)))
                .await
                .unwrap();
            trace.response(&format!("{mode}: {label}"), &response);
        };
        send(
            "request same",
            "/email-otp/request-email-change",
            json!({"newEmail":"owner@example.test"}),
        )
        .await;
        send(
            "request missing current proof",
            "/email-otp/request-email-change",
            json!({"newEmail":"next@example.test"}),
        )
        .await;
        send(
            "request to taken",
            "/email-otp/request-email-change",
            json!({"newEmail":"taken@example.test","otp":"000000"}),
        )
        .await;
        send(
            "confirm same",
            "/email-otp/change-email",
            json!({"newEmail":"owner@example.test","otp":"123456"}),
        )
        .await;
        send(
            "confirm unknown",
            "/email-otp/change-email",
            json!({"newEmail":"next@example.test","otp":"123456"}),
        )
        .await;
        trace.value(
            &format!("{mode}: verifications"),
            json!(db.count("verifications").await?),
        );
        B::close(connection).await?;
    }
    trace.assert("email-otp/change-email-policy");
    Ok(())
}

async fn email_otp_hooks_and_reset_edges<B: Backend>(db: Db) -> TestResult {
    use alibi::wire::UserView;
    let mut trace = Trace::default();
    for mode in ["passes", "api error", "internal"] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let mailbox = Arc::new(Mailbox::default());
        let hook =
            |kind: &'static str| -> alibi::plugins::email_verification::EmailVerificationHook {
                Arc::new(move |_: &UserView| {
                    Box::pin(async move {
                        match kind {
                            "api error" => Err(AuthError::forbidden("hook says no")),
                            "internal" => Err(AuthError::internal("hook crashed")),
                            _ => Ok(()),
                        }
                    })
                })
            };
        let auth = fast_builder::<B>(&connection)
            .plugin(plugin(
                &mailbox,
                EmailOtpConfig {
                    change_email_enabled: true,
                    before_email_verification: (mode != "passes").then(|| hook(mode)),
                    after_email_verification: (mode == "passes").then(|| hook(mode)),
                    ..Default::default()
                },
            ))
            .plugin(EmailVerificationPlugin::with_config(
                EmailVerificationConfig::default(),
            ))
            .build()
            .await?;
        let owner = cookies(&signup(&auth, "owner@example.test").await);
        let issue = async |kind: &str, input: Value| -> AuthResult<String> {
            let _ = Box::pin(auth.handle_request(raw(
                "/email-otp/send-verification-otp",
                &input.to_string(),
                "",
            )))
            .await?;
            let _ = kind;
            Ok(mailbox.take().otp)
        };
        let otp = issue(
            "verify",
            json!({"email":"owner@example.test","type":"email-verification"}),
        )
        .await?;
        trace.response(
            &format!("{mode}: verify email"),
            &Box::pin(auth.handle_request(raw(
                "/email-otp/verify-email",
                &json!({"email":"owner@example.test","otp":otp}).to_string(),
                "",
            )))
            .await?,
        );
        let _ = Box::pin(auth.handle_request(raw(
            "/email-otp/request-email-change",
            r#"{"newEmail":"moved@example.test"}"#,
            &owner,
        )))
        .await?;
        let otp = mailbox.take().otp;
        trace.response(
            &format!("{mode}: change email"),
            &Box::pin(auth.handle_request(raw(
                "/email-otp/change-email",
                &json!({"newEmail":"moved@example.test","otp":otp}).to_string(),
                &owner,
            )))
            .await?,
        );
        trace.value(
            &format!("{mode}: email"),
            json!(db.text("SELECT email FROM users", &[]).await?),
        );
        B::close(connection).await?;
    }
    trace.assert("email-otp/hooks-and-edges");
    Ok(())
}
