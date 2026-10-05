use super::*;
use async_trait::async_trait;
use better_auth::plugins::email_otp::{
    EmailOtpConfig, EmailOtpDelivery, EmailOtpPlugin, EmailOtpType, SendEmailOtp,
};
use better_auth::plugins::magic_link::{
    MagicLinkConfig, MagicLinkDelivery, MagicLinkPlugin, SendMagicLink,
};
use better_auth::plugins::one_time_token::OneTimeTokenPlugin;
use better_auth::plugins::phone_number::{
    PhoneNumberConfig, PhoneNumberPlugin, PhoneOtpDelivery, PhoneSignupIdentity, SendPhoneOtp,
};
use better_auth_core::{AuthResult, CallbackContext};

backend_tests!(
    magic_link_delivery_is_redeemable_once,
    email_otp_delivery_creates_one_verified_session,
    phone_otp_delivery_binds_verified_identity,
    phone_password_verification_and_reset_bind_one_credential,
    one_time_token_republishes_only_its_original_session
);
postgres_tests!(
    magic_link_delivery_is_redeemable_once,
    email_otp_delivery_creates_one_verified_session,
    phone_otp_delivery_binds_verified_identity,
    phone_password_verification_and_reset_bind_one_credential,
    one_time_token_republishes_only_its_original_session
);

pub(super) struct Mailbox<T>(Mutex<Vec<T>>);
impl<T> Default for Mailbox<T> {
    fn default() -> Self {
        Self(Mutex::new(Vec::new()))
    }
}
impl<T> Mailbox<T> {
    pub(super) fn take(&self) -> T {
        self.0
            .lock()
            .unwrap()
            .pop()
            .expect("handler delivered a challenge")
    }
}

#[async_trait]
impl SendMagicLink for Mailbox<MagicLinkDelivery> {
    async fn send(&self, delivery: &MagicLinkDelivery, _: &CallbackContext) -> AuthResult<()> {
        self.0.lock().unwrap().push(delivery.clone());
        Ok(())
    }
}
#[async_trait]
impl SendEmailOtp for Mailbox<EmailOtpDelivery> {
    async fn send(&self, delivery: &EmailOtpDelivery, _: &CallbackContext) -> AuthResult<()> {
        self.0.lock().unwrap().push(delivery.clone());
        Ok(())
    }
}
#[async_trait]
impl SendPhoneOtp for Mailbox<PhoneOtpDelivery> {
    async fn send(&self, delivery: &PhoneOtpDelivery, _: &CallbackContext) -> AuthResult<()> {
        self.0.lock().unwrap().push(delivery.clone());
        Ok(())
    }
}

async fn magic_link_delivery_is_redeemable_once<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mailbox = Arc::new(Mailbox::default());
    let auth = builder::<B>(&connection)
        .plugin(MagicLinkPlugin::new(MagicLinkConfig {
            send_magic_link: Some(mailbox.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let _ = call(
        &auth,
        request(
            "/sign-in/magic-link",
            Some(json!({"email":"magic@example.test"})),
            "",
        ),
        200,
    )
    .await;
    assert_eq!(db.count("users").await?, 0);
    assert_eq!(db.count("verifications").await?, 1);
    let delivery = mailbox.take();
    assert_eq!(delivery.email, "magic@example.test");
    let link = url::Url::parse(&delivery.url)?;
    assert_eq!(link.origin().ascii_serialization(), ORIGIN);
    let mut redeem = AuthRequest::new(HttpMethod::Get, link.path());
    redeem.query.extend(link.query_pairs().into_owned());
    let accepted = call(&auth, redeem.clone(), 302).await;
    authenticated(&auth, &cookies(&accepted), "magic@example.test").await;
    assert_eq!(db.count("sessions").await?, 1);
    assert_eq!(db.count("verifications").await?, 0);
    let replay = call(&auth, redeem, 302).await;
    let redirect = url::Url::parse(replay.headers.get("location").unwrap())?;
    assert!(
        redirect
            .query_pairs()
            .any(|(key, value)| key == "error" && value == "INVALID_TOKEN")
    );
    assert_eq!(db.count("sessions").await?, 1);
    B::close(connection).await
}

async fn email_otp_delivery_creates_one_verified_session<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mailbox = Arc::new(Mailbox::default());
    let auth = builder::<B>(&connection)
        .plugin(EmailOtpPlugin::new(EmailOtpConfig {
            send_verification_otp: Some(mailbox.clone()),
            ..Default::default()
        }))
        .build()
        .await?;
    let _ = call(
        &auth,
        request(
            "/email-otp/send-verification-otp",
            Some(json!({"email":"otp@example.test","type":"sign-in"})),
            "",
        ),
        200,
    )
    .await;
    let delivery = mailbox.take();
    assert_eq!(delivery.email, "otp@example.test");
    assert_eq!(delivery.otp_type, EmailOtpType::SignIn);
    assert_eq!(db.count("users").await?, 0);
    let input = request(
        "/sign-in/email-otp",
        Some(json!({"email":delivery.email,"otp":delivery.otp})),
        "",
    );
    let accepted = call(&auth, input.clone(), 200).await;
    assert_eq!(body(&accepted)["user"]["emailVerified"], true);
    authenticated(&auth, &cookies(&accepted), "otp@example.test").await;
    let replay = call(&auth, input, 400).await;
    assert_eq!(body(&replay)["code"], "INVALID_OTP");
    assert_eq!(db.count("sessions").await?, 1);
    B::close(connection).await
}

struct PhoneIdentity;
impl PhoneSignupIdentity for PhoneIdentity {
    fn temporary_email(&self, phone: &str) -> String {
        format!("{}@phone.example.test", phone.trim_start_matches('+'))
    }
}

async fn phone_otp_delivery_binds_verified_identity<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mailbox = Arc::new(Mailbox::default());
    let auth = builder::<B>(&connection)
        .plugin(PhoneNumberPlugin::new(PhoneNumberConfig {
            send_otp: Some(mailbox.clone()),
            sign_up_on_verification: Some(Arc::new(PhoneIdentity)),
            ..Default::default()
        }))
        .build()
        .await?;
    let phone = "+15551234567";
    let _ = call(
        &auth,
        request(
            "/phone-number/send-otp",
            Some(json!({"phoneNumber":phone})),
            "",
        ),
        200,
    )
    .await;
    let delivery = mailbox.take();
    assert_eq!(delivery.phone_number, phone);
    assert_eq!(db.count("users").await?, 0);
    let input = request(
        "/phone-number/verify",
        Some(json!({"phoneNumber":phone,"code":delivery.code})),
        "",
    );
    let accepted = call(&auth, input.clone(), 200).await;
    assert_eq!(body(&accepted)["user"]["phoneNumber"], phone);
    assert_eq!(body(&accepted)["user"]["phoneNumberVerified"], true);
    authenticated(&auth, &cookies(&accepted), "15551234567@phone.example.test").await;
    let replay = call(&auth, input, 400).await;
    assert_eq!(body(&replay)["code"], "OTP_NOT_FOUND");
    assert_eq!(db.count("sessions").await?, 1);
    B::close(connection).await
}

async fn one_time_token_republishes_only_its_original_session<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(OneTimeTokenPlugin::new())
        .build()
        .await?;
    let _ = call(&auth, request("/one-time-token/generate", None, ""), 401).await;
    assert_eq!(db.count("verifications").await?, 0);
    let issued = signup(&auth, "ott@example.test").await;
    let generated = call(
        &auth,
        request("/one-time-token/generate", None, &cookies(&issued)),
        200,
    )
    .await;
    let token = body(&generated)["token"].as_str().unwrap().to_owned();
    let input = request("/one-time-token/verify", Some(json!({"token":token})), "");
    let accepted = call(&auth, input.clone(), 200).await;
    assert_eq!(body(&accepted)["session"]["token"], body(&issued)["token"]);
    authenticated(&auth, &cookies(&accepted), "ott@example.test").await;
    let replay = call(&auth, input, 400).await;
    assert_eq!(body(&replay)["message"], "Invalid token");
    assert_eq!(
        db.count("sessions").await?,
        1,
        "redemption reuses the original session"
    );
    B::close(connection).await
}

// Promoted from the phone plugin's SeaORM-only direct-handler owners: the same
// contracts now cross installed hooks, transport, and both persistence adapters.
struct PhoneAdmission(std::sync::atomic::AtomicU8);
#[async_trait]
impl better_auth::plugins::phone_number::PhoneNumberValidator for PhoneAdmission {
    async fn is_valid(&self, phone: &str) -> AuthResult<bool> {
        assert_eq!(phone, "+15551110003");
        match self.0.load(std::sync::atomic::Ordering::SeqCst) {
            1 => Ok(false),
            2 => Err(better_auth_core::AuthError::internal(
                "phone policy failure",
            )),
            _ => Ok(true),
        }
    }
}

async fn phone_password_verification_and_reset_bind_one_credential<B: Backend>(
    db: Db,
) -> TestResult {
    use better_auth_core::{AuthSession, AuthUser};
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let codes = Arc::new(Mailbox::default());
    let reset = Arc::new(Mailbox::default());
    let admission = Arc::new(PhoneAdmission(std::sync::atomic::AtomicU8::new(0)));
    let auth = builder::<B>(&connection)
        .plugin(PhoneNumberPlugin::new(PhoneNumberConfig {
            send_otp: Some(codes.clone()),
            phone_number_validator: Some(admission.clone()),
            send_password_reset_otp: Some(reset.clone()),
            require_verification: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let phone = "+15551110003";
    let owner = call(&auth, request("/sign-up/email", Some(json!({"email":"phone-password@example.test", "name":"Phone Owner", "password":PASSWORD, "phoneNumber":phone})), ""), 200).await;
    let user = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let original = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    for (mode, status) in [(1, 400), (2, 500)] {
        admission.0.store(mode, std::sync::atomic::Ordering::SeqCst);
        for (path, input) in [
            ("/phone-number/send-otp", json!({"phoneNumber":phone})),
            (
                "/sign-in/phone-number",
                json!({"phoneNumber":phone,"password":PASSWORD}),
            ),
        ] {
            let _ = call(&auth, request(path, Some(input), ""), status).await;
            assert_eq!(
                db.tables(&["users", "accounts", "sessions", "verifications"])
                    .await?,
                original
            );
            assert!(codes.0.lock().unwrap().is_empty());
        }
    }
    admission.0.store(0, std::sync::atomic::Ordering::SeqCst);
    let original_sessions = db.table("sessions").await?;
    let rejected = call(
        &auth,
        request(
            "/sign-in/phone-number",
            Some(json!({"phoneNumber":phone,"password":"wrong"})),
            "",
        ),
        401,
    )
    .await;
    assert_eq!(body(&rejected)["code"], "PHONE_NUMBER_NOT_VERIFIED");
    assert_eq!(db.table("sessions").await?, original_sessions);
    let delivered = codes.take();
    assert_eq!(delivered.phone_number, phone);
    assert_eq!(
        db.text(
            "SELECT value FROM verifications WHERE identifier=$1",
            &[phone]
        )
        .await?
        .as_deref(),
        Some(delivered.code.as_str())
    );
    let verified = call(
        &auth,
        request(
            "/phone-number/verify",
            Some(json!({"phoneNumber":phone,"code":delivered.code,"disableSession":true})),
            "",
        ),
        200,
    )
    .await;
    assert_eq!(body(&verified)["token"], Value::Null);
    assert_eq!(db.table("sessions").await?, original_sessions);
    let _ = call(
        &auth,
        request(
            "/sign-in/phone-number",
            Some(json!({"phoneNumber":phone,"password":"wrong"})),
            "",
        ),
        401,
    )
    .await;
    let accepted = call(
        &auth,
        request(
            "/sign-in/phone-number",
            Some(json!({"phoneNumber":phone,"password":PASSWORD,"rememberMe":false})),
            "",
        ),
        200,
    )
    .await;
    authenticated(&auth, &cookies(&accepted), "phone-password@example.test").await;
    let session_cookie = accepted
        .headers
        .get_all("set-cookie")
        .find(|c| c.contains("session_token="))
        .unwrap();
    assert!(!session_cookie.contains("Max-Age"));
    assert!(cookies(&accepted).contains("dont_remember="));
    let session = auth
        .store()
        .get_session(body(&accepted)["token"].as_str().unwrap())
        .await?
        .unwrap();
    assert!(
        (session.expires_at() - chrono::Utc::now() - chrono::Duration::days(1))
            .num_seconds()
            .abs()
            <= 2
    );
    let accounts = db.table("accounts").await?;
    let _ = call(
        &auth,
        request(
            "/phone-number/request-password-reset",
            Some(json!({"phoneNumber":phone})),
            "",
        ),
        200,
    )
    .await;
    let code = reset.take();
    assert_eq!(code.phone_number, phone);
    let _ = call(
        &auth,
        request(
            "/phone-number/reset-password",
            Some(json!({"phoneNumber":phone,"otp":code.code,"newPassword":"short"})),
            "",
        ),
        400,
    )
    .await;
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM verifications WHERE identifier=$1",
            &[&format!("{phone}-request-password-reset")]
        )
        .await?,
        0
    );
    let _ = call(&auth, request("/phone-number/reset-password", Some(json!({"phoneNumber":phone,"otp":code.code,"newPassword":"replacement-password123"})), ""), 400).await;
    assert_eq!(db.table("accounts").await?, accounts);
    let _ = call(
        &auth,
        request(
            "/phone-number/request-password-reset",
            Some(json!({"phoneNumber":phone})),
            "",
        ),
        200,
    )
    .await;
    let code = reset.take();
    let _ = call(&auth, request("/phone-number/reset-password", Some(json!({"phoneNumber":phone,"otp":code.code,"newPassword":"replacement-password123"})), ""), 200).await;
    let _ = call(
        &auth,
        request(
            "/sign-in/phone-number",
            Some(json!({"phoneNumber":phone,"password":PASSWORD})),
            "",
        ),
        401,
    )
    .await;
    let login = call(
        &auth,
        request(
            "/sign-in/phone-number",
            Some(json!({"phoneNumber":phone,"password":"replacement-password123"})),
            "",
        ),
        200,
    )
    .await;
    authenticated(&auth, &cookies(&login), "phone-password@example.test").await;
    assert_eq!(db.count("accounts").await?, 1);
    assert!(
        !auth
            .store()
            .get_user_by_id(&user)
            .await?
            .unwrap()
            .email_verified()
    );
    let missing = "+15559990000";
    let _ = call(
        &auth,
        request(
            "/phone-number/request-password-reset",
            Some(json!({"phoneNumber":missing})),
            "",
        ),
        200,
    )
    .await;
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM verifications WHERE identifier=$1",
            &[&format!("{missing}-request-password-reset")]
        )
        .await?,
        1
    );
    assert!(
        reset.0.lock().unwrap().is_empty(),
        "unknown phone must not receive a reset code"
    );
    B::close(connection).await
}
