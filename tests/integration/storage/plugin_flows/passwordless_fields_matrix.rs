//! Passwordless sign-up applies the username policy and schema defaults before persistence.
use super::auth_probe::{Probe, fast_password};
use super::*;
use alibi::AuthResult;
use alibi::hooks::RequestHookContext;
use alibi::plugins::email_otp::{EmailOtpConfig, EmailOtpPlugin, EmailOtpType};
use alibi::plugins::{AdminPlugin, AnonymousPlugin, TwoFactorPlugin};
use alibi::user_validation::{UserInfoValidator, UserValidationData, UserValidationRejection};
use async_trait::async_trait;

backend_tests!(
    passwordless_signup_applies_username_policy_and_schema_defaults,
    additional_field_validation_and_username_stripping
);

struct Admit;
#[async_trait]
impl UserInfoValidator for Admit {
    async fn validate(
        &self,
        _: &mut UserValidationData,
        _: &RequestHookContext,
    ) -> AuthResult<Option<UserValidationRejection>> {
        Ok(None)
    }
}

async fn passwordless_signup_applies_username_policy_and_schema_defaults<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.user_validation = Some(Arc::new(Admit));
    let otp = EmailOtpPlugin::new(EmailOtpConfig::default());
    let auth = alibi::AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(fast_password().enable_username(true))
        .plugin(SessionManagementPlugin::new())
        .plugin(AdminPlugin::new())
        .plugin(AnonymousPlugin::new())
        .plugin(TwoFactorPlugin::new())
        .plugin(otp.clone())
        .build()
        .await?;
    let mut probe = Probe::new(&auth);
    for (label, email, extra) in [
        ("plain", "plain@example.test", json!({})),
        (
            "with username",
            "named@example.test",
            json!({"username":"Named_User","displayUsername":"Named User","name":"Named"}),
        ),
        (
            "username taken",
            "taken@example.test",
            json!({"username":"NAMED_user"}),
        ),
        (
            "username too short",
            "short@example.test",
            json!({"username":"ab"}),
        ),
        (
            "username invalid",
            "invalid@example.test",
            json!({"username":"not valid!"}),
        ),
        (
            "empty username",
            "empty@example.test",
            json!({"username":"","displayUsername":""}),
        ),
        (
            "display only",
            "display@example.test",
            json!({"displayUsername":"Only Display"}),
        ),
        (
            "numeric username",
            "numeric@example.test",
            json!({"username":5}),
        ),
    ] {
        let code = otp
            .create_verification_otp(auth.context(), email, EmailOtpType::SignIn)
            .await?;
        let mut input = json!({"email":email,"otp":code});
        input
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let _ = probe
            .post(label, "/sign-in/email-otp", &input.to_string(), "")
            .await;
    }
    probe.trace.value(
        "rows",
        json!({
            "users": db.count("users").await?,
            "defaults": db
                .count_where(
                    "SELECT COUNT(*) FROM users WHERE banned = false AND is_anonymous = false AND two_factor_enabled = false",
                    &[],
                )
                .await?,
            "usernames": db.text("SELECT username FROM users WHERE email = 'named@example.test'", &[]).await?,
        }),
    );
    probe.trace.assert("passwordless/signup-fields");
    B::close(connection).await
}

async fn additional_field_validation_and_username_stripping<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    _ = db
        .execute("ALTER TABLE users ADD COLUMN nickname TEXT", &[])
        .await?;
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    _ = config.user.additional_fields.insert(
        "nickname".into(),
        alibi::field_policy::FieldConfig::new(json!({"type":"string"})).validate(|value| {
            if value.as_str() == Some("bad") {
                Err("Nickname is not allowed".to_owned())
            } else {
                Ok(value.clone())
            }
        }),
    );
    let auth = alibi::AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(fast_password().enable_username(false))
        .plugin(SessionManagementPlugin::new())
        .plugin(alibi::plugins::UserManagementPlugin::new())
        .build()
        .await?;
    let mut probe = Probe::new(&auth);
    for (label, nickname) in [("rejected", "bad")] {
        let _ = probe
            .post(
                &format!("signup {label}"),
                "/sign-up/email",
                &json!({"email":format!("{label}@example.test"),"password":PASSWORD,"name":"N","nickname":nickname}).to_string(),
                "",
            )
            .await;
    }
    let owner = cookies(&signup(&auth, "owner@example.test").await);
    for text in [
        r#"{"nickname":"bad"}"#,
        r#"{"username":"ignored","displayUsername":"Ignored"}"#,
        r#"{"username":"ignored","displayUsername":"Ignored","name":"Renamed"}"#,
    ] {
        let _ = probe
            .post(&format!("update {text}"), "/update-user", text, &owner)
            .await;
    }
    probe
        .trace
        .assert("passwordless/additional-field-validation");
    B::close(connection).await
}
