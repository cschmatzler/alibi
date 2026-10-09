//! Change-email, delete-user and update-user policy branches.
use super::auth_probe::{fast_builder, fast_password, raw};
use super::*;
use crate::snapshot::Trace;
use alibi::plugins::user_management::{
    AfterDeleteUser, BeforeDeleteUser, SendChangeEmailConfirmation, SendDeleteAccountVerification,
    UserInfo,
};
use alibi::plugins::{
    EmailVerificationConfig, EmailVerificationPlugin, SendVerificationEmail, UserManagementPlugin,
};
use alibi::wire::UserView;
use alibi::{AuthError, AuthResult, CookieCacheConfig, CookieCacheStrategy};
use async_trait::async_trait;
use chrono::Duration;

backend_tests!(
    delete_user_policy_matrix,
    change_email_policy_matrix,
    update_user_input_matrix
);

#[derive(Default)]
struct Mail(Mutex<Vec<String>>);
#[async_trait]
impl SendDeleteAccountVerification for Mail {
    async fn send(&self, _: &UserInfo, url: &str, token: &str) -> AuthResult<()> {
        self.0.lock().unwrap().push(format!("{url} {token}"));
        Ok(())
    }
}
#[async_trait]
impl SendVerificationEmail for Mail {
    async fn send(&self, user: &UserView, _: &str, token: &str) -> AuthResult<()> {
        self.0
            .lock()
            .unwrap()
            .push(format!("{} {}", user.email.clone().unwrap(), token.len()));
        Ok(())
    }
}
#[async_trait]
impl SendChangeEmailConfirmation for Mail {
    async fn send(&self, _: &UserInfo, new_email: &str, _: &str, _: &str) -> AuthResult<()> {
        self.0.lock().unwrap().push(new_email.to_owned());
        Ok(())
    }
}

struct Hook(&'static str);
#[async_trait]
impl BeforeDeleteUser for Hook {
    async fn before_delete(&self, _: &UserInfo) -> AuthResult<()> {
        match self.0 {
            "deny" => Err(AuthError::forbidden("deletion blocked")),
            _ => Ok(()),
        }
    }
}
#[async_trait]
impl AfterDeleteUser for Hook {
    async fn after_delete(&self, _: &UserInfo) -> AuthResult<()> {
        Err(AuthError::forbidden("after hook failed"))
    }
}

fn plain_config() -> AuthConfig {
    AuthConfig::new(SECRET).base_url(ORIGIN)
}

fn builder_with<B: Backend>(
    config: AuthConfig,
    connection: &B::Connection,
) -> AuthBuilder<B::Schema> {
    AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(fast_password())
        .plugin(SessionManagementPlugin::new())
}

async fn delete_user_policy_matrix<B: Backend>(db: Db) -> TestResult {
    let mut trace = Trace::default();
    let long_password = "p".repeat(129);
    for mode in [
        "disabled",
        "hooks-deny",
        "after-hook",
        "stale-session",
        "zero-expiry",
        "no-sender",
    ] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let mail = Arc::new(Mail::default());
        let mut config = plain_config();
        if mode == "stale-session" {
            config.session.fresh_age = Some(Duration::minutes(5));
        }
        let mut plugin = UserManagementPlugin::new().delete_user_enabled(mode != "disabled");
        plugin = match mode {
            "hooks-deny" => plugin.before_delete(Arc::new(Hook("deny"))),
            "after-hook" => plugin.after_delete(Arc::new(Hook("after"))),
            "zero-expiry" => plugin
                .delete_token_expires_in(Duration::zero())
                .send_delete_account_verification(mail.clone()),
            "no-sender" => plugin.require_delete_verification(true),
            _ => plugin,
        };
        let auth = builder_with::<B>(config, &connection)
            .plugin(plugin)
            .build()
            .await?;
        let owner = signup(&auth, "owner@example.test").await;
        let cookie = cookies(&owner);
        macro_rules! respond {
            ($label:expr, $input:expr $(,)?) => {
                async {
                    let response = Box::pin(auth.handle_request($input)).await.unwrap();
                    trace.response(&format!("{mode}: {}", $label), &response);
                }
            };
        }
        respond!("callback without token", {
            let mut input = request("/delete-user/callback", None, &cookie);
            input.query.clear();
            input
        })
        .await;
        respond!(
            "callback anonymous",
            request("/delete-user/callback", None, "")
        )
        .await;
        respond!(
            "password too long",
            raw(
                "/delete-user",
                &json!({"password":long_password}).to_string(),
                &cookie,
            ),
        )
        .await;
        respond!(
            "unknown token",
            raw("/delete-user", r#"{"token":"unknown"}"#, &cookie),
        )
        .await;
        if mode == "stale-session" {
            db.set_timestamp(
                "sessions",
                "created_at",
                ("user_id", &user_id(&owner)),
                chrono::Utc::now() - Duration::hours(1),
            )
            .await?;
        }
        respond!("delete", raw("/delete-user", "{}", &cookie)).await;
        trace.value(&format!("{mode}: users"), json!(db.count("users").await?));
        if mode == "zero-expiry" {
            let expires = db
                .text("SELECT CAST(expires_at AS TEXT) FROM verifications", &[])
                .await?;
            assert!(expires.is_some());
            assert_eq!(mail.0.lock().unwrap().len(), 1);
        }
        if mode == "after-hook" {
            let mut callback = request("/delete-user/callback", None, &cookie);
            _ = callback.query.insert("token".into(), "x".into());
            respond!("callback unknown", callback).await;
            let owner = signup(&auth, "second@example.test").await;
            let direct = raw("/delete-user", "{}", &cookies(&owner));
            respond!("after hook failure", direct).await;
        }
        B::close(connection).await?;
    }
    trace.assert("user-management/delete-matrix");
    Ok(())
}

fn user_id(response: &AuthResponse) -> String {
    body(response)["user"]["id"].as_str().unwrap().to_owned()
}

async fn change_email_policy_matrix<B: Backend>(db: Db) -> TestResult {
    let mut trace = Trace::default();
    for mode in [
        "disabled",
        "no-delivery",
        "update-and-notify",
        "update-only",
        "confirmation",
        "verification-mail",
    ] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let mail = Arc::new(Mail::default());
        let mut config = plain_config();
        if mode == "update-and-notify" {
            config = config.session_cookie_cache(CookieCacheConfig {
                enabled: true,
                strategy: CookieCacheStrategy::Compact,
                max_age: 300.0,
                version: None,
            });
        }
        let mut plugin = UserManagementPlugin::new().change_email_enabled(mode != "disabled");
        plugin = match mode {
            "update-and-notify" | "update-only" => plugin.update_without_verification(true),
            "confirmation" => plugin.send_change_email_confirmation(mail.clone()),
            _ => plugin,
        };
        let mut auth = builder_with::<B>(config, &connection).plugin(plugin);
        if matches!(
            mode,
            "update-and-notify" | "confirmation" | "verification-mail"
        ) {
            auth = auth.plugin(EmailVerificationPlugin::with_config(
                EmailVerificationConfig {
                    send_verification_email: Some(mail.clone()),
                    ..Default::default()
                },
            ));
        }
        let auth = auth.build().await?;
        let owner = signup(&auth, "owner@example.test").await;
        let _ = signup(&auth, "taken@example.test").await;
        let cookie = cookies(&owner);
        if mode == "confirmation" {
            _ = db
                .execute("UPDATE users SET email_verified = true", &[])
                .await?;
        }
        macro_rules! respond {
            ($label:expr, $text:expr $(,)?) => {
                async {
                    let response =
                        Box::pin(auth.handle_request(raw("/change-email", $text, &cookie)))
                            .await
                            .unwrap();
                    trace.response(&format!("{mode}: {}", $label), &response);
                }
            };
        }
        respond!("same email", r#"{"newEmail":"owner@example.test"}"#).await;
        respond!("invalid body", r#"{"newEmail":"not-an-email"}"#).await;
        respond!("taken", r#"{"newEmail":"Taken@Example.test"}"#).await;
        respond!(
            "new",
            r#"{"newEmail":"Fresh@Example.test","callbackURL":"/done"}"#,
        )
        .await;
        trace.value(
            &format!("{mode}: emails"),
            json!(
                db.text("SELECT email FROM users WHERE name = 'Native owner' ORDER BY created_at LIMIT 1", &[])
                    .await?
            ),
        );
        trace.value(
            &format!("{mode}: mail"),
            json!(mail.0.lock().unwrap().len()),
        );
        B::close(connection).await?;
    }
    trace.assert("user-management/change-email-matrix");
    Ok(())
}

async fn update_user_input_matrix<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = fast_builder::<B>(&connection)
        .plugin(UserManagementPlugin::new())
        .build()
        .await?;
    let cookie = cookies(&signup(&auth, "profile@example.test").await);
    let mut trace = Trace::default();
    for text in [
        "[]",
        "null",
        "7",
        r#""text""#,
        "true",
        "{}",
        r#"{"email":"x@example.test"}"#,
        r#"{"email":0}"#,
        r#"{"email":false}"#,
        r#"{"email":""}"#,
        r#"{"email":null,"name":"Null email"}"#,
        r#"{"email":[],"name":"x"}"#,
        r#"{"email":{},"name":"x"}"#,
        r#"{"role":"admin","name":"x"}"#,
        r#"{"username":"ignored","displayUsername":"Ignored"}"#,
        r#"{"phoneNumber":null}"#,
        r#"{"name":"Renamed","image":null}"#,
        r#"{"name":5}"#,
    ] {
        trace.response(
            text,
            &Box::pin(auth.handle_request(raw("/update-user", text, &cookie))).await?,
        );
    }
    trace.value("name", json!(db.text("SELECT name FROM users", &[]).await?));
    trace.assert("user-management/update-user-inputs");
    B::close(connection).await
}
