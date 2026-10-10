//! Email verification token outcomes, change-email confirmation and session adoption.
use super::auth_probe::{Probe, fast_builder};
use super::*;
use alibi::AuthResult;
use alibi::plugins::user_management::{SendChangeEmailConfirmation, UserInfo};
use alibi::plugins::{
    EmailVerificationConfig, EmailVerificationPlugin, SendVerificationEmail, UserManagementPlugin,
};
use alibi::wire::UserView;
use async_trait::async_trait;
use chrono::Duration;

backend_tests!(
    verify_email_token_outcomes,
    verify_email_session_adoption,
    verify_email_change_confirmation_chain,
    send_verification_email_matrix,
    verification_after_hook_rejection_commits_user_without_issuing_session
);

#[derive(Default)]
struct Inbox(Mutex<Vec<(String, String)>>);
impl Inbox {
    fn take(&self) -> (String, String) {
        self.0.lock().unwrap().pop().unwrap()
    }
}
#[async_trait]
impl SendVerificationEmail for Inbox {
    async fn send(&self, user: &UserView, _: &str, token: &str) -> AuthResult<()> {
        self.0
            .lock()
            .unwrap()
            .push((user.email.clone().unwrap(), token.to_owned()));
        Ok(())
    }
}
#[async_trait]
impl SendChangeEmailConfirmation for Inbox {
    async fn send(&self, _: &UserInfo, new_email: &str, _: &str, token: &str) -> AuthResult<()> {
        self.0
            .lock()
            .unwrap()
            .push((new_email.to_owned(), token.to_owned()));
        Ok(())
    }
}

fn verify(token: &str, callback: Option<&str>, cookie: &str) -> AuthRequest {
    let mut input = request("/verify-email", None, cookie);
    _ = input.query.insert("token".into(), token.into());
    if let Some(callback) = callback {
        _ = input.query.insert("callbackURL".into(), callback.into());
    }
    input
}

fn forged(claims: &Value) -> String {
    jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        claims,
        &jsonwebtoken::EncodingKey::from_secret(SECRET.as_bytes()),
    )
    .unwrap()
}

fn plugins(
    inbox: &Arc<Inbox>,
    expiry: Duration,
    auto_sign_in: bool,
) -> (EmailVerificationPlugin, UserManagementPlugin) {
    (
        EmailVerificationPlugin::with_config(EmailVerificationConfig {
            send_verification_email: Some(inbox.clone()),
            send_on_sign_up: Some(true),
            auto_sign_in_after_verification: auto_sign_in,
            verification_token_expiry: expiry,
            ..Default::default()
        }),
        UserManagementPlugin::new()
            .change_email_enabled(true)
            .send_change_email_confirmation(inbox.clone()),
    )
}

async fn verify_email_token_outcomes<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let inbox = Arc::new(Inbox::default());
    let (verification, management) = plugins(&inbox, Duration::hours(1), false);
    let auth = fast_builder::<B>(&connection)
        .plugin(verification)
        .plugin(management)
        .build()
        .await?;
    let mut probe = Probe::new(&auth);
    let _ = signup(&auth, "first@example.test").await;
    let (_, token) = inbox.take();
    let _ = signup(&auth, "gone@example.test").await;
    let (_, gone) = inbox.take();
    _ = db
        .execute("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE email = 'gone@example.test')", &[])
        .await?;
    _ = db
        .execute("DELETE FROM accounts WHERE user_id IN (SELECT id FROM users WHERE email = 'gone@example.test')", &[])
        .await?;
    _ = db
        .execute("DELETE FROM users WHERE email = 'gone@example.test'", &[])
        .await?;
    let now = chrono::Utc::now().timestamp();
    let claims = |extra: Value| {
        let mut base = json!({"email":"first@example.test","iat":now,"exp":now + 3600});
        base.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        forged(&base)
    };
    for (label, token, callback) in [
        ("garbage", "not.a.token".to_owned(), None),
        (
            "garbage with callback",
            "not.a.token".to_owned(),
            Some("/done?x=1"),
        ),
        (
            "garbage with absolute callback",
            "x".to_owned(),
            Some("http://localhost:43219/done?x=1&"),
        ),
        ("owner deleted", gone, None),
        (
            "owner deleted with callback",
            forged(&json!({"email":"gone@example.test","exp":now + 60})),
            Some("/done"),
        ),
        ("expired", claims(json!({"exp":now - 10})), None),
        (
            "expired with callback",
            claims(json!({"exp":now - 10})),
            Some("/done"),
        ),
        ("not yet valid", claims(json!({"nbf":now + 600})), None),
        ("text expiry", claims(json!({"exp":"soon"})), None),
        ("numeric update target", claims(json!({"updateTo":5})), None),
        (
            "numeric request type",
            claims(json!({"requestType":5})),
            None,
        ),
        ("invalid email claim", claims(json!({"email":"nope"})), None),
        (
            "missing email claim",
            forged(&json!({"exp":now + 60})),
            None,
        ),
        (
            "wrong signature",
            jsonwebtoken::encode(
                &jsonwebtoken::Header::default(),
                &json!({"email":"first@example.test","exp":now + 60}),
                &jsonwebtoken::EncodingKey::from_secret(b"another-secret-another-secret-0000"),
            )
            .unwrap(),
            None,
        ),
        (
            "untrusted callback",
            token.clone(),
            Some("https://evil.example/"),
        ),
        ("verifies with callback", token.clone(), Some("/done?x=1")),
        (
            "already verified with callback",
            token.clone(),
            Some("/done"),
        ),
        ("already verified", token.clone(), None),
    ] {
        let _ = probe.send(label, verify(&token, callback, "")).await;
    }
    probe.trace.value(
        "verified",
        json!(
            db.count_where(
                "SELECT COUNT(*) FROM users WHERE email_verified = true",
                &[]
            )
            .await?
        ),
    );
    probe.trace.assert("email-verification/token-outcomes");
    B::close(connection).await
}

async fn verify_email_session_adoption<B: Backend>(db: Db) -> TestResult {
    let mut trace = crate::snapshot::Trace::default();
    for mode in ["no-auto-sign-in", "auto-sign-in"] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let inbox = Arc::new(Inbox::default());
        let (verification, management) =
            plugins(&inbox, Duration::hours(1), mode == "auto-sign-in");
        let auth = fast_builder::<B>(&connection)
            .plugin(verification)
            .plugin(management)
            .build()
            .await?;
        let mut probe = Probe::new(&auth);
        probe.trace = trace;
        probe.prefix = format!("{mode}: ");
        let anonymous = signup(&auth, "anon@example.test").await;
        let (_, anon_token) = inbox.take();
        let owner = signup(&auth, "owner@example.test").await;
        let (_, owner_token) = inbox.take();
        let stranger = signup(&auth, "stranger@example.test").await;
        let (_, stranger_token) = inbox.take();
        let _ = probe
            .send("anonymous browser", verify(&anon_token, None, ""))
            .await;
        let _ = probe
            .send(
                "matching session",
                verify(&owner_token, Some("/done"), &cookies(&owner)),
            )
            .await;
        let _ = probe
            .send(
                "other session",
                verify(&stranger_token, None, &cookies(&anonymous)),
            )
            .await;
        let _ = stranger;
        probe
            .trace
            .value("sessions", json!(db.count("sessions").await?));
        trace = probe.trace;
        B::close(connection).await?;
    }
    trace.assert("email-verification/session-adoption");
    Ok(())
}

async fn verify_email_change_confirmation_chain<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let inbox = Arc::new(Inbox::default());
    let (verification, management) = plugins(&inbox, Duration::hours(1), false);
    let auth = fast_builder::<B>(&connection)
        .plugin(verification)
        .plugin(management)
        .build()
        .await?;
    let mut probe = Probe::new(&auth);
    let mut accounts = Vec::new();
    for email in ["mover@example.test", "other@example.test"] {
        let response = signup(&auth, email).await;
        let _ = inbox.take();
        accounts.push(cookies(&response));
    }
    _ = db
        .execute("UPDATE users SET email_verified = true", &[])
        .await?;
    for (label, callback, target) in [
        ("with callback", Some("/done"), "moved@example.test"),
        ("json", None, "second@example.test"),
    ] {
        let _ = probe
            .post(
                &format!("request change {label}"),
                "/change-email",
                &json!({"newEmail":target.to_uppercase(),"callbackURL":"/done"}).to_string(),
                &accounts[0],
            )
            .await;
        let (new_email, confirmation) = inbox.take();
        assert_eq!(new_email, target);
        let _ = probe
            .send(
                &format!("confirm {label}"),
                verify(&confirmation, callback, &accounts[0]),
            )
            .await;
        let (sent_to, verification_token) = inbox.take();
        assert_eq!(sent_to, target);
        if label == "json" {
            let _ = probe
                .send(
                    "verify as other user",
                    verify(&verification_token, None, &accounts[1]),
                )
                .await;
            let _ = probe
                .send(
                    "verify without session",
                    verify(&verification_token, None, ""),
                )
                .await;
            probe.trace.value(
                "emails",
                json!([
                    db.text("SELECT email FROM users WHERE name = 'Native owner' ORDER BY created_at LIMIT 1", &[]).await?,
                    db.count("sessions").await?
                ]),
            );
        } else {
            let _ = probe
                .send(
                    "verify with session and callback",
                    verify(&verification_token, callback, &accounts[0]),
                )
                .await;
        }
    }
    probe
        .trace
        .assert("email-verification/change-confirmation-chain");
    B::close(connection).await
}

async fn send_verification_email_matrix<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let inbox = Arc::new(Inbox::default());
    let (verification, management) = plugins(&inbox, Duration::hours(1), false);
    let auth = fast_builder::<B>(&connection)
        .plugin(verification)
        .plugin(management)
        .build()
        .await?;
    let mut probe = Probe::new(&auth);
    let owner = signup(&auth, "owner@example.test").await;
    let _ = inbox.take();
    let owner = cookies(&owner);
    for text in [
        "[]",
        "null",
        "{}",
        r#"{"email":5}"#,
        r#"{"email":"nope"}"#,
        r#"{"email":"owner@example.test","callbackURL":5}"#,
    ] {
        let _ = probe
            .post(text, "/send-verification-email", text, &owner)
            .await;
    }
    for (label, email, cookie) in [
        ("session mismatch", "someone@example.test", owner.as_str()),
        ("session match", "OWNER@example.test", owner.as_str()),
        ("anonymous unknown", "ghost@example.test", ""),
    ] {
        let _ = probe
            .post(
                label,
                "/send-verification-email",
                &json!({"email":email,"callbackURL":"/done"}).to_string(),
                cookie,
            )
            .await;
    }
    _ = db
        .execute("UPDATE users SET email_verified = true", &[])
        .await?;
    let _ = probe
        .post(
            "session already verified",
            "/send-verification-email",
            r#"{"email":"owner@example.test"}"#,
            &owner,
        )
        .await;
    probe
        .trace
        .value("deliveries", json!(inbox.0.lock().unwrap().len()));
    probe.trace.assert("email-verification/send-matrix");
    B::close(connection).await
}

async fn verification_after_hook_rejection_commits_user_without_issuing_session<B: Backend>(
    db: Db,
) -> TestResult {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let inbox = Arc::new(Inbox::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let auth = fast_builder::<B>(&connection)
        .plugin(EmailVerificationPlugin::with_config(
            EmailVerificationConfig {
                send_verification_email: Some(inbox.clone()),
                send_on_sign_up: Some(true),
                auto_sign_in_after_verification: true,
                after_email_verification: Some(Arc::new(move |user| {
                    assert!(user.email_verified);
                    let _ = observed.fetch_add(1, Ordering::SeqCst);
                    Box::pin(async {
                        Err(alibi::AuthError::Upstream {
                            status: 403,
                            code: "VERIFICATION_VETO",
                            message: "Application veto",
                        })
                    })
                })),
                ..Default::default()
            },
        ))
        .build()
        .await?;
    let owner = signup(&auth, "verification-veto-owner@example.test").await;
    let (_, token) = inbox.take();
    let foreign = signup(&auth, "verification-veto-foreign@example.test").await;
    let rows = db.tables(&["accounts", "sessions"]).await?;
    let response = call(&auth, verify(&token, None, ""), 403).await;
    assert_eq!(body(&response)["code"], "VERIFICATION_VETO");
    assert!(!response.headers.contains_key("set-cookie"));
    let users: Value = serde_json::from_str(&db.table("users").await?)?;
    let updated = users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["id"] == body(&owner)["user"]["id"])
        .unwrap();
    assert_eq!(updated["email_verified"], json!(1));
    assert_eq!(db.tables(&["accounts", "sessions"]).await?, rows);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let replay = call(&auth, verify(&token, None, ""), 200).await;
    assert_eq!(body(&replay), json!({"status":true,"user":null}));
    assert!(!replay.headers.contains_key("set-cookie"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(db.tables(&["accounts", "sessions"]).await?, rows);
    authenticated(
        &auth,
        &cookies(&owner),
        "verification-veto-owner@example.test",
    )
    .await;
    authenticated(
        &auth,
        &cookies(&foreign),
        "verification-veto-foreign@example.test",
    )
    .await;
    Ok(())
}
