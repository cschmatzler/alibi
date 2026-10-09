//! Password reset, change and verification input handling and persisted effects.
use super::auth_probe::{FastHasher, Probe, fast_builder};
use super::*;
use alibi::plugins::PasswordManagementPlugin;
use alibi::plugins::password_management::{PasswordManagementConfig, SendResetPassword};
use alibi_core::{AuthError, AuthResult};
use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, Ordering};

backend_tests!(
    password_reset_token_matrix,
    change_and_verify_password_matrix
);

#[derive(Default)]
struct Mailbox(Mutex<Vec<(String, String)>>);
#[async_trait]
impl SendResetPassword for Mailbox {
    async fn send(&self, _: &Value, url: &str, token: &str) -> AuthResult<()> {
        self.0
            .lock()
            .unwrap()
            .push((url.to_owned(), token.to_owned()));
        Ok(())
    }
}

type HookFuture = std::pin::Pin<Box<dyn std::future::Future<Output = AuthResult<()>> + Send>>;

fn management(
    mailbox: &Arc<Mailbox>,
    refuse: &Arc<AtomicBool>,
    revoke: bool,
    require_current: bool,
) -> PasswordManagementPlugin {
    let refuse = refuse.clone();
    PasswordManagementPlugin::with_config(PasswordManagementConfig {
        send_reset_password: Some(mailbox.clone()),
        revoke_sessions_on_password_reset: revoke,
        require_current_password: require_current,
        password_hasher: Some(Arc::new(FastHasher)),
        on_password_reset: Some(Arc::new(move |_: Value| -> HookFuture {
            let refuse = refuse.load(Ordering::SeqCst);
            Box::pin(async move {
                if refuse {
                    Err(AuthError::forbidden("reset observed"))
                } else {
                    Ok(())
                }
            })
        })),
        ..Default::default()
    })
}

fn get(path: &str, query: &[(&str, &str)]) -> AuthRequest {
    let mut input = request(path, None, "");
    for (key, value) in query {
        _ = input.query.insert((*key).into(), (*value).into());
    }
    input
}

async fn password_reset_token_matrix<B: Backend>(db: Db) -> TestResult {
    let mut trace = crate::snapshot::Trace::default();
    for revoke in [false, true] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let mailbox = Arc::new(Mailbox::default());
        let refuse = Arc::new(AtomicBool::new(false));
        let auth = fast_builder::<B>(&connection)
            .plugin(management(&mailbox, &refuse, revoke, true))
            .build()
            .await?;
        let mut probe = Probe::new(&auth);
        probe.trace = trace;
        probe.prefix = format!("revoke={revoke}: ");
        let owner = cookies(&signup(&auth, "owner@example.test").await);
        let _ = signup(&auth, "doomed@example.test").await;
        for text in [
            "[]",
            "null",
            "{}",
            r#"{"email":5}"#,
            r#"{"email":"nope"}"#,
            r#"{"email":"ghost@example.test","redirectTo":"/reset"}"#,
            r#"{"email":"owner@example.test","redirectTo":"/reset?a=1&b=2"}"#,
        ] {
            let _ = probe.post(text, "/request-password-reset", text, "").await;
        }
        let (url, token) = mailbox.0.lock().unwrap().pop().unwrap();
        probe
            .trace
            .value("delivered url", json!(url.replace(&token, "<token>")));
        for (label, path, query) in [
            (
                "no token segment",
                "/reset-password/".to_owned(),
                vec![("callbackURL", "/reset")],
            ),
            ("no callback", format!("/reset-password/{token}"), vec![]),
            (
                "untrusted callback",
                format!("/reset-password/{token}"),
                vec![("callbackURL", "https://evil.example")],
            ),
            (
                "unknown token",
                "/reset-password/unknown".to_owned(),
                vec![("callbackURL", "/reset")],
            ),
            (
                "valid token",
                format!("/reset-password/{token}"),
                vec![("callbackURL", "/reset")],
            ),
            (
                "valid token with query",
                format!("/reset-password/{token}"),
                vec![("callbackURL", "/reset?token=old&x=1&token=dup")],
            ),
            (
                "absolute callback",
                format!("/reset-password/{token}"),
                vec![("callbackURL", "http://localhost:43219/reset#frag")],
            ),
        ] {
            let _ = probe.send(label, get(&path, &query)).await;
        }
        for text in [
            "[]",
            r#"{"newPassword":5}"#,
            r#"{"newPassword":"a-brand-new-password"}"#,
            r#"{"newPassword":"short","token":"x"}"#,
            r#"{"newPassword":"a-brand-new-password","token":"unknown"}"#,
        ] {
            let _ = probe.post(text, "/reset-password", text, "").await;
        }
        let _ = probe
            .post(
                "request second token",
                "/request-password-reset",
                r#"{"email":"owner@example.test"}"#,
                "",
            )
            .await;
        let (_, second) = mailbox.0.lock().unwrap().pop().unwrap();
        refuse.store(true, Ordering::SeqCst);
        let _ = probe
            .post(
                "hook refuses",
                "/reset-password",
                &json!({"newPassword":"a-brand-new-password","token":second}).to_string(),
                "",
            )
            .await;
        refuse.store(false, Ordering::SeqCst);
        let mut query_only = raw_reset("a-brand-new-password");
        _ = query_only.query.insert("token".into(), token.clone());
        let _ = probe.send("token from query", query_only).await;
        let _ = probe
            .post(
                "token already consumed",
                "/reset-password",
                &json!({"newPassword":"a-brand-new-password","token":token}).to_string(),
                "",
            )
            .await;
        _ = db
            .execute("DELETE FROM accounts WHERE provider_id = 'credential' AND user_id IN (SELECT id FROM users WHERE email = 'doomed@example.test')", &[])
            .await?;
        let _ = probe
            .post(
                "request for credentialless user",
                "/request-password-reset",
                r#"{"email":"doomed@example.test"}"#,
                "",
            )
            .await;
        let (_, token) = mailbox.0.lock().unwrap().pop().unwrap();
        _ = db
            .execute("UPDATE verifications SET value = 'missing-user'", &[])
            .await?;
        let _ = probe
            .post(
                "owner missing",
                "/reset-password",
                &json!({"newPassword":"a-brand-new-password","token":token}).to_string(),
                "",
            )
            .await;
        let after = body(&call(&auth, request("/get-session", None, &owner), 200).await);
        probe
            .trace
            .value("owner session kept", json!(!after.is_null()));
        trace = probe.trace;
        B::close(connection).await?;
    }
    trace.assert("password-management/reset-token-matrix");
    Ok(())
}

fn raw_reset(password: &str) -> AuthRequest {
    super::auth_probe::raw(
        "/reset-password",
        &json!({"newPassword":password}).to_string(),
        "",
    )
}

async fn change_and_verify_password_matrix<B: Backend>(db: Db) -> TestResult {
    let mut trace = crate::snapshot::Trace::default();
    for (mode, require_current) in [("current required", true), ("current optional", false)] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let mailbox = Arc::new(Mailbox::default());
        let auth = fast_builder::<B>(&connection)
            .plugin(management(
                &mailbox,
                &Arc::default(),
                false,
                require_current,
            ))
            .build()
            .await?;
        let mut probe = Probe::new(&auth);
        probe.trace = trace;
        probe.prefix = format!("{mode}: ");
        let owner = cookies(&signup(&auth, "owner@example.test").await);
        let remember = format!(
            "better-auth.dont_remember={}",
            alibi_core::utils::cookie_utils::sign_cookie_value("true", SECRET)
        );
        let _ = probe
            .post(
                "change anonymous",
                "/change-password",
                r#"{"currentPassword":"x","newPassword":"a-brand-new-password"}"#,
                "",
            )
            .await;
        for text in [
            "[]",
            r#"{"newPassword":5}"#,
            r#"{"newPassword":"short","currentPassword":"a-native-password-123"}"#,
            r#"{"newPassword":"a-brand-new-password","currentPassword":"wrong-password-1"}"#,
        ] {
            let _ = probe.post(text, "/change-password", text, &owner).await;
        }
        let _ = probe
            .post(
                "change keeping sessions",
                "/change-password",
                &json!({"newPassword":"a-second-password-1","currentPassword":PASSWORD})
                    .to_string(),
                &owner,
            )
            .await;
        let current = if require_current {
            "a-second-password-1"
        } else {
            "ignored"
        };
        let revoked = probe
            .post(
                "change revoking sessions",
                "/change-password",
                &json!({"newPassword":"a-third-password-123","currentPassword":current,"revokeOtherSessions":true}).to_string(),
                &owner,
            )
            .await;
        let _ = probe
            .post(
                "change revoking with dont-remember",
                "/change-password",
                &json!({"newPassword":"a-fourth-password-12","currentPassword":"a-third-password-123","revokeOtherSessions":true}).to_string(),
                &format!("{}; {remember}", cookies(&revoked)),
            )
            .await;
        let fresh = {
            let response = probe
                .post(
                    "sign in with last password",
                    "/sign-in/email",
                    &json!({"email":"owner@example.test","password":"a-fourth-password-12"})
                        .to_string(),
                    "",
                )
                .await;
            cookies(&response)
        };
        let _ = probe
            .post(
                "verify anonymous",
                "/verify-password",
                r#"{"password":"x"}"#,
                "",
            )
            .await;
        for (label, password) in [
            ("verify too long", "p".repeat(200)),
            ("verify wrong", "wrong-password-1".to_owned()),
            ("verify right", "a-fourth-password-12".to_owned()),
        ] {
            let _ = probe
                .post(
                    label,
                    "/verify-password",
                    &json!({"password":password}).to_string(),
                    &fresh,
                )
                .await;
        }
        _ = db
            .execute("DELETE FROM accounts WHERE provider_id = 'credential'", &[])
            .await?;
        let _ = probe
            .post(
                "verify without credential",
                "/verify-password",
                r#"{"password":"a-fourth-password-12"}"#,
                &fresh,
            )
            .await;
        let _ = probe
            .post(
                "change without credential",
                "/change-password",
                r#"{"newPassword":"a-fifth-password-123","currentPassword":"a-fourth-password-12"}"#,
                &fresh,
            )
            .await;
        trace = probe.trace;
        B::close(connection).await?;
    }
    trace.assert("password-management/change-and-verify-matrix");
    Ok(())
}
