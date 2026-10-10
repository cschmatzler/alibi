//! Password reset, change and verification input handling and persisted effects.
use super::auth_probe::{FastHasher, Probe, fast_builder};
use super::*;
use alibi::plugins::PasswordManagementPlugin;
use alibi::plugins::password_management::{PasswordManagementConfig, SendResetPassword};
use alibi::{AuthError, AuthResult};
use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, Ordering};

backend_tests!(
    password_reset_token_matrix,
    change_and_verify_password_matrix,
    disabled_reset_rejects_before_lookup_without_changing_principals,
    reset_callback_failure_keeps_new_password_and_existing_sessions,
    expired_delivered_reset_redirect_replaces_error_and_preserves_fragment,
    change_password_invalid_revocation_flag_never_runs_crypto,
    reset_hash_failure_consumes_proof_without_changing_credentials
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
            alibi::utils::cookie_utils::sign_cookie_value("true", SECRET)
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

async fn disabled_reset_rejects_before_lookup_without_changing_principals<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = fast_builder::<B>(&connection)
        .plugin(PasswordManagementPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "disabled-owner@example.test").await;
    let foreign = signup(&auth, "disabled-foreign@example.test").await;
    let before = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    let _ = db
        .execute(
            "ALTER TABLE users RENAME TO temporarily_unavailable_users",
            &[],
        )
        .await?;
    for email in ["disabled-owner@example.test", "missing@example.test"] {
        let rejected = call(
            &auth,
            request(
                "/request-password-reset",
                Some(json!({"email":email,"redirectTo":"/reset"})),
                "",
            ),
            400,
        )
        .await;
        assert_eq!(body(&rejected)["code"], "RESET_PASSWORD_DISABLED");
        assert!(!rejected.headers.contains_key("set-cookie"));
        assert_eq!(db.count("verifications").await?, 0);
    }
    let _ = db
        .execute(
            "ALTER TABLE temporarily_unavailable_users RENAME TO users",
            &[],
        )
        .await?;
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "verifications"])
            .await?,
        before
    );
    authenticated(&auth, &cookies(&owner), "disabled-owner@example.test").await;
    authenticated(&auth, &cookies(&foreign), "disabled-foreign@example.test").await;
    let mailbox = Arc::new(Mailbox::default());
    let enabled = fast_builder::<B>(&connection)
        .plugin(management(
            &mailbox,
            &Arc::new(AtomicBool::new(false)),
            false,
            true,
        ))
        .build()
        .await?;
    let _ = call(
        &enabled,
        request(
            "/request-password-reset",
            Some(json!({"email":"disabled-owner@example.test"})),
            "",
        ),
        200,
    )
    .await;
    let (_, token) = mailbox.0.lock().unwrap().pop().unwrap();
    let _ = call(
        &enabled,
        request(
            "/reset-password",
            Some(json!({"token":token,"newPassword":"enabled-new-password"})),
            "",
        ),
        200,
    )
    .await;
    let login = call(
        &enabled,
        request(
            "/sign-in/email",
            Some(json!({"email":"disabled-owner@example.test","password":"enabled-new-password"})),
            "",
        ),
        200,
    )
    .await;
    assert_eq!(body(&login)["user"]["id"], body(&owner)["user"]["id"]);
    Ok(())
}

async fn reset_callback_failure_keeps_new_password_and_existing_sessions<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mailbox = Arc::new(Mailbox::default());
    let refuse = Arc::new(AtomicBool::new(true));
    let auth = fast_builder::<B>(&connection)
        .plugin(management(&mailbox, &refuse, true, true))
        .build()
        .await?;
    let owner = signup(&auth, "reset-callback-owner@example.test").await;
    let foreign = signup(&auth, "reset-callback-foreign@example.test").await;
    let _ = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"reset-callback-owner@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    let _ = call(
        &auth,
        request(
            "/request-password-reset",
            Some(json!({"email":"reset-callback-owner@example.test"})),
            "",
        ),
        200,
    )
    .await;
    let (_, token) = mailbox.0.lock().unwrap().pop().unwrap();
    let before = db.tables(&["users", "sessions"]).await?;
    let response = call(
        &auth,
        request(
            "/reset-password",
            Some(json!({"token":token,"newPassword":"durable-new-password"})),
            "",
        ),
        403,
    )
    .await;
    assert!(!response.headers.contains_key("set-cookie"));
    assert_eq!(db.tables(&["users", "sessions"]).await?, before);
    assert_eq!(db.count("verifications").await?, 0);
    assert_eq!(
        db.text(
            "SELECT password FROM accounts WHERE user_id = $1",
            &[body(&owner)["user"]["id"].as_str().unwrap()]
        )
        .await?
        .as_deref(),
        Some("fast$durable-new-password")
    );
    let replay = call(
        &auth,
        request(
            "/reset-password",
            Some(json!({"token":token,"newPassword":"another-new-password"})),
            "",
        ),
        400,
    )
    .await;
    assert_eq!(body(&replay)["code"], "INVALID_TOKEN");
    authenticated(&auth, &cookies(&owner), "reset-callback-owner@example.test").await;
    authenticated(
        &auth,
        &cookies(&foreign),
        "reset-callback-foreign@example.test",
    )
    .await;
    let _ = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"reset-callback-owner@example.test","password":PASSWORD})),
            "",
        ),
        401,
    )
    .await;
    let login = call(&auth, request("/sign-in/email", Some(json!({"email":"reset-callback-owner@example.test","password":"durable-new-password"})), ""), 200).await;
    assert_eq!(body(&login)["user"]["id"], body(&owner)["user"]["id"]);
    Ok(())
}

async fn expired_delivered_reset_redirect_replaces_error_and_preserves_fragment<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mailbox = Arc::new(Mailbox::default());
    let auth = fast_builder::<B>(&connection)
        .plugin(management(
            &mailbox,
            &Arc::new(AtomicBool::new(false)),
            false,
            true,
        ))
        .build()
        .await?;
    let owner = signup(&auth, "expired-reset-owner@example.test").await;
    let foreign = signup(&auth, "expired-reset-foreign@example.test").await;
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    let callback = "/done?error=old&keep=a%2Bb#details";
    let _ = call(
        &auth,
        request(
            "/request-password-reset",
            Some(json!({"email":"expired-reset-owner@example.test","redirectTo":callback})),
            "",
        ),
        200,
    )
    .await;
    let (url, token) = mailbox.0.lock().unwrap().pop().unwrap();
    let identifier = format!("reset-password:{token}");
    db.set_timestamp(
        "verifications",
        "expires_at",
        ("identifier", &identifier),
        chrono::Utc::now() - chrono::Duration::hours(1),
    )
    .await?;
    let delivered = url::Url::parse(&url)?;
    let mut input = AuthRequest::new(HttpMethod::Get, delivered.path());
    input.query.extend(
        delivered
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned())),
    );
    let rejected = call(&auth, input, 302).await;
    let mut expected = url::Url::parse(ORIGIN)?.join(callback)?;
    expected.set_query(Some("error=INVALID_TOKEN&keep=a%2Bb"));
    assert_eq!(
        rejected.headers.get("location").map(String::as_str),
        Some(expected.as_str())
    );
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    authenticated(&auth, &cookies(&owner), "expired-reset-owner@example.test").await;
    authenticated(
        &auth,
        &cookies(&foreign),
        "expired-reset-foreign@example.test",
    )
    .await;
    let _ = call(
        &auth,
        request(
            "/request-password-reset",
            Some(json!({"email":"expired-reset-owner@example.test"})),
            "",
        ),
        200,
    )
    .await;
    let (_, fresh) = mailbox.0.lock().unwrap().pop().unwrap();
    let _ = call(
        &auth,
        request(
            "/reset-password",
            Some(json!({"token":fresh,"newPassword":"fresh-reset-password"})),
            "",
        ),
        200,
    )
    .await;
    Ok(())
}

async fn change_password_invalid_revocation_flag_never_runs_crypto<B: Backend>(
    db: Db,
) -> TestResult {
    struct CountingHasher {
        hashes: std::sync::atomic::AtomicUsize,
        verifies: std::sync::atomic::AtomicUsize,
        fail: AtomicBool,
    }
    #[async_trait]
    impl alibi::PasswordHasher for CountingHasher {
        async fn hash(&self, password: &str) -> AuthResult<String> {
            let _ = self.hashes.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                return Err(AuthError::internal("application hasher rejected"));
            }
            Ok(format!("fast${password}"))
        }
        async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
            let _ = self.verifies.fetch_add(1, Ordering::SeqCst);
            Ok(hash == format!("fast${password}"))
        }
    }
    let hasher = Arc::new(CountingHasher {
        hashes: 0.into(),
        verifies: 0.into(),
        fail: AtomicBool::new(false),
    });
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);

    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new().password_hasher(hasher.clone()))
        .plugin(SessionManagementPlugin::new())
        .plugin(PasswordManagementPlugin::with_config(
            PasswordManagementConfig {
                password_hasher: Some(hasher.clone()),
                ..Default::default()
            },
        ))
        .build()
        .await?;
    let owner = signup(&auth, "schema-owner@example.test").await;
    let foreign = signup(&auth, "schema-foreign@example.test").await;
    let _ = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"schema-owner@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    hasher.hashes.store(0, Ordering::SeqCst);
    hasher.verifies.store(0, Ordering::SeqCst);
    let before = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    for flag in [json!("true"), json!("false"), Value::Null, json!(1)] {
        let rejected = call(&auth, request("/change-password", Some(json!({"currentPassword":PASSWORD,"newPassword":"schema-new-password","revokeOtherSessions":flag})), &cookies(&owner)), 400).await;
        assert!(!rejected.headers.contains_key("set-cookie"));
        assert_eq!(hasher.hashes.load(Ordering::SeqCst), 0);
        assert_eq!(hasher.verifies.load(Ordering::SeqCst), 0);
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "verifications"])
                .await?,
            before
        );
    }
    let _ = call(&auth, request("/change-password", Some(json!({"currentPassword":PASSWORD,"newPassword":"schema-new-password","revokeOtherSessions":false})), &cookies(&owner)), 200).await;
    assert_eq!(hasher.hashes.load(Ordering::SeqCst), 1);
    assert_eq!(hasher.verifies.load(Ordering::SeqCst), 1);
    assert_eq!(db.count("sessions").await?, 3);
    assert_eq!(
        db.text(
            "SELECT password FROM accounts WHERE user_id = $1",
            &[body(&owner)["user"]["id"].as_str().unwrap()]
        )
        .await?
        .as_deref(),
        Some("fast$schema-new-password")
    );
    authenticated(&auth, &cookies(&foreign), "schema-foreign@example.test").await;
    Ok(())
}

async fn reset_hash_failure_consumes_proof_without_changing_credentials<B: Backend>(
    db: Db,
) -> TestResult {
    struct CountingHasher {
        hashes: std::sync::atomic::AtomicUsize,
        verifies: std::sync::atomic::AtomicUsize,
        fail: AtomicBool,
    }
    #[async_trait]
    impl alibi::PasswordHasher for CountingHasher {
        async fn hash(&self, password: &str) -> AuthResult<String> {
            let _ = self.hashes.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                return Err(AuthError::internal("application hasher rejected"));
            }
            Ok(format!("fast${password}"))
        }
        async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
            let _ = self.verifies.fetch_add(1, Ordering::SeqCst);
            Ok(hash == format!("fast${password}"))
        }
    }
    let hasher = Arc::new(CountingHasher {
        hashes: 0.into(),
        verifies: 0.into(),
        fail: AtomicBool::new(false),
    });
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);

    let mailbox = Arc::new(Mailbox::default());
    let callbacks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = callbacks.clone();
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new().password_hasher(hasher.clone()))
        .plugin(SessionManagementPlugin::new())
        .plugin(PasswordManagementPlugin::with_config(
            PasswordManagementConfig {
                send_reset_password: Some(mailbox.clone()),
                revoke_sessions_on_password_reset: true,
                on_password_reset: Some(Arc::new(move |_| {
                    let _ = observed.fetch_add(1, Ordering::SeqCst);
                    Box::pin(async { Ok(()) })
                })),
                ..Default::default()
            },
        ))
        .build()
        .await?;
    let owner = signup(&auth, "hash-failure-owner@example.test").await;
    let foreign = signup(&auth, "hash-failure-foreign@example.test").await;
    let _ = call(
        &auth,
        request(
            "/request-password-reset",
            Some(json!({"email":"hash-failure-owner@example.test"})),
            "",
        ),
        200,
    )
    .await;
    let (_, token) = mailbox.0.lock().unwrap().pop().unwrap();
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    hasher.hashes.store(0, Ordering::SeqCst);
    hasher.fail.store(true, Ordering::SeqCst);
    let failed = call(
        &auth,
        request(
            "/reset-password",
            Some(json!({"token":token,"newPassword":"hash-failure-replacement"})),
            "",
        ),
        500,
    )
    .await;
    assert!(!failed.headers.contains_key("set-cookie"));
    assert_eq!(hasher.hashes.load(Ordering::SeqCst), 1);
    assert_eq!(callbacks.load(Ordering::SeqCst), 0);
    assert_eq!(db.count("verifications").await?, 0);
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    let replay = call(
        &auth,
        request(
            "/reset-password",
            Some(json!({"token":token,"newPassword":"hash-failure-replacement"})),
            "",
        ),
        400,
    )
    .await;
    assert_eq!(body(&replay)["code"], "INVALID_TOKEN");
    assert_eq!(hasher.hashes.load(Ordering::SeqCst), 1);
    hasher.fail.store(false, Ordering::SeqCst);
    let login = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"hash-failure-owner@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    assert_eq!(body(&login)["user"]["id"], body(&owner)["user"]["id"]);
    authenticated(&auth, &cookies(&owner), "hash-failure-owner@example.test").await;
    authenticated(
        &auth,
        &cookies(&foreign),
        "hash-failure-foreign@example.test",
    )
    .await;
    Ok(())
}
