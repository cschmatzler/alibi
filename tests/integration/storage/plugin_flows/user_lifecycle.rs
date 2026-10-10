//! Delivered deletion proofs and physical removal must remain owner-scoped.
use super::*;
backend_tests!(
    account_deletion_consumes_delivered_owner_proof_and_preserves_foreign_identity,
    deletion_password_rejection_preserves_delivered_body_proof,
    concurrent_deletion_replay_rejects_before_awaited_owner_hook
);
postgres_tests!(account_deletion_consumes_delivered_owner_proof_and_preserves_foreign_identity);
#[derive(Default)]
struct DeletionMailbox(Mutex<Vec<(String, String, String)>>);
#[async_trait::async_trait]
impl alibi::plugins::user_management::SendDeleteAccountVerification for DeletionMailbox {
    async fn send(
        &self,
        user: &alibi::plugins::user_management::UserInfo,
        url: &str,
        token: &str,
    ) -> alibi::AuthResult<()> {
        self.0
            .lock()
            .unwrap()
            .push((user.id.clone(), url.into(), token.into()));
        Ok(())
    }
}
async fn account_deletion_consumes_delivered_owner_proof_and_preserves_foreign_identity<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    use alibi::plugins::{UserManagementPlugin, api_key::ApiKeyPlugin};
    for mode in ["callback", "nested-token", "immediate"] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let mailbox = Arc::new(DeletionMailbox::default());
        let mut plugin = UserManagementPlugin::new().delete_user_enabled(true);
        if mode != "immediate" {
            plugin = plugin.send_delete_account_verification(mailbox.clone());
        }
        let auth = builder::<B>(&connection)
            .plugin(plugin)
            .plugin(ApiKeyPlugin::builder().build())
            .build()
            .await?;
        let owner = signup(&auth, "delete-owner@example.test").await;
        let foreign = signup(&auth, "delete-foreign@example.test").await;
        let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
        let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
        let cookie = cookies(&owner);
        let peer = call(
            &auth,
            request(
                "/sign-in/email",
                Some(json!({"email":"delete-owner@example.test","password":PASSWORD})),
                "",
            ),
            200,
        )
        .await;
        let key = call(
            &auth,
            request(
                "/api-key/create",
                Some(json!({"name":"Owner secret"})),
                &cookie,
            ),
            200,
        )
        .await;
        let other_key = call(
            &auth,
            request(
                "/api-key/create",
                Some(json!({"name":"Foreign secret"})),
                &cookies(&foreign),
            ),
            200,
        )
        .await;
        let snapshot = db
            .tables(&["users", "accounts", "sessions", "api_keys"])
            .await?;
        let _ = call(&auth, request("/delete-user", Some(json!({})), ""), 401).await;
        let _ = call(
            &auth,
            request(
                "/delete-user",
                Some(json!({"password":"wrong-password"})),
                &cookie,
            ),
            400,
        )
        .await;
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "api_keys"])
                .await?,
            snapshot
        );
        assert!(mailbox.0.lock().unwrap().is_empty());
        let response = if mode == "immediate" {
            call(
                &auth,
                request("/delete-user", Some(json!({"password":PASSWORD})), &cookie),
                200,
            )
            .await
        } else {
            let deliver = || {
                request(
                    "/delete-user",
                    Some(json!({"callbackURL":format!("{ORIGIN}/gone")})),
                    &cookie,
                )
            };
            let pending = call(&auth, deliver(), 200).await;
            assert_eq!(body(&pending)["message"], "Verification email sent");
            assert_eq!(
                db.tables(&["users", "accounts", "sessions", "api_keys"])
                    .await?,
                snapshot
            );
            let (recipient, url, token) = mailbox.0.lock().unwrap().pop().unwrap();
            assert_eq!(recipient, owner_id);
            let delivered = url::Url::parse(&url)?;
            assert_eq!(delivered.path(), "/api/auth/delete-user/callback");
            assert!(
                delivered
                    .query_pairs()
                    .any(|(key, value)| key == "token" && value == token)
            );
            let mut callback = request("/delete-user/callback", None, &cookies(&foreign));
            callback.query = delivered.query_pairs().into_owned().collect();
            let _ = call(&auth, callback.clone(), 404).await;
            assert_eq!(
                db.tables(&["users", "accounts", "sessions", "api_keys"])
                    .await?,
                snapshot
            );
            assert_eq!(
                db.count("verifications").await?,
                0,
                "a mismatched owner consumes the delivered proof without deleting anyone"
            );
            drop(callback.headers.insert("cookie".into(), cookie.clone()));
            let _ = call(&auth, callback, 404).await;
            let _ = call(&auth, deliver(), 200).await;
            let (recipient, url, token) = mailbox.0.lock().unwrap().pop().unwrap();
            assert_eq!(recipient, owner_id);
            if mode == "nested-token" {
                let response = call(
                    &auth,
                    request("/delete-user", Some(json!({"token":token})), &cookie),
                    200,
                )
                .await;
                assert!(
                    response.headers.get("set-cookie").is_none(),
                    "nested token path drops callback cookie headers"
                );
                response
            } else {
                let delivered = url::Url::parse(&url)?;
                let mut callback = request("/delete-user/callback", None, &cookie);
                callback.query = delivered.query_pairs().into_owned().collect();
                let response = call(&auth, callback.clone(), 302).await;
                assert_eq!(
                    response.headers.get("location").map(String::as_str),
                    Some(format!("{ORIGIN}/gone").as_str())
                );
                drop(callback.headers.insert("cookie".into(), cookies(&foreign)));
                let remaining = db
                    .tables(&["users", "accounts", "sessions", "api_keys"])
                    .await?;
                let _ = call(&auth, callback, 404).await;
                assert_eq!(
                    db.tables(&["users", "accounts", "sessions", "api_keys"])
                        .await?,
                    remaining
                );
                response
            }
        };
        if mode != "nested-token" {
            assert!(response.headers.get_all("set-cookie").any(|cookie|cookie.contains("session_token=") && cookie.contains("Max-Age=0")));
        }
        for (table, column) in [
            ("users", "id"),
            ("accounts", "user_id"),
            ("sessions", "user_id"),
            ("api_keys", "reference_id"),
        ] {
            assert_eq!(
                db.count_where(
                    &format!("SELECT COUNT(*) FROM {table} WHERE {column}=$1"),
                    &[&owner_id]
                )
                .await?,
                i64::from(table == "api_keys"),
                "{mode}/{table}"
            );
            assert_eq!(
                db.count_where(
                    &format!("SELECT COUNT(*) FROM {table} WHERE {column}=$1"),
                    &[&foreign_id]
                )
                .await?,
                1,
                "{mode}/{table}"
            );
        }
        assert_eq!(db.count("verifications").await?, 0);
        assert!(
            auth.store()
                .get_api_key_by_id(body(&key)["id"].as_str().unwrap())
                .await?
                .is_some()
        );
        assert!(
            auth.store()
                .get_api_key_by_id(body(&other_key)["id"].as_str().unwrap())
                .await?
                .is_some()
        );
        for response in [&owner, &peer] {
            assert!(
                body(
                    &call(
                        &auth,
                        request("/get-session", None, &cookies(response)),
                        200
                    )
                    .await
                )
                .is_null()
            );
        }
        authenticated(&auth, &cookies(&foreign), "delete-foreign@example.test").await;
        B::close(connection).await?;
    }
    Ok(())
}

async fn deletion_password_rejection_preserves_delivered_body_proof<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::plugins::user_management::{AfterDeleteUser, BeforeDeleteUser, UserInfo};
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[derive(Default)]
    struct Hooks {
        before: AtomicUsize,
        after: AtomicUsize,
    }
    #[async_trait::async_trait]
    impl BeforeDeleteUser for Hooks {
        async fn before_delete(&self, _: &UserInfo) -> alibi::AuthResult<()> {
            let _ = self.before.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    #[async_trait::async_trait]
    impl AfterDeleteUser for Hooks {
        async fn after_delete(&self, _: &UserInfo) -> alibi::AuthResult<()> {
            let _ = self.after.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    let hooks = Arc::new(Hooks::default());
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mailbox = Arc::new(DeletionMailbox::default());
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(
            alibi::plugins::UserManagementPlugin::new()
                .delete_user_enabled(true)
                .send_delete_account_verification(mailbox.clone())
                .before_delete(hooks.clone())
                .after_delete(hooks.clone()),
        )
        .build()
        .await?;
    let owner = signup(&auth, "delete-password-owner@example.test").await;
    let foreign = signup(&auth, "delete-password-foreign@example.test").await;
    let cookie = cookies(&owner);
    let _ = call(
        &auth,
        request(
            "/delete-user",
            Some(json!({"callbackURL":"/gone"})),
            &cookie,
        ),
        200,
    )
    .await;
    let (_, _, token) = mailbox.0.lock().unwrap().pop().unwrap();
    let before = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    for (password, code) in [
        ("wrong-password".to_owned(), "INVALID_PASSWORD"),
        ("x".repeat(129), "PASSWORD_TOO_LONG"),
    ] {
        let rejected = call(
            &auth,
            request(
                "/delete-user",
                Some(json!({"password":password,"token":token})),
                &cookie,
            ),
            400,
        )
        .await;
        assert_eq!(body(&rejected)["code"], code);
        assert_eq!(hooks.before.load(Ordering::SeqCst), 0);
        assert_eq!(hooks.after.load(Ordering::SeqCst), 0);
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "verifications"])
                .await?,
            before
        );
        assert!(!rejected.headers.contains_key("set-cookie"));
    }
    let deleted = call(
        &auth,
        request(
            "/delete-user",
            Some(json!({"password":PASSWORD,"token":token})),
            &cookie,
        ),
        200,
    )
    .await;
    assert!(!deleted.headers.contains_key("set-cookie"));
    assert_eq!(hooks.before.load(Ordering::SeqCst), 1);
    assert_eq!(hooks.after.load(Ordering::SeqCst), 1);
    assert_eq!(db.count("verifications").await?, 0);
    assert_eq!(db.count("users").await?, 1);
    assert_eq!(db.count("accounts").await?, 1);
    assert_eq!(db.count("sessions").await?, 1);
    assert_eq!(
        db.text("SELECT id FROM users", &[]).await?.as_deref(),
        body(&foreign)["user"]["id"].as_str()
    );
    authenticated(
        &auth,
        &cookies(&foreign),
        "delete-password-foreign@example.test",
    )
    .await;
    Ok(())
}

async fn concurrent_deletion_replay_rejects_before_awaited_owner_hook<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::plugins::user_management::{AfterDeleteUser, BeforeDeleteUser, UserInfo};
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Gate {
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
        before: AtomicUsize,
        after: AtomicUsize,
    }
    #[async_trait::async_trait]
    impl BeforeDeleteUser for Gate {
        async fn before_delete(&self, _: &UserInfo) -> alibi::AuthResult<()> {
            let _ = self.before.fetch_add(1, Ordering::SeqCst);
            self.entered.notify_one();
            self.release.notified().await;
            Ok(())
        }
    }
    #[async_trait::async_trait]
    impl AfterDeleteUser for Gate {
        async fn after_delete(&self, _: &UserInfo) -> alibi::AuthResult<()> {
            let _ = self.after.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mailbox = Arc::new(DeletionMailbox::default());
    let gate = Arc::new(Gate {
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
        before: 0.into(),
        after: 0.into(),
    });
    let auth = Arc::new(
        super::auth_probe::fast_builder::<B>(&connection)
            .plugin(
                alibi::plugins::UserManagementPlugin::new()
                    .delete_user_enabled(true)
                    .send_delete_account_verification(mailbox.clone())
                    .before_delete(gate.clone())
                    .after_delete(gate.clone()),
            )
            .build()
            .await?,
    );
    let owner = signup(&auth, "delete-race-owner@example.test").await;
    let foreign = signup(&auth, "delete-race-foreign@example.test").await;
    let cookie = cookies(&owner);
    let _ = call(
        &auth,
        request(
            "/delete-user",
            Some(json!({"callbackURL":"/gone"})),
            &cookie,
        ),
        200,
    )
    .await;
    let (_, _, token) = mailbox.0.lock().unwrap().pop().unwrap();
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    let callback = |token: &str| {
        let mut input = request("/delete-user/callback", None, &cookie);
        let _ = input.query.insert("token".into(), token.into());
        input
    };
    let input = callback(&token);
    let worker = auth.clone();
    let first = tokio::spawn(async move { call(&worker, input, 200).await });
    tokio::time::timeout(std::time::Duration::from_secs(2), gate.entered.notified()).await?;
    assert_eq!(db.count("verifications").await?, 0);
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    let replay = call(&auth, callback(&token), 404).await;
    assert_eq!(body(&replay)["code"], "INVALID_TOKEN");
    assert_eq!(gate.before.load(Ordering::SeqCst), 1);
    assert_eq!(gate.after.load(Ordering::SeqCst), 0);
    gate.release.notify_one();
    let _ = first.await?;
    assert_eq!(gate.before.load(Ordering::SeqCst), 1);
    assert_eq!(gate.after.load(Ordering::SeqCst), 1);
    assert_eq!(db.count("users").await?, 1);
    assert_eq!(db.count("accounts").await?, 1);
    assert_eq!(db.count("sessions").await?, 1);
    assert_eq!(
        db.text("SELECT id FROM users", &[]).await?.as_deref(),
        body(&foreign)["user"]["id"].as_str()
    );
    authenticated(
        &auth,
        &cookies(&foreign),
        "delete-race-foreign@example.test",
    )
    .await;
    Ok(())
}
