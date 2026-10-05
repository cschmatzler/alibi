//! Public account/session operations must scope both reads and writes to the caller.
use super::*;
use better_auth::plugins::AccountManagementPlugin;
use better_auth_core::{CreateAccount, entity::AuthAccount};
use std::collections::BTreeSet;

backend_tests!(
    account_listing_and_unlinking_preserve_other_owners,
    session_listing_and_revocation_preserve_other_owners
);
postgres_tests!(
    account_listing_and_unlinking_preserve_other_owners,
    session_listing_and_revocation_preserve_other_owners
);

async fn account_listing_and_unlinking_preserve_other_owners<B: Backend>(db: Db) -> TestResult {
    for allow_all in [false, true] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
        config.account.account_linking.allow_unlinking_all = allow_all;
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .plugin(EmailPasswordPlugin::new())
            .plugin(SessionManagementPlugin::new())
            .plugin(AccountManagementPlugin::new())
            .build()
            .await?;
        let owner = signup(&auth, "account-owner@example.test").await;
        let foreign = signup(&auth, "account-foreign@example.test").await;
        let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
        let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
        let cookie = cookies(&owner);
        let mut inserted = Vec::new();
        for user in [&owner_id, &foreign_id] {
            let account = auth
                .store()
                .create_account(CreateAccount {
                    user_id: user.clone(),
                    account_id: format!("remote-{user}"),
                    provider_id: "google".into(),
                    access_token: Some("private-access".into()),
                    refresh_token: Some("private-refresh".into()),
                    id_token: Some("private-id-token".into()),
                    password: Some("private-password".into()),
                    scope: Some(" email profile, , offline_access ,email ".into()),
                    access_token_expires_at: None,
                    refresh_token_expires_at: None,
                    additional_fields: Default::default(),
                })
                .await?;
            inserted.push(account.id().to_string());
        }
        let original = db.tables(&["users", "accounts", "sessions"]).await?;
        let _ = call(&auth, request("/list-accounts", None, ""), 401).await;
        let listed = call(&auth, request("/list-accounts", None, &cookie), 200).await;
        let listed = body(&listed);
        let accounts = listed.as_array().unwrap();
        assert_eq!(accounts.len(), 2);
        assert!(accounts.iter().all(|account| account["userId"] == owner_id));
        let social = accounts
            .iter()
            .find(|account| account["id"] == inserted[0])
            .unwrap();
        assert_eq!(social["accountId"], format!("remote-{owner_id}"));
        assert_eq!(
            social["scopes"],
            json!(["email profile", "offline_access", "email"])
        );
        for account in accounts {
            for secret in ["accessToken", "refreshToken", "idToken", "password"] {
                assert!(account.get(secret).is_none(), "list leaked {secret}");
            }
        }
        // There are TWO caller-owned accounts, so the last-account guard cannot
        // accidentally supply this foreign-account denial.
        let denied = call(
            &auth,
            request(
                "/unlink-account",
                Some(json!({"accountId":inserted[1]})),
                &cookie,
            ),
            400,
        )
        .await;
        assert_eq!(body(&denied)["message"], "Account not found");
        let _ = call(
            &auth,
            request(
                "/unlink-account",
                Some(json!({"accountId":inserted[0]})),
                "",
            ),
            401,
        )
        .await;
        assert_eq!(
            db.tables(&["users", "accounts", "sessions"]).await?,
            original
        );
        let removed = call(
            &auth,
            request(
                "/unlink-account",
                Some(json!({"accountId":inserted[0]})),
                &cookie,
            ),
            200,
        )
        .await;
        assert_eq!(body(&removed)["status"], true);
        assert_eq!(
            db.count_where("SELECT COUNT(*) FROM accounts WHERE id=$1", &[&inserted[0]])
                .await?,
            0
        );
        let foreign_before = db.table("accounts").await?;
        let credential = accounts
            .iter()
            .find(|account| account["providerId"] == "credential")
            .unwrap()["id"]
            .as_str()
            .unwrap();
        let result = call(
            &auth,
            request(
                "/unlink-account",
                Some(json!({"accountId":credential})),
                &cookie,
            ),
            if allow_all { 200 } else { 400 },
        )
        .await;
        if allow_all {
            assert_eq!(body(&result)["status"], true);
            assert_eq!(
                db.count_where(
                    "SELECT COUNT(*) FROM accounts WHERE user_id=$1",
                    &[&owner_id]
                )
                .await?,
                0
            );
        } else {
            assert_eq!(
                body(&result)["message"],
                "You can't unlink your last account"
            );
            assert_eq!(db.table("accounts").await?, foreign_before);
        }
        let foreign_accounts = call(
            &auth,
            request("/list-accounts", None, &cookies(&foreign)),
            200,
        )
        .await;
        assert_eq!(body(&foreign_accounts).as_array().unwrap().len(), 2);
        assert!(
            body(&foreign_accounts)
                .as_array()
                .unwrap()
                .iter()
                .any(|account| account["id"] == inserted[1])
        );
        assert_eq!(db.table("users").await?, original[0]);
        assert_eq!(db.table("sessions").await?, original[2]);
        B::close(connection).await?;
    }
    Ok(())
}

async fn session_listing_and_revocation_preserve_other_owners<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection).build().await?;
    let owner = signup(&auth, "session-owner@example.test").await;
    let foreign = signup(&auth, "session-foreign@example.test").await;
    let cookie = cookies(&owner);
    let mut peers = Vec::new();
    for _ in 0..3 {
        peers.push(
            call(
                &auth,
                request(
                    "/sign-in/email",
                    Some(json!({"email":"session-owner@example.test","password":PASSWORD})),
                    "",
                ),
                200,
            )
            .await,
        );
    }
    let token = |response: &AuthResponse| body(response)["token"].as_str().unwrap().to_owned();
    // An expired physical row must neither leak into the active listing nor
    // prevent revocation of the caller's remaining active sessions.
    db.set_timestamp(
        "sessions",
        "expires_at",
        ("token", &token(&peers[2])),
        chrono::Utc::now() - chrono::Duration::days(1),
    )
    .await?;
    let listed = call(&auth, request("/list-sessions", None, &cookie), 200).await;
    let actual: BTreeSet<_> = body(&listed)
        .as_array()
        .unwrap()
        .iter()
        .map(|session| session["token"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        actual,
        BTreeSet::from([token(&owner), token(&peers[0]), token(&peers[1])])
    );
    let initial = db.table("sessions").await?;
    for target in [token(&foreign), "unknown-session-token".into()] {
        let response = call(
            &auth,
            request("/revoke-session", Some(json!({"token":target})), &cookie),
            200,
        )
        .await;
        assert_eq!(body(&response)["status"], true);
        assert_eq!(db.table("sessions").await?, initial);
    }
    for route in [
        "/revoke-session",
        "/revoke-other-sessions",
        "/revoke-sessions",
    ] {
        let _ = call(
            &auth,
            request(route, Some(json!({"token":token(&owner)})), ""),
            401,
        )
        .await;
        assert_eq!(db.table("sessions").await?, initial);
    }
    let _ = call(
        &auth,
        request(
            "/revoke-session",
            Some(json!({"token":token(&peers[0])})),
            &cookie,
        ),
        200,
    )
    .await;
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM sessions WHERE token=$1",
            &[&token(&peers[0])]
        )
        .await?,
        0
    );
    assert!(
        body(
            &call(
                &auth,
                request("/get-session", None, &cookies(&peers[0])),
                200
            )
            .await
        )
        .is_null()
    );
    authenticated(&auth, &cookies(&peers[1]), "session-owner@example.test").await;
    let _ = call(
        &auth,
        request("/revoke-other-sessions", Some(json!({})), &cookie),
        200,
    )
    .await;
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM sessions WHERE user_id=$1",
            &[body(&owner)["user"]["id"].as_str().unwrap()]
        )
        .await?,
        2
    );
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM sessions WHERE token=$1",
            &[&token(&peers[2])]
        )
        .await?,
        1,
        "revoke-other-sessions preserves already expired rows"
    );

    authenticated(&auth, &cookie, "session-owner@example.test").await;
    authenticated(&auth, &cookies(&foreign), "session-foreign@example.test").await;
    let _ = call(
        &auth,
        request("/revoke-sessions", Some(json!({})), &cookie),
        200,
    )
    .await;
    assert!(body(&call(&auth, request("/get-session", None, &cookie), 200).await).is_null());
    assert_eq!(db.count("sessions").await?, 1);
    assert_eq!(
        db.text("SELECT token FROM sessions", &[]).await?,
        Some(token(&foreign))
    );
    authenticated(&auth, &cookies(&foreign), "session-foreign@example.test").await;
    B::close(connection).await
}
