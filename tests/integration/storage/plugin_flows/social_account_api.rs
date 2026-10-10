//! Linked-account token and profile endpoints: input validation, authentication
//! and refresh outcomes.
use super::social_flows::{Social, authorize, callback};
use super::*;
use crate::snapshot::Trace;
use alibi::AccountConfig;
use alibi::plugins::oauth::{OAuthAccountApi, OAuthAccountSelection};

backend_tests!(
    account_endpoints_validate_selection_authentication_and_refresh,
    automatic_refresh_uses_access_expiry_without_refresh_lifetime_veto
);

async fn account_endpoints_validate_selection_authentication_and_refresh<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let social = Social::start().await;
    let mut trace = Trace::default();
    let account = AccountConfig {
        store_account_cookie: true,
        ..Default::default()
    };
    let auth = social.auth::<B>(&connection, account, |_| {}).await?;
    let (state, cookie) = authorize(
        &auth,
        "/sign-in/social",
        json!({"provider":"google","callbackURL":"/home"}),
        "",
    )
    .await;
    let signed_in = callback(&auth, &[("code", "grant"), ("state", &state)], &cookie).await;
    assert_eq!(signed_in.status, 302);
    let session = cookies(&signed_in);
    let id = db.text("SELECT id FROM accounts", &[]).await?.unwrap();

    let post = |path: &'static str, input: Value, cookie: String| {
        let auth = &auth;
        async move {
            Box::pin(auth.handle_request(request(path, Some(input), &cookie)))
                .await
                .unwrap()
        }
    };
    for path in ["/get-access-token", "/refresh-token"] {
        for (label, input) in [
            ("empty object", json!({})),
            ("array", json!([])),
            ("unknown key", json!({"accountId": id, "extra": 1})),
            (
                "unknown keys",
                json!({"accountId": id, "extra": 1, "more": 2}),
            ),
            (
                "both selectors",
                json!({"accountId": id, "useAccountCookie": true}),
            ),
            ("foreign user", json!({"accountId": id, "userId": 5})),
            ("account cookie selector", json!({"useAccountCookie": true})),
            ("unknown account", json!({"accountId": "missing"})),
        ] {
            trace.response(
                &format!("{path} {label}"),
                &post(path, input, session.clone()).await,
            );
        }
        trace.response(
            &format!("{path} unauthenticated"),
            &post(path, json!({"accountId": id}), String::new()).await,
        );
    }
    for (label, query, cookie) in [
        (
            "account-info selected",
            vec![("accountId", id.as_str())],
            session.as_str(),
        ),
        (
            "account-info unknown key",
            vec![("accountId", id.as_str()), ("extra", "1")],
            session.as_str(),
        ),
        ("account-info no selector", vec![], session.as_str()),
        (
            "account-info unauthenticated",
            vec![("accountId", id.as_str())],
            "",
        ),
    ] {
        let mut req = request("/account-info", None, cookie);
        req.set_query_pairs(query);
        trace.response(label, &Box::pin(auth.handle_request(req)).await?);
    }

    social.provider.respond(
        200,
        "application/json",
        json!({"access_token":"rotated-access","token_type":"Bearer","expires_in":3600})
            .to_string(),
    );
    let refreshed = post("/refresh-token", json!({"accountId": id}), session.clone()).await;
    trace.response("refresh without a new refresh token", &refreshed);
    assert_eq!(body(&refreshed)["refreshToken"], "provider-refresh");
    assert_eq!(
        db.text("SELECT refresh_token FROM accounts", &[])
            .await?
            .as_deref(),
        Some("provider-refresh")
    );

    for selection in [
        OAuthAccountSelection::Id(id.clone()),
        OAuthAccountSelection::Cookie,
    ] {
        let error = OAuthAccountApi::get_access_token("", selection, auth.context())
            .await
            .unwrap_err();
        trace.value("server call without user", json!(error.to_string()));
    }
    trace.assert("social/account-api");
    B::close(connection).await
}

async fn automatic_refresh_uses_access_expiry_without_refresh_lifetime_veto<B: Backend>(
    db: Db,
) -> TestResult {
    use chrono::{DateTime, Utc};
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let social = Social::start().await;
    let auth = social
        .auth::<B>(&connection, AccountConfig::default(), |_| {})
        .await?;
    let issue = async || {
        let (state, cookie) = authorize(
            &auth,
            "/sign-in/social",
            json!({"provider":"google","callbackURL":"/home"}),
            "",
        )
        .await;
        callback(&auth, &[("code", "grant"), ("state", &state)], &cookie).await
    };
    social
        .profile
        .set("foreign-sub", "foreign@example.test", true);
    let foreign = issue().await;
    assert_eq!(foreign.status, 302);
    social.profile.set("social-sub", "social@example.com", true);
    let owner = issue().await;
    assert_eq!(owner.status, 302);
    let cookie = cookies(&owner);
    let current = body(&call(&auth, request("/get-session", None, &cookie), 200).await);
    let owner_id = current["user"]["id"].clone();
    let id = db
        .text(
            "SELECT id FROM accounts WHERE account_id=$1 AND provider_id='google'",
            &["social-sub"],
        )
        .await?
        .unwrap();
    let past = DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")?.with_timezone(&Utc);
    let future = DateTime::parse_from_rfc3339("2099-01-01T00:00:00Z")?.with_timezone(&Utc);
    db.set_timestamp("accounts", "refresh_token_expires_at", ("id", &id), past)
        .await?;
    social.provider.respond(200,"application/json",json!({"access_token":"rotated-access","refresh_token":"rotated-refresh","token_type":"Bearer","expires_in":3600,"scope":"openid"}).to_string());
    _ = social.provider.take();
    for expiry in [None, Some(future), Some(past)] {
        _=db.execute("UPDATE accounts SET access_token='old-access',refresh_token='old-refresh',scope='calendar,drive',access_token_expires_at=NULL WHERE id=$1",&[&id]).await?;
        if let Some(expiry) = expiry {
            db.set_timestamp("accounts", "access_token_expires_at", ("id", &id), expiry)
                .await?;
        }
        let before = db.tables(&["users", "accounts", "sessions"]).await?;
        let started = Utc::now();
        let result = body(
            &call(
                &auth,
                request("/get-access-token", Some(json!({"accountId":id})), &cookie),
                200,
            )
            .await,
        );
        let finished = Utc::now();
        let receipts = social.provider.take();
        let after = db.tables(&["users", "accounts", "sessions"]).await?;
        if expiry != Some(past) {
            assert_eq!(result["accessToken"], "old-access");
            assert!(receipts.is_empty());
            assert_eq!(after, before);
        } else {
            assert_eq!(result["accessToken"], "rotated-access");
            assert_eq!(result["scopes"], json!(["calendar", "drive"]));
            assert_eq!(receipts.len(), 1);
            assert_eq!(receipts[0].method, axum::http::Method::POST);
            assert_eq!(receipts[0].path, "/token");
            let fields = url::form_urlencoded::parse(&receipts[0].body)
                .collect::<std::collections::BTreeMap<_, _>>();
            assert_eq!(
                fields.get("grant_type").map(|value| value.as_ref()),
                Some("refresh_token")
            );
            assert_eq!(
                fields.get("refresh_token").map(|value| value.as_ref()),
                Some("old-refresh")
            );
            assert_eq!(after[0], before[0]);
            assert_eq!(after[2], before[2]);
            let original: Vec<Value> = serde_json::from_str(&before[1])?;
            let updated: Vec<Value> = serde_json::from_str(&after[1])?;
            assert_eq!(updated.len(), original.len());
            let original_row = original.iter().find(|row| row["id"] == id).unwrap();
            let updated_row = updated.iter().find(|row| row["id"] == id).unwrap();
            for field in [
                "id",
                "account_id",
                "provider_id",
                "user_id",
                "scope",
                "created_at",
                "refresh_token_expires_at",
            ] {
                assert_eq!(updated_row[field], original_row[field], "{field}");
            }
            assert_eq!(updated_row["user_id"], owner_id);
            assert_eq!(updated_row["access_token"], "rotated-access");
            assert_eq!(updated_row["refresh_token"], "rotated-refresh");
            let expires = DateTime::parse_from_rfc3339(
                updated_row["access_token_expires_at"].as_str().unwrap(),
            )?
            .with_timezone(&Utc);
            assert!(expires >= started + chrono::Duration::seconds(3600));
            assert!(expires <= finished + chrono::Duration::seconds(3600));
            for row in original.iter().filter(|row| row["id"] != id) {
                assert!(updated.contains(row));
            }
        }
    }
    authenticated(&auth, &cookie, "social@example.com").await;
    authenticated(&auth, &cookies(&foreign), "foreign@example.test").await;
    B::close(connection).await
}
