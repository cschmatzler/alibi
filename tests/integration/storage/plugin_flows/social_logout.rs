//! Provider logout destinations after local sign-out, for each combination of
//! configured redirect, caller redirect and ID-token availability.
use super::social_flows::{Social, authorize, callback};
use super::*;
use alibi::AccountConfig;
use alibi::plugins::oauth::{OAuthEndSessionConfig, OAuthProvider};

backend_tests!(
    sign_out_builds_the_provider_logout_destination,
    logout_schema_rejection_preserves_owned_account_and_live_sessions,
    logout_selects_newest_eligible_owned_account
);

async fn sign_out_builds_the_provider_logout_destination<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let cases: Vec<(&str, Option<&str>, bool, Value, Option<&str>)> = vec![
        (
            "caller redirect, state and token",
            Some("https://idp.example/logout?keep=yes"),
            true,
            json!({"callbackURL":"/bye","state":"caller"}),
            None,
        ),
        (
            "configured redirect resolved against the auth base",
            Some("https://idp.example/logout"),
            true,
            json!({}),
            Some("/signed-out"),
        ),
        (
            "no redirect and no token identifies the client",
            Some("https://idp.example/logout"),
            false,
            json!({}),
            None,
        ),
        (
            "redirect without a token",
            Some("https://idp.example/logout"),
            false,
            json!({"callbackURL":"/bye"}),
            None,
        ),
        (
            "provider without logout endpoint",
            None,
            true,
            json!({"callbackURL":"/bye"}),
            None,
        ),
        (
            "unparsable logout endpoint",
            Some("not a url"),
            true,
            json!({}),
            None,
        ),
    ];
    for (index, (label, endpoint, token, input, configured)) in cases.into_iter().enumerate() {
        let social = Social::start().await;
        let mut grant = json!({"access_token":"logout-access","token_type":"Bearer"});
        if token {
            grant["id_token"] = json!("provider-id-token");
        }
        social
            .provider
            .respond(200, "application/json", grant.to_string());
        social.profile.set(
            &format!("logout-sub-{index}"),
            &format!("logout-{index}@example.com"),
            true,
        );
        let auth = social
            .auth::<B>(
                &connection,
                AccountConfig::default(),
                |provider: &mut OAuthProvider| {
                    provider.authorization.as_mut().unwrap().end_session =
                        endpoint.map(|endpoint| OAuthEndSessionConfig {
                            endpoint: endpoint.into(),
                            post_logout_redirect_uri: configured.map(Into::into),
                        });
                },
            )
            .await?;
        let (state, cookie) = authorize(
            &auth,
            "/sign-in/social",
            json!({"provider":"google","callbackURL":"/home"}),
            "",
        )
        .await;
        let signed_in = callback(&auth, &[("code", "grant"), ("state", &state)], &cookie).await;
        assert_eq!(signed_in.status, 302, "{label}");
        let mut input = input;
        input["disableRedirect"] = json!(true);
        let response = call(
            &auth,
            request("/sign-out", Some(input), &cookies(&signed_in)),
            200,
        )
        .await;
        let result = body(&response);
        assert_eq!(result["success"], true, "{label}");
        let expected: Option<Vec<(&str, &str)>> = match label {
            "caller redirect, state and token" => Some(vec![
                ("keep", "yes"),
                ("id_token_hint", "provider-id-token"),
                ("post_logout_redirect_uri", "http://localhost:43219/bye"),
                ("client_id", "google-client"),
                ("state", "caller"),
            ]),
            "configured redirect resolved against the auth base" => Some(vec![
                ("id_token_hint", "provider-id-token"),
                (
                    "post_logout_redirect_uri",
                    "http://localhost:43219/signed-out",
                ),
                ("client_id", "google-client"),
            ]),
            "no redirect and no token identifies the client" => {
                Some(vec![("client_id", "google-client")])
            }
            "redirect without a token" => Some(vec![
                ("post_logout_redirect_uri", "http://localhost:43219/bye"),
                ("client_id", "google-client"),
            ]),
            _ => None,
        };
        match expected {
            Some(expected) => {
                let url = url::Url::parse(result["url"].as_str().unwrap())?;
                let actual: Vec<_> = url.query_pairs().into_owned().collect();
                let expected: Vec<_> = expected
                    .into_iter()
                    .map(|(key, value)| (key.to_owned(), value.to_owned()))
                    .collect();
                assert_eq!(actual, expected, "{label}");
            }
            None => assert!(
                result.get("url").is_none_or(Value::is_null),
                "{label}: {result}"
            ),
        }
    }
    B::close(connection).await
}

async fn logout_schema_rejection_preserves_owned_account_and_live_sessions<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut provider = OAuthProvider::google("logout-client", "logout-secret");
    provider.authorization.as_mut().unwrap().end_session = Some(OAuthEndSessionConfig {
        endpoint: "https://idp.example/logout".into(),
        post_logout_redirect_uri: None,
    });
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(alibi::plugins::OAuthPlugin::new().add_provider("google", provider))
        .build()
        .await?;
    let owner = signup(&auth, "logout-schema-owner@example.test").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let sibling = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"logout-schema-owner@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    let foreign = signup(&auth, "logout-schema-foreign@example.test").await;
    _ = db.execute("INSERT INTO accounts (id,user_id,account_id,provider_id,id_token,created_at,updated_at) SELECT 'logout-schema-account',user_id,'logout-schema-sub','google','logout-owner-token',created_at,updated_at FROM accounts WHERE user_id=$1 AND provider_id='credential'", &[&owner_id]).await?;
    let before = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    for input in [
        json!({"disableRedirect":"yes"}),
        json!({"callbackURL":null}),
        json!({"state":123}),
    ] {
        let rejected = call(
            &auth,
            request("/sign-out", Some(input), &cookies(&owner)),
            400,
        )
        .await;
        assert_eq!(body(&rejected)["code"], "VALIDATION_ERROR");
        assert!(rejected.headers.get("location").is_none());
        assert!(cookies(&rejected).is_empty());
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "verifications"])
                .await?,
            before
        );
        authenticated(&auth, &cookies(&owner), "logout-schema-owner@example.test").await;
    }
    let retained = db.tables(&["users", "accounts", "verifications"]).await?;
    let accepted = call(
        &auth,
        request(
            "/sign-out",
            Some(json!({"disableRedirect":true})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    assert_eq!(body(&accepted)["success"], true);
    assert_eq!(body(&accepted)["redirect"], false);
    let location = url::Url::parse(body(&accepted)["url"].as_str().unwrap())?;
    assert_eq!(
        location.as_str(),
        "https://idp.example/logout?id_token_hint=logout-owner-token"
    );
    assert!(accepted.headers.get("location").is_none());
    assert_eq!(
        db.tables(&["users", "accounts", "verifications"]).await?,
        retained
    );
    assert_eq!(db.count("sessions").await?, 2);
    assert!(
        body(&call(&auth, request("/get-session", None, &cookies(&owner)), 200).await).is_null()
    );
    authenticated(
        &auth,
        &cookies(&sibling),
        "logout-schema-owner@example.test",
    )
    .await;
    authenticated(
        &auth,
        &cookies(&foreign),
        "logout-schema-foreign@example.test",
    )
    .await;
    B::close(connection).await
}

async fn logout_selects_newest_eligible_owned_account<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let provider = |endpoint: &str| {
        let mut provider = OAuthProvider::google("logout-order-client", "logout-order-secret");
        provider.authorization.as_mut().unwrap().end_session = Some(OAuthEndSessionConfig {
            endpoint: endpoint.into(),
            post_logout_redirect_uri: None,
        });
        provider
    };
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(
            alibi::plugins::OAuthPlugin::new()
                .add_provider("primary", provider("https://primary.example/logout"))
                .add_provider("backup", provider("https://backup.example/logout"))
                .add_provider("invalid", provider("not a URL")),
        )
        .build()
        .await?;
    let owner = signup(&auth, "logout-order-owner@example.test").await;
    let foreign = signup(&auth, "logout-order-foreign@example.test").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
    for (provider_id, account_id, token, updated) in [
        (
            "backup",
            "backup-account",
            "backup-token",
            "2020-01-01T00:00:00Z",
        ),
        (
            "primary",
            "older-account",
            "older-token",
            "2021-01-01T00:00:00Z",
        ),
        (
            "primary",
            "newer-account",
            "newer-token",
            "2022-01-01T00:00:00Z",
        ),
        (
            "invalid",
            "invalid-account",
            "invalid-token",
            "2023-01-01T00:00:00Z",
        ),
        (
            "unregistered",
            "unknown-account",
            "unknown-token",
            "2024-01-01T00:00:00Z",
        ),
    ] {
        _ = db.execute("INSERT INTO accounts (id,user_id,account_id,provider_id,id_token,created_at,updated_at) VALUES ($1,$2,$1,$3,$4,$5,$5)", &[account_id,&owner_id,provider_id,token,updated]).await?;
    }
    _ = db.execute("INSERT INTO accounts (id,user_id,account_id,provider_id,id_token,created_at,updated_at) VALUES ('foreign-account',$1,'foreign-account','primary','foreign-token','2025-01-01T00:00:00Z','2025-01-01T00:00:00Z')", &[&foreign_id]).await?;
    let preserved = db.tables(&["users", "accounts", "verifications"]).await?;
    let completed = call(
        &auth,
        request(
            "/sign-out",
            Some(json!({"disableRedirect":true})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    assert_eq!(body(&completed)["success"], true);
    assert_eq!(body(&completed)["redirect"], false);
    assert_eq!(
        body(&completed)["url"],
        "https://primary.example/logout?id_token_hint=newer-token"
    );
    assert!(completed.headers.get("location").is_none());
    assert_eq!(
        db.tables(&["users", "accounts", "verifications"]).await?,
        preserved
    );
    assert_eq!(db.count("sessions").await?, 1);
    authenticated(
        &auth,
        &cookies(&foreign),
        "logout-order-foreign@example.test",
    )
    .await;
    let replay = call(
        &auth,
        request("/sign-out", Some(json!({})), &cookies(&owner)),
        200,
    )
    .await;
    assert_eq!(body(&replay), json!({"success":true}));
    assert!(replay.headers.get("location").is_none());
    assert_eq!(
        db.tables(&["users", "accounts", "verifications"]).await?,
        preserved
    );
    assert_eq!(db.count("sessions").await?, 1);
    B::close(connection).await
}
