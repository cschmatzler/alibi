//! Public deletion authenticates the stored owner and removes all of that owner's records.
use super::auth_probe::fast_password;
use super::server_revocation_support::{Observer, options};
use super::*;
use alibi::AuthResult;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::UserManagementPlugin;

fn endpoint(body: &Value) -> AuthResult<ServerEndpoint<alibi::SuccessMessageResponse>> {
    UserManagementPlugin::delete_user_endpoint(
        &alibi::plugins::user_management::DeleteUserRequest::default(),
    )?
    .with_body(body)
}
backend_tests!(server_delete_user_deletes_only_authenticated_owner_and_all_owned_sessions);
async fn server_delete_user_deletes_only_authenticated_owner_and_all_owned_sessions<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .session_cookie_cache(alibi::CookieCacheConfig {
            enabled: true,
            max_age: 300.0,
            ..Default::default()
        });
    let observer = Observer::new("deleteUser", "/delete-user");
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(fast_password())
        .plugin(UserManagementPlugin::new().delete_user_enabled(true))
        .endpoint_hook(observer.clone())
        .build()
        .await?;
    let email = "logical-delete-owner@example.test";
    let owner = signup(&auth, email).await;
    let second = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":email,"password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    let foreign = signup(&auth, "logical-delete-foreign@example.test").await;
    assert!(cookies(&owner).contains("better-auth.session_data="));
    let owner_id = body(&owner)["user"]["id"].clone();
    let before = db
        .tables(&["user", "account", "session", "verification"])
        .await?;
    let sessions: Vec<Value> = serde_json::from_str(&before[2])?;
    assert_eq!(
        sessions
            .iter()
            .filter(|row| row["userId"] == owner_id)
            .count(),
        2
    );
    for malformed in [
        json!(null),
        json!([]),
        json!({"password":7}),
        json!({"token":null}),
        json!({"callbackURL":null}),
    ] {
        let rejected = auth
            .dispatch_endpoint(endpoint(&malformed)?, options(&owner))
            .await
            .unwrap_err();
        assert_eq!(rejected.error.status_code(), 400, "{rejected}");
        assert!(rejected.error.to_string().contains("[body"));
    }
    let guest = auth
        .dispatch_endpoint(endpoint(&json!({}))?, EndpointOptions::default())
        .await
        .unwrap_err();
    assert_eq!(guest.error.status_code(), 401);
    let wrong = auth
        .dispatch_endpoint(
            UserManagementPlugin::delete_user_endpoint(
                &alibi::plugins::user_management::DeleteUserRequest {
                    password: Some("wrong-password".into()),
                    ..Default::default()
                },
            )?,
            options(&owner),
        )
        .await
        .unwrap_err();
    assert_eq!(wrong.error.status_code(), 400);
    assert!(wrong.error.to_string().contains("Invalid password"));
    assert_eq!(
        db.tables(&["user", "account", "session", "verification"])
            .await?,
        before
    );
    let deleted = auth
        .dispatch_endpoint(
            endpoint(&json!({"password":PASSWORD,"userId":body(&foreign)["user"]["id"]}))?,
            options(&owner),
        )
        .await?;
    let response = deleted.decode()?;
    assert!(response.success);
    assert_eq!(response.message, "User deleted");
    for name in ["session_token", "session_data", "dont_remember"] {
        let prefix = format!("better-auth.{name}=");
        assert!(
            deleted
                .headers()
                .get_all("set-cookie")
                .any(|cookie| cookie.starts_with(&prefix) && cookie.contains("Max-Age=0")),
            "missing retirement for {name}"
        );
    }
    for cookie in deleted.headers().get_all("set-cookie") {
        if cookie.starts_with("better-auth.session_data=") {
            assert!(
                cookie.contains("Max-Age=0"),
                "deletion republished live cache: {cookie}"
            );
        }
    }
    assert_eq!(
        observer.0.lock().unwrap().last().unwrap().as_deref(),
        owner_id.as_str()
    );
    for (index, table) in ["user", "account", "session", "verification"]
        .iter()
        .enumerate()
    {
        let original: Vec<Value> = serde_json::from_str(&before[index])?;
        let expected: Vec<_> = original
            .into_iter()
            .filter(|row| match *table {
                "user" => row["id"] != owner_id,
                "account" | "session" => row["userId"] != owner_id,
                _ => true,
            })
            .collect();
        let actual: Vec<Value> = serde_json::from_str(&db.table(table).await?)?;
        assert_eq!(actual, expected, "unexpected writes to {table}");
    }
    let after = db
        .tables(&["user", "account", "session", "verification"])
        .await?;
    for saved in [&owner, &second] {
        let replay = auth
            .dispatch_endpoint(endpoint(&json!({}))?, options(saved))
            .await
            .unwrap_err();
        assert_eq!(replay.error.status_code(), 401);
    }
    assert_eq!(
        db.tables(&["user", "account", "session", "verification"])
            .await?,
        after
    );
    authenticated(
        &auth,
        &cookies(&foreign),
        "logical-delete-foreign@example.test",
    )
    .await;
    B::close(connection).await
}
