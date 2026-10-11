//! Logical sign-out accepts guests, clears cookies, and trusts only the signed token.
use super::server_revocation_support::{Observer, options};
use super::*;
use alibi::Headers;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::session_management::{SignOutRequest, SignOutResponse};
backend_tests!(server_sign_out_clears_cookies_without_authenticating_cache_authority);
fn endpoint() -> ServerEndpoint<SignOutResponse> {
    SessionManagementPlugin::sign_out_endpoint()
}
fn assert_cleared(headers: &Headers, incoming_cache: bool) {
    let names: Vec<_> = headers
        .get_all("set-cookie")
        .map(|raw| {
            let mut parts = raw.split(';').map(str::trim);
            let (name, value) = parts.next().unwrap().split_once('=').unwrap();
            assert_eq!(value, "");
            let attributes: Vec<_> = parts.collect();
            for required in ["Max-Age=0", "Path=/", "HttpOnly", "SameSite=Lax"] {
                assert!(attributes.contains(&required), "{raw}");
            }
            name.to_owned()
        })
        .collect();
    let mut expected = vec!["better-auth.session_token", "better-auth.session_data"];
    if incoming_cache {
        expected.push("better-auth.session_data");
    }
    expected.push("better-auth.dont_remember");
    assert_eq!(names, expected);
}
async fn server_sign_out_clears_cookies_without_authenticating_cache_authority<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let observer = Observer::new("signOut", "/sign-out");
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.session.cookie_cache = Some(alibi::CookieCacheConfig {
        enabled: true,
        max_age: 300.0,
        ..Default::default()
    });
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .endpoint_hook(observer.clone())
        .plugin(super::auth_probe::fast_password())
        .build()
        .await?;
    let owner = signup(&auth, "logical-signout-owner@example.test").await;
    let other = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"logical-signout-owner@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    let foreign = signup(&auth, "logical-signout-foreign@example.test").await;
    let token = |response: &AuthResponse| body(response)["token"].as_str().unwrap().to_owned();
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    for input in [
        json!(null),
        json!([]),
        json!({"callbackURL":7}),
        json!({"disableRedirect":"false"}),
        json!({"state":7}),
    ] {
        let denied = auth
            .dispatch_endpoint(endpoint().with_body(&input)?, EndpointOptions::default())
            .await
            .unwrap_err();
        assert_eq!(denied.error.status_code(), 400, "{denied}");
        assert!(denied.error.to_string().contains("[body"));
        assert!(
            denied
                .headers
                .as_ref()
                .is_none_or(|headers| headers.get_all("set-cookie").next().is_none())
        );
    }
    let missing = auth
        .dispatch_endpoint(endpoint(), EndpointOptions::default())
        .await
        .unwrap_err();
    assert_eq!(missing.error.status_code(), 400);
    assert!(missing.error.to_string().contains("Headers is required"));
    let guest = auth
        .dispatch_endpoint(
            endpoint(),
            EndpointOptions {
                headers: Some(Default::default()),
                ..Default::default()
            },
        )
        .await?;
    assert!(guest.decode()?.success);
    assert_cleared(guest.headers(), false);
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    let cache_only = cookies(&owner)
        .split("; ")
        .filter(|raw| !raw.starts_with("better-auth.session_token="))
        .collect::<Vec<_>>()
        .join("; ");
    assert!(cache_only.contains("better-auth.session_data="));
    let detached = auth
        .dispatch_endpoint(
            endpoint(),
            EndpointOptions {
                headers: Some([("cookie".into(), cache_only)].into_iter().collect()),
                ..Default::default()
            },
        )
        .await?;
    assert!(detached.decode()?.success);
    assert_cleared(detached.headers(), true);
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    db.set_timestamp(
        "sessions",
        "expires_at",
        ("token", &token(&owner)),
        chrono::DateTime::from_timestamp(1_577_836_800, 0).unwrap(),
    )
    .await?;
    let expired = db.tables(&["users", "accounts", "sessions"]).await?;
    let retired=auth.dispatch_endpoint(endpoint().with_body(&json!({"callbackURL":"/bye","disableRedirect":true,"state":"client","token":token(&foreign)}))?,options(&owner)).await?;
    let decoded = retired.decode()?;
    assert!(decoded.success);
    assert!(decoded.url.is_none());
    assert!(decoded.redirect.is_none());
    assert_eq!(
        serde_json::to_value(retired.value())?,
        json!({"success":true})
    );
    assert_eq!(
        retired
            .headers()
            .get("x-revocation-result")
            .map(String::as_str),
        Some("logical")
    );
    assert_cleared(retired.headers(), true);
    assert!(auth.store().get_session(&token(&owner)).await?.is_none());
    assert!(auth.store().get_session(&token(&other)).await?.is_some());
    assert!(auth.store().get_session(&token(&foreign)).await?.is_some());
    let after = db.tables(&["users", "accounts", "sessions"]).await?;
    assert_eq!(after[..2], expired[..2]);
    let rows: Vec<Value> = serde_json::from_str(&expired[2])?;
    let retained: Vec<_> = rows
        .into_iter()
        .filter(|row| row["token"] != token(&owner))
        .collect();
    assert_eq!(serde_json::from_str::<Vec<Value>>(&after[2])?, retained);
    let repeated = auth
        .dispatch_endpoint(
            endpoint().with_body(&SignOutRequest::default())?,
            options(&owner),
        )
        .await?;
    assert!(repeated.decode()?.success);
    assert_cleared(repeated.headers(), true);
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, after);
    assert!(observer.0.lock().unwrap().iter().all(Option::is_none));
    B::close(connection).await
}
