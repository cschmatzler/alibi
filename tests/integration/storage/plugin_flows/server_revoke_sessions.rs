//! Logical all-session revocation consumes current and expired authority without touching foreign rows.
use super::server_revocation_support::{Observer, options};
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::{AuthResult, StatusResponse};
backend_tests!(server_revoke_sessions_deletes_all_owned_rows_and_rejects_cached_authority);
fn endpoint(token: &str) -> AuthResult<ServerEndpoint<StatusResponse>> {
    SessionManagementPlugin::revoke_sessions_endpoint()
        .with_body(&json!({"token":token}))?
        .with_query(&json!({"disableRefresh":true}))
}
async fn server_revoke_sessions_deletes_all_owned_rows_and_rejects_cached_authority<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let observer = Observer::new("revokeSessions", "/revoke-sessions");
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
    let owner = signup(&auth, "logical-all-owner@example.test").await;
    let mut peers = Vec::new();
    for _ in 0..2 {
        peers.push(
            call(
                &auth,
                request(
                    "/sign-in/email",
                    Some(json!({"email":"logical-all-owner@example.test","password":PASSWORD})),
                    "",
                ),
                200,
            )
            .await,
        );
    }
    let foreign = signup(&auth, "logical-all-foreign@example.test").await;
    let token = |response: &AuthResponse| body(response)["token"].as_str().unwrap().to_owned();
    assert!(cookies(&peers[0]).contains("better-auth.session_data="));
    db.set_timestamp(
        "session",
        "expiresAt",
        ("token", &token(&peers[1])),
        chrono::DateTime::from_timestamp(1_577_836_800, 0).unwrap(),
    )
    .await?;
    db.set_timestamp(
        "session",
        "expiresAt",
        ("token", &token(&owner)),
        chrono::Utc::now() + chrono::Duration::hours(1),
    )
    .await?;
    let before = db.tables(&["user", "account", "session"]).await?;
    let missing = auth
        .dispatch_endpoint(endpoint(&token(&foreign))?, EndpointOptions::default())
        .await
        .unwrap_err();
    assert_eq!(missing.error.status_code(), 400, "{missing}");
    assert!(missing.error.to_string().contains("Headers is required"));
    let guest = auth
        .dispatch_endpoint(
            endpoint(&token(&foreign))?,
            EndpointOptions {
                headers: Some(Default::default()),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(guest.error.status_code(), 401);
    assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    let revoked = auth
        .dispatch_endpoint(endpoint(&token(&foreign))?, options(&owner))
        .await?;
    assert!(revoked.decode()?.status);
    assert_eq!(
        revoked
            .headers()
            .get("x-revocation-result")
            .map(String::as_str),
        Some("logical")
    );
    assert!(revoked.headers().get_all("set-cookie").next().is_none());
    let after = db.tables(&["user", "account", "session"]).await?;
    assert_eq!(after[..2], before[..2]);
    assert!(auth.store().get_session(&token(&peers[0])).await?.is_none());
    for removed in [&owner, &peers[1]] {
        assert!(auth.store().get_session(&token(removed)).await?.is_none());
    }
    assert!(auth.store().get_session(&token(&foreign)).await?.is_some());
    let before_sessions: Vec<Value> = serde_json::from_str(&before[2])?;
    let expected: Vec<_> = before_sessions
        .into_iter()
        .filter(|row| row["token"] == token(&foreign))
        .collect();
    assert_eq!(serde_json::from_str::<Vec<Value>>(&after[2])?, expected);
    let stale = auth
        .dispatch_endpoint(endpoint(&token(&foreign))?, options(&peers[0]))
        .await
        .unwrap_err();
    assert_eq!(stale.error.status_code(), 401);
    assert_eq!(db.tables(&["user", "account", "session"]).await?, after);
    let stale_owner = auth
        .dispatch_endpoint(endpoint(&token(&foreign))?, options(&owner))
        .await
        .unwrap_err();
    assert_eq!(stale_owner.error.status_code(), 401);
    assert_eq!(db.tables(&["user", "account", "session"]).await?, after);
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        observer
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|id| id.as_deref() == Some(&owner_id))
            .count(),
        1
    );
    B::close(connection).await
}
