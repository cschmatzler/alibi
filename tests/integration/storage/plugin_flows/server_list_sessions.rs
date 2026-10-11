//! Listing uses fresh ordinary cache authority and returns only active owned rows.
use super::server_revocation_support::{Observer, options};
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::{AuthResult, AuthSession, SessionView};
backend_tests!(server_list_sessions_retains_cached_freshness_and_filters_physical_rows);
fn endpoint(disable_cache: bool) -> AuthResult<ServerEndpoint<Vec<SessionView>>> {
    SessionManagementPlugin::list_sessions_endpoint()
        .with_query(&json!({"disableRefresh":true,"disableCookieCache":disable_cache}))
}
async fn server_list_sessions_retains_cached_freshness_and_filters_physical_rows<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let observer = Observer::new("listSessions", "/list-sessions");
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
    let owner = signup(&auth, "logical-list-owner@example.test").await;
    let mut peers = Vec::new();
    for _ in 0..2 {
        peers.push(
            call(
                &auth,
                request(
                    "/sign-in/email",
                    Some(json!({"email":"logical-list-owner@example.test","password":PASSWORD})),
                    "",
                ),
                200,
            )
            .await,
        );
    }
    let foreign = signup(&auth, "logical-list-foreign@example.test").await;
    let token = |response: &AuthResponse| body(response)["token"].as_str().unwrap().to_owned();
    let old = chrono::DateTime::from_timestamp(1_577_836_800, 0).unwrap();
    db.set_timestamp("sessions", "expires_at", ("token", &token(&peers[1])), old)
        .await?;
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    let missing = auth
        .dispatch_endpoint(endpoint(false)?, EndpointOptions::default())
        .await
        .unwrap_err();
    assert_eq!(missing.error.status_code(), 400, "{missing}");
    assert!(missing.error.to_string().contains("Headers is required"));
    let guest = auth
        .dispatch_endpoint(
            endpoint(false)?,
            EndpointOptions {
                headers: Some(Default::default()),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(guest.error.status_code(), 401);
    let listed = auth
        .dispatch_endpoint(endpoint(false)?, options(&owner))
        .await?;
    assert_eq!(
        listed
            .headers()
            .get("x-revocation-result")
            .map(String::as_str),
        Some("logical")
    );
    let sessions = listed.decode()?;
    assert_eq!(sessions.len(), 2);
    for source in [&owner, &peers[0]] {
        let row = sessions
            .iter()
            .find(|row| row.token == token(source))
            .unwrap();
        let stored = auth.store().get_session(&token(source)).await?.unwrap();
        assert_eq!(row.id, stored.id());
        assert_eq!(row.user_id, stored.user_id());
        assert_eq!(
            row.expires_at.timestamp_millis(),
            stored.expires_at().timestamp_millis()
        );
        assert_eq!(
            row.created_at.timestamp_millis(),
            stored.created_at().timestamp_millis()
        );
        assert_eq!(
            row.updated_at.timestamp_millis(),
            stored.updated_at().timestamp_millis()
        );
        assert_eq!(row.ip_address.as_deref(), stored.ip_address());
        assert_eq!(row.user_agent.as_deref(), stored.user_agent());
    }
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    db.set_timestamp("sessions", "created_at", ("token", &token(&owner)), old)
        .await?;
    let aged = db.tables(&["users", "accounts", "sessions"]).await?;
    let cached = auth
        .dispatch_endpoint(endpoint(false)?, options(&owner))
        .await?;
    assert_eq!(
        cached
            .decode()?
            .iter()
            .find(|row| row.token == token(&owner))
            .unwrap()
            .created_at,
        old
    );
    let stale = auth
        .dispatch_endpoint(endpoint(true)?, options(&owner))
        .await
        .unwrap_err();
    assert_eq!(stale.error.status_code(), 403);
    assert!(stale.error.to_string().contains("Session is not fresh"));
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, aged);
    db.set_timestamp("sessions", "expires_at", ("token", &token(&owner)), old)
        .await?;
    let expired = db.tables(&["users", "accounts", "sessions"]).await?;
    let cached = auth
        .dispatch_endpoint(endpoint(false)?, options(&owner))
        .await?;
    assert_eq!(
        cached
            .decode()?
            .iter()
            .map(|row| row.token.clone())
            .collect::<Vec<_>>(),
        vec![token(&peers[0])]
    );
    let absent = auth
        .dispatch_endpoint(endpoint(true)?, options(&owner))
        .await
        .unwrap_err();
    assert_eq!(absent.error.status_code(), 401);
    let after_expired_lookup = db.tables(&["users", "accounts", "sessions"]).await?;
    assert_eq!(after_expired_lookup[..2], expired[..2]);
    let expired_rows: Vec<Value> = serde_json::from_str(&expired[2])?;
    let retained: Vec<_> = expired_rows
        .into_iter()
        .filter(|row| row["token"] != token(&owner))
        .collect();
    assert_eq!(
        serde_json::from_str::<Vec<Value>>(&after_expired_lookup[2])?,
        retained
    );
    let foreign_list = auth
        .dispatch_endpoint(endpoint(false)?, options(&foreign))
        .await?;
    assert_eq!(
        foreign_list
            .decode()?
            .iter()
            .map(|row| row.token.clone())
            .collect::<Vec<_>>(),
        vec![token(&foreign)]
    );
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        observer
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|id| id.as_deref() == Some(&owner_id))
            .count(),
        4
    );
    B::close(connection).await
}
