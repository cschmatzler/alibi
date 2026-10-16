use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::entity::AuthSession as _;
use alibi::integrations::axum::AxumIntegration;
use axum::{Router, body::Body, http::Request};
use tower::ServiceExt as _;

backend_tests!(
    session_post_media_is_admitted_before_refresh_and_keeps_logical_calls_transport_free
);
postgres_tests!(
    session_post_media_is_admitted_before_refresh_and_keeps_logical_calls_transport_free
);

async fn session_post_media_is_admitted_before_refresh_and_keeps_logical_calls_transport_free<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.session.defer_session_refresh = true;
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .build()
        .await?;
    let auth = Arc::new(auth);
    let router = Router::new()
        .nest("/api/auth", Arc::clone(&auth).axum_router())
        .with_state(Arc::clone(&auth));
    let owner = signup(&auth, "session-media-owner@example.test").await;
    let token = body(&owner)["token"].as_str().unwrap().to_owned();
    let cookie = cookies(&owner);
    let expires = chrono::Utc::now() + chrono::Duration::hours(1);
    db.set_timestamp("session", "expiresAt", ("token", &token), expires)
        .await?;
    let original = db.tables(&["session"]).await?;
    for (content_type, bytes, status, code, message) in [
        (
            None,
            None,
            415,
            "UNSUPPORTED_MEDIA_TYPE",
            "Content-Type is required. Allowed types: application/json",
        ),
        (
            Some("text/plain"),
            Some(""),
            415,
            "UNSUPPORTED_MEDIA_TYPE",
            "Content-Type \"text/plain\" is not allowed. Allowed types: application/json",
        ),
        (
            Some("application/json"),
            None,
            400,
            "BAD_REQUEST",
            "Invalid JSON in request body",
        ),
        (
            Some("application/json"),
            Some("{"),
            400,
            "BAD_REQUEST",
            "Invalid JSON in request body",
        ),
    ] {
        let mut input = Request::builder()
            .method("POST")
            .uri("/api/auth/get-session")
            .header("origin", ORIGIN)
            .header("cookie", &cookie);
        if let Some(content_type) = content_type {
            input = input.header("content-type", content_type);
        }
        let response = router
            .clone()
            .oneshot(input.body(Body::from(bytes.unwrap_or_default()))?)
            .await?;
        assert_eq!(response.status().as_u16(), status);
        assert!(!response.headers().contains_key("set-cookie"));
        let returned: Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1024 * 1024).await?,
        )?;
        assert_eq!(returned, json!({"code":code,"message":message}));
        assert_eq!(db.tables(&["session"]).await?, original);
    }
    let logical = auth
        .dispatch_endpoint(
            SessionManagementPlugin::get_session_endpoint(),
            EndpointOptions {
                method: Some(HttpMethod::Post),
                headers: Some([("cookie".into(), cookie.clone())].into_iter().collect()),
                ..Default::default()
            },
        )
        .await?;
    let session = logical.decode()?;
    assert_eq!(session.as_ref().unwrap().session.token(), token);
    assert!(session.unwrap().session.expires_at() > expires + chrono::Duration::days(6));
    db.set_timestamp("session", "expiresAt", ("token", &token), expires)
        .await?;
    let renewed = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/get-session")
                .header("origin", ORIGIN)
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from("{}"))?,
        )
        .await?;
    assert_eq!(renewed.status().as_u16(), 200);
    let returned: Value =
        serde_json::from_slice(&axum::body::to_bytes(renewed.into_body(), 1024 * 1024).await?)?;
    assert_eq!(returned["session"]["token"], token);
    assert!(
        auth.store()
            .get_session(&token)
            .await?
            .unwrap()
            .expires_at()
            > expires + chrono::Duration::days(6)
    );
    Ok(())
}
