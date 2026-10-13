//! Default direct session updates validate records before admitting their owner.
use super::server_revocation_support::{Observer, options};
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};

backend_tests!(server_update_session_validates_records_and_preserves_default_owner);
async fn server_update_session_validates_records_and_preserves_default_owner<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let observer = Observer::new("updateSession", "/update-session");
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .endpoint_hook(observer.clone())
        .plugin(super::auth_probe::fast_password())
        .build()
        .await?;
    let owner = signup(&auth, "logical-session-owner@example.test").await;
    let foreign = signup(&auth, "logical-session-foreign@example.test").await;
    let before = db.tables(&["user", "account", "session"]).await?;
    for input in [json!(null), json!([]), json!(7)] {
        let denied = auth
            .dispatch_endpoint(
                SessionManagementPlugin::update_session_endpoint(&input)?,
                EndpointOptions::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(denied.error.status_code(), 400, "{denied}");
        assert!(denied.error.to_string().contains("[body]"));
    }
    let endpoint = || {
        ServerEndpoint::<Value>::new("session-management", "updateSession")
            .with_body(&json!({"label":"guest"}))
    };
    let guest = auth
        .dispatch_endpoint(endpoint()?, EndpointOptions::default())
        .await
        .unwrap_err();
    assert_eq!(guest.error.status_code(), 401);
    for input in [
        json!({}),
        json!({"token":body(&foreign)["token"],"userId":body(&foreign)["user"]["id"],"expiresAt":"2099-01-01T00:00:00.000Z"}),
    ] {
        let denied = auth
            .dispatch_endpoint(
                SessionManagementPlugin::update_session_endpoint(&input)?
                    .with_query(&json!({"disableRefresh":true}))?,
                options(&owner),
            )
            .await
            .unwrap_err();
        assert_eq!(denied.error.status_code(), 400);
        assert!(denied.error.to_string().contains("No fields to update"));
    }
    assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    let events = observer.0.lock().unwrap().clone();
    assert_eq!(
        events.last().unwrap().as_deref(),
        body(&owner)["user"]["id"].as_str()
    );
    B::close(connection).await
}
