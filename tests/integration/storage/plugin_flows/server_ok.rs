//! The default public health operation ignores input and credentials without reading auth state.
use super::auth_probe::fast_builder;
use super::server_revocation_support::{Observer, options};
use super::*;
use alibi::endpoint::EndpointOptions;

backend_tests!(server_ok_ignores_input_and_credentials_without_auth_state_changes);
async fn server_ok_ignores_input_and_credentials_without_auth_state_changes<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let observer = Observer::new("ok", "/ok");
    let auth = fast_builder::<B>(&connection)
        .endpoint_hook(observer.clone())
        .build()
        .await?;
    let owner = signup(&auth, "logical-health-owner@example.test").await;
    let before = db
        .tables(&["user", "account", "session", "verification"])
        .await?;
    for (body, query, options) in [
        (None, None, EndpointOptions::default()),
        (Some(json!(null)), Some(json!(7)), options(&owner)),
        (
            Some(json!({"userId":body(&owner)["user"]["id"],"ok":false})),
            Some(json!(["ignored"])),
            EndpointOptions {
                headers: Some(
                    [("authorization".into(), "Bearer invalid.signature".into())]
                        .into_iter()
                        .collect(),
                ),
                ..Default::default()
            },
        ),
    ] {
        let mut endpoint = alibi::plugins::user_management::ok_endpoint();
        if let Some(body) = body {
            endpoint = endpoint.with_body(&body)?;
        }
        if let Some(query) = query {
            endpoint = endpoint.with_query(&query)?;
        }
        let result = auth.dispatch_endpoint(endpoint, options).await?;
        assert!(result.decode()?.ok);
        assert_eq!(serde_json::to_value(result.value())?, json!({"ok":true}));
        assert_eq!(
            result
                .headers()
                .get("x-revocation-result")
                .map(String::as_str),
            Some("logical")
        );
        assert!(result.headers().get_all("set-cookie").next().is_none());
        assert_eq!(
            db.tables(&["user", "account", "session", "verification"])
                .await?,
            before
        );
    }
    {
        let events = observer.0.lock().unwrap();
        assert_eq!(events.len(), 3);
        assert!(events.iter().all(Option::is_none));
    }
    B::close(connection).await
}
