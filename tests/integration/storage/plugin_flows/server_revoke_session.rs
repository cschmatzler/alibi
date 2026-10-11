//! Logical session revocation validates first and scopes deletion to genuine authority.
use super::*;
use alibi::endpoint::{
    EndpointCall, EndpointHook, EndpointOptions, EndpointResponse, ServerEndpoint,
};
use alibi::plugins::session_management::RevokeSessionRequest;
use alibi::{AuthContext, AuthResult, StatusResponse};

backend_tests!(server_revoke_session_preserves_foreign_authority_and_rejects_revoked_cache);

#[derive(Clone, Default)]
struct RevocationObserver(Arc<Mutex<Vec<Option<String>>>>);
#[async_trait::async_trait]
impl<S: AuthSchema> EndpointHook<S> for RevocationObserver {
    fn matches_after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        _: &EndpointResponse,
    ) -> AuthResult<bool> {
        Ok(call.operation_id() == "revokeSession")
    }
    async fn after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        response: EndpointResponse,
    ) -> AuthResult<EndpointResponse> {
        assert!(call.request().is_none());
        assert_eq!(call.path(), Some("/revoke-session"));
        self.0
            .lock()
            .unwrap()
            .push(call.session().map(|(user, _)| user.id));
        Ok(response.with_header("x-revocation-result", "logical"))
    }
}
fn revoke_endpoint(token: &str) -> AuthResult<ServerEndpoint<StatusResponse>> {
    SessionManagementPlugin::revoke_session_endpoint(&RevokeSessionRequest {
        token: token.into(),
    })?
    .with_query(&json!({"disableRefresh":true}))
}
fn options(response: &AuthResponse) -> EndpointOptions {
    EndpointOptions {
        headers: Some([("cookie".into(), cookies(response))].into_iter().collect()),
        ..Default::default()
    }
}
async fn server_revoke_session_preserves_foreign_authority_and_rejects_revoked_cache<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let observer = RevocationObserver::default();
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
        .plugin(SessionManagementPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "logical-revoke-owner@example.test").await;
    let other = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"logical-revoke-owner@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    let foreign = signup(&auth, "logical-revoke-foreign@example.test").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let owner_token = body(&owner)["token"].as_str().unwrap().to_owned();
    let other_token = body(&other)["token"].as_str().unwrap().to_owned();
    let foreign_token = body(&foreign)["token"].as_str().unwrap().to_owned();
    assert!(cookies(&owner).contains("better-auth.session_data="));
    db.set_timestamp(
        "sessions",
        "expires_at",
        ("token", &owner_token),
        chrono::Utc::now() + chrono::Duration::hours(1),
    )
    .await?;
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    for input in [json!({}), json!({"token":null}), json!({"token":7})] {
        let denied = auth
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("session-management", "revokeSession")
                    .with_body(&input)?,
                EndpointOptions::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(denied.error.status_code(), 400, "{denied}");
        assert!(denied.error.to_string().contains("[body.token]"));
    }
    let missing_headers = auth
        .dispatch_endpoint(revoke_endpoint(&other_token)?, EndpointOptions::default())
        .await
        .unwrap_err();
    assert_eq!(missing_headers.error.status_code(), 400);
    assert!(
        missing_headers
            .error
            .to_string()
            .contains("Headers is required")
    );
    let guest = auth
        .dispatch_endpoint(
            revoke_endpoint(&other_token)?,
            EndpointOptions {
                headers: Some(Default::default()),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(guest.error.status_code(), 401);
    for token in [&foreign_token, "missing-session", ""] {
        let noop = auth
            .dispatch_endpoint(revoke_endpoint(token)?, options(&owner))
            .await?;
        assert!(noop.decode()?.status);
        assert!(noop.headers().get_all("set-cookie").next().is_none());
    }
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    let revoked = auth
        .dispatch_endpoint(revoke_endpoint(&other_token)?, options(&owner))
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
    assert!(auth.store().get_session(&other_token).await?.is_none());
    assert!(auth.store().get_session(&owner_token).await?.is_some());
    assert!(auth.store().get_session(&foreign_token).await?.is_some());
    let current = db.tables(&["users", "accounts", "sessions"]).await?;
    assert_eq!(current[..2], before[..2]);
    let stale = auth
        .dispatch_endpoint(revoke_endpoint(&foreign_token)?, options(&other))
        .await
        .unwrap_err();
    assert_eq!(stale.error.status_code(), 401);
    assert_eq!(
        db.tables(&["users", "accounts", "sessions"]).await?,
        current
    );
    let self_revoke = auth
        .dispatch_endpoint(revoke_endpoint(&owner_token)?, options(&owner))
        .await?;
    assert!(self_revoke.decode()?.status);
    assert!(self_revoke.headers().get_all("set-cookie").next().is_none());
    assert!(auth.store().get_session(&owner_token).await?.is_none());
    let after = db.tables(&["users", "accounts", "sessions"]).await?;
    let stale = auth
        .dispatch_endpoint(revoke_endpoint(&foreign_token)?, options(&owner))
        .await
        .unwrap_err();
    assert_eq!(stale.error.status_code(), 401);
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, after);
    assert!(auth.store().get_session(&foreign_token).await?.is_some());
    {
        let events = observer.0.lock().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|id| id.as_deref() == Some(&owner_id))
                .count(),
            5
        );
        assert!(events.last().unwrap().is_none());
    }
    B::close(connection).await
}
