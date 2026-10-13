//! Public logical password verification admits genuine current session authority.
use super::*;
use alibi::endpoint::{
    EndpointCall, EndpointHook, EndpointOptions, EndpointResponse, ServerEndpoint,
};
use alibi::plugins::password_management::{
    PasswordManagementConfig, PasswordManagementPlugin, VerifyPasswordRequest,
    VerifyPasswordResponse,
};
use alibi::{AuthContext, AuthResult};

backend_tests!(server_verify_password_validates_then_checks_authoritative_owner);

#[derive(Clone, Default)]
struct VerificationObserver(Arc<Mutex<Vec<(bool, Option<String>)>>>);
#[async_trait::async_trait]
impl<S: AuthSchema> EndpointHook<S> for VerificationObserver {
    fn matches_after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        _: &EndpointResponse,
    ) -> AuthResult<bool> {
        Ok(call.operation_id() == "verifyPassword")
    }
    async fn after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        response: EndpointResponse,
    ) -> AuthResult<EndpointResponse> {
        assert!(call.request().is_none());
        assert_eq!(call.path(), Some("/verify-password"));
        self.0.lock().unwrap().push((
            response.result().is_ok(),
            call.session().map(|(user, _)| user.id),
        ));
        Ok(response.with_header("x-verification-result", "logical"))
    }
}
fn verify_endpoint(password: &str) -> AuthResult<ServerEndpoint<VerifyPasswordResponse>> {
    PasswordManagementPlugin::verify_password_endpoint(&VerifyPasswordRequest {
        password: password.into(),
    })?
    .with_query(&json!({"disableRefresh":true}))
}
fn options(response: &AuthResponse) -> EndpointOptions {
    EndpointOptions {
        headers: Some([("cookie".into(), cookies(response))].into_iter().collect()),
        ..Default::default()
    }
}
async fn server_verify_password_validates_then_checks_authoritative_owner<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let observer = VerificationObserver::default();
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
        .plugin(PasswordManagementPlugin::with_config(
            PasswordManagementConfig {
                password_hasher: Some(Arc::new(super::auth_probe::FastHasher)),
                ..Default::default()
            },
        ))
        .build()
        .await?;
    let owner = signup(&auth, "logical-verify-owner@example.test").await;
    assert!(cookies(&owner).contains("better-auth.session_data="));
    let foreign = call(&auth, request("/sign-up/email", Some(json!({"email":"logical-verify-foreign@example.test","password":"foreign-password-123","name":"Foreign"})), ""), 200).await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let owner_token = body(&owner)["token"].as_str().unwrap().to_owned();
    db.set_timestamp(
        "session",
        "expiresAt",
        ("token", &owner_token),
        chrono::Utc::now() + chrono::Duration::hours(1),
    )
    .await?;
    let before = db.tables(&["user", "account", "session"]).await?;
    for input in [json!({}), json!({"password":null}), json!({"password":7})] {
        let rejected = auth
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("password-management", "verifyPassword")
                    .with_body_value(alibi::utils::json::parse_value(&input.to_string())?),
                EndpointOptions::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(rejected.error.status_code(), 400, "{rejected}");
        assert!(rejected.error.to_string().contains("[body.password]"));
    }
    let guest = auth
        .dispatch_endpoint(verify_endpoint(PASSWORD)?, EndpointOptions::default())
        .await
        .unwrap_err();
    assert_eq!(guest.error.status_code(), 401);
    for (password, authority) in [
        ("wrong-password", &owner),
        ("foreign-password-123", &owner),
        (PASSWORD, &foreign),
    ] {
        let wrong = auth
            .dispatch_endpoint(verify_endpoint(password)?, options(authority))
            .await
            .unwrap_err();
        assert_eq!(wrong.error.status_code(), 400);
        assert!(wrong.error.to_string().contains("Invalid password"));
    }
    for (password, authority) in [(PASSWORD, &owner), ("foreign-password-123", &foreign)] {
        let verified = auth
            .dispatch_endpoint(verify_endpoint(password)?, options(authority))
            .await?;
        assert!(verified.decode()?.status);
        assert_eq!(
            verified
                .headers()
                .get("x-verification-result")
                .map(String::as_str),
            Some("logical")
        );
        assert!(verified.headers().get_all("set-cookie").next().is_none());
    }
    assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    auth.store().delete_session(&owner_token).await?;
    let revoked_before = db.tables(&["user", "account", "session"]).await?;
    let revoked = auth
        .dispatch_endpoint(verify_endpoint(PASSWORD)?, options(&owner))
        .await
        .unwrap_err();
    assert_eq!(revoked.error.status_code(), 401);
    assert_eq!(
        db.tables(&["user", "account", "session"]).await?,
        revoked_before
    );
    {
        let events = observer.0.lock().unwrap();
        assert_eq!(events.iter().filter(|(success, _)| *success).count(), 2);
        assert!(
            events
                .iter()
                .any(|(success, id)| *success && id.as_deref() == Some(owner_id.as_str()))
        );
        assert!(events.last().unwrap().1.is_none());
    }
    B::close(connection).await
}
