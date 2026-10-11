//! Direct password changes expose actual projected results and usable replacement authority.
use super::*;
use alibi::endpoint::{
    EndpointCall, EndpointHook, EndpointOptions, EndpointResponse, ServerEndpoint,
};
use alibi::plugins::password_management::{
    ChangePasswordRequest, ChangePasswordResponse, PasswordManagementConfig,
    PasswordManagementPlugin,
};
use alibi::{AuthContext, AuthResult, entity::AuthSession};

fn change_endpoint(
    input: &ChangePasswordRequest,
) -> AuthResult<ServerEndpoint<ChangePasswordResponse<alibi::UserView>>> {
    PasswordManagementPlugin::change_password_endpoint(input)?
        .with_query(&json!({"disableRefresh":true}))
}

backend_tests!(server_change_password_preserves_logical_authority_and_returns_usable_rotation);

#[derive(Clone, Default)]
struct PasswordObserver(Arc<Mutex<Vec<(bool, Option<String>)>>>);
#[async_trait::async_trait]
impl<S: AuthSchema> EndpointHook<S> for PasswordObserver {
    fn matches_before(&self, call: &EndpointCall, _: &AuthContext<S>) -> AuthResult<bool> {
        Ok(call.operation_id() == "changePassword")
    }
    fn matches_after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        _: &EndpointResponse,
    ) -> AuthResult<bool> {
        Ok(call.operation_id() == "changePassword")
    }
    async fn after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        response: EndpointResponse,
    ) -> AuthResult<EndpointResponse> {
        assert!(call.request().is_none());
        assert_eq!(call.path(), Some("/change-password"));
        self.0.lock().unwrap().push((
            response.result().is_ok(),
            call.session().map(|(user, _)| user.id),
        ));
        Ok(response
            .with_header("x-password-result", "logical")
            .with_header("set-cookie", "password-first=owned; Path=/; HttpOnly")
            .with_header("set-cookie", "password-second=owned; Path=/; HttpOnly"))
    }
}
fn physical_owner(snapshot: &[String], user_id: &str) -> Vec<Vec<Value>> {
    snapshot
        .iter()
        .map(|table| {
            serde_json::from_str::<Vec<Value>>(table)
                .unwrap()
                .into_iter()
                .filter(|row| row["user_id"] == user_id || row["id"] == user_id)
                .collect()
        })
        .collect()
}
fn options(response: &AuthResponse) -> EndpointOptions {
    EndpointOptions {
        headers: Some(
            [
                ("cookie".into(), cookies(response)),
                ("user-agent".into(), "Logical-password-agent".into()),
                ("x-forwarded-for".into(), "198.51.100.31".into()),
            ]
            .into_iter()
            .collect(),
        ),
        ..Default::default()
    }
}
async fn server_change_password_preserves_logical_authority_and_returns_usable_rotation<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let observer = PasswordObserver::default();
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
    let owner = signup(&auth, "logical-password-owner@example.test").await;
    let sibling = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"logical-password-owner@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    let foreign = signup(&auth, "logical-password-foreign@example.test").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let foreign_token = body(&foreign)["token"].as_str().unwrap().to_owned();
    // A due physical session must remain unrenewed when the logical caller disables refresh.
    db.set_timestamp(
        "sessions",
        "expires_at",
        ("token", body(&owner)["token"].as_str().unwrap()),
        chrono::Utc::now() + chrono::Duration::hours(1),
    )
    .await?;
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
    let foreign_physical = physical_owner(&before, &foreign_id);
    for input in [
        json!({"newPassword":"a-new-password-123"}),
        json!({"newPassword":"a-new-password-123","currentPassword":PASSWORD,"revokeOtherSessions":"true"}),
    ] {
        let error = auth
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("password-management", "changePassword")
                    .with_body_value(alibi::utils::json::parse_value(&input.to_string())?),
                EndpointOptions::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), 400, "{error}");
        assert!(error.error.to_string().contains("[body."));
    }
    let input = ChangePasswordRequest {
        current_password: "incorrect-password".into(),
        new_password: "a-new-password-123".into(),
        revoke_other_sessions: Some(false),
    };
    let guest = auth
        .dispatch_endpoint(change_endpoint(&input)?, EndpointOptions::default())
        .await
        .unwrap_err();
    assert_eq!(guest.error.status_code(), 401);
    let wrong = auth
        .dispatch_endpoint(change_endpoint(&input)?, options(&owner))
        .await
        .unwrap_err();
    assert_eq!(wrong.error.status_code(), 400);
    assert!(wrong.error.to_string().contains("Invalid password"));
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    let original_users_sessions = db.tables(&["users", "sessions"]).await?;
    let input = ChangePasswordRequest {
        current_password: PASSWORD.into(),
        new_password: "a-kept-password-123".into(),
        revoke_other_sessions: None,
    };
    let kept = auth
        .dispatch_endpoint(change_endpoint(&input)?, options(&owner))
        .await?;
    let receipt = kept.decode()?;
    assert!(receipt.token.is_none());
    assert_eq!(receipt.user.id, owner_id);
    assert_eq!(
        receipt.user.email.as_deref(),
        Some("logical-password-owner@example.test")
    );
    assert_eq!(
        db.tables(&["users", "sessions"]).await?,
        original_users_sessions
    );
    assert!(
        !kept
            .headers()
            .get_all("set-cookie")
            .any(|header| header.starts_with("better-auth.session_token="))
    );
    for response in [&owner, &sibling, &foreign] {
        let mut read = request("/get-session", None, &cookies(response));
        _ = read.query.insert("disableRefresh".into(), "true".into());
        let _ = call(&auth, read, 200).await;
    }
    let explicit_false = ChangePasswordRequest {
        current_password: "a-kept-password-123".into(),
        new_password: "a-kept-password-123".into(),
        revoke_other_sessions: Some(false),
    };
    let false_result = auth
        .dispatch_endpoint(change_endpoint(&explicit_false)?, options(&owner))
        .await?;
    assert!(false_result.decode()?.token.is_none());
    assert!(
        !false_result
            .headers()
            .get_all("set-cookie")
            .any(|header| header.starts_with("better-auth.session_token="))
    );
    assert_eq!(
        db.tables(&["users", "sessions"]).await?,
        original_users_sessions
    );
    let foreign_before = auth.store().get_session(&foreign_token).await?.unwrap();
    let input = ChangePasswordRequest {
        current_password: "a-kept-password-123".into(),
        new_password: "a-rotated-password-123".into(),
        revoke_other_sessions: Some(true),
    };
    let rotated = auth
        .dispatch_endpoint(change_endpoint(&input)?, options(&owner))
        .await?;
    let receipt = rotated.decode()?;
    assert_eq!(receipt.user.id, owner_id);
    let token = receipt.token.unwrap();
    let actual = auth.store().get_session(&token).await?.unwrap();
    assert_eq!(actual.user_id().as_ref(), owner_id);
    assert_eq!(actual.user_agent(), Some("Logical-password-agent"));
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM sessions WHERE user_id = $1",
            &[&owner_id]
        )
        .await?,
        1
    );
    assert_eq!(
        rotated
            .headers()
            .get("x-password-result")
            .map(String::as_str),
        Some("logical")
    );
    for application_cookie in [
        "password-first=owned; Path=/; HttpOnly",
        "password-second=owned; Path=/; HttpOnly",
    ] {
        assert!(
            rotated
                .headers()
                .get_all("set-cookie")
                .any(|header| header == application_cookie)
        );
    }
    let restored_cookie = rotated
        .headers()
        .get_all("set-cookie")
        .map(|header| header.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ");
    let restored = call(&auth, request("/get-session", None, &restored_cookie), 200).await;
    assert_eq!(body(&restored)["session"]["token"], token);
    assert_eq!(body(&restored)["user"]["id"], owner_id);
    // Both old cookies still include unexpired cache data. Sensitive logical calls
    // must re-read storage and reject them without changing the new credential.
    let after = db.tables(&["users", "accounts", "sessions"]).await?;
    assert_eq!(physical_owner(&after, &foreign_id), foreign_physical);
    for response in [&owner, &sibling] {
        let rejected = auth
            .dispatch_endpoint(change_endpoint(&input)?, options(response))
            .await
            .unwrap_err();
        assert_eq!(rejected.error.status_code(), 401);
        assert!(
            auth.store()
                .get_session(body(response)["token"].as_str().unwrap())
                .await?
                .is_none()
        );
    }
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, after);
    let foreign_after = auth.store().get_session(&foreign_token).await?.unwrap();
    assert_eq!(foreign_after.created_at(), foreign_before.created_at());
    assert_eq!(foreign_after.updated_at(), foreign_before.updated_at());
    assert_eq!(foreign_after.expires_at(), foreign_before.expires_at());
    let _ = call(
        &auth,
        request("/get-session", None, &cookies(&foreign)),
        200,
    )
    .await;
    let signin = call(&auth, request("/sign-in/email", Some(json!({"email":"logical-password-owner@example.test","password":"a-rotated-password-123"})), ""), 200).await;
    assert_eq!(body(&signin)["user"]["id"], owner_id);
    {
        let events = observer.0.lock().unwrap();
        assert_eq!(events.iter().filter(|(success, _)| *success).count(), 3);
        assert!(
            events
                .iter()
                .filter(|(success, _)| *success)
                .all(|(_, id)| id.as_deref() == Some(owner_id.as_str()))
        );
    }
    B::close(connection).await
}
