//! Builtin logical profile updates publish actual updated browser authority.
use super::*;
use alibi::endpoint::{
    EndpointCall, EndpointHook, EndpointOptions, EndpointResponse, ServerEndpoint,
};
use alibi::{AuthContext, AuthResult, entity::AuthUser};
backend_tests!(
    server_update_user_is_builtin_and_publishes_owned_profile,
    server_phone_profile_guard_precedes_admission
);
postgres_tests!(server_phone_profile_guard_precedes_admission);

async fn server_phone_profile_guard_precedes_admission<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .plugin(alibi::plugins::phone_number::PhoneNumberPlugin::new(
            Default::default(),
        ))
        .build()
        .await?;
    for phone in [
        json!(""),
        json!(0),
        json!(false),
        json!([]),
        json!({}),
        json!("+15555555555"),
    ] {
        let denied = auth
            .dispatch_endpoint(
                update_endpoint(&json!({"phoneNumber":phone,"name":42}))?,
                EndpointOptions {
                    headers: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert_eq!(denied.error.status_code(), 400);
        assert_eq!(
            serde_json::from_slice::<Value>(&denied.error.to_auth_response().body)?,
            json!({"code":"PHONE_NUMBER_CANNOT_BE_UPDATED","message":"Phone number cannot be updated"})
        );
    }
    for body in [
        None,
        Some(json!(null)),
        Some(json!(1)),
        Some(json!("x")),
        Some(json!(false)),
        Some(json!([])),
        Some(json!({})),
        Some(json!({"phoneNumber":null})),
    ] {
        let mut endpoint = ServerEndpoint::<Value>::new("core", "updateUser");
        if let Some(body) = &body {
            endpoint = endpoint.with_body(body)?;
        }
        let denied = auth
            .dispatch_endpoint(
                endpoint,
                EndpointOptions {
                    headers: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        let expected = match &body {
            Some(Value::Object(_)) => 401,
            Some(Value::Array(_)) => 400,
            _ => 500,
        };
        assert_eq!(denied.error.status_code(), expected, "{body:?}: {denied}");
        if expected == 500 {
            assert!(
                denied
                    .error
                    .to_string()
                    .contains("An error occurred during hook matcher execution")
            );
        }
    }
    assert_eq!(
        db.tables(&["user", "session", "verification"]).await?,
        vec!["[]".to_owned(); 3]
    );
    B::close(connection).await
}

#[derive(Clone, Default)]
struct ProfileObserver(Arc<Mutex<Vec<Option<String>>>>);
#[async_trait::async_trait]
impl<S: AuthSchema> EndpointHook<S> for ProfileObserver {
    fn matches_after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        _: &EndpointResponse,
    ) -> AuthResult<bool> {
        Ok(call.operation_id() == "updateUser")
    }
    async fn after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        response: EndpointResponse,
    ) -> AuthResult<EndpointResponse> {
        assert!(call.request().is_none());
        assert_eq!(call.path(), Some("/update-user"));
        self.0
            .lock()
            .unwrap()
            .push(call.session().map(|(user, _)| user.id));
        Ok(response
            .with_header("x-profile-result", "logical")
            .with_header("set-cookie", "profile-first=owned; Path=/; HttpOnly")
            .with_header("set-cookie", "profile-second=owned; Path=/; HttpOnly"))
    }
}
fn update_endpoint(body: &Value) -> AuthResult<ServerEndpoint<alibi::StatusResponse>> {
    alibi::plugins::user_management::update_user_endpoint(body)?
        .with_query(&json!({"disableRefresh":true}))
}
fn physical_user(snapshot: &[String], user_id: &str) -> Value {
    serde_json::from_str::<Vec<Value>>(&snapshot[0])
        .unwrap()
        .into_iter()
        .find(|row| row["id"] == user_id)
        .unwrap()
}
fn options(cookie: &str) -> EndpointOptions {
    EndpointOptions {
        headers: Some([("cookie".into(), cookie.into())].into_iter().collect()),
        ..Default::default()
    }
}
async fn server_update_user_is_builtin_and_publishes_owned_profile<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let observer = ProfileObserver::default();
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.session.cookie_cache = Some(alibi::CookieCacheConfig {
        enabled: true,
        max_age: 300.0,
        ..Default::default()
    });
    // No UserManagementPlugin: profile updates are a builtin operation.
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .endpoint_hook(observer.clone())
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "logical-profile-owner@example.test").await;
    let foreign = signup(&auth, "logical-profile-foreign@example.test").await;
    let cookie = cookies(&owner);
    assert!(cookie.contains("better-auth.session_data="));
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
    let token = body(&owner)["token"].as_str().unwrap().to_owned();
    let sessions = db.tables(&["session", "account"]).await?;
    let foreign_before = auth.store().get_user_by_id(&foreign_id).await?.unwrap();
    let users_before = db.tables(&["user"]).await?;
    let foreign_physical = physical_user(&users_before, &foreign_id);
    for invalid in [json!([]), json!(null), json!("profile")] {
        let rejection = auth
            .dispatch_endpoint(update_endpoint(&invalid)?, EndpointOptions::default())
            .await
            .unwrap_err();
        assert_eq!(rejection.error.status_code(), 400, "{rejection}");
        assert!(rejection.error.to_string().contains("[body]"));
    }
    let guest = auth
        .dispatch_endpoint(
            update_endpoint(&json!({"name":"Guest"}))?,
            EndpointOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(guest.error.status_code(), 401);
    let denied = auth
        .dispatch_endpoint(
            update_endpoint(&json!({"email":"foreign@example.test"}))?,
            options(&cookie),
        )
        .await
        .unwrap_err();
    assert_eq!(denied.error.status_code(), 400);
    assert_eq!(db.tables(&["user"]).await?, users_before);
    for (input, expected_image) in [
        (
            json!({"name":"Logical Profile","image":"https://example.test/avatar.png"}),
            Some("https://example.test/avatar.png"),
        ),
        (json!({"image":null}), None),
    ] {
        let updated = auth
            .dispatch_endpoint(update_endpoint(&input)?, options(&cookie))
            .await?;
        assert!(updated.decode()?.status);
        assert!(!updated.headers().contains_key("content-type"));
        assert_eq!(
            updated
                .headers()
                .get("x-profile-result")
                .map(String::as_str),
            Some("logical")
        );
        for expected in [
            "profile-first=owned; Path=/; HttpOnly",
            "profile-second=owned; Path=/; HttpOnly",
        ] {
            assert!(
                updated
                    .headers()
                    .get_all("set-cookie")
                    .any(|header| header == expected)
            );
        }
        assert!(
            updated
                .headers()
                .get_all("set-cookie")
                .any(|header| header.starts_with("better-auth.session_data="))
        );
        let receipt = updated
            .headers()
            .get_all("set-cookie")
            .map(|raw| raw.split(';').next().unwrap())
            .collect::<Vec<_>>()
            .join("; ");
        let restored = call(&auth, request("/get-session", None, &receipt), 200).await;
        assert_eq!(body(&restored)["user"]["id"], owner_id);
        assert_eq!(body(&restored)["user"]["name"], "Logical Profile");
        assert_eq!(
            body(&restored)["user"]["image"],
            expected_image.map_or(Value::Null, |value| json!(value))
        );
        assert_eq!(body(&restored)["session"]["token"], token);
        let stored = auth.store().get_user_by_id(&owner_id).await?.unwrap();
        assert_eq!(stored.name(), Some("Logical Profile"));
        assert_eq!(stored.image(), expected_image);
        assert_eq!(db.tables(&["session", "account"]).await?, sessions);
    }
    assert_eq!(
        physical_user(&db.tables(&["user"]).await?, &foreign_id),
        foreign_physical
    );
    let foreign_after = auth.store().get_user_by_id(&foreign_id).await?.unwrap();
    assert_eq!(foreign_after.updated_at(), foreign_before.updated_at());
    assert_eq!(foreign_after.name(), foreign_before.name());
    {
        let events = observer.0.lock().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|id| id.as_deref() == Some(owner_id.as_str()))
                .count(),
            3
        );
    }
    B::close(connection).await
}
