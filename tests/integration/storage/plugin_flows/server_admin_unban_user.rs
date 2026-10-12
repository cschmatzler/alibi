//! Unbanning clears stored flags without restoring previously revoked sessions.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{AdminPlugin, RolePermissions};
use alibi::utils::json::JsValue;
use alibi::{AuthUser, UpdateUser};

backend_tests!(server_admin_unban_user_clears_ban_fields_without_restoring_sessions);

async fn server_admin_unban_user_clears_ban_fields_without_restoring_sessions<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config.clone()), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(AdminPlugin::new())
        .endpoint_hook(super::server_admin_support::AdminObserver)
        .build()
        .await?;
    let admin = signup(&auth, "server-unban-admin@example.test").await;
    let admin_id = body(&admin)["user"]["id"].as_str().unwrap().to_owned();
    drop(
        auth.store()
            .update_user(
                &admin_id,
                UpdateUser {
                    role: Some("admin".into()),
                    ..Default::default()
                },
            )
            .await?,
    );
    let target = signup(&auth, "server-unban-target@example.test").await;
    let id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
    let foreign = signup(&auth, "server-unban-foreign@example.test").await;
    let options = |response: &AuthResponse| EndpointOptions {
        headers: Some([("cookie".into(), cookies(response))].into_iter().collect()),
        ..Default::default()
    };
    let banned = call(
        &auth,
        request(
            "/admin/ban-user",
            Some(json!({"userId":id,"banReason":"review","banExpiresIn":3600})),
            &cookies(&admin),
        ),
        200,
    )
    .await;
    assert_eq!(body(&banned)["user"]["banned"], true);
    assert!(body(&banned)["user"]["banExpires"].is_string());
    assert!(auth.store().get_user_sessions(&id).await?.is_empty());
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    for (input, headers, status, code) in [
        (None, EndpointOptions::default(), 400, "VALIDATION_ERROR"),
        (
            Some(json!(null)),
            EndpointOptions::default(),
            400,
            "VALIDATION_ERROR",
        ),
        (
            Some(json!(7)),
            EndpointOptions::default(),
            400,
            "VALIDATION_ERROR",
        ),
        (
            Some(json!({"userId":{"toString":"bad"}})),
            options(&admin),
            400,
            "VALIDATION_ERROR",
        ),
        (
            Some(json!({"userId":id})),
            EndpointOptions::default(),
            401,
            "",
        ),
        (
            Some(json!({"userId":id})),
            EndpointOptions {
                headers: Some(Default::default()),
                ..Default::default()
            },
            401,
            "",
        ),
        (
            Some(json!({"userId":id})),
            options(&foreign),
            403,
            "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS",
        ),
        (
            Some(json!({"userId":"missing-user"})),
            options(&admin),
            404,
            "USER_NOT_FOUND",
        ),
        (
            Some(json!({"userId":null})),
            options(&admin),
            404,
            "USER_NOT_FOUND",
        ),
        (
            Some(json!({"userId":7})),
            options(&admin),
            404,
            "USER_NOT_FOUND",
        ),
        (
            Some(json!({"userId":[]})),
            options(&admin),
            404,
            "USER_NOT_FOUND",
        ),
    ] {
        let mut endpoint = ServerEndpoint::<JsValue>::new("admin", "unbanUser");
        if let Some(input) = input {
            endpoint = endpoint.with_body(&input)?;
        }
        let error = auth.dispatch_endpoint(endpoint, headers).await.unwrap_err();
        assert_eq!(error.error.status_code(), status);
        if status == 401 {
            assert!(error.body_absent);
        } else {
            assert_eq!(body(&error.error.to_auth_response())["code"], code);
        }
    }
    let no_ban = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .plugin(SessionManagementPlugin::new())
        .plugin(AdminPlugin::new().roles(std::collections::HashMap::from([(
            "admin".into(),
            RolePermissions::new().allow("user", ["update"]),
        )])))
        .build()
        .await?;
    let error = no_ban
        .dispatch_endpoint(
            ServerEndpoint::<JsValue>::new("admin", "unbanUser")
                .with_body(&json!({"userId":id}))?,
            options(&admin),
        )
        .await
        .unwrap_err();
    assert_eq!(error.error.status_code(), 403);
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    let immutable = db.tables(&["accounts", "sessions"]).await?;
    let original_admin =
        serde_json::to_value(auth.store().get_user_by_id(&admin_id).await?.unwrap())?;
    let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
    let original_foreign =
        serde_json::to_value(auth.store().get_user_by_id(&foreign_id).await?.unwrap())?;
    for _ in 0..2 {
        let output = auth
            .dispatch_endpoint(
                AdminPlugin::unban_user_endpoint(id.clone())
                    .with_body(&json!({"userId":id,"banReason":"forged","banned":true}))?
                    .with_query(&json!({"userId":foreign_id}))?,
                options(&admin),
            )
            .await?;
        assert_eq!(output.decode()?.user.values().get("id"), Some(&json!(id)));
        let user = output.value().get("user").unwrap();
        assert_eq!(user.get("id"), Some(&JsValue::String(id.clone())));
        assert_eq!(user.get("banned"), Some(&JsValue::Bool(false)));
        assert_eq!(user.get("banReason"), Some(&JsValue::Null));
        assert_eq!(user.get("banExpires"), Some(&JsValue::Null));
        assert!(user.get("password").is_none());
        let stored = auth.store().get_user_by_id(&id).await?.unwrap();
        assert!(!stored.banned());
        assert_eq!(stored.ban_reason(), None);
        assert_eq!(stored.ban_expires(), None);
        assert_eq!(stored.email(), Some("server-unban-target@example.test"));
        assert_eq!(stored.role(), Some("user"));
        assert_eq!(output.headers().get("x-admin-principal"), Some(&admin_id));
        assert_eq!(
            output
                .headers()
                .get_all("set-cookie")
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec![
                "application_a=first; Path=/; HttpOnly",
                "application_b=second; Path=/; HttpOnly"
            ]
        );
        assert_eq!(db.tables(&["accounts", "sessions"]).await?, immutable);
        assert_eq!(
            serde_json::to_value(auth.store().get_user_by_id(&admin_id).await?.unwrap())?,
            original_admin
        );
        assert_eq!(
            serde_json::to_value(auth.store().get_user_by_id(&foreign_id).await?.unwrap())?,
            original_foreign
        );
    }
    let old = call(&auth, request("/get-session", None, &cookies(&target)), 200).await;
    assert_eq!(body(&old), Value::Null);
    let login = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"server-unban-target@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    assert_eq!(body(&login)["user"]["id"], id);
    assert_eq!(auth.store().get_user_sessions(&id).await?.len(), 1);
    B::close(connection).await
}
