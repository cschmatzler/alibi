//! Logical ban policy owns persisted flags and target-session revocation.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{AdminBanUserRequest, AdminConfig, AdminPlugin, RolePermissions};
use alibi::utils::json::JsValue;
use alibi::{AuthUser, UpdateUser};

backend_tests!(server_admin_ban_user_applies_policy_and_revokes_target_sessions);

async fn server_admin_ban_user_applies_policy_and_revokes_target_sessions<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(AdminPlugin::new())
        .endpoint_hook(super::server_admin_support::AdminObserver)
        .build()
        .await?;
    let admin = signup(&auth, "server-ban-admin@example.test").await;
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
    let target = signup(&auth, "server-ban-target@example.test").await;
    let id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
    let foreign = signup(&auth, "server-ban-foreign@example.test").await;
    drop(
        call(
            &auth,
            request(
                "/sign-in/email",
                Some(json!({"email":"server-ban-target@example.test","password":PASSWORD})),
                "",
            ),
            200,
        )
        .await,
    );
    assert_eq!(auth.store().get_user_sessions(&id).await?.len(), 2);
    let options = |response: &AuthResponse| EndpointOptions {
        headers: Some([("cookie".into(), cookies(response))].into_iter().collect()),
        ..Default::default()
    };
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    for (input, headers, status, code) in [
        (None, EndpointOptions::default(), 400, "VALIDATION_ERROR"),
        (
            Some(json!({"userId":id,"banReason":null})),
            EndpointOptions::default(),
            400,
            "VALIDATION_ERROR",
        ),
        (
            Some(json!({"userId":id,"banExpiresIn":"60"})),
            EndpointOptions::default(),
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
            options(&foreign),
            403,
            "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS",
        ),
        (
            Some(json!({"userId":admin_id})),
            options(&admin),
            400,
            "YOU_CANNOT_BAN_YOURSELF",
        ),
        (
            Some(json!({"userId":null})),
            options(&admin),
            404,
            "USER_NOT_FOUND",
        ),
        (
            Some(json!({"userId":"missing"})),
            options(&admin),
            404,
            "USER_NOT_FOUND",
        ),
    ] {
        let mut endpoint = ServerEndpoint::<JsValue>::new("admin", "banUser");
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
    let profile_config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let no_ban = AuthBuilder::new(profile_config.clone())
        .store(B::store(Arc::new(profile_config.clone()), &connection))
        .plugin(SessionManagementPlugin::new())
        .plugin(AdminPlugin::new().roles(std::collections::HashMap::from([(
            "admin".into(),
            RolePermissions::new().allow("user", ["update"]),
        )])))
        .build()
        .await?;
    let denied = no_ban
        .dispatch_endpoint(
            ServerEndpoint::<JsValue>::new("admin", "banUser").with_body(&json!({"userId":id}))?,
            options(&admin),
        )
        .await
        .unwrap_err();
    assert_eq!(denied.error.status_code(), 403);
    let invalid = auth
        .dispatch_endpoint(
            ServerEndpoint::<JsValue>::new("admin", "banUser")
                .with_body(&json!({"userId":id,"banExpiresIn":1e20}))?,
            options(&admin),
        )
        .await
        .unwrap_err();
    assert_eq!(invalid.error.status_code(), 500);
    assert!(invalid.body_absent);
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    let accounts = db.tables(&["accounts"]).await?;
    let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
    let admin_sessions = auth.store().get_user_sessions(&admin_id).await?;
    let foreign_sessions = auth.store().get_user_sessions(&foreign_id).await?;
    let configured = AuthBuilder::new(profile_config.clone())
        .store(B::store(Arc::new(profile_config), &connection))
        .plugin(SessionManagementPlugin::new())
        .plugin(AdminPlugin::with_config(AdminConfig {
            default_ban_reason: Some("configured reason".into()),
            default_ban_expires_in: Some(120.75),
            ..Default::default()
        }))
        .endpoint_hook(super::server_admin_support::AdminObserver)
        .build()
        .await?;
    let original_admin =
        serde_json::to_value(auth.store().get_user_by_id(&admin_id).await?.unwrap())?;
    let original_foreign =
        serde_json::to_value(auth.store().get_user_by_id(&foreign_id).await?.unwrap())?;
    for (active, reason, duration, expected_reason, expires) in [
        (&auth, "review", 60.0, "review", true),
        (&auth, "", 0.0, "No reason", false),
        (&configured, "", 0.0, "configured reason", true),
    ] {
        let mut input = AdminBanUserRequest::new(id.clone());
        input.ban_reason = Some(reason.into());
        input.ban_expires_in = Some(duration);
        let output = active.dispatch_endpoint(
            AdminPlugin::ban_user_endpoint(&input)?
                .with_body(&json!({"userId":id,"banReason":reason,"banExpiresIn":duration,"banned":false}))?
                .with_query(&json!({"userId":foreign_id}))?, options(&admin)).await?;
        assert_eq!(output.decode()?.user.values().get("id"), Some(&json!(id)));
        let stored = auth.store().get_user_by_id(&id).await?.unwrap();
        assert!(stored.banned());
        assert_eq!(stored.ban_reason(), Some(expected_reason));
        assert_eq!(stored.ban_expires().is_some(), expires);
        assert_eq!(stored.email(), Some("server-ban-target@example.test"));
        assert_eq!(
            serde_json::to_value(auth.store().get_user_by_id(&admin_id).await?.unwrap())?,
            original_admin
        );
        assert_eq!(
            serde_json::to_value(auth.store().get_user_by_id(&foreign_id).await?.unwrap())?,
            original_foreign
        );
        let user = output.value().get("user").unwrap();
        assert_eq!(user.get("id"), Some(&JsValue::String(id.clone())));
        assert_eq!(user.get("banned"), Some(&JsValue::Bool(true)));
        assert_eq!(
            user.get("banReason"),
            Some(&JsValue::String(expected_reason.into()))
        );
        assert_eq!(user.get("banExpires") == Some(&JsValue::Null), !expires);
        assert!(user.get("password").is_none());
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
        assert!(auth.store().get_user_sessions(&id).await?.is_empty());
        assert_eq!(db.tables(&["accounts"]).await?, accounts);
        assert_eq!(
            serde_json::to_value(auth.store().get_user_sessions(&admin_id).await?)?,
            serde_json::to_value(&admin_sessions)?
        );
        assert_eq!(
            serde_json::to_value(auth.store().get_user_sessions(&foreign_id).await?)?,
            serde_json::to_value(&foreign_sessions)?
        );
    }
    let old = call(&auth, request("/get-session", None, &cookies(&target)), 200).await;
    assert_eq!(body(&old), Value::Null);
    let denied = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"server-ban-target@example.test","password":PASSWORD})),
            "",
        ),
        403,
    )
    .await;
    assert_eq!(body(&denied)["code"], "BANNED_USER");
    B::close(connection).await
}
