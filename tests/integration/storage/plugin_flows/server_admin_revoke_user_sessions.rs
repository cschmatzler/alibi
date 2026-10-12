//! Administrative bulk revocation removes live and expired target rows.
use super::*;
use alibi::UpdateUser;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{AdminPlugin, RolePermissions};
use alibi::utils::json::JsValue;

backend_tests!(server_admin_revoke_user_sessions_deletes_all_target_rows);

async fn server_admin_revoke_user_sessions_deletes_all_target_rows<B: Backend>(
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
    let admin = signup(&auth, "server-revoke-all-admin@example.test").await;
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
    let target = signup(&auth, "server-revoke-all-target@example.test").await;
    let id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
    let token = body(&target)["token"].as_str().unwrap().to_owned();
    let foreign = signup(&auth, "server-revoke-all-foreign@example.test").await;
    let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
    let peer = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"server-revoke-all-target@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    drop(
        call(
            &auth,
            request(
                "/sign-in/email",
                Some(json!({"email":"server-revoke-all-admin@example.test","password":PASSWORD})),
                "",
            ),
            200,
        )
        .await,
    );
    let expired = chrono::DateTime::parse_from_rfc3339("2020-01-01T00:00:00.000Z")?
        .with_timezone(&chrono::Utc);
    db.set_timestamp("sessions", "expires_at", ("token", &token), expired)
        .await?;
    assert_eq!(auth.store().get_user_sessions(&id).await?.len(), 2);
    assert_eq!(auth.store().get_user_sessions(&admin_id).await?.len(), 2);
    let options = |response: &AuthResponse| EndpointOptions {
        headers: Some([("cookie".into(), cookies(response))].into_iter().collect()),
        ..Default::default()
    };
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
            Some(json!({})),
            EndpointOptions::default(),
            400,
            "VALIDATION_ERROR",
        ),
        (
            Some(json!({"userId":{"toString":"bad"}})),
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
            "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS",
        ),
    ] {
        let mut endpoint = ServerEndpoint::<JsValue>::new("admin", "revokeUserSessions");
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
    let restricted = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .plugin(SessionManagementPlugin::new())
        .plugin(AdminPlugin::new().roles(std::collections::HashMap::from([(
            "admin".into(),
            RolePermissions::new().allow("user", ["update"]),
        )])))
        .build()
        .await?;
    let error = restricted
        .dispatch_endpoint(
            ServerEndpoint::<JsValue>::new("admin", "revokeUserSessions")
                .with_body(&json!({"userId":id}))?,
            options(&admin),
        )
        .await
        .unwrap_err();
    assert_eq!(error.error.status_code(), 403);
    for user_id in [
        json!("missing-user"),
        json!(null),
        json!(7),
        json!([]),
        json!({}),
        json!(false),
    ] {
        let output = auth
            .dispatch_endpoint(
                ServerEndpoint::<JsValue>::new("admin", "revokeUserSessions")
                    .with_body(&json!({"userId":user_id}))?,
                options(&admin),
            )
            .await?;
        assert_eq!(output.value().get("success"), Some(&JsValue::Bool(true)));
    }
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    let immutable = db.tables(&["users", "accounts"]).await?;
    let original_admin = serde_json::to_value(auth.store().get_user_sessions(&admin_id).await?)?;
    let original_foreign =
        serde_json::to_value(auth.store().get_user_sessions(&foreign_id).await?)?;
    for _ in 0..2 {
        let output = auth
            .dispatch_endpoint(
                AdminPlugin::revoke_user_sessions_endpoint(id.clone())
                    .with_body(&json!({"userId":id,"sessionToken":body(&foreign)["token"]}))?
                    .with_query(&json!({"userId":foreign_id}))?,
                options(&admin),
            )
            .await?;
        assert_eq!(output.value().get("success"), Some(&JsValue::Bool(true)));
        assert!(output.decode()?.success);
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
        assert_eq!(db.tables(&["users", "accounts"]).await?, immutable);
        assert_eq!(
            serde_json::to_value(auth.store().get_user_sessions(&admin_id).await?)?,
            original_admin
        );
        assert_eq!(
            serde_json::to_value(auth.store().get_user_sessions(&foreign_id).await?)?,
            original_foreign
        );
    }
    assert_eq!(
        body(&call(&auth, request("/get-session", None, &cookies(&peer)), 200).await),
        Value::Null
    );
    let output = auth
        .dispatch_endpoint(
            ServerEndpoint::<JsValue>::new("admin", "revokeUserSessions")
                .with_body(&json!({"userId":admin_id}))?,
            options(&admin),
        )
        .await?;
    assert_eq!(output.value().get("success"), Some(&JsValue::Bool(true)));
    assert_eq!(output.headers().get("x-admin-principal"), Some(&admin_id));
    assert!(auth.store().get_user_sessions(&admin_id).await?.is_empty());
    let stale = auth
        .dispatch_endpoint(
            ServerEndpoint::<JsValue>::new("admin", "revokeUserSessions")
                .with_body(&json!({"userId":foreign_id}))?,
            options(&admin),
        )
        .await
        .unwrap_err();
    assert_eq!(stale.error.status_code(), 401);
    assert!(stale.body_absent);
    assert_eq!(
        serde_json::to_value(auth.store().get_user_sessions(&foreign_id).await?)?,
        original_foreign
    );
    let login = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"server-revoke-all-target@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    assert_eq!(body(&login)["user"]["id"], id);
    assert_eq!(auth.store().get_user_sessions(&id).await?.len(), 1);
    B::close(connection).await
}
