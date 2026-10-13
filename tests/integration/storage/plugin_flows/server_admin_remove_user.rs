//! Logical removal deletes owned rows while preserving foreign physical state.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{AdminPlugin, RolePermissions};
use alibi::utils::json::JsValue;
use alibi::{CreateAccount, UpdateUser};

backend_tests!(server_admin_remove_user_deletes_only_target_rows);

async fn server_admin_remove_user_deletes_only_target_rows<B: Backend>(db: Db) -> TestResult {
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
    let admin = signup(&auth, "server-remove-admin@example.test").await;
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
    let target = signup(&auth, "server-remove-target@example.test").await;
    let id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
    let token = body(&target)["token"].as_str().unwrap().to_owned();
    let foreign = signup(&auth, "server-remove-foreign@example.test").await;
    let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
    let peer = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"server-remove-target@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    drop(
        auth.store()
            .create_account(CreateAccount {
                user_id: id.clone(),
                account_id: "remove-remote".into(),
                provider_id: "mock".into(),
                access_token: Some("private-access".into()),
                refresh_token: Some("private-refresh".into()),
                id_token: None,
                password: None,
                access_token_expires_at: None,
                refresh_token_expires_at: None,
                scope: None,
                additional_fields: Default::default(),
            })
            .await?,
    );
    let expired = chrono::DateTime::parse_from_rfc3339("2020-01-01T00:00:00.000Z")?
        .with_timezone(&chrono::Utc);
    db.set_timestamp("session", "expiresAt", ("token", &token), expired)
        .await?;
    assert_eq!(auth.store().get_user_accounts(&id).await?.len(), 2);
    assert_eq!(auth.store().get_user_sessions(&id).await?.len(), 2);
    let options = |response: &AuthResponse| EndpointOptions {
        headers: Some([("cookie".into(), cookies(response))].into_iter().collect()),
        ..Default::default()
    };
    let before = db.tables(&["user", "account", "session"]).await?;
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
            "YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS",
        ),
        (
            Some(json!({"userId":admin_id})),
            options(&admin),
            400,
            "YOU_CANNOT_REMOVE_YOURSELF",
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
        (
            Some(json!({"userId":{}})),
            options(&admin),
            404,
            "USER_NOT_FOUND",
        ),
    ] {
        let mut endpoint = ServerEndpoint::<JsValue>::new("admin", "removeUser");
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
            ServerEndpoint::<JsValue>::new("admin", "removeUser")
                .with_body(&json!({"userId":id}))?,
            options(&admin),
        )
        .await
        .unwrap_err();
    assert_eq!(error.error.status_code(), 403);
    assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    let output = auth
        .dispatch_endpoint(
            AdminPlugin::remove_user_endpoint(id.clone())
                .with_body(&json!({"userId":id,"sessionToken":body(&foreign)["token"]}))?
                .with_query(&json!({"userId":foreign_id}))?,
            options(&admin),
        )
        .await?;
    assert!(output.decode()?.success);
    assert_eq!(output.value().get("success"), Some(&JsValue::Bool(true)));
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
    let remaining = before
        .iter()
        .map(|snapshot| {
            let mut rows: Vec<Value> = serde_json::from_str(snapshot)?;
            rows.retain(|row| row["id"] != id && row["userId"] != id);
            Ok(Value::Array(rows))
        })
        .collect::<serde_json::Result<Vec<_>>>()?;
    let actual = db
        .tables(&["user", "account", "session"])
        .await?
        .iter()
        .map(|snapshot| serde_json::from_str::<Value>(snapshot))
        .collect::<serde_json::Result<Vec<_>>>()?;
    assert_eq!(actual, remaining);
    assert!(auth.store().get_user_by_id(&id).await?.is_none());
    assert!(auth.store().get_user_accounts(&id).await?.is_empty());
    assert!(auth.store().get_user_sessions(&id).await?.is_empty());
    assert_eq!(
        body(&call(&auth, request("/get-session", None, &cookies(&peer)), 200).await),
        Value::Null
    );
    let login = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"server-remove-target@example.test","password":PASSWORD})),
            "",
        ),
        401,
    )
    .await;
    assert_eq!(body(&login)["code"], "INVALID_EMAIL_OR_PASSWORD");
    let repeated = auth
        .dispatch_endpoint(
            ServerEndpoint::<JsValue>::new("admin", "removeUser")
                .with_body(&json!({"userId":id}))?,
            options(&admin),
        )
        .await
        .unwrap_err();
    assert_eq!(repeated.error.status_code(), 404);
    assert_eq!(
        body(&repeated.error.to_auth_response())["code"],
        "USER_NOT_FOUND"
    );
    assert_eq!(
        body(&call(&auth, request("/get-session", None, &cookies(&admin)), 200).await)["user"]["id"],
        admin_id
    );
    B::close(connection).await
}
