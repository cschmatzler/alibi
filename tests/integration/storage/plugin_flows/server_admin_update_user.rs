//! Logical admin updates validate before mutation and preserve unrelated principals.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{AdminPlugin, AdminUpdateUserRequest, RolePermissions};
use alibi::utils::json::JsValue;
use alibi::{AuthUser, UpdateUser};

backend_tests!(server_admin_update_user_preserves_authority_and_targets_mutations);

async fn server_admin_update_user_preserves_authority_and_targets_mutations<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config.clone()), &connection))
        .plugin(super::auth_probe::fast_password().enable_username(true))
        .plugin(SessionManagementPlugin::new())
        .plugin(AdminPlugin::new())
        .endpoint_hook(super::server_admin_support::AdminObserver)
        .build()
        .await?;
    let admin = signup(&auth, "update-admin@example.test").await;
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
    let target = signup(&auth, "update-target@example.test").await;
    let id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
    let foreign = signup(&auth, "update-foreign@example.test").await;
    let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
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
            Some(json!({"userId":id,"data":[]})),
            options(&admin),
            400,
            "VALIDATION_ERROR",
        ),
        (
            Some(json!({"userId":id,"data":{"name":"Denied"}})),
            EndpointOptions::default(),
            401,
            "",
        ),
        (
            Some(json!({"userId":id,"data":{"name":"Denied"}})),
            options(&target),
            403,
            "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS",
        ),
        (
            Some(json!({"userId":id,"data":{}})),
            options(&admin),
            400,
            "NO_DATA_TO_UPDATE",
        ),
        (
            Some(json!({"userId":admin_id,"data":{"password":"x","banned":true,"username":"x"}})),
            options(&admin),
            400,
            "PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER",
        ),
        (
            Some(json!({"userId":admin_id,"data":{"banned":true}})),
            options(&admin),
            400,
            "YOU_CANNOT_BAN_YOURSELF",
        ),
        (
            Some(json!({"userId":id,"data":{"username":"x","name":"Denied"}})),
            options(&admin),
            400,
            "USERNAME_TOO_SHORT",
        ),
        (
            Some(json!({"userId":id,"data":{"role":7,"name":"Denied"}})),
            options(&admin),
            400,
            "INVALID_ROLE_TYPE",
        ),
        (
            Some(
                json!({"userId":id,"data":{"email":"update-foreign@example.test","name":"Denied"}}),
            ),
            options(&admin),
            400,
            "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
        ),
        (
            Some(json!({"userId":"missing","data":{"name":"Denied"}})),
            options(&admin),
            404,
            "USER_NOT_FOUND",
        ),
    ] {
        let mut endpoint = ServerEndpoint::<JsValue>::new("admin", "adminUpdateUser");
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
    let configured = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .plugin(AdminPlugin::new().roles(std::collections::HashMap::from([(
            "admin".into(),
            RolePermissions::new().allow("user", ["update", "set-role"]),
        )])))
        .build()
        .await?;
    for (target_id, data, status, code) in [
        (
            "missing",
            json!({"role":"ghost"}),
            400,
            "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE",
        ),
        (
            id.as_str(),
            json!({"banned":false,"name":"Denied"}),
            403,
            "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS",
        ),
        (
            id.as_str(),
            json!({"emailVerified":true,"name":"Denied"}),
            403,
            "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_EMAIL",
        ),
    ] {
        let error = configured
            .dispatch_endpoint(
                ServerEndpoint::<JsValue>::new("admin", "adminUpdateUser")
                    .with_body(&json!({"userId":target_id,"data":data}))?,
                options(&admin),
            )
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), status);
        assert_eq!(body(&error.error.to_auth_response())["code"], code);
    }
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    let immutable_accounts_sessions = db.tables(&["accounts", "sessions"]).await?;
    let original_admin =
        serde_json::to_value(auth.store().get_user_by_id(&admin_id).await?.unwrap())?;
    let original_foreign =
        serde_json::to_value(auth.store().get_user_by_id(&foreign_id).await?.unwrap())?;
    for data in [
        json!({"name":"Managed","image":"https://example.test/avatar.png"}),
        json!({"image":null}),
        json!({"username":"MANAGED_USER","displayUsername":"Managed Label"}),
        json!({"role":["user","admin"]}),
        json!({"email":"REPLACEMENT@EXAMPLE.TEST","emailVerified":true}),
    ] {
        let typed = AdminUpdateUserRequest::new(id.clone(), data.as_object().unwrap().clone());
        let output = auth
            .dispatch_endpoint(
                AdminPlugin::admin_update_user_endpoint(&typed)?
                    .with_body(&json!({"userId":id,"data":data,"ignored":"value"}))?
                    .with_query(&json!({"userId":foreign_id}))?,
                options(&admin),
            )
            .await?;
        assert_eq!(output.decode()?.values().get("id"), Some(&json!(id)));
        assert_eq!(output.value().get("id"), Some(&JsValue::String(id.clone())));
        assert!(output.value().get("user").is_none());
        assert!(output.value().get("password").is_none());
        for (key, value) in data.as_object().unwrap() {
            let expected = if matches!(key.as_str(), "email" | "username") {
                json!(value.as_str().unwrap().to_lowercase())
            } else if key == "role" {
                json!("user,admin")
            } else {
                value.clone()
            };
            assert_eq!(output.value().get(key), Some(&JsValue::from(expected)));
        }
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
        assert_eq!(
            db.tables(&["accounts", "sessions"]).await?,
            immutable_accounts_sessions
        );
        assert_eq!(
            serde_json::to_value(auth.store().get_user_by_id(&admin_id).await?.unwrap())?,
            original_admin
        );
        assert_eq!(
            serde_json::to_value(auth.store().get_user_by_id(&foreign_id).await?.unwrap())?,
            original_foreign
        );
    }
    let unchanged = db.tables(&["users", "accounts", "sessions"]).await?;
    let duplicate = auth
        .dispatch_endpoint(
            ServerEndpoint::<JsValue>::new("admin", "adminUpdateUser").with_body(
                &json!({"userId":id,"data":{"username":"managed_user","name":"Denied"}}),
            )?,
            options(&admin),
        )
        .await
        .unwrap_err();
    assert_eq!(
        body(&duplicate.error.to_auth_response())["code"],
        "USERNAME_IS_ALREADY_TAKEN"
    );
    assert_eq!(
        db.tables(&["users", "accounts", "sessions"]).await?,
        unchanged
    );
    let login = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"replacement@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    assert_eq!(body(&login)["user"]["id"], id);
    assert_eq!(auth.store().get_user_sessions(&id).await?.len(), 2);
    let accounts = db.tables(&["accounts"]).await?;
    let owner_sessions = serde_json::to_value(auth.store().get_user_sessions(&admin_id).await?)?;
    let foreign_sessions =
        serde_json::to_value(auth.store().get_user_sessions(&foreign_id).await?)?;
    let banned = auth
        .dispatch_endpoint(
            ServerEndpoint::<JsValue>::new("admin", "adminUpdateUser")
                .with_body(&json!({"userId":id,"data":{"banned":true,"banReason":"review"}}))?,
            options(&admin),
        )
        .await?;
    assert_eq!(banned.value().get("banned"), Some(&JsValue::Bool(true)));
    assert!(auth.store().get_user_by_id(&id).await?.unwrap().banned());
    assert!(auth.store().get_user_sessions(&id).await?.is_empty());
    assert_eq!(db.tables(&["accounts"]).await?, accounts);
    assert_eq!(
        serde_json::to_value(auth.store().get_user_sessions(&admin_id).await?)?,
        owner_sessions
    );
    assert_eq!(
        serde_json::to_value(auth.store().get_user_sessions(&foreign_id).await?)?,
        foreign_sessions
    );
    let refused = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"replacement@example.test","password":PASSWORD})),
            "",
        ),
        403,
    )
    .await;
    assert_eq!(body(&refused)["code"], "BANNED_USER");
    B::close(connection).await
}
