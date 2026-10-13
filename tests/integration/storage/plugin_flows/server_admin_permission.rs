//! Server permission evaluation uses trusted selectors or genuine session authority.
use super::*;
use alibi::UpdateUser;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{AdminPermissionRequest, AdminPlugin, RolePermissions};
use alibi::utils::json::JsValue;

backend_tests!(server_admin_permission_resolves_selectors_without_mutating_or_forging_sessions);

async fn server_admin_permission_resolves_selectors_without_mutating_or_forging_sessions<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config.clone()), &connection))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(AdminPlugin::new())
        .endpoint_hook(super::server_admin_support::AdminObserver)
        .build()
        .await?;
    let admin = signup(&auth, "permission-admin@example.test").await;
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
    let member = signup(&auth, "permission-member@example.test").await;
    let member_id = body(&member)["user"]["id"].as_str().unwrap().to_owned();
    let headers = |response: &AuthResponse| EndpointOptions {
        headers: Some([("cookie".into(), cookies(response))].into_iter().collect()),
        ..Default::default()
    };
    let checks = json!({"user":["get"]});
    let before = db.tables(&["user", "account", "session"]).await?;
    for (input, options, status, message) in [
        (None, EndpointOptions::default(), 400, None),
        (Some(json!(null)), EndpointOptions::default(), 400, None),
        (Some(json!({})), EndpointOptions::default(), 400, None),
        (
            Some(json!({"role":null,"permissions":checks})),
            EndpointOptions::default(),
            400,
            None,
        ),
        (
            Some(json!({"role":"admin","permissions":{"user":[7]}})),
            EndpointOptions::default(),
            400,
            None,
        ),
        (
            Some(json!({"role":"admin","permission":checks,"permissions":checks})),
            EndpointOptions::default(),
            400,
            None,
        ),
        (
            Some(json!({"role":"admin","permission":checks})),
            headers(&admin),
            400,
            Some("invalid permission check. no permission(s) were passed."),
        ),
        (
            Some(json!({"permissions":checks})),
            EndpointOptions::default(),
            400,
            Some("user id or role is required"),
        ),
        (
            Some(json!({"role":"","permissions":checks})),
            EndpointOptions::default(),
            400,
            Some("user id or role is required"),
        ),
        (
            Some(json!({"userId":[],"permissions":checks})),
            EndpointOptions::default(),
            400,
            Some("user id or role is required"),
        ),
        (
            Some(json!({"userId":null,"permissions":checks})),
            EndpointOptions::default(),
            400,
            Some("user not found"),
        ),
        (
            Some(json!({"userId":7,"permissions":checks})),
            EndpointOptions::default(),
            400,
            Some("user not found"),
        ),
        (
            Some(json!({"userId":"missing","permissions":checks})),
            EndpointOptions::default(),
            400,
            Some("user not found"),
        ),
        (
            Some(json!({"role":"admin","permissions":checks})),
            EndpointOptions {
                headers: Some(Default::default()),
                ..Default::default()
            },
            401,
            None,
        ),
    ] {
        let mut endpoint = ServerEndpoint::<JsValue>::new("admin", "userHasPermission");
        if let Some(input) = input {
            endpoint = endpoint.with_body(&input)?;
        }
        let error = auth
            .dispatch_endpoint(endpoint.with_query(&json!({"role":"admin"}))?, options)
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), status);
        if let Some(message) = message {
            assert_eq!(
                error.error.to_auth_response().body,
                serde_json::to_vec(&json!({"message":message}))?
            );
        } else if status == 401 {
            assert!(error.body_absent);
        }
    }
    for (input, options, allowed, principal) in [
        (
            json!({"role":"admin","permissions":checks}),
            EndpointOptions::default(),
            true,
            None,
        ),
        (
            json!({"role":"admin","userId":"missing","permissions":checks}),
            EndpointOptions::default(),
            true,
            None,
        ),
        (
            json!({"userId":admin_id,"permissions":checks}),
            EndpointOptions::default(),
            true,
            None,
        ),
        (
            json!({"userId":member_id,"role":"","permissions":checks}),
            EndpointOptions::default(),
            false,
            None,
        ),
        (
            json!({"role":"user, admin","permissions":checks}),
            EndpointOptions::default(),
            false,
            None,
        ),
        (
            json!({"role":"ghost","permissions":{}}),
            EndpointOptions::default(),
            false,
            None,
        ),
        (
            json!({"role":"user","permissions":{}}),
            EndpointOptions::default(),
            false,
            None,
        ),
        (
            json!({"role":"admin","permissions":{"user":[]}}),
            EndpointOptions::default(),
            false,
            None,
        ),
        (
            json!({"role":"admin","permissions":{"missing":["get"]}}),
            EndpointOptions::default(),
            false,
            None,
        ),
        (
            json!({"role":"user","userId":member_id,"permissions":checks}),
            headers(&admin),
            true,
            Some(&admin_id),
        ),
        (
            json!({"role":"admin","userId":admin_id,"permissions":checks}),
            headers(&member),
            false,
            Some(&member_id),
        ),
    ] {
        let typed: AdminPermissionRequest = serde_json::from_value(input.clone())?;
        let output = auth
            .dispatch_endpoint(
                AdminPlugin::user_has_permission_endpoint(&typed)?.with_body(&input)?,
                options,
            )
            .await?;
        assert_eq!(output.decode()?.success, allowed);
        assert_eq!(
            output.value(),
            &JsValue::from(json!({"error":null,"success":allowed}))
        );
        assert_eq!(output.headers().get("x-admin-principal"), principal);
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
    }
    for (roles, role, permission, allowed) in [
        (std::collections::HashMap::new(), "admin", "get", false),
        (
            std::collections::HashMap::from([(
                "creator".into(),
                RolePermissions::new().allow("user", ["create"]),
            )]),
            "creator",
            "create",
            true,
        ),
        (
            std::collections::HashMap::from([(
                "creator".into(),
                RolePermissions::new().allow("user", ["create"]),
            )]),
            "creator",
            "set-role",
            false,
        ),
    ] {
        let configured = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config.clone()), &connection))
            .plugin(AdminPlugin::new().roles(roles))
            .build()
            .await?;
        let mut typed = AdminPermissionRequest::new(std::collections::HashMap::from([(
            "user".into(),
            vec![permission.into()],
        )]));
        typed.role = Some(role.into());
        let output = configured
            .dispatch_endpoint(
                AdminPlugin::user_has_permission_endpoint(&typed)?,
                EndpointOptions::default(),
            )
            .await?;
        assert_eq!(
            output.value(),
            &JsValue::from(json!({"error":null,"success":allowed}))
        );
    }
    assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    B::close(connection).await
}
