//! Logical role updates validate input and use the acting session's configured grants.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{AdminPlugin, AdminRoleInput, AdminSetRoleRequest, RolePermissions};
use alibi::utils::json::JsValue;
use alibi::{AuthUser, UpdateUser};

backend_tests!(server_admin_set_role_validates_and_mutates_only_the_requested_user);

async fn server_admin_set_role_validates_and_mutates_only_the_requested_user<B: Backend>(
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
    let owner = signup(&auth, "set-role-admin@example.test").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    drop(
        auth.store()
            .update_user(
                &owner_id,
                UpdateUser {
                    role: Some("admin".into()),
                    ..Default::default()
                },
            )
            .await?,
    );
    let target = signup(&auth, "set-role-target@example.test").await;
    let target_id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
    let foreign = signup(&auth, "set-role-foreign@example.test").await;
    let admin_cookie = cookies(&owner);
    let member_cookie = cookies(&target);
    let options = |cookie: &str| EndpointOptions {
        headers: Some([("cookie".into(), cookie.into())].into_iter().collect()),
        ..Default::default()
    };
    let before = db.tables(&["user", "account", "session"]).await?;
    for (input, cookie, status) in [
        (None, None, 400),
        (Some(json!(null)), None, 400),
        (Some(json!(7)), None, 400),
        (Some(json!({})), None, 400),
        (
            Some(json!({"userId":target_id,"role":7})),
            Some(&admin_cookie),
            400,
        ),
        (
            Some(json!({"userId":target_id,"role":["admin",7]})),
            Some(&admin_cookie),
            400,
        ),
        (Some(json!({"userId":target_id,"role":"admin"})), None, 400),
        (
            Some(json!({"userId":target_id,"role":"admin"})),
            Some(&member_cookie),
            403,
        ),
    ] {
        let mut endpoint = ServerEndpoint::<JsValue>::new("admin", "setRole");
        if let Some(input) = input {
            endpoint = endpoint.with_body(&input)?;
        }
        let error = auth
            .dispatch_endpoint(
                endpoint,
                cookie.map_or_else(EndpointOptions::default, |cookie| options(cookie)),
            )
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), status);
    }
    let missing = ServerEndpoint::<JsValue>::new("admin", "setRole")
        .with_body(&json!({"userId":target_id,"role":"admin"}))?;
    let error = auth
        .dispatch_endpoint(
            missing,
            EndpointOptions {
                headers: Some(Default::default()),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(error.error.status_code(), 401);
    assert!(error.body_absent);
    for (id, status) in [
        (json!(null), 404),
        (json!(7), 404),
        (json!(true), 404),
        (json!([]), 404),
        (json!({}), 404),
        (json!({"toString":"bad"}), 400),
    ] {
        let error = auth
            .dispatch_endpoint(
                ServerEndpoint::<JsValue>::new("admin", "setRole")
                    .with_body(&json!({"userId":id,"role":"user"}))?,
                options(&admin_cookie),
            )
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), status);
    }
    let restricted = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .plugin(SessionManagementPlugin::new())
        .plugin(AdminPlugin::new().roles(std::collections::HashMap::from([
            (
                "admin".into(),
                RolePermissions::new().allow("user", ["set-role"]),
            ),
            ("user".into(), RolePermissions::new()),
        ])))
        .build()
        .await?;
    for (role, status) in [("ghost", 400), ("user", 404)] {
        let error = restricted
            .dispatch_endpoint(
                ServerEndpoint::<JsValue>::new("admin", "setRole")
                    .with_body(&json!({"userId":"missing-target","role":role}))?,
                options(&admin_cookie),
            )
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), status);
        if status == 400 {
            assert!(error.error.to_string().contains("non-existent"));
        }
    }
    assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    let immutable = db.tables(&["account", "session"]).await?;
    let other_before = [
        auth.store().get_user_by_id(&owner_id).await?.unwrap(),
        auth.store()
            .get_user_by_id(body(&foreign)["user"]["id"].as_str().unwrap())
            .await?
            .unwrap(),
    ];
    for (role, stored) in [
        (json!("admin"), "admin"),
        (json!(["user", "admin"]), "user,admin"),
        (json!([]), ""),
        (json!(""), ""),
        (json!("user"), "user"),
    ] {
        let typed = AdminPlugin::set_role_endpoint(&AdminSetRoleRequest {
            user_id: target_id.clone(),
            role: serde_json::from_value::<AdminRoleInput>(role.clone())?,
        })?;
        let output = auth
            .dispatch_endpoint(
                typed
                    .with_body(&json!({"userId":target_id,"role":role,"ignored":"value"}))?
                    .with_query(&json!({"userId":body(&foreign)["user"]["id"],"role":"admin"}))?,
                options(&admin_cookie),
            )
            .await?;
        assert_eq!(
            output.decode()?.user.values().get("role"),
            Some(&json!(stored))
        );
        assert_eq!(output.headers().get("x-admin-principal"), Some(&owner_id));
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
            output.value().get("user").and_then(|user| user.get("id")),
            Some(&JsValue::String(target_id.clone()))
        );
        assert_eq!(
            output.value().get("user").and_then(|user| user.get("role")),
            Some(&JsValue::String(stored.into()))
        );
        assert!(
            output
                .value()
                .get("user")
                .unwrap()
                .get("password")
                .is_none()
        );
        assert_eq!(
            db.text("SELECT \"role\" FROM \"user\" WHERE id = $1", &[&target_id])
                .await?
                .as_deref(),
            Some(stored)
        );
        assert_eq!(db.tables(&["account", "session"]).await?, immutable);
        for other in &other_before {
            assert_eq!(
                serde_json::to_value(
                    auth.store()
                        .get_user_by_id(other.id().as_ref())
                        .await?
                        .unwrap()
                )?,
                serde_json::to_value(other)?
            );
        }
    }
    B::close(connection).await
}
