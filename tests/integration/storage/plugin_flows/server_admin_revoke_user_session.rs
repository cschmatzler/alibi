//! Admin token revocation preserves every unrelated persisted session.
use super::*;
use alibi::UpdateUser;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{AdminPlugin, RolePermissions};
use alibi::utils::json::JsValue;

backend_tests!(server_admin_revoke_user_session_deletes_token_and_preserves_peers);

async fn server_admin_revoke_user_session_deletes_token_and_preserves_peers<B: Backend>(
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
    let admin = signup(&auth, "server-revoke-admin@example.test").await;
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
    let target = signup(&auth, "server-revoke-target@example.test").await;
    let id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
    let token = body(&target)["token"].as_str().unwrap().to_owned();
    let foreign = signup(&auth, "server-revoke-foreign@example.test").await;
    let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
    let foreign_token = body(&foreign)["token"].as_str().unwrap().to_owned();
    let peer = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"server-revoke-target@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
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
            Some(json!({})),
            EndpointOptions::default(),
            400,
            "VALIDATION_ERROR",
        ),
        (
            Some(json!({"sessionToken":7})),
            EndpointOptions::default(),
            400,
            "VALIDATION_ERROR",
        ),
        (
            Some(json!({"sessionToken":null})),
            EndpointOptions::default(),
            400,
            "VALIDATION_ERROR",
        ),
        (
            Some(json!({"sessionToken":token})),
            EndpointOptions::default(),
            401,
            "",
        ),
        (
            Some(json!({"sessionToken":token})),
            EndpointOptions {
                headers: Some(Default::default()),
                ..Default::default()
            },
            401,
            "",
        ),
        (
            Some(json!({"sessionToken":token})),
            options(&foreign),
            403,
            "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS",
        ),
    ] {
        let mut endpoint = ServerEndpoint::<JsValue>::new("admin", "revokeUserSession");
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
            ServerEndpoint::<JsValue>::new("admin", "revokeUserSession")
                .with_body(&json!({"sessionToken":token}))?,
            options(&admin),
        )
        .await
        .unwrap_err();
    assert_eq!(error.error.status_code(), 403);
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    let immutable = db.tables(&["users", "accounts"]).await?;
    let original_target = serde_json::to_value(auth.store().get_user_sessions(&id).await?)?;
    let original_admin = serde_json::to_value(auth.store().get_user_sessions(&admin_id).await?)?;
    let original_foreign =
        serde_json::to_value(auth.store().get_user_sessions(&foreign_id).await?)?;
    let selected_id = original_target
        .as_array()
        .unwrap()
        .iter()
        .find(|session| session["token"] == token)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    for selected in [
        "",
        "missing-session-token",
        selected_id.as_str(),
        token.as_str(),
        token.as_str(),
    ] {
        let output = auth
            .dispatch_endpoint(
                AdminPlugin::revoke_user_session_endpoint(selected)
                    .with_body(&json!({"sessionToken":selected,"userId":foreign_id}))?
                    .with_query(&json!({"sessionToken":foreign_token}))?,
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
        let expected = if selected == token {
            Value::Array(
                original_target
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|session| session["token"] != token)
                    .cloned()
                    .collect(),
            )
        } else {
            original_target.clone()
        };
        assert_eq!(
            serde_json::to_value(auth.store().get_user_sessions(&id).await?)?,
            expected
        );
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
        body(&call(&auth, request("/get-session", None, &cookies(&target)), 200).await),
        Value::Null
    );
    assert_eq!(
        body(&call(&auth, request("/get-session", None, &cookies(&peer)), 200).await)["user"]["id"],
        id
    );
    let admin_token = body(&admin)["token"].as_str().unwrap().to_owned();
    let output = auth
        .dispatch_endpoint(
            ServerEndpoint::<JsValue>::new("admin", "revokeUserSession")
                .with_body(&json!({"sessionToken":admin_token}))?,
            options(&admin),
        )
        .await?;
    assert_eq!(output.value().get("success"), Some(&JsValue::Bool(true)));
    assert_eq!(output.headers().get("x-admin-principal"), Some(&admin_id));
    assert!(auth.store().get_user_sessions(&admin_id).await?.is_empty());
    let stale = auth
        .dispatch_endpoint(
            ServerEndpoint::<JsValue>::new("admin", "revokeUserSession")
                .with_body(&json!({"sessionToken":foreign_token}))?,
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
    B::close(connection).await
}
