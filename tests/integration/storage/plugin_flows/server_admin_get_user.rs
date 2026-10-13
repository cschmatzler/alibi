//! The logical admin lookup uses stored authority, strict query input and safe output.
use super::server_admin_support::AdminObserver;
use super::*;
use alibi::UpdateUser;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::AdminPlugin;
use alibi::utils::json::JsValue;

backend_tests!(server_admin_get_user_validates_query_and_rejects_stale_admin_authority);

async fn server_admin_get_user_validates_query_and_rejects_stale_admin_authority<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .session_cookie_cache(alibi::CookieCacheConfig {
            enabled: true,
            max_age: 300.0,
            ..Default::default()
        });
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(AdminPlugin::new())
        .endpoint_hook(AdminObserver)
        .build()
        .await?;
    let first = signup(&auth, "server-admin@example.test").await;
    let administrator = body(&first)["user"]["id"].as_str().unwrap().to_owned();
    drop(
        auth.store()
            .update_user(
                &administrator,
                UpdateUser {
                    role: Some("admin".into()),
                    ..Default::default()
                },
            )
            .await?,
    );
    // Issue a genuine cached admin session after application provisioning.
    let signed_in = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"server-admin@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    let admin_cookie = cookies(&signed_in);
    let member = signup(&auth, "server-member@example.test").await;
    let target = body(&member)["user"]["id"].as_str().unwrap().to_owned();
    let member_cookie = cookies(&member);
    let before = db.tables(&["user", "account", "session"]).await?;
    let denied_config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .session_cookie_cache(alibi::CookieCacheConfig {
            enabled: true,
            max_age: 300.0,
            ..Default::default()
        });
    let deny_all = AuthBuilder::new(denied_config.clone())
        .store(B::store(Arc::new(denied_config), &connection))
        .plugin(AdminPlugin::new().roles(std::collections::HashMap::new()))
        .plugin(SessionManagementPlugin::new())
        .build()
        .await?;
    let denied = deny_all
        .dispatch_endpoint(
            AdminPlugin::get_user_endpoint(target.clone()),
            EndpointOptions {
                headers: Some(
                    [("cookie".into(), admin_cookie.clone())]
                        .into_iter()
                        .collect(),
                ),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(denied.error.status_code(), 403);
    let empty_headers = auth
        .dispatch_endpoint(
            AdminPlugin::get_user_endpoint(target.clone()),
            EndpointOptions {
                headers: Some(Default::default()),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(empty_headers.error.status_code(), 401);
    assert!(empty_headers.body_absent);
    for (query, cookie, status) in [
        (None, None, 400),
        (Some(json!(null)), None, 400),
        (Some(json!(7)), None, 400),
        (Some(json!({})), None, 400),
        (Some(json!({"id":7})), Some(&admin_cookie), 400),
        (Some(json!({"id":target})), None, 401),
        (Some(json!({"id":target})), Some(&member_cookie), 403),
        (Some(json!({"id":""})), Some(&admin_cookie), 404),
        (Some(json!({"id":"missing"})), Some(&admin_cookie), 404),
    ] {
        let mut endpoint = ServerEndpoint::<JsValue>::new("admin", "getUser");
        if let Some(query) = query {
            endpoint = endpoint.with_query(&query)?;
        }
        let error = auth
            .dispatch_endpoint(
                endpoint,
                EndpointOptions {
                    headers: cookie.map(|cookie| {
                        [
                            ("cookie".into(), cookie.clone()),
                            ("x-user-role".into(), "admin".into()),
                        ]
                        .into_iter()
                        .collect()
                    }),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), status);
        if status == 401 {
            assert!(error.body_absent);
        }
        if status == 403 {
            assert!(
                error
                    .error
                    .to_string()
                    .contains("You are not allowed to get user")
            );
        }
    }
    for supplied_body in [json!({"id":administrator,"role":"admin"}), json!(7)] {
        let output = auth
            .dispatch_endpoint(
                AdminPlugin::get_user_endpoint(target.clone())
                    .with_query(&json!({"id":target,"userId":administrator,"role":"admin"}))?
                    .with_body(&supplied_body)?,
                EndpointOptions {
                    headers: Some(
                        [("cookie".into(), admin_cookie.clone())]
                            .into_iter()
                            .collect(),
                    ),
                    ..Default::default()
                },
            )
            .await?;
        assert_eq!(
            output.headers().get("x-admin-principal"),
            Some(&administrator)
        );
        assert_eq!(
            output
                .headers()
                .get_all("set-cookie")
                .map(String::as_str)
                .collect::<Vec<_>>()[1..],
            vec![
                "application_a=first; Path=/; HttpOnly",
                "application_b=second; Path=/; HttpOnly"
            ]
        );
        let decoded = output.decode()?;
        assert_eq!(decoded.values().get("id"), Some(&json!(target)));
        let value = output.value();
        assert_eq!(value.get("id"), Some(&JsValue::String(target.clone())));
        assert_eq!(value.get("role"), Some(&JsValue::String("user".into())));
        for private in ["password", "token", "user"] {
            assert!(value.get(private).is_none());
        }
    }
    assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    let _ = call(
        &auth,
        request(
            "/admin/set-role",
            Some(json!({"userId":administrator,"role":"user"})),
            &admin_cookie,
        ),
        200,
    )
    .await;
    assert_eq!(
        db.text(
            "SELECT \"role\" FROM \"user\" WHERE id = $1",
            &[&administrator]
        )
        .await?
        .as_deref(),
        Some("user")
    );
    let demoted = db.tables(&["user", "account", "session"]).await?;
    let endpoint = AdminPlugin::get_user_endpoint(target.clone());
    let options = EndpointOptions {
        headers: Some(
            [("cookie".into(), admin_cookie.clone())]
                .into_iter()
                .collect(),
        ),
        ..Default::default()
    };
    let error = auth
        .dispatch_endpoint(
            AdminPlugin::get_user_endpoint(target.clone()),
            options.clone(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.error.status_code(), 403);
    assert_eq!(
        error.headers.unwrap().get("x-admin-principal"),
        Some(&administrator)
    );
    assert_eq!(db.tables(&["user", "account", "session"]).await?, demoted);
    let _ = call(
        &auth,
        request("/sign-out", Some(json!({})), &admin_cookie),
        200,
    )
    .await;
    let error = auth.dispatch_endpoint(endpoint, options).await.unwrap_err();
    assert_eq!(error.error.status_code(), 401);
    assert!(error.body_absent);
    B::close(connection).await
}
