//! Administrative listing exposes stored sessions without deleting expired rows.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{AdminPlugin, RolePermissions};
use alibi::utils::json::JsValue;
use alibi::{AuthSession, UpdateUser};

backend_tests!(server_admin_list_user_sessions_preserves_expired_target_rows_and_authority);

async fn server_admin_list_user_sessions_preserves_expired_target_rows_and_authority<B: Backend>(
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
    let admin = signup(&auth, "admin-session-owner@example.test").await;
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
    let target = signup(&auth, "admin-session-target@example.test").await;
    let target_id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
    let foreign = signup(&auth, "admin-session-foreign@example.test").await;
    let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
    let peer = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":"admin-session-target@example.test","password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    let expired = body(&target)["token"].as_str().unwrap().to_owned();
    let old = chrono::DateTime::parse_from_rfc3339("2020-01-01T00:00:00.000Z")?
        .with_timezone(&chrono::Utc);
    db.set_timestamp("session", "expiresAt", ("token", &expired), old)
        .await?;
    let options = |response: &AuthResponse| EndpointOptions {
        headers: Some([("cookie".into(), cookies(response))].into_iter().collect()),
        ..Default::default()
    };
    let before = db.tables(&["user", "account", "session"]).await?;
    for (input, headers, status) in [
        (None, EndpointOptions::default(), 400),
        (Some(json!(null)), EndpointOptions::default(), 400),
        (Some(json!(7)), EndpointOptions::default(), 400),
        (
            Some(json!({"userId":{"toString":"bad"}})),
            options(&admin),
            400,
        ),
        (
            Some(json!({"userId":target_id})),
            EndpointOptions::default(),
            401,
        ),
        (
            Some(json!({"userId":target_id})),
            EndpointOptions {
                headers: Some(Default::default()),
                ..Default::default()
            },
            401,
        ),
        (Some(json!({"userId":target_id})), options(&foreign), 403),
    ] {
        let mut endpoint = ServerEndpoint::<JsValue>::new("admin", "listUserSessions");
        if let Some(input) = input {
            endpoint = endpoint.with_body(&input)?;
        }
        let error = auth.dispatch_endpoint(endpoint, headers).await.unwrap_err();
        assert_eq!(error.error.status_code(), status);
        if status == 401 {
            assert!(error.body_absent);
        } else if status == 403 {
            assert_eq!(
                body(&error.error.to_auth_response())["code"],
                "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS"
            );
        }
    }
    let user_grant = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .plugin(SessionManagementPlugin::new())
        .plugin(AdminPlugin::new().roles(std::collections::HashMap::from([(
            "admin".into(),
            RolePermissions::new().allow("user", ["list", "get"]),
        )])))
        .build()
        .await?;
    let denied = user_grant
        .dispatch_endpoint(
            ServerEndpoint::<JsValue>::new("admin", "listUserSessions")
                .with_body(&json!({"userId":target_id}))?,
            options(&admin),
        )
        .await
        .unwrap_err();
    assert_eq!(denied.error.status_code(), 403);
    for (user_id, tokens) in [
        (
            json!(target_id),
            vec![
                expired.clone(),
                body(&peer)["token"].as_str().unwrap().to_owned(),
            ],
        ),
        (
            json!(foreign_id),
            vec![body(&foreign)["token"].as_str().unwrap().to_owned()],
        ),
        (json!("missing-user"), vec![]),
        (json!(null), vec![]),
        (json!(7), vec![]),
        (json!([]), vec![]),
    ] {
        let output = auth
            .dispatch_endpoint(
                AdminPlugin::list_user_sessions_endpoint(target_id.clone())
                    .with_body(&json!({"userId":user_id,"onlyActiveSessions":true}))?
                    .with_query(&json!({"userId":admin_id}))?,
                options(&admin),
            )
            .await?;
        assert_eq!(output.decode()?.sessions.len(), tokens.len());
        let value: Value = alibi::utils::json::from_value(output.value().clone())?;
        let rows = value["sessions"].as_array().unwrap();
        let mut actual = rows
            .iter()
            .map(|row| row["token"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        actual.sort();
        let mut expected = tokens;
        expected.sort();
        assert_eq!(actual, expected);
        for row in rows {
            let stored = auth
                .store()
                .get_session(row["token"].as_str().unwrap())
                .await?
                .unwrap();
            assert_eq!(row["id"], stored.id().as_ref());
            assert_eq!(row["userId"], stored.user_id().as_ref());
            assert_eq!(
                row["expiresAt"],
                stored
                    .expires_at()
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
            );
            assert!(row.get("user").is_none());
            assert!(row.get("password").is_none());
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
    }
    assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
    B::close(connection).await
}
