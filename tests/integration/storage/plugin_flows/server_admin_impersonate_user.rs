//! SDK impersonation publishes verifiable cookies with a real stored session.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{AdminConfig, AdminPlugin, RolePermissions};
use alibi::utils::json::JsValue;
use alibi::{AuthSession, UpdateUser};

backend_tests!(server_admin_impersonate_user_publishes_usable_signed_session);
async fn server_admin_impersonate_user_publishes_usable_signed_session<B: Backend>(
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
    let admin = signup(&auth, "server-impersonate-admin@example.test").await;
    let admin_id = body(&admin)["user"]["id"].as_str().unwrap().to_owned();
    let admin_token = body(&admin)["token"].as_str().unwrap().to_owned();
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
    let target = signup(&auth, "server-impersonate-target@example.test").await;
    let id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
    let foreign = signup(&auth, "server-impersonate-foreign@example.test").await;
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
            "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS",
        ),
        (
            Some(json!({"userId":admin_id})),
            options(&admin),
            403,
            "YOU_CANNOT_IMPERSONATE_ADMINS",
        ),
        (
            Some(json!({"userId":null})),
            options(&admin),
            404,
            "USER_NOT_FOUND",
        ),
        (
            Some(json!({"userId":"missing-user"})),
            options(&admin),
            404,
            "USER_NOT_FOUND",
        ),
    ] {
        let mut endpoint = ServerEndpoint::<JsValue>::new("admin", "impersonateUser");
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
        .store(B::store(Arc::new(config.clone()), &connection))
        .plugin(SessionManagementPlugin::new())
        .plugin(AdminPlugin::new().roles(std::collections::HashMap::from([(
            "admin".into(),
            RolePermissions::new().allow("user", ["update"]),
        )])))
        .build()
        .await?;
    let error = restricted
        .dispatch_endpoint(
            ServerEndpoint::<JsValue>::new("admin", "impersonateUser")
                .with_body(&json!({"userId":id}))?,
            options(&admin),
        )
        .await
        .unwrap_err();
    assert_eq!(error.error.status_code(), 403);
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    let configured = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .plugin(SessionManagementPlugin::new())
        .plugin(AdminPlugin::with_config(AdminConfig {
            impersonation_session_duration: Some(120.75),
            ..Default::default()
        }))
        .endpoint_hook(super::server_admin_support::AdminObserver)
        .build()
        .await?;
    for (active, duration_millis) in [(&auth, 3_600_000_i64), (&configured, 120_750)] {
        let mut headers = options(&admin).headers.unwrap();
        drop(headers.insert("x-forwarded-for".into(), "203.0.113.46".into()));
        drop(headers.insert("user-agent".into(), "logical-admin-sdk".into()));
        let output = active
            .dispatch_endpoint(
                AdminPlugin::impersonate_user_endpoint(id.clone())
                    .with_body(&json!({"userId":id,"impersonatedBy":foreign_id}))?
                    .with_query(&json!({"userId":foreign_id}))?,
                EndpointOptions {
                    headers: Some(headers),
                    ..Default::default()
                },
            )
            .await?;
        assert_eq!(output.decode()?.user.id, id);
        let session = output.value().get("session").unwrap();
        let token = session.get("token").and_then(JsValue::as_str).unwrap();
        assert_ne!(token, admin_token);
        assert_eq!(session.get("userId"), Some(&JsValue::String(id.clone())));
        assert_eq!(
            session.get("impersonatedBy"),
            Some(&JsValue::String(admin_id.clone()))
        );
        assert_eq!(output.headers().get("x-admin-principal"), Some(&admin_id));
        let stored = auth
            .store()
            .get_user_sessions(&id)
            .await?
            .into_iter()
            .find(|row| row.token() == token)
            .unwrap();
        assert_eq!(stored.ip_address(), Some("203.0.113.46"));
        assert_eq!(stored.user_agent(), Some("logical-admin-sdk"));
        let elapsed = stored
            .expires_at()
            .signed_duration_since(stored.created_at())
            .num_milliseconds();
        assert!((elapsed - duration_millis).abs() < 2000);
        let raw = output
            .headers()
            .get_all("set-cookie")
            .cloned()
            .collect::<Vec<_>>();
        let mut jar = std::collections::BTreeMap::new();
        for value in &raw {
            let pair = value.split(';').next().unwrap();
            let (name, value) = pair.split_once('=').unwrap();
            if value.is_empty() {
                drop(jar.remove(name));
            } else {
                drop(jar.insert(name.to_owned(), value.to_owned()));
            }
        }
        assert_eq!(
            alibi::utils::cookie_utils::verify_cookie_value(
                &jar["better-auth.admin_session"],
                SECRET
            ),
            Some(format!("{admin_token}:"))
        );
        assert_eq!(
            alibi::utils::cookie_utils::verify_cookie_value(
                &jar["better-auth.session_token"],
                SECRET
            ),
            Some(token.into())
        );
        assert_eq!(
            alibi::utils::cookie_utils::verify_cookie_value(
                &jar["better-auth.dont_remember"],
                SECRET
            ),
            Some("true".into())
        );
        assert_eq!(jar.get("application_a").map(String::as_str), Some("first"));
        assert_eq!(jar.get("application_b").map(String::as_str), Some("second"));
        let cookie = jar
            .into_iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        let current = call(&auth, request("/get-session", None, &cookie), 200).await;
        assert_eq!(body(&current)["user"]["id"], id);
        assert_eq!(body(&current)["session"]["token"], token);
        let restored = call(
            &auth,
            request("/admin/stop-impersonating", Some(json!({})), &cookie),
            200,
        )
        .await;
        assert_eq!(body(&restored)["user"]["id"], admin_id);
        assert_eq!(body(&restored)["session"]["token"], admin_token);
        assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    }
    B::close(connection).await
}
