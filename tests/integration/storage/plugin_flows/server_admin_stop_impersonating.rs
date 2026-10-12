//! Logical restoration consumes only the matching signed owner proof.
use super::*;
use alibi::UpdateUser;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::AdminPlugin;
use alibi::utils::json::JsValue;

backend_tests!(server_admin_stop_impersonating_restores_owner_and_remember_policy);
async fn server_admin_stop_impersonating_restores_owner_and_remember_policy<B: Backend>(
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
    let admin = signup(&auth, "server-stop-admin@example.test").await;
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
    let target = signup(&auth, "server-stop-target@example.test").await;
    let id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
    let foreign = signup(&auth, "server-stop-foreign@example.test").await;
    let foreign_token = body(&foreign)["token"].as_str().unwrap().to_owned();
    let options = |cookie: String| EndpointOptions {
        headers: Some([("cookie".into(), cookie)].into_iter().collect()),
        ..Default::default()
    };
    for (headers, status, message) in [
        (EndpointOptions::default(), 400, "Headers is required"),
        (
            EndpointOptions {
                headers: Some(Default::default()),
                ..Default::default()
            },
            401,
            "",
        ),
        (
            options(cookies(&admin)),
            400,
            "You are not impersonating anyone",
        ),
        (
            options(cookies(&foreign)),
            400,
            "You are not impersonating anyone",
        ),
    ] {
        let error = auth
            .dispatch_endpoint(
                AdminPlugin::stop_impersonating_endpoint().with_body(&json!(7))?,
                headers,
            )
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), status);
        if status == 401 {
            assert!(error.body_absent);
        } else {
            assert_eq!(body(&error.error.to_auth_response())["message"], message);
        }
    }
    for remember in [false, true] {
        let (short_token, original_cookie) = if remember {
            let login=call(&auth,request("/sign-in/email",Some(json!({"email":"server-stop-admin@example.test","password":PASSWORD,"rememberMe":false})),""),200).await;
            (
                body(&login)["token"].as_str().unwrap().to_owned(),
                cookies(&login),
            )
        } else {
            (admin_token.clone(), cookies(&admin))
        };
        let before = db.tables(&["users", "accounts", "sessions"]).await?;
        let impersonated = auth
            .dispatch_endpoint(
                AdminPlugin::impersonate_user_endpoint(id.clone()),
                options(original_cookie),
            )
            .await?;
        let impersonated_cookie = cookies(&impersonated.into_response()?);
        let session_only = impersonated_cookie
            .split("; ")
            .filter(|pair| !pair.starts_with("better-auth.admin_session="))
            .collect::<Vec<_>>()
            .join("; ");
        let during = db.tables(&["users", "accounts", "sessions"]).await?;
        for proof in [
            None,
            Some("invalid".to_owned()),
            Some(alibi::utils::cookie_utils::sign_cookie_value(
                &format!("{foreign_token}:"),
                SECRET,
            )),
        ] {
            let cookie = proof.map_or_else(
                || session_only.clone(),
                |proof| format!("{session_only}; better-auth.admin_session={proof}"),
            );
            let error = auth
                .dispatch_endpoint(AdminPlugin::stop_impersonating_endpoint(), options(cookie))
                .await
                .unwrap_err();
            assert_eq!(error.error.status_code(), 500);
            assert_eq!(
                body(&error.error.to_auth_response())["message"],
                "Failed to find admin session"
            );
            assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, during);
        }
        let stopped = auth
            .dispatch_endpoint(
                AdminPlugin::stop_impersonating_endpoint()
                    .with_body(&json!(7))?
                    .with_query(&json!({"userId":"foreign","sessionToken":foreign_token}))?,
                options(impersonated_cookie.clone()),
            )
            .await?;
        assert_eq!(stopped.decode()?.user.id, admin_id);
        assert_eq!(
            stopped.value().get("user").unwrap().get("id"),
            Some(&JsValue::String(admin_id.clone()))
        );
        assert_eq!(
            stopped.value().get("session").unwrap().get("token"),
            Some(&JsValue::String(short_token.clone()))
        );
        assert_eq!(stopped.headers().get("x-admin-principal"), Some(&id));
        let raw = stopped
            .headers()
            .get_all("set-cookie")
            .cloned()
            .collect::<Vec<_>>();
        let restored = raw
            .iter()
            .find(|cookie| cookie.starts_with("better-auth.session_token="))
            .unwrap();
        let value = restored
            .split(';')
            .next()
            .unwrap()
            .split_once('=')
            .unwrap()
            .1;
        assert_eq!(
            alibi::utils::cookie_utils::verify_cookie_value(value, SECRET),
            Some(short_token)
        );
        assert_eq!(restored.contains("Max-Age="), !remember);
        assert!(
            raw.iter()
                .any(|cookie| cookie.starts_with("better-auth.admin_session=;")
                    && cookie.contains("Max-Age=0"))
        );
        assert!(raw.contains(&"application_a=first; Path=/; HttpOnly".into()));
        assert!(raw.contains(&"application_b=second; Path=/; HttpOnly".into()));
        assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
        let restored_cookie = cookies(&stopped.into_response()?);
        let current = call(&auth, request("/get-session", None, &restored_cookie), 200).await;
        assert_eq!(body(&current)["user"]["id"], admin_id);
        let replay = auth
            .dispatch_endpoint(
                AdminPlugin::stop_impersonating_endpoint(),
                options(impersonated_cookie),
            )
            .await
            .unwrap_err();
        assert_eq!(replay.error.status_code(), 401);
        assert!(replay.body_absent);
    }
    B::close(connection).await
}
