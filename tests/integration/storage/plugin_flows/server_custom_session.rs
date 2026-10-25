//! A custom session owns SDK and HTTP getSession regardless of core plugin order.
use super::*;
use alibi::endpoint::{EndpointOptions, EndpointResponse, ServerEndpoint};
use alibi::plugins::{CustomSessionPlugin, SessionTransform, SessionTransformContext};
struct Projection;
#[async_trait::async_trait]
impl<S: AuthSchema> SessionTransform<S> for Projection {
    async fn transform(
        &self,
        mut session: Value,
        frame: &SessionTransformContext,
        ctx: &alibi::AuthContext<S>,
    ) -> alibi::AuthResult<Value> {
        match frame.header("x-custom-session").map(String::as_str) {
            Some("error") => {
                return Err(alibi::AuthError::Api {
                    status: 403,
                    code: Some("CUSTOM_SESSION_DENIED".into()),
                    message: "Application session denied".into(),
                });
            }
            Some("null") => return Ok(Value::Null),
            Some("filtered") => {
                return Ok(
                    json!({"userId":session.pointer("/user/id"),"label":session.pointer("/user/name")}),
                );
            }
            _ => {}
        }
        use alibi::AuthUser;
        let uid = session.pointer("/user/id").and_then(Value::as_str).unwrap();
        let user = ctx.database.get_user_by_id(uid).await?.unwrap();
        _=session.as_object_mut().unwrap().insert("application".into(),json!({"label":user.name(),"userId":user.id(),"path":frame.path(),"hasRequest":frame.request().is_some(),"marker":frame.header("x-custom-marker")}));
        Ok(session)
    }
}
backend_tests!(
    server_custom_session_overrides_core_get_session_with_real_callback_context,
    server_custom_session_projects_device_lists_only_when_enabled
);
postgres_tests!(
    server_custom_session_overrides_core_get_session_with_real_callback_context,
    server_custom_session_projects_device_lists_only_when_enabled
);
async fn read<S: AuthSchema>(
    auth: &Alibi<S>,
    plugin: &str,
    headers: Option<std::collections::HashMap<String, String>>,
    request: Option<AuthRequest>,
) -> alibi::AuthResult<AuthResponse> {
    let endpoint = if plugin == "custom-session" {
        CustomSessionPlugin::<S>::get_session_endpoint()
    } else {
        ServerEndpoint::<Value>::new("session-management", "getSession")
    };
    match Box::pin(auth.dispatch_endpoint(
        endpoint,
        EndpointOptions {
            headers,
            request,
            ..Default::default()
        },
    ))
    .await
    {
        Ok(output) => output.into_response(),
        Err(error) => {
            let mut response = EndpointResponse::error(error.error);
            if let Some(body) = error.body {
                response = response.with_error_body(*body);
            }
            if let Some(headers) = error.headers {
                response.merge_headers(headers);
            }
            response.to_response()
        }
    }
}
async fn server_custom_session_overrides_core_get_session_with_real_callback_context<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    for custom_first in [false, true] {
        let config = AuthConfig::new(SECRET).base_url(ORIGIN);
        let builder = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new());
        let auth = if custom_first {
            builder
                .plugin(CustomSessionPlugin::new(Projection))
                .plugin(SessionManagementPlugin::new())
        } else {
            builder
                .plugin(SessionManagementPlugin::new())
                .plugin(CustomSessionPlugin::new(Projection))
        }
        .build()
        .await?;
        let signed = signup(&auth, &format!("custom-sdk-{custom_first}@example.com")).await;
        let cookie = cookies(&signed);
        let expected = body(&signed)["user"]["id"].clone();
        let label = body(&signed)["user"]["name"].clone();
        let missing = read(
            &auth,
            "session-management",
            Some(
                [("x-custom-session".into(), "error".into())]
                    .into_iter()
                    .collect(),
            ),
            None,
        )
        .await?;
        assert_eq!(missing.status, 200);
        assert_eq!(body(&missing), Value::Null);
        // Since 1.7.12 a null session still forwards the core read's headers.
        assert_eq!(
            missing
                .headers
                .get("cache-control")
                .map(|value| value.as_str()),
            Some("no-store")
        );
        let headers = [
            ("cookie".into(), cookie.clone()),
            ("x-custom-marker".into(), "sdk".into()),
        ]
        .into_iter()
        .collect();
        let output = read(&auth, "session-management", Some(headers), None).await?;
        assert_eq!(output.status, 200);
        assert_eq!(
            body(&output)["application"],
            json!({"userId":expected,"label":label,"path":"/get-session","hasRequest":false,"marker":"sdk"})
        );
        assert_eq!(
            output.headers.get("cache-control").map(String::as_str),
            Some("no-store")
        );
        let own = read(
            &auth,
            "custom-session",
            Some([("cookie".into(), cookie.clone())].into_iter().collect()),
            None,
        )
        .await?;
        assert_eq!(own.status, 200);
        assert_eq!(body(&own)["application"]["hasRequest"], false);
        let mut original = AuthRequest::new(HttpMethod::Get, "/api/auth/get-session");
        _ = original
            .headers
            .insert("x-custom-marker".into(), "original".into());
        let response = read(
            &auth,
            "session-management",
            Some(
                [
                    ("cookie".into(), cookie.clone()),
                    ("x-custom-marker".into(), "explicit".into()),
                ]
                .into_iter()
                .collect(),
            ),
            Some(original),
        )
        .await?;
        assert_eq!(response.status, 200);
        assert_eq!(body(&response)["application"]["hasRequest"], true);
        assert_eq!(body(&response)["application"]["marker"], "explicit");
        for (mode, status) in [("filtered", 200), ("null", 200), ("error", 403)] {
            let response = read(
                &auth,
                "session-management",
                Some(
                    [
                        ("cookie".into(), cookie.clone()),
                        ("x-custom-session".into(), mode.into()),
                    ]
                    .into_iter()
                    .collect(),
                ),
                None,
            )
            .await?;
            assert_eq!(response.status, status);
            match mode {
                "filtered" => assert_eq!(body(&response), json!({"userId":expected,"label":label})),
                "null" => {
                    assert_eq!(body(&response), Value::Null);
                    assert_eq!(
                        response.headers.get("cache-control").map(String::as_str),
                        Some("no-store")
                    );
                }
                _ => assert_eq!(body(&response)["code"], "CUSTOM_SESSION_DENIED"),
            }
        }
        let mut original = AuthRequest::new(HttpMethod::Get, "/api/auth/get-session");
        _ = original.headers.insert("cookie".into(), cookie.clone());
        assert_eq!(
            read(&auth, "session-management", None, Some(original))
                .await?
                .status,
            400
        );
        let mut req = request("/get-session", None, &cookie);
        _ = req.headers.insert("x-custom-marker".into(), "http".into());
        let http = call(&auth, req, 200).await;
        assert_eq!(body(&http)["application"]["hasRequest"], true);
        assert_eq!(body(&http)["application"]["marker"], "http");
        _ = call(
            &auth,
            request("/get-session", Some(json!({})), &cookie),
            404,
        )
        .await;
    }
    Ok(())
}

async fn device_list<S: AuthSchema>(
    auth: &Alibi<S>,
    cookie: &str,
    mode: &str,
    original: bool,
) -> alibi::AuthResult<AuthResponse> {
    let headers = [
        ("cookie".into(), cookie.into()),
        ("x-custom-session".into(), mode.into()),
        ("x-custom-marker".into(), "sdk".into()),
    ]
    .into_iter()
    .collect();
    let request = original.then(|| AuthRequest::new(HttpMethod::Get, "/actual-device-request"));
    match Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("multi-session", "listDeviceSessions"),
        EndpointOptions {
            headers: Some(headers),
            request,
            ..Default::default()
        },
    ))
    .await
    {
        Ok(output) => output.into_response(),
        Err(error) => EndpointResponse::error(error.error).to_response(),
    }
}
async fn server_custom_session_projects_device_lists_only_when_enabled<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    for enabled in [false, true] {
        let auth = builder::<B>(&connection)
            .plugin(CustomSessionPlugin::new(Projection).mutate_device_sessions(enabled))
            .plugin(alibi::plugins::MultiSessionPlugin::new())
            .build()
            .await?;
        let mut jar = Vec::new();
        let mut owners = Vec::new();
        for name in ["first", "second"] {
            let response =
                signup(&auth, &format!("custom-list-{enabled}-{name}@example.com")).await;
            jar.push(cookies(&response));
            owners.push(body(&response)["user"]["id"].clone());
        }
        let cookie = jar.join("; ");
        let listed = device_list(&auth, &cookie, "", false).await?;
        assert_eq!(listed.status, 200);
        let rows = body(&listed);
        assert_eq!(rows.as_array().unwrap().len(), 2);
        for row in rows.as_array().unwrap() {
            assert!(owners.contains(&row["user"]["id"]));
            if enabled {
                assert_eq!(row["application"]["userId"], row["user"]["id"]);
                assert_eq!(
                    row["application"]["path"],
                    "/multi-session/list-device-sessions"
                );
                assert_eq!(row["application"]["hasRequest"], false);
                assert_eq!(row["application"]["marker"], "sdk");
            } else {
                assert!(row.get("application").is_none());
            }
        }
        if enabled {
            let original = device_list(&auth, &cookie, "", true).await?;
            assert!(
                body(&original)
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|row| row["application"]["hasRequest"] == true)
            );
            let filtered = device_list(&auth, &cookie, "filtered", false).await?;
            for row in body(&filtered).as_array().unwrap() {
                assert!(owners.contains(&row["userId"]));
                assert!(row.get("session").is_none());
            }
            assert_eq!(
                body(&device_list(&auth, &cookie, "null", false).await?),
                json!([null, null])
            );
            let denied = device_list(&auth, &cookie, "error", false).await?;
            assert_eq!(denied.status, 403);
            assert_eq!(body(&denied)["code"], "CUSTOM_SESSION_DENIED");
        } else {
            assert_eq!(
                device_list(&auth, &cookie, "error", false).await?.status,
                200
            );
        }
        assert_eq!(
            body(&device_list(&auth, "", "error", false).await?),
            json!([])
        );
    }
    Ok(())
}
