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
backend_tests!(server_custom_session_overrides_core_get_session_with_real_callback_context);
postgres_tests!(server_custom_session_overrides_core_get_session_with_real_callback_context);
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
        assert!(missing.headers.get("cache-control").is_none());
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
