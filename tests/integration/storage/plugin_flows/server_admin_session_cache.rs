//! Both public transports issue cache data for the switched stored identity.
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::integrations::axum::AxumIntegration;
use alibi::plugins::AdminPlugin;
use alibi::session::cookie_cache::{CompactCache, decode_compact};
use tower::ServiceExt;

backend_tests!(admin_session_switches_publish_fresh_cache_on_sdk_and_http);
fn published_cache(response: &AuthResponse) -> CompactCache {
    let value = response
        .headers
        .get_all("set-cookie")
        .filter(|cookie| {
            cookie.starts_with("better-auth.session_data=") && !cookie.contains("Max-Age=0")
        })
        .last()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .split_once('=')
        .unwrap()
        .1;
    decode_compact(value, SECRET).unwrap()
}
async fn axum_call(
    router: axum::Router,
    path: &str,
    input: Value,
    cookie: &str,
) -> TestResult<AuthResponse> {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/api/auth{path}"))
        .header("origin", ORIGIN)
        .header("host", url::Url::parse(ORIGIN)?.host_str().unwrap())
        .header("content-type", "application/json")
        .header("cookie", cookie)
        .body(axum::body::Body::from(serde_json::to_vec(&input)?))?;
    let response = router.oneshot(request).await?;
    let mut result = AuthResponse::new(response.status().as_u16());
    for (name, value) in response.headers() {
        result.headers.append(name.as_str(), value.to_str()?);
    }
    result.body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await?
        .to_vec();
    assert_eq!(result.status, 200);
    Ok(result)
}
async fn admin_session_switches_publish_fresh_cache_on_sdk_and_http<B: Backend>(
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
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(AdminPlugin::new().default_role("admin"))
        .endpoint_hook(super::server_admin_support::AdminObserver)
        .build()
        .await?;
    let auth = Arc::new(auth);
    let router = axum::Router::new()
        .nest("/api/auth", auth.clone().axum_router())
        .with_state(auth.clone());
    let admin = signup(&auth, "server-cache-switch-admin@example.test").await;
    let admin_id = body(&admin)["user"]["id"].as_str().unwrap().to_owned();
    let admin_token = body(&admin)["token"].as_str().unwrap().to_owned();
    let target = signup(&auth, "server-cache-switch-target@example.test").await;
    let id = body(&target)["user"]["id"].as_str().unwrap().to_owned();
    drop(
        auth.store()
            .update_user(
                &id,
                alibi::UpdateUser {
                    role: Some("user".into()),
                    ..Default::default()
                },
            )
            .await?,
    );
    drop(signup(&auth, "server-cache-switch-foreign@example.test").await);
    let before = db.tables(&["users", "accounts", "sessions"]).await?;
    let options = |cookie: String| EndpointOptions {
        headers: Some([("cookie".into(), cookie)].into_iter().collect()),
        ..Default::default()
    };
    for sdk in [true, false] {
        let impersonated = if sdk {
            auth.dispatch_endpoint(
                AdminPlugin::impersonate_user_endpoint(id.clone()),
                options(cookies(&admin)),
            )
            .await?
            .into_response()?
        } else {
            axum_call(
                router.clone(),
                "/admin/impersonate-user",
                json!({"userId":id}),
                &cookies(&admin),
            )
            .await?
        };
        let cache = published_cache(&impersonated);
        assert_eq!(cache.user.id, id);
        assert_eq!(
            cache.session.token,
            body(&impersonated)["session"]["token"].as_str().unwrap()
        );
        assert_eq!(
            cache.session.impersonated_by.as_deref(),
            Some(admin_id.as_str())
        );
        let now: f64 = chrono::Utc::now().timestamp_millis().to_string().parse()?;
        assert!((cache.expires_at - now - 60_000.0).abs() < 2000.0);
        let active = cookies(&impersonated);
        assert_eq!(
            body(&call(&auth, request("/get-session", None, &active), 200).await)["user"]["id"],
            id
        );
        let restored = if sdk {
            auth.dispatch_endpoint(AdminPlugin::stop_impersonating_endpoint(), options(active))
                .await?
                .into_response()?
        } else {
            axum_call(
                router.clone(),
                "/admin/stop-impersonating",
                json!({}),
                &active,
            )
            .await?
        };
        let cache = published_cache(&restored);
        assert_eq!(cache.user.id, admin_id);
        assert_eq!(cache.session.token, admin_token);
        assert_eq!(cache.user.role.as_deref(), Some("admin"));
        let now: f64 = chrono::Utc::now().timestamp_millis().to_string().parse()?;
        assert!((cache.expires_at - now - 300_000.0).abs() < 2000.0);
        assert_eq!(
            body(
                &call(
                    &auth,
                    request("/get-session", None, &cookies(&restored)),
                    200
                )
                .await
            )["user"]["id"],
            admin_id
        );
        assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
    }
    B::close(connection).await
}
