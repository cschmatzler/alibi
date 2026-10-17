//! Shared database rate limits across independent storage instances.

use super::{Backend, Db, Raw, TestResult, backend_tests, on_raw, postgres_tests};
use alibi::middleware::{Middleware, RateLimitConfig, RateLimitMiddleware};
use alibi::sqlx::sqlx;
use alibi::store::SchemaMigrator;
use alibi::{
    AuthRequest, EndpointRateLimit, HttpMethod, PluginRateLimit, RateLimitDecision,
    RateLimitStorage,
};
use std::{collections::HashMap, sync::Arc};
#[path = "../../fixtures/oauth/rate-limits.rs"]
mod oauth_policies;

backend_tests!(
    independent_sqlite_instances_preserve_quota_expiry_and_fail_closed,
    oauth_protocol_quotas_use_shared_http_storage_and_exempt_private_dispatch
);
postgres_tests!(independent_sqlite_instances_preserve_quota_expiry_and_fail_closed,);

async fn oauth_protocol_quotas_use_shared_http_storage_and_exempt_private_dispatch<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::integrations::axum::AxumIntegration as _;
    use alibi::plugins::{OAuthProviderConfig, OAuthProviderPlugin};
    use serde_json::json;
    let secret = "native-oauth-rate-policy-secret-at-least-32";
    let (first, _) = db.migrated::<B>(secret).await?;
    B::rate_limit(&first).migrate().await?;
    let second = B::connect(&db.url, None).await?;
    for (mode_index, mode) in [
        "rate-default",
        "rate-override",
        "rate-false",
        "rate-global-disabled",
        "rate-application",
    ]
    .into_iter()
    .enumerate()
    {
        let ip = format!("198.51.100.{}", mode_index + 1);
        let mut auths = Vec::new();
        let mut routers = Vec::new();
        for connection in [&first, &second] {
            let (rate_limit, global) = oauth_policies::policies(mode);
            let config = alibi::AuthConfig::new(secret).base_url("http://localhost:43219");
            let auth = Arc::new(
                Box::pin(
                    alibi::AuthBuilder::<B::Schema>::new(config.clone())
                        .store(B::store(Arc::new(config), connection))
                        .rate_limit(global.storage(Arc::new(B::rate_limit(connection))))
                        .plugin(OAuthProviderPlugin::with_config(OAuthProviderConfig {
                            rate_limit,
                            disable_jwt_plugin: true,
                            ..Default::default()
                        }))
                        .build(),
                )
                .await?,
            );
            routers.push(axum::Router::new().nest(
                "/api/auth",
                auth.clone().axum_router().with_state(auth.clone()),
            ));
            auths.push(auth);
        }
        for (path, default_max, status) in [
            ("token", 20, 400),
            ("authorize", 30, 302),
            ("introspect", 100, 400),
            ("revoke", 30, 400),
            ("register", 5, 403),
            ("userinfo", 60, 401),
        ] {
            let (max, retry) = match (mode, path) {
                ("rate-default", _) => (default_max, Some("60")),
                ("rate-override", "token") => (2, Some("120")),
                ("rate-override", "authorize") => (1, Some("60")),
                ("rate-override", "introspect")
                | ("rate-global-disabled", _)
                | ("rate-application", "token") => (3, None),
                ("rate-override", _) => continue,
                ("rate-false", _) => (2, Some("120")),
                ("rate-application", _) => (1, Some("180")),
                _ => return Err("unknown quota profile".into()),
            };
            for index in 0..max {
                let response =
                    oauth_http_method(&routers[index % 2], path, &ip, index % 2 == 1).await?;
                assert_eq!(
                    response.status,
                    status,
                    "{mode} {path} admission {index}: {}",
                    String::from_utf8_lossy(&response.body)
                );
                assert!(response.headers.get("x-retry-after").is_none());
            }
            if let Some(retry) = retry {
                let blocked = oauth_http(&routers[1], path, &ip).await?;
                assert_eq!(blocked.status, 429, "{mode} {path}");
                assert_eq!(
                    blocked.body,
                    br#"{"message":"Too many requests. Please try again later."}"#
                );
                assert_eq!(
                    blocked.headers.get("content-type").map(String::as_str),
                    Some("application/json")
                );
                assert_eq!(
                    blocked.headers.get("x-retry-after").map(String::as_str),
                    Some(retry)
                );
                assert!(!blocked.headers.contains_key("set-cookie"));
                assert_eq!(
                    row(&db, &format!("{ip}|/oauth2/{path}")).await?.unwrap().1,
                    i32::try_from(max)?
                );
                // A different trusted client has its own bucket even on the same route.
                assert_eq!(
                    oauth_http(&routers[0], path, &format!("198.51.101.{}", mode_index + 1))
                        .await?
                        .status,
                    status
                );
            }
        }
        if mode == "rate-default" {
            let key = format!("{ip}|/oauth2/token");
            let before = row(&db, &key).await?.unwrap();
            for physical in [false, true] {
                let input = json!({"grant_type":"client_credentials","client_id":"quota-missing","client_secret":"not-secret","scope":"email"});
                let mut request = AuthRequest::new(HttpMethod::Post, "/api/auth/oauth2/token");
                _ = request.headers.insert("x-forwarded-for".into(), ip.clone());
                let error = Box::pin(auths[0].dispatch_endpoint(
                    OAuthProviderPlugin::oauth2_token_endpoint(&input)?,
                    alibi::endpoint::EndpointOptions {
                        headers: Some(request.headers.clone()),
                        request: physical.then_some(request),
                        ..Default::default()
                    },
                ))
                .await
                .unwrap_err();
                assert_eq!(
                    error.error.status_code(),
                    400,
                    "private dispatch bypasses the exhausted HTTP quota"
                );
            }
            assert_eq!(row(&db, &key).await?, Some(before.clone()));
            set_last_request(&db, &key, chrono::Utc::now().timestamp_millis() - 61_000).await?;
            assert_eq!(oauth_http(&routers[1], "token", &ip).await?.status, 400);
            let reset = row(&db, &key).await?.unwrap();
            assert_eq!(reset.1, 1);
            assert!(reset.2 >= before.2);
            for _ in 0..2 {
                assert_eq!(
                    oauth_http(&routers[0], "token-extra", &ip).await?.status,
                    404
                );
            }
            assert_eq!(
                oauth_http(&routers[1], "token-extra", &ip)
                    .await?
                    .headers
                    .get("x-retry-after")
                    .map(String::as_str),
                Some("120"),
                "plugin matchers are exact"
            );
        }
        if matches!(mode, "rate-global-disabled" | "rate-application") {
            assert!(row(&db, &format!("{ip}|/oauth2/token")).await?.is_none());
        }
        if mode == "rate-override" {
            assert_eq!(
                row(&db, &format!("{ip}|/oauth2/introspect"))
                    .await?
                    .unwrap()
                    .1,
                1,
                "zero window resets the real ledger on every request"
            );
        }
    }
    B::close(first).await?;
    B::close(second).await
}

async fn oauth_http(
    router: &axum::Router,
    path: &str,
    ip: &str,
) -> TestResult<alibi::AuthResponse> {
    oauth_http_method(router, path, ip, false).await
}

async fn oauth_http_method(
    router: &axum::Router,
    path: &str,
    ip: &str,
    post: bool,
) -> TestResult<alibi::AuthResponse> {
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;
    let get = !post && matches!(path, "authorize" | "userinfo");
    let input = match path {
        "authorize" => {
            "client_id=quota-missing&response_type=code&redirect_uri=https%3A%2F%2Fapp.fixture.test%2Fcallback"
        }
        "token" => {
            "grant_type=client_credentials&client_id=quota-missing&client_secret=not-secret&scope=email"
        }
        "userinfo" => "access_token=missing",
        _ => "client_id=quota-missing&client_secret=not-secret&token=missing",
    };
    let uri = format!(
        "/api/auth/oauth2/{path}{}",
        if path == "authorize" {
            format!("?{input}")
        } else {
            String::new()
        }
    );
    let request = axum::http::Request::builder()
        .method(if get { "GET" } else { "POST" })
        .uri(uri)
        .header("origin", "http://localhost:43219")
        .header("x-forwarded-for", ip)
        .header(
            "content-type",
            if path == "register" {
                "application/json"
            } else {
                "application/x-www-form-urlencoded"
            },
        );
    let request = if path == "userinfo" && get {
        request.header("authorization", "Bearer missing")
    } else {
        request
    };
    let request = request.body(axum::body::Body::from(if get {
        String::new()
    } else if path == "register" {
        r#"{"redirect_uris":["https://app.fixture.test/callback"]}"#.into()
    } else {
        input.into()
    }))?;
    let response = router.clone().oneshot(request).await?;
    let (parts, body) = response.into_parts();
    let mut response = alibi::AuthResponse::new(parts.status.as_u16());
    response.body = body.collect().await?.to_bytes().to_vec();
    for (name, value) in &parts.headers {
        _ = response.headers.insert(name.as_str(), value.to_str()?);
    }
    Ok(response)
}

#[derive(Debug)]
struct ApplicationRule;
#[async_trait::async_trait]
impl alibi::middleware::rate_limit::RateLimitResolver for ApplicationRule {
    async fn resolve(
        &self,
        request: &AuthRequest,
        inherited: &EndpointRateLimit,
    ) -> alibi::AuthResult<Option<EndpointRateLimit>> {
        assert_eq!(request.path, "/api/auth/dynamic-rule");
        assert_eq!(inherited.max_requests, 3.0, "first matching plugin wins");
        assert_eq!(inherited.window_seconds, 180.0);
        match request.headers.get("x-policy").map(String::as_str) {
            Some("disabled") => Ok(None),
            Some("error") => Err(alibi::AuthError::forbidden("application rate policy veto")),
            _ => Ok(Some(EndpointRateLimit {
                max_requests: 1.0,
                window_seconds: 120.0,
            })),
        }
    }
}

type Row = (String, i32, i64);

async fn row(db: &Db, key: &str) -> TestResult<Option<Row>> {
    on_raw!(&db.raw, |pool| Ok(sqlx::query_as(
        "SELECT \"key\", \"count\", \"lastRequest\" FROM \"rateLimit\" WHERE \"key\" = $1",
    )
    .bind(key)
    .fetch_optional(pool)
    .await?))
}

async fn insert(db: &Db, row: Row) -> TestResult {
    let (key, count, last_request) = row;
    on_raw!(&db.raw, |pool| {
        _ = sqlx::query(
            "INSERT INTO \"rateLimit\" (\"id\", \"key\", \"count\", \"lastRequest\") VALUES ($1, $2, $3, $4)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&key)
        .bind(count)
        .bind(last_request)
        .execute(pool)
        .await?;
    });
    Ok(())
}

async fn set_last_request(db: &Db, key: &str, last_request: i64) -> TestResult {
    on_raw!(&db.raw, |pool| {
        _ = sqlx::query("UPDATE \"rateLimit\" SET \"lastRequest\" = $1 WHERE \"key\" = $2")
            .bind(last_request)
            .bind(key)
            .execute(pool)
            .await?;
    });
    Ok(())
}

async fn independent_sqlite_instances_preserve_quota_expiry_and_fail_closed<B: Backend>(
    db: Db,
) -> TestResult {
    let first = B::connect(&db.url, None).await?;
    let second = B::connect(&db.url, None).await?;
    let stores = [B::rate_limit(&first), B::rate_limit(&second)];
    stores[0].migrate().await?;
    // Migration is idempotent across instances sharing one ledger.
    stores[1].migrate().await?;
    let key = format!("198.51.100.1|/proof-{}-'", uuid::Uuid::new_v4());
    let rule = EndpointRateLimit {
        window_seconds: 120.0,
        max_requests: 3.0,
    };
    let dynamic = RateLimitMiddleware::new(
        RateLimitConfig::new()
            .storage(Arc::new(stores[0].clone()))
            .rule(
                "/dynamic-rule",
                alibi::middleware::rate_limit::RateLimitRule::Dynamic(Arc::new(ApplicationRule)),
            ),
    )
    .with_base_path("/api/auth")
    .with_plugin_rules(vec![
        PluginRateLimit {
            matches: |path| path == "/dynamic-rule",
            limit: EndpointRateLimit {
                window_seconds: 180.0,
                max_requests: 3.0,
            },
        },
        PluginRateLimit {
            matches: |_| true,
            limit: EndpointRateLimit {
                window_seconds: 60.0,
                max_requests: 99.0,
            },
        },
    ]);
    let mut dynamic_request = AuthRequest::new(HttpMethod::Get, "/api/auth/dynamic-rule");
    let dynamic_key = "no-trusted-ip|/dynamic-rule";
    for mode in ["disabled", "error"] {
        drop(
            dynamic_request
                .headers
                .insert("x-policy".into(), mode.into()),
        );
        let result = dynamic.before_request(&dynamic_request).await;
        if mode == "disabled" {
            assert!(result?.is_none());
        } else {
            assert_eq!(result.unwrap_err().status_code(), 403);
        }
        assert!(row(&db, dynamic_key).await?.is_none());
    }
    drop(dynamic_request.headers.remove("x-policy"));
    assert!(dynamic.before_request(&dynamic_request).await?.is_none());
    let consumed = row(&db, dynamic_key).await?.unwrap();
    assert_eq!(consumed.1, 1);
    let blocked = dynamic.before_request(&dynamic_request).await?.unwrap();
    assert_eq!(blocked.status, 429);
    assert_eq!(row(&db, dynamic_key).await?, Some(consumed));
    let now = chrono::Utc::now().timestamp_millis();
    let old_key = format!("stale-{key}");
    let protected_key = format!("protected-{key}");
    let protected: Row = (protected_key.clone(), 3, now - 121_000);
    for (key, count, last_request) in [(old_key.clone(), 3, now - 181_000), protected.clone()] {
        insert(&db, (key, count, last_request)).await?;
    }
    let infinite_key = format!("infinite-{key}");
    let infinite_rule = EndpointRateLimit {
        window_seconds: f64::INFINITY,
        max_requests: 1.0,
    };
    assert!(matches!(
        stores[0].consume(&infinite_key, &infinite_rule).await?,
        RateLimitDecision::Allowed
    ));
    set_last_request(&db, &infinite_key, now - 181_000).await?;
    let infinite = row(&db, &infinite_key)
        .await?
        .ok_or("missing infinite row")?;
    // Requests under a shorter rule preserve other keys' quotas.
    assert!(matches!(
        stores[1].consume(&format!("cleanup-{key}"), &rule).await?,
        RateLimitDecision::Allowed
    ));
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..32 {
        let storage = stores[index % 2].clone();
        let key = key.clone();
        let rule = rule.clone();
        _ = tasks.spawn(async move { storage.consume(&key, &rule).await });
    }
    let mut results = Vec::new();
    while let Some(result) = tasks.join_next().await {
        results.push(result??);
    }
    assert_eq!(
        row(&db, &old_key).await?,
        Some((old_key.clone(), 3, now - 181_000))
    );
    assert_eq!(row(&db, &protected_key).await?, Some(protected));
    assert_eq!(row(&db, &infinite_key).await?, Some(infinite));
    assert!(
        matches!(stores[1].consume(&infinite_key, &infinite_rule).await?, RateLimitDecision::Blocked { retry_after } if retry_after.is_infinite())
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, RateLimitDecision::Allowed))
            .count(),
        3
    );
    let before = row(&db, &key).await?.ok_or("missing quota row")?;
    assert_eq!(before.1.to_string(), "3");
    assert!(matches!(
        stores[1].consume(&key, &rule).await?,
        RateLimitDecision::Blocked { .. }
    ));
    assert_eq!(row(&db, &key).await?, Some(before.clone()));
    // Concurrency must not race a short wall-clock window. Age the actual
    // ledger after asserting quota, then let a separate adapter reset it.
    set_last_request(&db, &key, chrono::Utc::now().timestamp_millis() - 121_000).await?;
    assert!(matches!(
        stores[0].consume(&key, &rule).await?,
        RateLimitDecision::Allowed
    ));
    let reset = row(&db, &key).await?.ok_or("missing reset row")?;
    assert_eq!(reset.1.to_string(), "1");
    assert!(reset.2 >= before.2);
    // An absent/misconfigured backend fails closed before endpoint dispatch.
    _ = db.execute("DROP TABLE \"rateLimit\"", &[]).await?;
    let middleware =
        RateLimitMiddleware::new(RateLimitConfig::new().storage(Arc::new(stores[0].clone())));
    let request = AuthRequest::from_parts(
        HttpMethod::Post,
        "/sign-in/email".to_owned(),
        HashMap::new(),
        None,
        HashMap::new(),
    );
    let failure = middleware
        .before_request(&request)
        .await
        .unwrap_err()
        .to_auth_response();
    assert_eq!(failure.status, 500);
    assert!(!String::from_utf8_lossy(&failure.body).contains("rateLimit"));
    B::close(first).await?;
    B::close(second).await
}
