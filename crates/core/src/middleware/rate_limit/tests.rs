use super::*;
use crate::types::HttpMethod;
use std::collections::HashMap as StdHashMap;

fn make_request(path: &str, ip: &str) -> AuthRequest {
    let mut headers = StdHashMap::new();
    headers.insert("x-forwarded-for".to_owned(), ip.to_owned());
    AuthRequest::from_parts(
        HttpMethod::Post,
        path.to_owned(),
        headers,
        None,
        StdHashMap::new(),
    )
}

// Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
#[tokio::test]
async fn test_rate_limit_allows_within_limit() {
    let config = RateLimitConfig::new().default_limit(Duration::from_secs(60), 5);
    let mw = RateLimitMiddleware::new(config);
    let req = make_request("/get-session", "1.2.3.4");

    for _ in 0..5 {
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }
}

// Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
#[tokio::test]
async fn test_rate_limit_blocks_over_limit() {
    let config = RateLimitConfig::new().default_limit(Duration::from_secs(60), 3);
    let mw = RateLimitMiddleware::new(config);
    let req = make_request("/get-session", "1.2.3.4");

    for _ in 0..3 {
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }

    let resp = mw.before_request(&req).await.unwrap();
    assert!(resp.is_some());
    assert_eq!(resp.unwrap().status, 429);
}

// Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
#[tokio::test]
async fn test_rate_limit_per_client() {
    let config = RateLimitConfig::new().default_limit(Duration::from_secs(60), 2);
    let mw = RateLimitMiddleware::new(config);

    let req_a = make_request("/get-session", "1.1.1.1");
    let req_b = make_request("/get-session", "2.2.2.2");

    // Client A uses up its limit
    for _ in 0..2 {
        assert!(mw.before_request(&req_a).await.unwrap().is_none());
    }
    assert!(mw.before_request(&req_a).await.unwrap().is_some());

    // Client B should still be allowed
    assert!(mw.before_request(&req_b).await.unwrap().is_none());
}

// Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
#[tokio::test]
async fn test_rate_limit_per_endpoint_override() {
    for (pattern, path, matches) in [
        ("/sign-in/email", "/sign-in/email", true),
        ("/sign-in/*", "/sign-in/email", true),
        ("/email-otp/*", "/email-otp/send-verification-otp", true),
        ("/email-otp/*", "/email-otp/nested/send", true),
        ("/literal/?", "/literal/q", false),
    ] {
        let config = RateLimitConfig::new()
            .default_limit(Duration::from_secs(60), 100)
            .endpoint(pattern, Duration::from_secs(60), 2);
        let mw = RateLimitMiddleware::new(config);
        let req = make_request(path, "1.2.3.4");
        for _ in 0..2 {
            assert!(mw.before_request(&req).await.unwrap().is_none());
        }
        let response = mw.before_request(&req).await.unwrap();
        assert_eq!(
            response.as_ref().map(|response| response.status),
            matches.then_some(429)
        );
    }
}

// Rust-specific surface: Rust middleware implementations are library-specific behavior with no direct TS analogue.
#[tokio::test]
async fn test_rate_limit_disabled() {
    let config = RateLimitConfig::new()
        .default_limit(Duration::from_secs(60), 1)
        .enabled(false);
    let mw = RateLimitMiddleware::new(config);
    let req = make_request("/sign-in/email", "1.2.3.4");

    for _ in 0..10 {
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }
}

// The real middleware must protect sensitive routes without application overrides.
#[tokio::test]
async fn default_sensitive_routes_are_limited_before_generic_routes() {
    for path in [
        "/sign-in/email",
        "/sign-up/email",
        "/change-password",
        "/change-email",
        "/request-password-reset",
        "/send-verification-email",
        "/forget-password/email",
        "/email-otp/send-verification-otp",
        "/email-otp/request-password-reset",
    ] {
        let mw = RateLimitMiddleware::new(RateLimitConfig::new());
        let req = make_request(path, "192.0.2.1");
        for _ in 0..3 {
            assert!(mw.before_request(&req).await.unwrap().is_none());
        }
        assert_eq!(
            mw.before_request(&req).await.unwrap().unwrap().status,
            429,
            "{path}"
        );
    }
    let mw = RateLimitMiddleware::new(RateLimitConfig::new());
    let req = make_request("/get-session", "192.0.2.1");
    for _ in 0..100 {
        assert!(mw.before_request(&req).await.unwrap().is_none());
    }
    let response = mw.before_request(&req).await.unwrap().unwrap();
    assert_eq!(response.status, 429);
    assert!(
        response
            .headers
            .get("x-retry-after")
            .unwrap()
            .parse::<u64>()
            .unwrap()
            <= 10
    );
}

// Capacity and expiry are observable admission behavior, not private map layout.
#[tokio::test]
async fn bounded_buckets_preserve_active_quotas_and_recover_after_expiry() {
    let mw = RateLimitMiddleware::new(
        RateLimitConfig::new()
            .default_limit(Duration::from_millis(250), 2)
            .max_buckets(2),
    );
    let first = make_request("/get-session", "192.0.2.1");
    let second = make_request("/get-session", "192.0.2.2");
    let third = make_request("/get-session", "192.0.2.3");
    assert!(mw.before_request(&first).await.unwrap().is_none());
    assert!(mw.before_request(&second).await.unwrap().is_none());
    for _ in 0..8 {
        assert_eq!(
            mw.before_request(&third).await.unwrap().unwrap().status,
            429
        );
    }
    assert!(mw.before_request(&first).await.unwrap().is_none());
    assert_eq!(
        mw.before_request(&first).await.unwrap().unwrap().status,
        429
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(mw.before_request(&third).await.unwrap().is_none());
    assert!(mw.before_request(&first).await.unwrap().is_none());
}

#[tokio::test]
async fn mounted_and_internal_paths_share_sensitive_route_quotas() {
    let mw = RateLimitMiddleware::new(RateLimitConfig::new()).with_base_path("/api/auth/");
    let mounted = make_request("/api/auth/sign-in/email", "192.0.2.1");
    let internal = make_request("/sign-in/email", "192.0.2.1");
    assert!(mw.before_request(&mounted).await.unwrap().is_none());
    assert!(mw.before_request(&internal).await.unwrap().is_none());
    assert!(mw.before_request(&mounted).await.unwrap().is_none());
    assert_eq!(
        mw.before_request(&internal).await.unwrap().unwrap().status,
        429
    );
    let trailing = make_request("/api/auth/sign-in/email///", "192.0.2.1");
    assert_eq!(
        mw.before_request(&trailing).await.unwrap().unwrap().status,
        429
    );
    let other_mount = make_request("/unrelated/sign-in/email", "192.0.2.1");
    for _ in 0..4 {
        assert!(mw.before_request(&other_mount).await.unwrap().is_none());
    }
}

#[tokio::test]
async fn raw_numeric_limits_preserve_admission_and_retry_headers() {
    for (window, max, expected) in [
        (60.0, 0.0, [200, 429, 429]),
        (60.0, -1.0, [200, 429, 429]),
        (60.0, 1.5, [200, 200, 429]),
        (0.0, 1.0, [200, 200, 200]),
        (-1.0, 1.0, [200, 200, 200]),
        (f64::NAN, 1.0, [200, 200, 200]),
        (60.0, f64::NAN, [200, 200, 200]),
        (f64::INFINITY, 1.0, [200, 429, 429]),
    ] {
        let middleware = RateLimitMiddleware::new(RateLimitConfig::new().rule(
            "/get-session",
            RateLimitRule::Limit(EndpointRateLimit {
                window_seconds: window,
                max_requests: max,
            }),
        ));
        let request = make_request("/get-session", "198.51.100.10");
        for status in expected {
            let response = middleware.before_request(&request).await.unwrap();
            assert_eq!(
                response.as_ref().map_or(200, |response| response.status),
                status
            );
            if let Some(response) = response {
                assert_eq!(
                    response.headers.get("x-retry-after").unwrap(),
                    if window.is_infinite() {
                        "Infinity"
                    } else {
                        "60"
                    }
                );
            }
        }
    }
}

#[tokio::test]
async fn independent_instances_share_atomic_memory_quota_and_expiry() {
    let storage = Arc::new(MemoryRateLimitStorage::new(100));
    let config = RateLimitConfig::new()
        .default_limit(Duration::from_millis(250), 3)
        .storage(storage);
    let instances = [
        Arc::new(RateLimitMiddleware::new(config.clone())),
        Arc::new(RateLimitMiddleware::new(config)),
    ];
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..32 {
        let middleware = instances.get(index % 2).unwrap().clone();
        _ = tasks.spawn(async move {
            middleware
                .before_request(&make_request("/get-session", "198.51.100.11"))
                .await
                .unwrap()
        });
    }
    let mut admitted = 0;
    while let Some(result) = tasks.join_next().await {
        if result.unwrap().is_none() {
            admitted += 1;
        }
    }
    assert_eq!(admitted, 3);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        instances
            .first()
            .unwrap()
            .before_request(&make_request("/get-session", "198.51.100.11"))
            .await
            .unwrap()
            .is_none()
    );
}

#[cfg(feature = "redis-cache")]
#[tokio::test]
#[ignore = "requires an isolated Redis server"]
async fn independent_redis_instances_share_fixed_ttl_and_backend_errors_fail_closed() {
    use crate::store::cache::{CacheAdapter, RedisAdapter};
    let url = std::env::var("TEST_RATE_LIMIT_REDIS_URL").unwrap();
    let first = Arc::new(RedisAdapter::new(&url).await.unwrap());
    let second = Arc::new(RedisAdapter::new(&url).await.unwrap());
    let storage = [
        CacheRateLimitStorage::new(first.clone()),
        CacheRateLimitStorage::new(second.clone()),
    ];
    let rule = EndpointRateLimit {
        window_seconds: 1.0,
        max_requests: 3.0,
    };
    let key = format!("198.51.100.12|/get-session-{}", uuid::Uuid::new_v4());
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..24 {
        let adapter = if index % 2 == 0 {
            first.clone()
        } else {
            second.clone()
        };
        let key = key.clone();
        _ = tasks.spawn(async move {
            CacheRateLimitStorage::new(adapter)
                .consume(
                    &key,
                    &EndpointRateLimit {
                        window_seconds: 1.0,
                        max_requests: 3.0,
                    },
                )
                .await
                .unwrap()
        });
    }
    let mut admitted = 0;
    while let Some(result) = tasks.join_next().await {
        if matches!(result.unwrap(), RateLimitDecision::Allowed) {
            admitted += 1;
        }
    }
    assert_eq!(admitted, 3);
    assert_eq!(first.get(&key).await.unwrap().unwrap(), "24");
    tokio::time::sleep(Duration::from_millis(650)).await;
    assert!(matches!(
        storage.first().unwrap().consume(&key, &rule).await.unwrap(),
        RateLimitDecision::Blocked { retry_after: 1.0 }
    ));
    tokio::time::sleep(Duration::from_millis(450)).await;
    assert!(matches!(
        storage.last().unwrap().consume(&key, &rule).await.unwrap(),
        RateLimitDecision::Allowed
    ));
    assert_eq!(second.get(&key).await.unwrap().unwrap(), "1");
    first.delete(&key).await.unwrap();
    let invalid_key = format!("invalid-{key}");
    assert!(
        first
            .increment(&invalid_key, Duration::from_millis(300))
            .await
            .is_err()
    );
    assert!(first.get(&invalid_key).await.unwrap().is_none());

    let unavailable = Arc::new(RedisAdapter::new("redis://127.0.0.1:9").await.unwrap());
    let middleware = RateLimitMiddleware::new(
        RateLimitConfig::new().storage(Arc::new(CacheRateLimitStorage::new(unavailable))),
    );
    let error = middleware
        .before_request(&make_request("/get-session", "198.51.100.12"))
        .await
        .unwrap_err()
        .to_auth_response();
    assert_eq!(error.status, 500);
    assert!(!String::from_utf8_lossy(&error.body).contains("Redis"));
}
