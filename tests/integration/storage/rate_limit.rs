//! Shared database rate limits across independent storage instances.

use super::{Backend, Db, Raw, TestResult, backend_tests, on_raw, postgres_tests};
use better_auth_core::middleware::{Middleware, RateLimitConfig, RateLimitMiddleware};
use better_auth_core::store::SchemaMigrator;
use better_auth_core::{
    AuthRequest, EndpointRateLimit, HttpMethod, PluginRateLimit, RateLimitDecision,
    RateLimitStorage,
};
use better_auth_sqlx::sqlx;
use std::{collections::HashMap, sync::Arc};

backend_tests!(independent_sqlite_instances_preserve_quota_expiry_and_fail_closed);
postgres_tests!(independent_sqlite_instances_preserve_quota_expiry_and_fail_closed,);

#[derive(Debug)]
struct ApplicationRule;
#[async_trait::async_trait]
impl better_auth_core::middleware::rate_limit::RateLimitResolver for ApplicationRule {
    async fn resolve(
        &self,
        request: &AuthRequest,
        inherited: &EndpointRateLimit,
    ) -> better_auth_core::AuthResult<Option<EndpointRateLimit>> {
        assert_eq!(request.path, "/api/auth/dynamic-rule");
        assert_eq!(inherited.max_requests, 3.0, "first matching plugin wins");
        assert_eq!(inherited.window_seconds, 180.0);
        match request.headers.get("x-policy").map(String::as_str) {
            Some("disabled") => Ok(None),
            Some("error") => Err(better_auth_core::AuthError::forbidden(
                "application rate policy veto",
            )),
            _ => Ok(Some(EndpointRateLimit {
                max_requests: 1.0,
                window_seconds: 120.0,
            })),
        }
    }
}

type Row = (String, f64, i64, Option<i64>);

async fn row(db: &Db, key: &str) -> TestResult<Option<Row>> {
    on_raw!(&db.raw, |pool| Ok(sqlx::query_as(
        "SELECT key, count, last_request, expires_at FROM rate_limit WHERE key = $1",
    )
    .bind(key)
    .fetch_optional(pool)
    .await?))
}

async fn insert(db: &Db, row: Row) -> TestResult {
    let (key, count, last_request, expires_at) = row;
    on_raw!(&db.raw, |pool| {
        _ = sqlx::query(
            "INSERT INTO rate_limit (key, count, last_request, expires_at) VALUES ($1, $2, $3, $4)",
        )
        .bind(&key)
        .bind(count)
        .bind(last_request)
        .bind(expires_at)
        .execute(pool)
        .await?;
    });
    Ok(())
}

async fn set_last_request(db: &Db, key: &str, last_request: i64) -> TestResult {
    on_raw!(&db.raw, |pool| {
        _ = sqlx::query("UPDATE rate_limit SET last_request = $1 WHERE key = $2")
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
                better_auth_core::middleware::rate_limit::RateLimitRule::Dynamic(Arc::new(
                    ApplicationRule,
                )),
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
    assert_eq!(consumed.1, 1.0);
    let blocked = dynamic.before_request(&dynamic_request).await?.unwrap();
    assert_eq!(blocked.status, 429);
    assert_eq!(row(&db, dynamic_key).await?, Some(consumed));
    let now = chrono::Utc::now().timestamp_millis();
    let old_key = format!("stale-{key}");
    let protected_key = format!("protected-{key}");
    let protected: Row = (
        protected_key.clone(),
        3.0,
        now - 121_000,
        Some(now + 59_000),
    );
    for (key, count, last_request, expires_at) in [
        (old_key.clone(), 3.0, now - 181_000, Some(now - 1_000)),
        protected.clone(),
    ] {
        insert(&db, (key, count, last_request, expires_at)).await?;
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
    assert_eq!(infinite.3, None);
    // The independent shorter-window process performs cleanup without
    // retiring another process's long-lived or nonexpiring quota.
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
    assert!(row(&db, &old_key).await?.is_none());
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
    _ = db.execute("DROP TABLE rate_limit", &[]).await?;
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
    assert!(!String::from_utf8_lossy(&failure.body).contains("rate_limit"));
    B::close(first).await?;
    B::close(second).await
}
