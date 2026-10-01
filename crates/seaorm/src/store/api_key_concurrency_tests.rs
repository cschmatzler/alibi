use super::*;
use crate::store::{bundled_schema::BundledSchema, migrator::run_migrations};
use better_auth_core::AuthConfig;
use sea_orm::{ConnectOptions, Database};
use std::sync::Arc;
use tokio::sync::Barrier;
use tokio::task::JoinSet;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn file_sqlite_connections_consume_quota_without_lock_upgrade_errors()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = std::env::temp_dir().join(format!("better-auth-api-key-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory)?;
    let outcome = async {
        let mut options = ConnectOptions::new(format!(
            "sqlite://{}?mode=rwc",
            directory.join("auth.sqlite").display()
        ));
        let _ = options.min_connections(8).max_connections(8);
        let database = Database::connect(options).await?;
        let result = async {
            run_migrations(&database).await?;
            let store = Arc::new(SeaOrmStore::<BundledSchema>::new(
                AuthConfig::new("a-secret-that-is-at-least-32-characters"),
                database.clone(),
            ));
            let key = store
                .create_api_key(CreateApiKey {
                    reference_id: "owner".to_string(),
                    config_id: "default".to_string(),
                    name: None,
                    prefix: None,
                    key_hash: "concurrent-key-hash".to_string(),
                    start: None,
                    expires_at: None,
                    remaining: Some(12.5),
                    rate_limit_enabled: true,
                    rate_limit_time_window: Some(86_400_000.0),
                    rate_limit_max: Some(2.5),
                    refill_interval: None,
                    refill_amount: None,
                    permissions: None,
                    metadata: None,
                    enabled: true,
                })
                .await?;
            let barrier = Arc::new(Barrier::new(32));
            let mut tasks = JoinSet::new();
            for _ in 0..32 {
                let store = store.clone();
                let barrier = barrier.clone();
                let id = key.id.clone();
                let _ = tasks.spawn(async move {
                    let _ = barrier.wait().await;
                    store.consume_api_key_usage(&id, true).await
                });
            }
            let mut counts = [0; 3];
            while let Some(result) = tasks.join_next().await {
                match result?? {
                    ConsumeApiKeyResult::Allowed(_) => counts[0] += 1,
                    ConsumeApiKeyResult::RateLimited { .. } => counts[1] += 1,
                    ConsumeApiKeyResult::UsageExhausted => counts[2] += 1,
                }
            }
            let persisted = store.get_api_key_by_id(&key.id).await?;
            Ok::<_, Box<dyn std::error::Error>>((counts, persisted))
        }
        .await;
        let closed = database.close().await;
        closed?;
        result
    }
    .await;
    let removed = std::fs::remove_dir_all(&directory);
    removed?;
    let (counts, persisted) = outcome?;
    // Upstream accepts fractional limits and consumes quota before rate-limit rejection.
    assert_eq!(counts, [3, 10, 19]);
    let persisted = persisted
        .ok_or_else(|| std::io::Error::other("fractional exhausted quota must retain the key"))?;
    assert_eq!(persisted.remaining, Some(-0.5));
    assert_eq!(persisted.request_count, Some(3.0));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn independent_connections_reject_final_quota_loser_without_deleting_credential()
-> Result<(), Box<dyn std::error::Error>> {
    let directory =
        std::env::temp_dir().join(format!("better-auth-final-quota-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory)?;
    let outcome = async {
        let mut options = ConnectOptions::new(format!(
            "sqlite://{}?mode=rwc",
            directory.join("auth.sqlite").display()
        ));
        let _ = options.min_connections(1).max_connections(1);
        let first = Database::connect(options.clone()).await?;
        let second = Database::connect(options).await?;
        let result = async {
            run_migrations(&first).await?;
            let config = AuthConfig::new("a-secret-that-is-at-least-32-characters");
            let stores = [
                Arc::new(SeaOrmStore::<BundledSchema>::new(
                    config.clone(),
                    first.clone(),
                )),
                Arc::new(SeaOrmStore::<BundledSchema>::new(config, second.clone())),
            ];
            let mut input = CreateApiKey {
                reference_id: "owner".into(),
                config_id: "default".into(),
                name: Some("last-use".into()),
                prefix: None,
                key_hash: "last-use-hash".into(),
                start: None,
                expires_at: None,
                remaining: Some(1.0),
                rate_limit_enabled: false,
                rate_limit_time_window: None,
                rate_limit_max: None,
                refill_interval: None,
                refill_amount: None,
                permissions: None,
                metadata: None,
                enabled: true,
            };
            let key = stores[0].create_api_key(input.clone()).await?;
            input.reference_id = "foreign-owner".into();
            input.key_hash = "foreign-hash".into();
            let foreign = stores[0].create_api_key(input).await?;
            let barrier = Arc::new(Barrier::new(2));
            let mut tasks = JoinSet::new();
            for store in &stores {
                let store = store.clone();
                let id = key.id.clone();
                let barrier = barrier.clone();
                let _ = tasks.spawn(async move {
                    let _ = barrier.wait().await;
                    store.consume_api_key_usage(&id, false).await
                });
            }
            let mut allowed = None;
            let mut exhausted = 0;
            while let Some(result) = tasks.join_next().await {
                match result?? {
                    ConsumeApiKeyResult::Allowed(key) => {
                        assert!(allowed.is_none());
                        allowed = Some(*key);
                    }
                    ConsumeApiKeyResult::UsageExhausted => exhausted += 1,
                    ConsumeApiKeyResult::RateLimited { .. } => {
                        panic!("disabled rate limit must not deny")
                    }
                }
            }
            let allowed =
                allowed.ok_or_else(|| std::io::Error::other("one final use must succeed"))?;
            assert_eq!(exhausted, 1);
            assert_eq!(allowed.remaining, Some(0.0));
            let persisted = stores[1]
                .get_api_key_by_id(&key.id)
                .await?
                .ok_or_else(|| std::io::Error::other("quota loser must retain the credential"))?;
            assert_eq!(
                serde_json::to_value(&persisted)?,
                serde_json::to_value(&allowed)?
            );
            assert!(matches!(
                stores[0].consume_api_key_usage(&key.id, false).await?,
                ConsumeApiKeyResult::UsageExhausted
            ));
            assert_eq!(
                serde_json::to_value(stores[1].get_api_key_by_id(&key.id).await?)?,
                serde_json::to_value(Some(&persisted))?
            );
            assert_eq!(
                serde_json::to_value(stores[1].get_api_key_by_id(&foreign.id).await?)?,
                serde_json::to_value(Some(&foreign))?
            );
            // Application retry can refill the same actual credential; the
            // atomic denial must not destroy the row or replace its ownership.
            let reset = stores[0]
                .update_api_key(
                    &key.id,
                    UpdateApiKey {
                        remaining: Some(1.0),
                        ..Default::default()
                    },
                )
                .await?;
            assert_eq!(reset.id, key.id);
            assert_eq!(reset.reference_id, "owner");
            let retry = stores[1].consume_api_key_usage(&key.id, false).await?;
            let ConsumeApiKeyResult::Allowed(retry) = retry else {
                panic!("refilled credential must authenticate");
            };
            assert_eq!(retry.id, key.id);
            assert_eq!(retry.remaining, Some(0.0));
            Ok::<_, Box<dyn std::error::Error>>(())
        }
        .await;
        first.close().await?;
        second.close().await?;
        result
    }
    .await;
    std::fs::remove_dir_all(&directory)?;
    outcome
}
