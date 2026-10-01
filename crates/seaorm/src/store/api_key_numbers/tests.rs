use super::*;
use crate::store::{SeaOrmStore, bundled_schema::BundledSchema};
use better_auth_core::store::{ApiKeyStore, ConsumeApiKeyResult};
use better_auth_core::{AuthConfig, UpdateApiKey};
use sea_orm::{ConnectionTrait, Database};

#[tokio::test]
async fn existing_integer_columns_preserve_fractional_usage() {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    let _ignored_result = database
        .execute_unprepared(
            "CREATE TABLE api_keys (
                id TEXT PRIMARY KEY, name TEXT, start TEXT, prefix TEXT,
                key TEXT NOT NULL UNIQUE, reference_id TEXT NOT NULL, config_id TEXT NOT NULL,
                refill_interval INTEGER, refill_amount INTEGER, last_refill_at TEXT,
                enabled BOOLEAN NOT NULL, rate_limit_enabled BOOLEAN NOT NULL,
                rate_limit_time_window INTEGER, rate_limit_max INTEGER, request_count INTEGER,
                remaining INTEGER, last_request TEXT, expires_at TEXT,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL, permissions TEXT, metadata TEXT
            );
            INSERT INTO api_keys (id, key, reference_id, config_id, enabled, rate_limit_enabled,
                remaining, created_at, updated_at)
            VALUES ('existing', 'hash', 'user', 'default', 1, 0, 2147483648,
                '2026-09-30T00:00:00Z', '2026-09-30T00:00:00Z')",
        )
        .await
        .unwrap();
    ApiKeyNumbers
        .up(&SchemaManager::new(&database))
        .await
        .unwrap();
    let store = SeaOrmStore::<BundledSchema>::new(AuthConfig::new("test-secret"), database);
    let existing = store.get_api_key_by_id("existing").await.unwrap().unwrap();
    assert_eq!(existing.remaining, Some(2_147_483_648.0));
    drop(
        store
            .update_api_key(
                "existing",
                UpdateApiKey {
                    remaining: Some(2.5),
                    ..Default::default()
                },
            )
            .await
            .unwrap(),
    );
    let result = store
        .consume_api_key_usage("existing", false)
        .await
        .unwrap();
    let ConsumeApiKeyResult::Allowed(key) = result else {
        panic!("key must remain usable after migration")
    };
    assert_eq!(key.remaining, Some(1.5));
    let persisted = store.get_api_key_by_id("existing").await.unwrap().unwrap();
    assert_eq!(persisted.remaining, Some(1.5));
    assert_eq!(persisted.key_hash, "hash");
    assert_eq!(persisted.reference_id, "user");
}
