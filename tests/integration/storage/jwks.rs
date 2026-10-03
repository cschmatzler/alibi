//! JWT keyring rows retain private key material and configured list pages.

use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use better_auth::AuthConfig;
use better_auth_core::store::JwkStore;
use better_auth_core::types::CreateJwk;
use chrono::{Duration, Utc};
use std::sync::Arc;

backend_tests!(persists_private_key_material_and_lists_expired_keys);
postgres_tests!(persists_private_key_material_and_lists_expired_keys,);

async fn persists_private_key_material_and_lists_expired_keys<B: Backend>(db: Db) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("keyring-local-test-secret-long-enough")
        .await?;
    let now = Utc::now();
    for (id, created_at, expires_at, alg, crv) in [
        (
            "expired",
            now - Duration::days(3),
            Some(now - Duration::days(1)),
            None,
            None,
        ),
        (
            "current",
            now,
            None,
            Some("ES256".to_owned()),
            Some("P-256".to_owned()),
        ),
    ] {
        drop(
            store
                .create_jwk(CreateJwk {
                    id: Some(id.to_owned()),
                    public_key: "public JSON".to_owned(),
                    private_key: "encrypted private JSON".to_owned(),
                    created_at,
                    expires_at,
                    alg,
                    crv,
                })
                .await?,
        );
    }
    assert_eq!(
        store
            .list_jwks()
            .await?
            .iter()
            .map(|key| key.id.as_str())
            .collect::<Vec<_>>(),
        vec!["expired", "current"]
    );
    let mut config = AuthConfig::new("keyring-local-test-secret-long-enough");
    config.advanced.database.default_find_many_limit = 1;
    let limited = B::store(Arc::new(config), &connection);
    assert_eq!(
        limited
            .list_jwks()
            .await?
            .iter()
            .map(|row| row.id.as_str())
            .collect::<Vec<_>>(),
        vec!["expired"]
    );
    let expired = store
        .get_jwk_by_id("expired")
        .await?
        .ok_or("missing expired key")?;
    assert_eq!(expired.private_key, "encrypted private JSON");
    assert!(expired.expires_at.is_some_and(|expiry| expiry < now));
    assert!(expired.alg.is_none());
    assert!(expired.crv.is_none());
    assert!(store.get_jwk_by_id("unknown").await?.is_none());
    B::close(connection).await
}
