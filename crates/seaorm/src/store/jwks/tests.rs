use super::*;
use crate::store::{bundled_schema::BundledSchema, migrator::run_migrations};
use chrono::{Duration, Utc};
use sea_orm::Database;
#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
async fn persists_private_key_material_and_lists_expired_legacy_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    run_migrations(&database).await?;
    let store = SeaOrmStore::<BundledSchema>::new(
        better_auth_core::AuthConfig::new("keyring-local-test-secret-long-enough"),
        database,
    );
    let now = Utc::now();
    for (id, created_at, expires_at, alg, crv) in [
        (
            "legacy",
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
    let keys = store.list_jwks().await?;
    assert_eq!(
        keys.iter().map(|key| key.id.as_str()).collect::<Vec<_>>(),
        vec!["legacy", "current"]
    );
    let mut config = store.config().as_ref().clone();
    config.advanced.database.default_find_many_limit = 1;
    let limited = SeaOrmStore::<BundledSchema>::new(config, store.connection().clone());
    assert_eq!(
        limited
            .list_jwks()
            .await?
            .iter()
            .map(|row| row.id.as_str())
            .collect::<Vec<_>>(),
        vec!["legacy"]
    );
    let legacy = store
        .get_jwk_by_id("legacy")
        .await?
        .ok_or_else(|| std::io::Error::other("missing legacy key"))?;
    assert_eq!(legacy.private_key, "encrypted private JSON");
    assert!(legacy.expires_at.is_some_and(|expiry| expiry < now));
    assert!(legacy.alg.is_none());
    assert!(legacy.crv.is_none());
    assert!(store.get_jwk_by_id("unknown").await?.is_none());
    Ok(())
}
