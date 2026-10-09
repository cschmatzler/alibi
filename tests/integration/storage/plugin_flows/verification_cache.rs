//! Secondary-storage-only verifications decode every JavaScript date shape found in cached JSON.
#![allow(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "tests assert independently specified wire fields and fixtures"
)]
use super::*;
use alibi_core::store::CacheAdapter;
use alibi_core::store::secondary_storage::MemoryCacheAdapter;
use alibi_core::{AuthError, CreateVerification, UpdateVerification};
use chrono::{Duration, Utc};

backend_tests!(
    cached_expiry_shapes_follow_javascript_date_coercion,
    cached_updates_patch_value_and_expiry_without_a_database_row
);
postgres_tests!(
    cached_expiry_shapes_follow_javascript_date_coercion,
    cached_updates_patch_value_and_expiry_without_a_database_row
);

const FUTURE_MILLIS: i64 = 4_102_444_800_000;

async fn secondary_only<B: Backend>(
    db: &Db,
) -> TestResult<(BetterAuth<B::Schema>, Arc<MemoryCacheAdapter>)> {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let cache = Arc::new(MemoryCacheAdapter::new());
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.verification.secondary_storage = Some(cache.clone());
    config.verification.store_in_database = false;
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .build()
        .await?;
    Ok((auth, cache))
}

async fn seed(cache: &MemoryCacheAdapter, identifier: &str, raw: &str) -> TestResult {
    cache
        .set(
            &format!("verification:{identifier}"),
            raw,
            Duration::minutes(5),
        )
        .await?;
    Ok(())
}

async fn cached_expiry_shapes_follow_javascript_date_coercion<B: Backend>(db: Db) -> TestResult {
    let (auth, cache) = secondary_only::<B>(&db).await?;
    let values = auth.context().verifications();
    let live = [
        (
            "number",
            format!(r#"{{"value":"v","expiresAt":{FUTURE_MILLIS}}}"#),
        ),
        (
            "iso-array",
            r#"{"value":"v","expiresAt":["2099-01-01T00:00:00.000Z"]}"#.into(),
        ),
        (
            "legacy-string",
            r#"{"value":"v","expiresAt":"Jan 1 2099 00:00:00 GMT"}"#.into(),
        ),
        (
            "iso",
            r#"{"value":"v","expiresAt":"2099-01-01T00:00:00.000Z"}"#.into(),
        ),
    ];
    for (name, raw) in &live {
        seed(&cache, name, raw).await?;
        let found = values.find(name).await?.unwrap_or_else(|| panic!("{name}"));
        assert!(!found.is_expired(), "{name}");
        assert_eq!(found.value()?, "v");
        let consumed = values
            .consume(name)
            .await?
            .unwrap_or_else(|| panic!("{name}"));
        assert!(consumed.expires_at()? > Utc::now(), "{name}");
        assert!(values.consume(name).await?.is_none(), "{name} replayed");
    }

    seed(
        &cache,
        "numeric-string",
        &format!(r#"{{"value":"v","expiresAt":"{FUTURE_MILLIS}"}}"#),
    )
    .await?;
    assert!(!values.find("numeric-string").await?.unwrap().is_expired());
    assert!(values.consume("numeric-string").await?.is_none());

    for (name, raw) in [
        ("bool-expired", r#"{"value":"v","expiresAt":true}"#),
        ("null-expired", r#"{"value":"v","expiresAt":null}"#),
        ("object-invalid", r#"{"value":"v","expiresAt":{}}"#),
        ("missing", r#"{"value":"v"}"#),
        ("garbage-string", r#"{"value":"v","expiresAt":"never"}"#),
    ] {
        seed(&cache, name, raw).await?;
        assert!(values.consume(name).await?.is_none(), "{name}");
    }
    for (name, raw) in [
        ("zero", "0"),
        ("empty", r#""""#),
        ("false", "false"),
        ("null", "null"),
    ] {
        seed(&cache, name, raw).await?;
        assert!(values.find(name).await?.is_none(), "{name}");
    }

    seed(
        &cache,
        "extreme",
        r#"{"value":"v","expiresAt":8640000000000000}"#,
    )
    .await?;
    let extreme = values.consume("extreme").await?.unwrap();
    assert!(matches!(
        extreme.expires_at(),
        Err(AuthError::NotImplemented(_))
    ));

    seed(&cache, "typed", r#"{"value":1,"expiresAt":4102444800000}"#).await?;
    let typed = values.find("typed").await?.unwrap();
    assert!(typed.value().is_err());
    assert!(typed.identifier().is_err());
    assert_eq!(typed.id(), None);
    Ok(())
}

async fn cached_updates_patch_value_and_expiry_without_a_database_row<B: Backend>(
    db: Db,
) -> TestResult {
    let (auth, cache) = secondary_only::<B>(&db).await?;
    let values = auth.context().verifications();
    let expires = Utc::now() + Duration::minutes(10);
    let created = values
        .create(CreateVerification {
            identifier: "patched".into(),
            value: "first".into(),
            expires_at: expires,
        })
        .await?
        .unwrap();
    assert_eq!(created.value()?, "first");
    assert_eq!(db.count("verifications").await?, 0);

    let later = Utc::now() + Duration::minutes(20);
    let updated = values
        .update(
            "patched",
            UpdateVerification {
                value: Some("second".into()),
                expires_at: Some(later),
            },
        )
        .await?
        .unwrap();
    assert_eq!(updated.value()?, "second");
    assert_eq!(
        updated.expires_at()?.timestamp_millis(),
        later.timestamp_millis()
    );
    let reread = values.find("patched").await?.unwrap();
    assert_eq!(reread.value()?, "second");

    let missing = values
        .update(
            "absent",
            UpdateVerification {
                value: Some("only".into()),
                expires_at: Some(later),
            },
        )
        .await?
        .unwrap();
    assert_eq!(missing.value()?, "only");
    assert_eq!(cache.get("verification:absent").await?, None);

    seed(&cache, "spread-array", r#"["a","b"]"#).await?;
    let spread = values
        .update(
            "spread-array",
            UpdateVerification {
                value: Some("c".into()),
                expires_at: None,
            },
        )
        .await?
        .unwrap();
    assert_eq!(spread.data().get("0").and_then(|v| v.as_str()), Some("a"));
    seed(&cache, "spread-string", r#""ab""#).await?;
    let spread = values
        .update(
            "spread-string",
            UpdateVerification {
                value: Some("c".into()),
                expires_at: None,
            },
        )
        .await?
        .unwrap();
    assert_eq!(spread.data().get("1").and_then(|v| v.as_str()), Some("b"));
    assert_eq!(db.count("verifications").await?, 0);
    Ok(())
}
