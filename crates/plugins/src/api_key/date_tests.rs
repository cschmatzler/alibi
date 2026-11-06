mod dates {
    use super::*;
    use alibi_core::store::{CacheAdapter, MemoryCacheAdapter};

    #[derive(Default)]
    struct DateStorage {
        cache: MemoryCacheAdapter,
        writes: std::sync::Mutex<Vec<(String, Option<Duration>)>>,
    }

    #[async_trait::async_trait]
    impl ApiKeyStorage for DateStorage {
        async fn get(&self, key: &str) -> AuthResult<Option<String>> {
            self.cache.get(key).await
        }
        async fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> AuthResult<()> {
            self.writes.lock().unwrap().push((key.to_owned(), ttl));
            match ttl {
                Some(ttl) => self.cache.set(key, value, ttl).await,
                None => self.cache.set_without_expiry(key, value).await,
            }
        }
        async fn delete(&self, key: &str) -> AuthResult<()> {
            self.cache.delete(key).await
        }
    }

    #[tokio::test]
    async fn secondary_js_dates_set_ttl_and_canonical_storage_dates() {
        let (ctx, owner, _) = context().await;
        let storage = Arc::new(DateStorage::default());
        let plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
            storage: ApiKeyStorageMode::SecondaryStorage,
            custom_storage: Some(storage.clone()),
            ..Default::default()
        });
        let created = server_key(&plugin, &ctx, &owner, "default").await;
        let mut key =
            super::super::storage::read_storage(storage.as_ref(), &created.api_key.id, false)
                .await
                .unwrap()
                .unwrap();
        key.expires_at = Some("2099-01-01".into());
        key.created_at = "2020-01-01".into();
        storage.writes.lock().unwrap().clear();
        super::super::storage::write_storage(storage.clone(), &key, false)
            .await
            .unwrap();
        let writes = storage.writes.lock().unwrap();
        let indexed: Vec<_> = writes
            .iter()
            .filter(|(key, _)| !key.starts_with("api-key:by-ref:"))
            .collect();
        assert_eq!(indexed.len(), 2);
        for (_, ttl) in indexed {
            let seconds = ttl.unwrap().num_seconds();
            let expected = (alibi_core::utils::datetime::parse_date_millis("2099-01-01").unwrap()
                - Utc::now().timestamp_millis())
            .div_euclid(1000);
            assert!((seconds - expected).abs() <= 1);
        }
        drop(writes);
        let row: serde_json::Value = serde_json::from_str(
            &storage
                .get(&format!("api-key:by-id:{}", key.id))
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(row["expiresAt"], "2099-01-01T00:00:00.000Z");
        assert_eq!(row["createdAt"], "2020-01-01T00:00:00.000Z");
    }

    #[tokio::test]
    async fn secondary_revives_date_constructor_scalars_and_optional_falsy_values() {
        let (ctx, owner, _) = context().await;
        let storage = Arc::new(DateStorage::default());
        let plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
            storage: ApiKeyStorageMode::SecondaryStorage,
            custom_storage: Some(storage.clone()),
            ..Default::default()
        });
        let created = server_key(&plugin, &ctx, &owner, "default").await;
        let id = format!("api-key:by-id:{}", created.api_key.id);
        let original: serde_json::Value =
            serde_json::from_str(&storage.get(&id).await.unwrap().unwrap()).unwrap();
        for (date, expected) in [
            (json!(null), "1970-01-01T00:00:00.000Z"),
            (json!(true), "1970-01-01T00:00:00.001Z"),
            (json!(1.9), "1970-01-01T00:00:00.001Z"),
            (json!(["2020-01-01"]), "2020-01-01T00:00:00.000Z"),
            (json!("nonsense"), "Invalid Date"),
            (json!({}), "Invalid Date"),
        ] {
            let mut row = original.clone();
            row["createdAt"] = date;
            row["expiresAt"] = json!(0);
            row["lastRefillAt"] = json!(false);
            row["lastRequest"] = json!("");
            storage
                .cache
                .set_without_expiry(&id, &row.to_string())
                .await
                .unwrap();
            let key =
                super::super::storage::read_storage(storage.as_ref(), &created.api_key.id, false)
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(key.created_at, expected);
            assert!(key.expires_at.is_none());
            assert!(key.last_refill_at.is_none());
            assert!(key.last_request.is_none());
            let wire = serde_json::to_value(alibi_core::wire::ApiKeyView::from(&key)).unwrap();
            assert_eq!(
                wire["createdAt"],
                if expected == "Invalid Date" {
                    json!(null)
                } else {
                    json!(expected)
                }
            );
        }
    }

    #[tokio::test]
    async fn secondary_nonobject_payloads_are_not_api_keys() {
        let storage = DateStorage::default();
        for payload in ["null", "false", "1", "\"text\"", "[]", "[1]"] {
            storage
                .cache
                .set_without_expiry("api-key:by-id:key", payload)
                .await
                .unwrap();
            assert!(
                super::super::storage::read_storage(&storage, "key", false)
                    .await
                    .unwrap()
                    .is_none(),
                "{payload}"
            );
        }
    }

    #[tokio::test]
    async fn invalid_secondary_dates_fail_only_at_write_and_respect_defer_updates() {
        for deferred in [false, true] {
            for field in ["createdAt", "expiresAt", "lastRefillAt"] {
                let (mut ctx, owner, _) = context().await;
                let completions = Arc::new(ApplicationCompletions::default());
                let mut config = (*ctx.config).clone();
                config.background_tasks = Some(completions.clone());
                ctx.config = Arc::new(config);
                let storage = Arc::new(DateStorage::default());
                let plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
                    storage: ApiKeyStorageMode::SecondaryStorage,
                    custom_storage: Some(storage.clone()),
                    defer_updates: deferred,
                    ..Default::default()
                });
                let created = server_key(&plugin, &ctx, &owner, "default").await;
                let id = format!("api-key:by-id:{}", created.api_key.id);
                let hash = format!("api-key:{}", ApiKeyPlugin::hash_key(&created.key));
                let mut row: serde_json::Value =
                    serde_json::from_str(&storage.get(&id).await.unwrap().unwrap()).unwrap();
                row[field] = json!("invalid-date");
                row["remaining"] = json!(2);
                row["refillAmount"] = json!(20);
                row["refillInterval"] = json!(1);
                let original = row.to_string();
                for index in [&id, &hash] {
                    storage
                        .cache
                        .set_without_expiry(index, &original)
                        .await
                        .unwrap();
                }
                storage.writes.lock().unwrap().clear();
                let result = plugin
                    .verify_api_key(
                        &VerifyApiKey {
                            key: &created.key,
                            config_id: None,
                            permissions: None,
                        },
                        &ctx,
                    )
                    .await;
                if deferred {
                    let verified = result.unwrap();
                    assert_eq!(verified.remaining, Some(1.0));
                    let wire = serde_json::to_value(&verified).unwrap();
                    assert_eq!(wire[field], json!(null));
                } else {
                    assert!(
                        result
                            .unwrap_err()
                            .to_string()
                            .contains("Invalid time value")
                    );
                }
                completions.drain().await;
                assert!(storage.writes.lock().unwrap().is_empty());
                assert_eq!(
                    storage.get(&id).await.unwrap().as_deref(),
                    Some(original.as_str())
                );
                assert_eq!(
                    storage.get(&hash).await.unwrap().as_deref(),
                    Some(original.as_str())
                );
            }
        }
    }

    #[tokio::test]
    async fn invalid_secondary_last_request_uses_nan_rate_comparison_and_is_repaired() {
        let (ctx, owner, _) = context().await;
        let storage = Arc::new(DateStorage::default());
        let plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
            storage: ApiKeyStorageMode::SecondaryStorage,
            custom_storage: Some(storage.clone()),
            ..Default::default()
        });
        for (count, denied) in [(10, true), (0, false)] {
            let created = server_key(&plugin, &ctx, &owner, "default").await;
            let id = format!("api-key:by-id:{}", created.api_key.id);
            let hash = format!("api-key:{}", ApiKeyPlugin::hash_key(&created.key));
            let mut row: serde_json::Value =
                serde_json::from_str(&storage.get(&id).await.unwrap().unwrap()).unwrap();
            row["lastRequest"] = json!("invalid-date");
            row["updatedAt"] = json!("invalid-date");
            row["rateLimitEnabled"] = json!(true);
            row["rateLimitMax"] = json!(10);
            row["rateLimitTimeWindow"] = json!(1000);
            row["requestCount"] = json!(count);
            for index in [&id, &hash] {
                storage
                    .cache
                    .set_without_expiry(index, &row.to_string())
                    .await
                    .unwrap();
            }
            storage.writes.lock().unwrap().clear();
            let result = plugin
                .verify_api_key(
                    &VerifyApiKey {
                        key: &created.key,
                        config_id: None,
                        permissions: None,
                    },
                    &ctx,
                )
                .await;
            if denied {
                let ApiKeyVerificationError::Validation(error) = result.unwrap_err() else {
                    panic!("expected rate denial")
                };
                assert_eq!(error.code, ApiKeyErrorCode::RateLimited);
                assert!(error.details.unwrap().try_again_in.is_nan());
                assert!(storage.writes.lock().unwrap().is_empty());
            } else {
                let key = result.unwrap();
                assert_eq!(key.request_count, Some(1.0));
                assert!(
                    key.last_request
                        .as_deref()
                        .and_then(alibi_core::utils::datetime::parse_date_millis)
                        .is_some()
                );
                assert!(alibi_core::utils::datetime::parse_date_millis(&key.updated_at).is_some());
            }
        }
    }
}
