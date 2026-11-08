//! `SQLx`-backed persistence implementation for built-in auth tables.

#[cfg(test)]
mod json_metadata_tests {
    #[derive(crate::AuthEntity, Clone, Debug, PartialEq, serde::Serialize, sqlx::FromRow)]
    #[auth(role = "user", table = "user", secondary_storage)]
    struct RichUser {
        id: String,
        name: String,
        email: String,
        #[sqlx(rename = "emailVerified")]
        email_verified: bool,
        image: Option<String>,
        #[sqlx(rename = "createdAt")]
        created_at: chrono::DateTime<chrono::Utc>,
        #[sqlx(rename = "updatedAt")]
        updated_at: chrono::DateTime<chrono::Utc>,
        metadata: crate::JsonMetadata,
    }

    struct Schema;
    impl alibi_core::AuthSchema for Schema {
        type User = RichUser;
        type Session = <super::bundled_schema::BundledSchema as alibi_core::AuthSchema>::Session;
        type Account = <super::bundled_schema::BundledSchema as alibi_core::AuthSchema>::Account;
        type Verification =
            <super::bundled_schema::BundledSchema as alibi_core::AuthSchema>::Verification;
    }

    use alibi_core::utils::json::{self, JsValue};
    use alibi_core::{AuthConfig, AuthError, AuthUser, CreateUser};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    #[tokio::test]
    async fn adapter_input_undefined_defaults_and_updates_reach_actual_sqlite_cells() {
        use alibi_core::UpdateUser;
        use alibi_core::store::UserStore;
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let base = super::SqlxStore::<Schema>::new(AuthConfig::default(), pool.clone());
        super::migrator::run_migrations(&base.pool).await.unwrap();
        _ = sqlx::query("ALTER TABLE user ADD COLUMN metadata TEXT NOT NULL DEFAULT '{}'")
            .execute(&pool)
            .await
            .unwrap();

        for (label, on_update) in [("enabled", true), ("disabled", false)] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let inputs = Arc::new(Mutex::new(Vec::new()));
            let mut config = AuthConfig::default();
            let default_events = events.clone();
            let mut field =
                alibi_core::field_policy::FieldConfig::new(serde_json::json!({"type":"string"}))
                    .default_callback(move || {
                        default_events.lock().unwrap().push("default");
                        JsValue::String("default".into())
                    });
            if on_update {
                let update_events = events.clone();
                field = field.on_update(move || {
                    update_events.lock().unwrap().push("update");
                    JsValue::String("updated".into())
                });
            }
            let transform_events = events.clone();
            let transform_inputs = inputs.clone();
            field = field.transform_adapter_input(move |value| {
                transform_events.lock().unwrap().push("input");
                transform_inputs.lock().unwrap().push(value.clone());
                async move { Ok(value) }
            });
            _ = config.user.additional_fields.insert("image".into(), field);
            let config = Arc::new(config);
            let inner = Arc::new(super::SqlxStore::<Schema>::new(
                (*config).clone(),
                pool.clone(),
            ));
            let store = alibi_core::AuthInitContext::new(config, inner.clone())
                .database_with_registered_transforms();
            let mut input = CreateUser::new()
                .with_email(format!("{label}@fixture.test"))
                .with_name("fixture");
            _ = input
                .additional_fields
                .insert("image".into(), JsValue::Undefined);
            let user = store.create_user(input).await.unwrap();
            let id = user.id().into_owned();
            assert_eq!(user.image(), Some("default"));
            assert_eq!(*events.lock().unwrap(), ["default", "input"]);
            assert_eq!(
                *inputs.lock().unwrap(),
                [Some(JsValue::String("default".into()))]
            );

            for (value, expected) in [
                (
                    None,
                    if on_update {
                        Some("updated")
                    } else {
                        Some("default")
                    },
                ),
                (
                    Some(JsValue::Undefined),
                    if on_update {
                        Some("updated")
                    } else {
                        Some("default")
                    },
                ),
                (Some(JsValue::Null), None),
                (Some(JsValue::String("".into())), Some("")),
                (Some(JsValue::String("supplied".into())), Some("supplied")),
            ] {
                events.lock().unwrap().clear();
                inputs.lock().unwrap().clear();
                let mut update = UpdateUser::default();
                if let Some(value) = value.clone() {
                    _ = update.additional_fields.insert("image".into(), value);
                }
                let user = store.update_user(&id, update).await.unwrap();
                assert_eq!(user.image(), expected);
                assert_eq!(
                    inner.get_user_by_id(&id).await.unwrap().unwrap().image(),
                    expected,
                );
                let missing = value.as_ref().is_none_or(JsValue::is_undefined);
                let expected_events: &[&str] = if missing {
                    if on_update { &["update", "input"] } else { &[] }
                } else {
                    &["input"]
                };
                assert_eq!(*events.lock().unwrap(), expected_events);
                let expected_inputs: Vec<_> = if missing {
                    if on_update {
                        vec![Some(JsValue::String("updated".into()))]
                    } else {
                        vec![]
                    }
                } else {
                    vec![value]
                };
                assert_eq!(*inputs.lock().unwrap(), expected_inputs);
            }
        }
    }

    #[tokio::test]
    async fn initialized_json_output_observes_physical_cell_before_read_codec() {
        let original = {
            let mut value = json::parse_value(r#"{"\ud800":"\udfff","null":null,"$serde_json::private::Number":"literal","alibi::JsValue/v1":"literal"}"#).unwrap();
            let object = value.as_object_mut().unwrap();
            _ = object.insert("nested".into(), json::parse_value(r#"{"iso":"2020-01-01T00:00:00.123456Z","2020-01-01T00:00:00.123456Z":"key stays text"}"#).unwrap());
            _ = object.insert("undefined".into(), JsValue::Undefined);
            _ = object.insert(
                "array".into(),
                JsValue::Array(vec![JsValue::Undefined, JsValue::Null]),
            );
            _ = object.insert(
                "date".into(),
                JsValue::Date(
                    chrono::DateTime::from_timestamp(1_700_000_000, 123_456_789).unwrap(),
                ),
            );
            value
        };
        let physical = json::to_string(&original).unwrap();
        let returned_object = {
            let mut value = original.clone();
            _ = value.as_object_mut().unwrap().insert(
                "literalDate".into(),
                JsValue::String("2020-01-01T00:00:00.123456Z".into()),
            );
            value
        };
        let literal_json =
            JsValue::String(alibi_core::utils::json::JsString::from_code_units(vec![
                34, 0xd800, 34,
            ]));
        let outputs = Arc::new(vec![
            Some(JsValue::String(physical.clone().into())),
            Some(returned_object.clone()),
            Some(literal_json.clone()),
            Some(JsValue::Undefined),
            Some(JsValue::Null),
            Some(JsValue::String("not JSON".into())),
        ]);
        let expected = [
            json::parse_adapter_value(&physical),
            returned_object.clone(),
            json::parse_adapter_string(literal_json.as_js_string().unwrap()),
            JsValue::Undefined,
            JsValue::Null,
            JsValue::Null,
        ];
        let mode = Arc::new(AtomicUsize::new(0));
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut config = AuthConfig::default();
        let cache = Arc::new(alibi_core::store::MemoryCacheAdapter::new());
        config.session.secondary_storage = Some(cache.clone());
        config.session.store_in_database = true;
        let input_events = events.clone();
        let input_mode = mode.clone();
        let input_original = original.clone();
        let output_events = events.clone();
        let output_mode = mode.clone();
        let output_physical = physical.clone();
        _ = config.user.additional_fields.insert(
            "metadata".into(),
            alibi_core::field_policy::FieldConfig::new(serde_json::json!({"type":"json"}))
                .transform_adapter_input(move |value| {
                    if input_mode.load(Ordering::SeqCst) == 6 {
                        assert_eq!(value.as_ref().and_then(JsValue::as_str), Some("not JSON"));
                    } else {
                        assert_eq!(value.as_ref(), Some(&input_original));
                    }
                    input_events.lock().unwrap().push("input");
                    async move { Ok(value) }
                })
                .transform_output(move |value| {
                    output_events.lock().unwrap().push("output");
                    let index = output_mode.load(Ordering::SeqCst);
                    let expected = if index == 6 {
                        "not JSON"
                    } else {
                        &output_physical
                    };
                    assert_eq!(value.as_ref().and_then(JsValue::as_str), Some(expected));
                    if index < 6 {
                        assert!(expected.contains("\\ud800"));
                    }
                    let result = if index == 6 {
                        Err(AuthError::internal("json-output-marker"))
                    } else {
                        Ok(outputs[index].clone())
                    };
                    async move { result }
                }),
        );

        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let raw_pool = pool.clone();
        let inner = Arc::new(super::SqlxStore::<Schema>::new(config.clone(), pool));
        super::migrator::run_migrations(&inner.pool).await.unwrap();
        _ = sqlx::query("ALTER TABLE user ADD COLUMN metadata TEXT NOT NULL DEFAULT '{}'")
            .execute(&raw_pool)
            .await
            .unwrap();
        type User = RichUser;
        let allowed = config.user.additional_fields.clone();
        let config = Arc::new(config);
        let initialized = alibi_core::plugin::AuthInitContext::new(config.clone(), inner.clone())
            .database_with_registered_transforms();
        for index in 0..=6 {
            mode.store(index, Ordering::SeqCst);
            events.lock().unwrap().clear();
            let mut input = CreateUser::new().with_email(format!("json-{index}@fixture.test"));
            _ = input.additional_fields.insert(
                "metadata".into(),
                if index == 6 {
                    JsValue::String("not JSON".into())
                } else {
                    original.clone()
                },
            );
            let result = initialized.create_user_record(input).await;
            assert_eq!(*events.lock().unwrap(), ["input", "output"], "{result:?}");
            if index == 6 {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("json-output-marker")
                );
                continue;
            }
            let record = result.unwrap();
            let metadata = &record.raw_snapshot().values()["metadata"];
            assert_eq!(metadata, &expected[index]);
            if index == 0 {
                assert!(matches!(metadata["nested"]["iso"], JsValue::Date(_)));
            } else if index == 1 {
                assert_eq!(
                    metadata["nested"]["iso"].as_str(),
                    Some("2020-01-01T00:00:00.123456Z")
                );
                assert_eq!(
                    metadata["literalDate"].as_str(),
                    Some("2020-01-01T00:00:00.123456Z")
                );
                assert_eq!(metadata["date"], returned_object["date"]);
            }
            // The authority getter is logical stored JSON, not the mapped public value or an encoded cell.
            assert_eq!(
                record.stored().metadata(),
                json::parse_adapter_value(&physical)
            );

            let stored: String = sqlx::query_scalar("SELECT metadata FROM user WHERE id = ?")
                .bind(record.id().as_ref())
                .fetch_one(&raw_pool)
                .await
                .unwrap();
            assert_eq!(stored, physical);
            let response = alibi_core::endpoint::EndpointResponse::json(&record).unwrap();
            assert_eq!(
                response.result().as_ref().unwrap().get("metadata"),
                Some(metadata)
            );
            let http = response.to_response().unwrap();
            let wire = json::parse_value(std::str::from_utf8(&http.body).unwrap()).unwrap();
            if metadata.is_undefined() {
                assert!(wire.get("metadata").is_none());
            } else {
                let expected_wire = json::parse_value(&json::to_string(metadata).unwrap()).unwrap();
                assert_eq!(wire["metadata"], expected_wire);
            }
            let snapshot = record.secondary_snapshot().unwrap();
            let cache_text = json::to_string(&snapshot).unwrap();
            let cached = json::parse_adapter_value(&cache_text);
            let restored =
                <User as AuthUser>::from_secondary_snapshot_record_with_fields(cached, &allowed)
                    .unwrap();
            let cached_value = restored.raw_snapshot().values().get("metadata").unwrap();
            if metadata.is_undefined() {
                assert!(cached_value.is_undefined());
            } else {
                let mut expected_cache =
                    json::parse_value(&json::to_string(metadata).unwrap()).unwrap();
                json::revive_json_dates(&mut expected_cache);
                assert_eq!(*cached_value, expected_cache);
            }
            let token = format!("json-cache-{index}");
            _ = initialized
                .create_session(alibi_core::CreateSession {
                    user_id: record.id().into_owned(),
                    token: Some(token.clone()),
                    expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
                    ip_address: None,
                    user_agent: None,
                    impersonated_by: None,
                    active_organization_id: None,
                    active_team_id: None,
                    additional_fields: Default::default(),
                })
                .await
                .unwrap();
            let callbacks = events.lock().unwrap().len();
            let reader = alibi_core::plugin::AuthInitContext::new(config.clone(), inner.clone())
                .database_with_registered_transforms();
            let cached = reader
                .get_session_user_record(&token)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                events.lock().unwrap().len(),
                callbacks,
                "cache read replayed output transform"
            );
            let actual = &cached.raw_snapshot().values()["metadata"];
            let normalized = if metadata.is_undefined() {
                JsValue::Undefined
            } else {
                json::parse_adapter_value(&json::to_string(metadata).unwrap())
            };
            assert_eq!(actual, &normalized);
            if index < 2 {
                assert!(matches!(actual["nested"]["iso"], JsValue::Date(_)));
                assert!(matches!(actual["date"], JsValue::Date(_)));
                assert_eq!(
                    actual["nested"]["2020-01-01T00:00:00.123456Z"].as_str(),
                    Some("key stays text")
                );
            }
            let JsValue::Date(created) = json::parse_adapter_value(
                &json::to_string(&record.raw_snapshot().values()["createdAt"]).unwrap(),
            ) else {
                panic!("expected public creation date");
            };
            assert_eq!(
                cached.created_at().timestamp_millis(),
                created.timestamp_millis()
            );
            assert_eq!(
                cached.raw_snapshot().values()["createdAt"],
                JsValue::Date(created)
            );
        }
    }

    #[tokio::test]
    async fn non_policy_metadata_getters_decode_logically_without_leaking_sqlite_text() {
        use alibi_core::AuthOrganization;
        use alibi_core::store::OrganizationStore;

        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let raw_pool = pool.clone();
        let inner = super::SqlxStore::<super::bundled_schema::BundledSchema>::new(
            AuthConfig::default(),
            pool,
        );
        super::migrator::run_migrations(&inner.pool).await.unwrap();
        let physical = r#"{"\ud800":"\udfff","nested":{"iso":"2020-01-01T00:00:00.123456Z"},"alibi::JsValue/v1":"literal","null":null}"#.to_owned();
        let expected = json::parse_adapter_value(&physical);
        let org = inner
            .create_organization(alibi_core::types::CreateOrganization::new(
                "Metadata",
                "logical-metadata",
            ))
            .await
            .unwrap();

        _ = sqlx::query("UPDATE organization SET metadata = ? WHERE id = ?")
            .bind(&physical)
            .bind(&org.id)
            .execute(&raw_pool)
            .await
            .unwrap();
        let model = sqlx::query_as::<_,super::entities::oauth_client_resource::Model>(
        "SELECT 'r' AS id, 'c' AS \"clientId\", 'resource' AS \"resourceId\", ? AS metadata, NULL AS \"createdAt\"")
        .bind(&physical).fetch_one(&raw_pool).await.unwrap();
        let resource = alibi_core::store::OAuthClientResource::try_from(model).unwrap();
        assert_eq!(resource.metadata, expected);
        let org = inner
            .get_organization_by_id(&org.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(org.metadata(), Some(expected.clone()));
        let response = alibi_core::endpoint::EndpointResponse::json(&org).unwrap();
        assert_eq!(
            response.result().as_ref().unwrap()["metadata"].as_str(),
            Some(json::to_string(&expected).unwrap().as_str())
        );
        assert!(matches!(
            org.metadata().unwrap()["nested"]["iso"],
            JsValue::Date(_)
        ));
        let decoded: alibi_core::types::Organization =
            json::from_value(response.result().as_ref().unwrap().clone()).unwrap();
        assert_eq!(
            decoded.metadata,
            Some(JsValue::String(json::to_string(&expected).unwrap().into()))
        );
    }
}

#[cfg(test)]
mod update_hook_tests {
    mod cases {
        include!("../../../../tests/integration/storage/plugin_flows/user_update_patch_cases.rs");
    }

    mod falsy_id_cases {
        include!(
            "../../../../tests/integration/storage/plugin_flows/user_update_falsy_id_cases.rs"
        );
    }

    #[tokio::test]
    async fn falsy_update_ids_bind_on_real_sqlite() {
        let config = std::sync::Arc::new(alibi_core::AuthConfig::default());
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let store = super::SqlxStore::<super::bundled_schema::BundledSchema>::new(config, pool);
        super::migrator::run_migrations(&store.pool).await.unwrap();
        falsy_id_cases::exercise(&store).await;
    }

    #[derive(crate::AuthEntity, Clone, Debug, PartialEq, serde::Serialize, sqlx::FromRow)]
    #[auth(role = "user", table = "renamed_user", secondary_storage)]
    struct RenamedUser {
        #[sqlx(rename = "pk")]
        id: String,
        #[sqlx(rename = "full_name")]
        name: String,
        email: String,
        #[sqlx(rename = "verified")]
        email_verified: bool,
        #[sqlx(rename = "avatar")]
        image: Option<String>,
        username: Option<String>,
        #[sqlx(rename = "display_name")]
        display_username: Option<String>,
        role: Option<String>,
        banned: Option<bool>,
        #[sqlx(rename = "reason")]
        ban_reason: Option<String>,
        #[sqlx(rename = "expiry")]
        ban_expires: Option<chrono::DateTime<chrono::Utc>>,
        #[sqlx(rename = "login_method")]
        last_login_method: Option<String>,
        #[sqlx(rename = "created")]
        created_at: chrono::DateTime<chrono::Utc>,
        #[sqlx(rename = "updated")]
        updated_at: chrono::DateTime<chrono::Utc>,
    }
    struct RenamedSchema;
    impl alibi_core::AuthSchema for RenamedSchema {
        type User = RenamedUser;
        type Session = <super::bundled_schema::BundledSchema as alibi_core::AuthSchema>::Session;
        type Account = <super::bundled_schema::BundledSchema as alibi_core::AuthSchema>::Account;
        type Verification =
            <super::bundled_schema::BundledSchema as alibi_core::AuthSchema>::Verification;
    }
    #[tokio::test]
    async fn original_input_update_patches_renamed_model_sqlite() {
        let effects = std::sync::Arc::new(cases::Effects::default());
        let config = cases::config(&effects, "display_name");
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let store = super::SqlxStore::<RenamedSchema>::new(config.clone(), pool.clone());
        super::migrator::run_migrations(&store.pool).await.unwrap();
        _ = sqlx::query("CREATE TABLE renamed_user (pk TEXT PRIMARY KEY, full_name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, verified BOOLEAN NOT NULL, avatar TEXT, username TEXT, display_name TEXT, role TEXT, banned BOOLEAN, reason TEXT, expiry DATE, login_method TEXT, created DATE NOT NULL, updated DATE NOT NULL)").execute(&pool).await.unwrap();
        cases::exercise(
            config,
            std::sync::Arc::new(
                store.with_hooks(vec![std::sync::Arc::new(cases::PhysicalHook(
                    effects.clone(),
                ))]),
            ),
            effects,
        )
        .await;
    }
    #[tokio::test]
    async fn original_input_update_patches_bind_and_rollback_on_real_sqlite() {
        let effects = std::sync::Arc::new(cases::Effects::default());
        let config = cases::config(&effects, "displayUsername");
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let store =
            super::SqlxStore::<super::bundled_schema::BundledSchema>::new(config.clone(), pool);
        super::migrator::run_migrations(&store.pool).await.unwrap();
        let store = store.with_hooks(vec![std::sync::Arc::new(cases::PhysicalHook(
            effects.clone(),
        ))]);
        cases::exercise(config, std::sync::Arc::new(store), effects).await;
    }
}

mod accounts;
mod api_key_usage_phases;
mod api_keys;
mod bundled_schema;
mod device_codes;
pub mod entities;
mod invitations;
mod jwks;
mod members;
pub(crate) mod migrator;
mod oauth_clients;
mod organization_roles;
mod organizations;
mod passkeys;
mod sessions;
mod teams;
mod two_factor;
#[cfg(all(test, feature = "sqlite"))]
mod user_native_tests {
    use super::SqlxStore;
    use super::bundled_schema::BundledSchema;
    use alibi_core::store::UserStore;
    use alibi_core::{AuthUser, CreateUser};
    use serde_json::json;

    #[tokio::test]
    async fn native_username_lookup_observes_sqlite_affinity_and_current_transaction() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let store = SqlxStore::<BundledSchema>::new(alibi_core::AuthConfig::default(), pool);
        super::migrator::run_migrations(&store.pool).await.unwrap();
        let mut input = CreateUser::new().with_email("raw-username@fixture.test");
        _ = input
            .adapter_native_fields
            .insert("username".into(), json!(42).into());
        let user = store.create_user(input).await.unwrap();
        let found = store
            .get_user_by_username_value(&alibi_core::utils::json::JsValue::Number(42.0))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.id(), user.id());
        for raw in [json!([]), json!({})] {
            assert!(store.get_user_by_username_value(&raw.into()).await.is_err());
        }
        alibi_core::store::transaction(&store, |tx| {
            Box::pin(async move {
                let mut input = CreateUser::new().with_email("transaction-username@fixture.test");
                _ = input
                    .adapter_native_fields
                    .insert("username".into(), json!(73).into());
                let created = tx.create_user(input).await?;
                let found = tx
                    .get_user_by_username_value(&alibi_core::utils::json::JsValue::Number(73.0))
                    .await?
                    .unwrap();
                assert_eq!(found.id(), created.id());
                assert!(
                    tx.get_user_by_username_value(&alibi_core::utils::json::JsValue::Number(999.0))
                        .await?
                        .is_none()
                );
                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn native_username_creation_without_plugin_preserves_case() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let store = SqlxStore::<BundledSchema>::new(alibi_core::AuthConfig::default(), pool);
        super::migrator::run_migrations(&store.pool).await.unwrap();
        let mut input = CreateUser::new().with_email("case@fixture.test");
        input.username = Some("KeEpCaSe".into());
        let created = store.create_user(input).await.unwrap();
        assert_eq!(created.username(), Some("KeEpCaSe"));
        assert_eq!(
            store
                .get_user_by_id(&created.id())
                .await
                .unwrap()
                .unwrap()
                .username(),
            Some("KeEpCaSe")
        );
    }

    #[derive(crate::AuthEntity, Clone, Debug, PartialEq, serde::Serialize, sqlx::FromRow)]
    #[auth(role = "user", table = "custom_user", secondary_storage)]
    struct OptionalNativeUser {
        id: String,
        name: String,
        email: String,
        email_verified: bool,
        image: Option<String>,
        created_at: chrono::DateTime<chrono::Utc>,
        updated_at: chrono::DateTime<chrono::Utc>,
        #[sqlx(rename = "physical_color")]
        favorite_color: Option<String>,
        absent_marker: Option<String>,
    }

    #[test]
    fn native_secondary_optional_fields_retain_declared_wire_presence() {
        let source = json!({
            "id": "cache-only", "name": null, "email": "cached@fixture.test",
            "email_verified": false, "created_at": "2020-01-01T00:00:00.000Z",
            "updated_at": "2020-01-01T00:00:00.000Z", "favorite_color": null,
            "unknown_extra": "ignored"
        });
        let record = OptionalNativeUser::from_secondary_snapshot_record(source.into()).unwrap();
        assert_eq!(record.stored().name, "");
        assert_eq!(record.stored().image, None);
        assert_eq!(record.stored().absent_marker, None);
        assert!(record.raw_snapshot().field_is_undefined("image"));
        assert!(record.raw_snapshot().field_is_undefined("absentMarker"));
        assert_eq!(
            record.raw_snapshot().values()["favoriteColor"],
            serde_json::Value::Null
        );
        assert!(!record.raw_snapshot().contains_field("unknownExtra"));
        let wire = serde_json::to_value(alibi_core::UserView::from(&record)).unwrap();
        assert_eq!(wire.get("name"), Some(&serde_json::Value::Null));
        assert!(wire.get("image").is_none());
        assert!(wire.get("absentMarker").is_none());
        assert_eq!(wire.get("favoriteColor"), Some(&serde_json::Value::Null));
        let encoded = record.secondary_snapshot().unwrap();
        assert_eq!(
            encoded.get("name"),
            Some(&alibi_core::utils::json::JsValue::Null)
        );
        assert!(encoded.get("image").is_none());
        assert!(encoded.get("absent_marker").is_none());
        assert_eq!(
            encoded.get("favorite_color"),
            Some(&alibi_core::utils::json::JsValue::Null)
        );
        assert!(encoded.get("physical_color").is_none());
        assert!(encoded.get("unknown_extra").is_none());
    }

    #[test]
    fn native_secondary_custom_texts_keep_raw_values() {
        for value in [json!(42), json!({"custom": true}), json!(null)] {
            let source = json!({
                "id": "cache-custom", "name": 42, "email": null, "image": {"cached": true},
                "email_verified": false, "created_at": "2020-01-01T00:00:00.000Z",
                "updated_at": "2020-01-01T00:00:00.000Z", "favorite_color": value
            });
            let record =
                OptionalNativeUser::from_secondary_snapshot_record(source.clone().into()).unwrap();
            assert_eq!(record.stored().favorite_color, None);
            let wire = serde_json::to_value(alibi_core::UserView::from(&record)).unwrap();
            assert_eq!(wire["favoriteColor"], value);
            assert_eq!(wire["email"], serde_json::Value::Null);
            assert_eq!(wire["image"], source["image"]);
            assert!(wire.get("absentMarker").is_none());
            assert_eq!(
                record.secondary_snapshot().unwrap()["favorite_color"],
                value
            );
        }
        let source = json!({
            "id": "cache-missing-text", "email_verified": false,
            "created_at": "2020-01-01T00:00:00.000Z",
            "updated_at": "2020-01-01T00:00:00.000Z"
        });
        let record = OptionalNativeUser::from_secondary_snapshot_record(source.into()).unwrap();
        assert_eq!(record.stored().name, "");
        assert_eq!(record.stored().email, "");
        let wire = serde_json::to_value(alibi_core::UserView::from(&record)).unwrap();
        let encoded = record.secondary_snapshot().unwrap();
        for field in ["name", "email"] {
            assert!(record.raw_snapshot().field_is_undefined(field));
            assert!(wire.get(field).is_none());
            assert!(encoded.get(field).is_none());
        }
    }

    #[tokio::test]
    async fn false_ban_patch_preserves_omissions_and_applies_explicit_values() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let store = SqlxStore::<BundledSchema>::new(alibi_core::AuthConfig::default(), pool);
        super::migrator::run_migrations(&store.pool).await.unwrap();
        let user = store
            .create_user(CreateUser::new().with_email("false-ban@fixture.test"))
            .await
            .unwrap();
        let expiry = chrono::Utc::now() + chrono::Duration::hours(1);
        let _ = store
            .update_user(
                &user.id(),
                alibi_core::UpdateUser {
                    banned: Some(true),
                    ban_reason: Some("preserved".into()),
                    ban_expires: Some(Some(expiry)),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        for (update, reason, expected_expiry) in [
            (
                alibi_core::UpdateUser {
                    banned: Some(false),
                    ..Default::default()
                },
                Some("preserved"),
                Some(expiry),
            ),
            (
                alibi_core::UpdateUser {
                    banned: Some(false),
                    ban_reason: Some("replacement".into()),
                    ban_expires: Some(Some(expiry + chrono::Duration::hours(1))),
                    ..Default::default()
                },
                Some("replacement"),
                Some(expiry + chrono::Duration::hours(1)),
            ),
            (
                alibi_core::UpdateUser {
                    banned: Some(false),
                    clear_ban_reason: true,
                    ban_expires: Some(None),
                    ..Default::default()
                },
                None,
                None,
            ),
        ] {
            let _ = store.update_user(&user.id(), update).await.unwrap();
            let stored = store.get_user_by_id(&user.id()).await.unwrap().unwrap();
            assert!(!stored.banned());
            assert_eq!(stored.ban_reason(), reason);
            assert_eq!(stored.ban_expires(), expected_expiry);
        }
    }

    #[tokio::test]
    async fn native_creation_persists_sqlite_scalars_and_retains_boolean_output() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let store =
            SqlxStore::<BundledSchema>::new(alibi_core::AuthConfig::default(), pool.clone());
        super::migrator::run_migrations(&store.pool).await.unwrap();
        let mut input = CreateUser {
            email: Some("native-sqlx@fixture.test".into()),
            name: Some("Native".into()),
            ..Default::default()
        };
        input.adapter_native_fields = [
            ("image", json!(42)),
            ("emailVerified", json!("not-a-boolean")),
            ("banned", json!(2)),
            ("twoFactorEnabled", json!("false")),
            ("isAnonymous", json!(null)),
            ("phoneNumberVerified", json!(1)),
            ("displayUsername", json!(false)),
            ("banReason", json!(7)),
            ("banExpires", json!("2099-01-01T00:00:00.000Z")),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value.into()))
        .collect();
        let created = store.create_user_record(input).await.unwrap();
        assert_eq!(created.image(), Some("42"));
        assert_eq!(created.display_username(), Some("0"));
        assert_eq!(created.ban_reason(), Some("7"));
        assert!(!created.banned());
        let retained = store
            .get_user_by_id_record(&created.id())
            .await
            .unwrap()
            .unwrap();
        let response = serde_json::to_value(alibi_core::wire::UserView::from(&retained)).unwrap();
        assert_eq!(response["emailVerified"], "not-a-boolean");
        assert_eq!(response["banned"], false);
        assert_eq!(response["twoFactorEnabled"], "false");
        assert_eq!(response["isAnonymous"], serde_json::Value::Null);
        assert_eq!(response["phoneNumberVerified"], true);
        let raw: (String, String, i64, String) = sqlx::query_as(
            "SELECT image, \"displayUsername\", banned, \"banReason\" FROM user WHERE id = ?",
        )
        .bind(created.id().as_ref())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(raw, ("42".to_owned(), "0".to_owned(), 2, "7".to_owned()));
    }

    #[tokio::test]
    async fn native_creation_numeric_dates_preserve_storage_type_and_wire_scalars() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let store =
            SqlxStore::<BundledSchema>::new(alibi_core::AuthConfig::default(), pool.clone());
        super::migrator::run_migrations(&store.pool).await.unwrap();
        for (index, value) in [json!(0), json!(-1), json!(1.9), json!(true), json!(1e20)]
            .into_iter()
            .enumerate()
        {
            let mut input = CreateUser {
                email: Some(format!("native-dates-{index}@fixture.test")),
                name: Some("Date".into()),
                ..Default::default()
            };
            for field in ["createdAt", "updatedAt", "banExpires"] {
                _ = input
                    .adapter_native_fields
                    .insert(field.to_owned(), value.clone().into());
            }
            let created = store.create_user_record(input).await.unwrap();
            let expected = if value.is_boolean() { json!(1) } else { value };
            let response =
                serde_json::to_value(alibi_core::wire::UserView::from(&created)).unwrap();
            for field in ["createdAt", "updatedAt", "banExpires"] {
                assert_eq!(response[field], expected, "{field}");
            }
            let retained = store
                .get_user_by_id_record(&created.id())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(retained.raw_snapshot().values()["createdAt"], expected);
            type User = <BundledSchema as alibi_core::AuthSchema>::User;
            let snapshot = retained.secondary_snapshot().unwrap();
            let decoded = User::from_secondary_snapshot_record(snapshot).unwrap();
            let wire = serde_json::to_value(alibi_core::UserView::from(&decoded)).unwrap();
            assert_eq!(wire["createdAt"], expected);
            assert_eq!(wire["updatedAt"], expected);
            assert_eq!(wire["banExpires"], expected);
            let (kind, stored): (String, f64) = sqlx::query_as(
                "SELECT typeof(\"createdAt\"), CAST(\"createdAt\" AS REAL) FROM user WHERE id = ?",
            )
            .bind(created.id().as_ref())
            .fetch_one(&pool)
            .await
            .unwrap();
            assert!(matches!(kind.as_str(), "integer" | "real"), "{kind}");
            assert_eq!(stored, expected.as_f64().unwrap());
        }
    }

    #[tokio::test]
    async fn native_creation_rejects_structured_scalar_parameters_without_persistence() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let store =
            SqlxStore::<BundledSchema>::new(alibi_core::AuthConfig::default(), pool.clone());
        super::migrator::run_migrations(&store.pool).await.unwrap();
        for (index, field) in ["image", "banned", "createdAt"].into_iter().enumerate() {
            let email = format!("native-invalid-{index}@fixture.test");
            let mut input = CreateUser {
                email: Some(email.clone()),
                name: Some("Invalid".into()),
                ..Default::default()
            };
            _ = input
                .adapter_native_fields
                .insert(field.to_owned(), json!({"unsupported": true}).into());
            assert!(store.create_user(input).await.is_err());
            assert!(
                store
                    .get_user_by_email(&alibi_core::utils::json::JsString::from(&email))
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[tokio::test]
    async fn unrelated_user_update_retains_native_sqlite_scalars() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let store =
            SqlxStore::<BundledSchema>::new(alibi_core::AuthConfig::default(), pool.clone());
        super::migrator::run_migrations(&store.pool).await.unwrap();
        let mut input = CreateUser::new().with_email("update-native@fixture.test");
        input.adapter_native_fields = [
            ("emailVerified", json!(2)),
            ("banned", json!(0.5)),
            ("twoFactorEnabled", json!(-1)),
            ("isAnonymous", json!("pending")),
            ("phoneNumberVerified", json!(-2)),
            ("createdAt", json!(1e20)),
            ("banExpires", json!(-0.5)),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.into()))
        .collect();
        let created = store.create_user_record(input).await.unwrap();
        let updated = store
            .update_user_record(
                &created.id(),
                alibi_core::UpdateUser {
                    name: Some("Changed".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.name(), Some("Changed"));
        let wire = serde_json::to_value(alibi_core::UserView::from(&updated)).unwrap();
        assert_eq!(wire["banned"], false);
        assert_eq!(wire["emailVerified"], false);
        assert_eq!(wire["twoFactorEnabled"], false);
        assert_eq!(wire["isAnonymous"], "pending");
        assert_eq!(wire["phoneNumberVerified"], false);
        assert_eq!(wire["createdAt"], json!(1e20));
        assert_eq!(wire["banExpires"], json!(-0.5));
        let row: (String, f64, f64, f64) = sqlx::query_as(
            "SELECT typeof(banned), banned, createdAt, banExpires FROM user WHERE id = ?",
        )
        .bind(created.id().as_ref())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row, ("real".into(), 0.5, 1e20, -0.5));
    }

    #[tokio::test]
    async fn native_ban_expiry_updates_preserve_scalars_and_expanded_dates() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let store =
            SqlxStore::<BundledSchema>::new(alibi_core::AuthConfig::default(), pool.clone());
        super::migrator::run_migrations(&store.pool).await.unwrap();
        let expanded = "+275760-09-13T00:00:00.000Z";
        let mut input = CreateUser::new().with_email("expanded-date@fixture.test");
        for field in ["createdAt", "updatedAt", "banExpires"] {
            _ = input
                .adapter_native_fields
                .insert(field.into(), json!(expanded).into());
        }
        let created = store.create_user_record(input).await.unwrap();
        let wire = serde_json::to_value(alibi_core::UserView::from(&created)).unwrap();
        for field in ["createdAt", "updatedAt", "banExpires"] {
            assert_eq!(wire[field], expanded);
        }
        for value in [
            json!(0),
            json!(-0.5),
            json!(1.9),
            json!(true),
            json!(1e20),
            json!(-1e20),
            json!(expanded),
            json!(null),
        ] {
            let updated = store
                .update_user_record(
                    &created.id(),
                    alibi_core::UpdateUser {
                        adapter_native_fields: [("banExpires".into(), value.clone().into())]
                            .into_iter()
                            .collect(),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            let expected = if value.is_boolean() { json!(1) } else { value };
            let wire = serde_json::to_value(alibi_core::UserView::from(&updated)).unwrap();
            assert_eq!(wire["banExpires"], expected);
            let raw: (String, String) = sqlx::query_as(
                "SELECT json_quote(banExpires), typeof(banExpires) FROM user WHERE id = ?",
            )
            .bind(created.id().as_ref())
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&raw.0).unwrap(),
                expected
            );
            if expected.is_number() {
                assert!(matches!(raw.1.as_str(), "integer" | "real"));
            }
            let loaded = store
                .get_user_by_id_record(&created.id())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(loaded.raw_snapshot().values()["banExpires"], expected);
        }
    }

    #[tokio::test]
    async fn supplied_native_ids_use_sqlite_binding_and_generate_only_for_defaults() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let mut config = alibi_core::AuthConfig::default();
        config.advanced.database.generate_id =
            Some(alibi_core::config::DatabaseIdStrategy::Custom(Arc::new(
                move |model: &str, _: Option<usize>| {
                    assert_eq!(model, "user");
                    Ok(Some(format!(
                        "generated-{}",
                        observed.fetch_add(1, Ordering::SeqCst)
                    )))
                },
            )));
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let store = SqlxStore::<BundledSchema>::new(config, pool);
        super::migrator::run_migrations(&store.pool).await.unwrap();
        let mut typed = CreateUser::new().with_email("provided-string@fixture.test");
        typed.id = Some("provided".into());
        let user = store.create_user(typed).await.unwrap();
        assert_eq!(user.id(), "provided");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        for (index, (raw, expected)) in [(json!(71), "71"), (json!(1.9), "1.9"), (json!(true), "1")]
            .into_iter()
            .enumerate()
        {
            let mut input = CreateUser::new().with_email(format!("native-id-{index}@fixture.test"));
            _ = input.adapter_native_fields.insert("id".into(), raw.into());
            let user = store.create_user(input).await.unwrap();
            assert_eq!(user.id(), expected);
            let row = store.get_user_by_id(expected).await.unwrap().unwrap();
            assert_eq!(
                row.email(),
                Some(format!("native-id-{index}@fixture.test").as_str())
            );
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
        for (index, raw) in [json!(false), json!(0), json!(""), json!({}), json!([])]
            .into_iter()
            .enumerate()
        {
            let email = format!("invalid-id-{index}@fixture.test");
            let mut input = CreateUser::new().with_email(&email);
            _ = input
                .adapter_native_fields
                .insert("id".into(), raw.clone().into());
            let error = store.create_user(input).await.unwrap_err();
            assert_eq!(error.status_code(), 500, "{raw:?}: {error:?}");
            assert!(
                store
                    .get_user_by_email(&email.into())
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
        for index in 0..2 {
            let mut input =
                CreateUser::new().with_email(format!("default-id-{index}@fixture.test"));
            if index == 0 {
                _ = input
                    .adapter_native_fields
                    .insert("id".into(), json!(null).into());
            }
            let user = store.create_user(input).await.unwrap();
            assert_eq!(user.id(), format!("generated-{index}"));
            assert_eq!(calls.load(Ordering::SeqCst), index + 1);
        }
    }

    #[tokio::test]
    async fn native_username_updates_use_sqlite_affinity_without_unconditional_lowercase() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let store =
            SqlxStore::<BundledSchema>::new(alibi_core::AuthConfig::default(), pool.clone());
        super::migrator::run_migrations(&store.pool).await.unwrap();
        let created = store
            .create_user(CreateUser::new().with_email("username-updates@fixture.test"))
            .await
            .unwrap();
        for (raw, expected) in [
            (json!(42), json!("42")),
            (json!(false), json!("0")),
            (json!(""), json!("")),
            (json!(null), json!(null)),
        ] {
            let updated = store
                .update_user(
                    created.id().as_ref(),
                    alibi_core::UpdateUser {
                        adapter_native_fields: [
                            ("username".into(), raw.into()),
                            ("displayUsername".into(), json!(false).into()),
                        ]
                        .into(),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(
                serde_json::to_value(alibi_core::UserView::from(&updated)).unwrap()["username"],
                expected
            );
            let physical: (Option<String>, Option<String>) =
                sqlx::query_as("SELECT username,displayUsername FROM user WHERE id=?")
                    .bind(created.id().as_ref())
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(serde_json::to_value(physical.0).unwrap(), expected);
            assert_eq!(physical.1.as_deref(), Some("0"));
        }
        let updated = store
            .update_user(
                created.id().as_ref(),
                alibi_core::UpdateUser {
                    username: Some("UnChangedCase".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.username(), Some("UnChangedCase"));
        let error = store
            .update_user(
                created.id().as_ref(),
                alibi_core::UpdateUser {
                    name: Some("NotStored".into()),
                    adapter_native_fields: [("username".into(), json!({}).into())].into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.status_code(), 500);
        assert_ne!(
            store
                .get_user_by_id(created.id().as_ref())
                .await
                .unwrap()
                .unwrap()
                .name(),
            Some("NotStored")
        );
    }
}

mod users;
mod verifications;
mod wallets;

#[doc(hidden)]
pub mod __private_test_support {
    pub mod bundled_schema {
        pub use super::super::bundled_schema::BundledSchema;
    }

    pub mod migrator {
        pub use super::super::migrator::run_migrations;
    }
}

use crate::OrganizationModels;
use crate::hooks::{DatabaseHooks, SqlxBackend, SqlxHookContext, current_request_hook_context};
use crate::pool::{Engine, Exec, SqlxPool, SqlxTransaction};
use crate::schema::{
    AuthSchema, SqlxAccountModel, SqlxSessionModel, SqlxUserModel, SqlxVerificationModel,
};
use crate::sql::Sql;
use alibi_core::config::AuthConfig;
use alibi_core::error::AuthResult;
use alibi_core::field_policy::FieldValues;
use alibi_core::store::SchemaMigrator;
use alibi_core::store::adapter::{AfterHook, AfterHookQueue};
use alibi_core::store::{
    AuthTransaction, BoxedTransactionValue, TransactionStore, TransactionWork,
};
use alibi_core::types::{AddTeamMemberResult, CreateJwk, Jwk, Member, Team};
use alibi_core::user_validation::PreparedUserCreation;
use alibi_core::verification::{
    VerificationCreation, VerificationPublication, VerificationSnapshot,
};
use alibi_core::{
    CreateAccount, CreateMember, CreatePasskey, CreateSession, CreateUser, CreateVerification,
    Passkey,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::marker::PhantomData;
use std::sync::Arc;

#[derive(Clone)]
pub struct SqlxStore<S: AuthSchema> {
    config: Arc<AuthConfig>,
    pool: SqlxPool,
    hooks: Vec<Arc<dyn DatabaseHooks<S, SqlxBackend>>>,
    organization_models: OrganizationModels,
    _schema: PhantomData<S>,
}

impl<S: AuthSchema> std::fmt::Debug for SqlxStore<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqlxStore").finish_non_exhaustive()
    }
}

impl<S: AuthSchema> SqlxStore<S> {
    #[must_use]
    pub fn new(config: impl Into<Arc<AuthConfig>>, pool: impl Into<SqlxPool>) -> Self {
        Self {
            config: config.into(),
            pool: pool.into(),
            hooks: Vec::new(),
            organization_models: crate::OrganizationModels::default(),
            _schema: PhantomData,
        }
    }

    /// Bind the organization plugin to application-owned tables.
    #[must_use]
    pub fn with_organization_models(mut self, models: OrganizationModels) -> Self {
        self.organization_models = models;
        self
    }

    #[must_use]
    pub fn with_hooks(mut self, hooks: Vec<Arc<dyn DatabaseHooks<S, SqlxBackend>>>) -> Self {
        self.hooks = hooks;
        self
    }

    #[must_use]
    pub fn hook<H: DatabaseHooks<S, SqlxBackend> + 'static>(mut self, hook: H) -> Self {
        self.hooks.push(Arc::new(hook));
        self
    }

    #[must_use]
    pub const fn pool(&self) -> &SqlxPool {
        &self.pool
    }

    #[must_use]
    pub const fn config(&self) -> &Arc<AuthConfig> {
        &self.config
    }

    pub(crate) fn hooks(&self) -> &[Arc<dyn DatabaseHooks<S, SqlxBackend>>] {
        &self.hooks
    }

    pub(crate) async fn generated_id(
        &self,
        exec: Exec<'_>,
        model: &str,
        table: &str,
        column: &str,
    ) -> AuthResult<Option<String>> {
        let policy = &self.config.advanced.database;
        if !policy.serial_ids() {
            return policy.generated_id(model);
        }
        let [ddl, allocate] = alibi_core::config::serial_id_statements(
            table,
            column,
            exec.engine() == Engine::Postgres,
        );
        _ = exec.execute(Sql::with(exec.engine(), &ddl)).await?;
        let value = exec
            .fetch_scalar::<i64>(Sql::with(exec.engine(), &allocate))
            .await?
            .ok_or_else(|| alibi_core::AuthError::internal("ID allocation returned no value"))?;
        Ok(Some(value.to_string()))
    }

    async fn begin(&self, immediate: bool) -> AuthResult<SqlxTransaction> {
        let mut transaction = self.pool.begin(immediate).await?;
        transaction.config = Some(self.config.clone());
        Ok(transaction)
    }

    pub(crate) fn exec(&self) -> Exec<'_> {
        Exec::pool(&self.pool).with_config(self.config.as_ref())
    }

    pub(crate) fn hook_context<'a>(
        &'a self,
        tx: Option<&'a SqlxTransaction>,
    ) -> SqlxHookContext<'a> {
        SqlxHookContext {
            config: self.config.as_ref(),
            db: &self.pool,
            tx,
            request: current_request_hook_context(),
        }
    }

    pub(crate) fn find_many_limit(&self) -> i64 {
        // Mirrors the unsigned page binding of the reference adapter.
        i64::try_from(self.config.advanced.database.default_find_many_limit).unwrap_or(i64::MAX)
    }

    /// Run work on a fresh transaction, committing on success. On failure the
    /// transaction is dropped, which rolls it back, and the work's error returns.
    pub(crate) async fn in_transaction<T>(
        &self,
        immediate: bool,
        work: impl AsyncFnOnce(&SqlxTransaction) -> AuthResult<T>,
    ) -> AuthResult<T> {
        let transaction = self.begin(immediate).await?;
        let value = work(&transaction).await?;
        transaction.commit().await?;
        Ok(value)
    }
}

/// Installs the bundled auth schema in `better_auth_migrations`, the ledger
/// the `SeaORM` adapter also records.
#[async_trait]
impl<S: AuthSchema> SchemaMigrator for SqlxStore<S> {
    async fn migrate(&self) -> AuthResult<()> {
        migrator::run_migrations_scoped(&self.pool, &self.config).await?;
        if self.config.advanced.database.serial_ids() {
            let [ddl, _] = alibi_core::config::serial_id_statements("", "", false);
            let exec = self.exec();
            _ = exec.execute(Sql::with(exec.engine(), &ddl)).await?;
        }
        if let Some(mapping) = &self.config.advanced.database.two_factor {
            let commands = mapping.migration_statements()?;
            self.in_transaction(false, async move |tx| {
                let exec = Exec::tx(tx);
                if migrator::has_table(exec, "twoFactor").await? {
                    for command in commands {
                        _ = exec.execute(Sql::with(exec.engine(), &command)).await?;
                    }
                }
                Ok(())
            })
            .await?;
        }
        if let Some(mapping) = &self.config.advanced.database.sso_provider {
            let commands = mapping.migration_statements()?;
            self.in_transaction(false, async move |tx| {
                let exec = Exec::tx(tx);
                if migrator::has_table(exec, "ssoProvider").await? {
                    for command in commands {
                        _ = exec.execute(Sql::with(exec.engine(), &command)).await?;
                    }
                }
                Ok(())
            })
            .await?;
        }

        let storage = &self.config.advanced.database;
        alibi_core::store::validate_sso_fields(storage)?;
        if !storage.sso_provider_fields.0.is_empty() {
            let table = storage
                .sso_provider
                .as_ref()
                .map_or("ssoProvider", |mapping| mapping.table_name.as_str());
            self.in_transaction(false, async move |tx| {
                let exec = Exec::tx(tx);
                for (name, field) in &storage.sso_provider_fields.0 {
                    let column = alibi_core::store::sso_field_column(name, field);
                    if !migrator::has_column(exec, table, column).await? {
                        let definition = alibi_core::store::sso_field_definition(
                            name,
                            field,
                            exec.engine() == crate::pool::Engine::Postgres,
                        )?;
                        let mut ddl = Sql::with(exec.engine(), "ALTER TABLE ");
                        ddl.ident(table);
                        ddl.push(" ADD COLUMN ");
                        ddl.push(&definition);
                        _ = exec.execute(ddl).await?;
                    }
                }
                Ok(())
            })
            .await?;
        }

        Ok(())
    }
}

struct SqlxStoreTransaction<'a, S: AuthSchema> {
    store: &'a SqlxStore<S>,
    tx: &'a SqlxTransaction,
    pending_after: AfterHookQueue<S>,
}

#[async_trait]
impl<S> AuthTransaction<S> for SqlxStoreTransaction<'_, S>
where
    S: AuthSchema,
    S::User: SqlxUserModel,
    S::Account: SqlxAccountModel,
    S::Session: SqlxSessionModel,
    S::Verification: SqlxVerificationModel,
{
    async fn get_scim_connection_binding(
        &self,
        id: &str,
    ) -> AuthResult<Option<alibi_core::store::ScimConnectionBinding>> {
        self.store
            .get_scim_connection_binding_with_exec(Exec::tx(self.tx), id)
            .await
    }
    async fn scim_projection_candidates(
        &self,
        domain: &str,
        cursor: Option<&str>,
    ) -> AuthResult<Vec<alibi_core::store::ScimProjectionCandidate>> {
        self.store
            .scim_projection_candidates_with_exec(Exec::tx(self.tx), domain, cursor)
            .await
    }
    async fn renew_scim_decommission_lease(
        &self,
        binding: &alibi_core::store::ScimConnectionBinding,
        lease: &str,
    ) -> AuthResult<bool> {
        self.store
            .renew_scim_decommission_lease_with_exec(Exec::tx(self.tx), binding, lease)
            .await
    }
    async fn advance_scim_decommission(
        &self,
        binding: &alibi_core::store::ScimConnectionBinding,
        lease: &str,
        cursor: Option<&str>,
        count: usize,
        more: bool,
    ) -> AuthResult<Option<alibi_core::store::ScimConnectionBinding>> {
        self.store
            .advance_scim_decommission_with_exec(
                Exec::tx(self.tx),
                binding,
                lease,
                cursor,
                count,
                more,
            )
            .await
    }
    async fn reconcile_scim_identity(
        &self,
        user_id: &str,
    ) -> AuthResult<alibi_core::store::ScimIdentityState> {
        self.store
            .reconcile_scim_identity_with_exec(Exec::tx(self.tx), user_id)
            .await
    }
    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
        use crate::model::SqlxModel;
        let sessions = self.get_user_sessions(user_id).await?;
        let context = self.store.hook_context(Some(self.tx));
        for session in &sessions {
            for hook in self.store.hooks() {
                if hook
                    .before_delete_session(session, &context)
                    .await?
                    .is_cancelled()
                {
                    return Ok(());
                }
            }
        }
        let exec = Exec::tx(self.tx);
        let table = <S::Session as SqlxModel>::TABLE;
        let id = <S::Session as SqlxSessionModel>::parse_user_id(user_id)?;
        let mut sql = Sql::with(exec.engine(), "DELETE FROM ");
        sql.ident(table);
        sql.push(" WHERE ");
        sql.compare_model::<S::Session>(table, S::Session::user_id_column(), " = ", id);
        _ = exec.execute(sql).await?;
        for session in sessions {
            self.pending_after
                .push(AfterHook::SessionDeleted(session))
                .await;
        }
        Ok(())
    }
    async fn queue_session_revocation(
        &self,
        session_ids: &[String],
        revocation: Arc<dyn alibi_core::store::SessionRevocation>,
    ) -> AuthResult<()> {
        self.pending_after
            .attach_session_revocation(session_ids, revocation)
            .await;
        Ok(())
    }
    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<S::Session>> {
        use crate::model::SqlxModel;
        let exec = Exec::tx(self.tx);
        let table = <S::Session as SqlxModel>::TABLE;
        let mut sql = crate::model::select_model::<S::Session>(exec);
        sql.push(" WHERE ");
        sql.compare_model::<S::Session>(
            table,
            S::Session::user_id_column(),
            " = ",
            S::Session::parse_user_id(user_id)?,
        );
        sql.push(" LIMIT ");
        sql.bind(self.store.find_many_limit());
        exec.fetch_all::<S::Session>(sql).await
    }
    async fn list_oauth_tokens_for_session(
        &self,
        kind: alibi_core::store::OAuthTokenKind,
        session_id: &str,
    ) -> AuthResult<Vec<alibi_core::store::OAuthToken>> {
        self.store
            .session_oauth_tokens(Exec::tx(self.tx), kind, session_id)
            .await
    }
    async fn get_oauth_client(
        &self,
        client_id: &str,
    ) -> AuthResult<Option<alibi_core::store::OAuthClient>> {
        self.store
            .oauth_client_with_exec(Exec::tx(self.tx), client_id)
            .await
    }
    async fn queue_session_deletion_work(
        &self,
        session_id: &str,
        works: Vec<Box<dyn alibi_core::store::SessionDeletionWork<S>>>,
        context: Arc<alibi_core::AuthContext<S>>,
    ) -> AuthResult<()> {
        self.pending_after
            .attach_session_retirement(session_id, works, context)
            .await;
        Ok(())
    }
    async fn check_scim_user_attributes(
        &self,
        id: &str,
        connection: &str,
        attributes: &alibi_core::store::ScimUserAttributes,
    ) -> AuthResult<()> {
        self.store
            .assert_scim_user_keys_with_exec(
                Exec::tx(self.tx),
                connection,
                &attributes.user_name_key,
                attributes.external_id_key.as_deref(),
                None,
                Some(id),
            )
            .await
    }
    async fn lock_scim_user(
        &self,
        id: &str,
        connection: &str,
        domain: &str,
        attributes: Option<&alibi_core::store::ScimUserAttributes>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<alibi_core::store::ScimUserMutationContext> {
        self.store
            .lock_scim_user_with_exec(Exec::tx(self.tx), id, connection, domain, attributes, now)
            .await
    }
    async fn replace_scim_user(
        &self,
        id: &str,
        data: alibi_core::store::ReplaceScimUser,
        roles: bool,
    ) -> AuthResult<(
        alibi_core::store::ScimUserRecord,
        Vec<alibi_core::store::ScimProjectionPreparedUser>,
    )> {
        self.store
            .replace_scim_user_with_exec(Exec::tx(self.tx), id, data, roles)
            .await
    }
    async fn create_scim_user(
        &self,
        data: alibi_core::store::CreateScimUser,
        roles: bool,
    ) -> AuthResult<(
        alibi_core::store::ScimUserRecord,
        Vec<alibi_core::store::ScimProjectionPreparedUser>,
    )> {
        self.store
            .create_scim_user_with_exec(Exec::tx(self.tx), data, roles)
            .await
    }
    async fn delete_scim_user(
        &self,
        id: &str,
        connection: &str,
        domain: &str,
        roles: bool,
    ) -> AuthResult<(String, Vec<alibi_core::store::ScimProjectionPreparedUser>)> {
        self.store
            .delete_scim_user_with_exec(Exec::tx(self.tx), id, connection, domain, roles)
            .await
    }
    async fn patch_scim_group(
        &self,
        id: &str,
        connection: &str,
        domain: &str,
        patch: alibi_core::store::ScimGroupPatch,
        roles: bool,
    ) -> AuthResult<(
        alibi_core::store::ScimGroupRecord,
        Vec<alibi_core::store::ScimProjectionPreparedUser>,
    )> {
        self.store
            .patch_scim_group_with_exec(Exec::tx(self.tx), id, connection, domain, patch, roles)
            .await
    }
    async fn replace_scim_group(
        &self,
        id: &str,
        data: alibi_core::store::ReplaceScimGroup,
        roles: bool,
    ) -> AuthResult<(
        alibi_core::store::ScimGroupRecord,
        Vec<alibi_core::store::ScimProjectionPreparedUser>,
    )> {
        self.store
            .replace_scim_group_with_exec(Exec::tx(self.tx), id, data, roles)
            .await
    }
    async fn delete_scim_group(
        &self,
        id: &str,
        connection: &str,
        domain: &str,
        roles: bool,
    ) -> AuthResult<Vec<alibi_core::store::ScimProjectionPreparedUser>> {
        self.store
            .delete_scim_group_with_exec(Exec::tx(self.tx), id, connection, domain, roles)
            .await
    }
    async fn create_scim_group(
        &self,
        data: alibi_core::store::CreateScimGroup,
        roles: bool,
    ) -> AuthResult<(
        alibi_core::store::ScimGroupRecord,
        Vec<alibi_core::store::ScimProjectionPreparedUser>,
    )> {
        self.store
            .create_scim_group_with_exec(Exec::tx(self.tx), data, roles)
            .await
    }
    async fn fence_scim_connection(&self, id: &str, key: &str) -> AuthResult<()> {
        self.store
            .fence_scim_connection_with_exec(Exec::tx(self.tx), id, key)
            .await
    }
    async fn prepare_scim_projection(
        &self,
        domain: &str,
        ids: &[String],
        roles: bool,
    ) -> AuthResult<Vec<alibi_core::store::ScimProjectionPreparedUser>> {
        self.store
            .prepare_scim_projection_with_exec(Exec::tx(self.tx), domain, ids, roles)
            .await
    }
    async fn create_scim_projection_grant(
        &self,
        data: alibi_core::store::CreateScimProjectionGrant,
    ) -> AuthResult<()> {
        self.store
            .create_scim_projection_grant_with_exec(Exec::tx(self.tx), data)
            .await
    }
    async fn remove_scim_projection_grants(
        &self,
        domain: &str,
        user_id: &str,
        ids: &[String],
    ) -> AuthResult<()> {
        self.store
            .remove_scim_projection_grants_with_exec(Exec::tx(self.tx), domain, user_id, ids)
            .await
    }
    async fn get_user_by_email(
        &self,
        email: &alibi_core::utils::json::JsString,
    ) -> AuthResult<Option<S::User>> {
        self.store
            .get_user_by_email_with_connection(Exec::tx(self.tx), email)
            .await
    }
    async fn get_account(
        &self,
        provider: &str,
        account_id: &alibi_core::utils::json::JsString,
    ) -> AuthResult<Option<S::Account>> {
        self.store
            .get_account_with_connection(Exec::tx(self.tx), provider, account_id)
            .await
    }
    async fn update_user(&self, id: &str, update: alibi_core::UpdateUser) -> AuthResult<S::User> {
        self.update_user_prepared(
            id,
            alibi_core::store::PreparedUserUpdate::from_typed(&update),
        )
        .await
    }
    async fn update_user_prepared(
        &self,
        id: &str,
        update: alibi_core::store::PreparedUserUpdate,
    ) -> AuthResult<S::User> {
        let user = self
            .store
            .update_user_prepared_with_connection(Exec::tx(self.tx), Some(self.tx), id, update)
            .await?;
        let event = user.as_ref().map_or_else(
            || AfterHook::UserUpdateMissing(id.to_owned()),
            |user| AfterHook::UserUpdated(user.clone()),
        );
        self.pending_after.push(event).await;
        user.ok_or_else(crate::error::record_not_updated)
    }
    async fn update_account(
        &self,
        id: &str,
        update: alibi_core::UpdateAccount,
    ) -> AuthResult<S::Account> {
        let account = self
            .store
            .update_account_with_connection(Exec::tx(self.tx), Some(self.tx), id, update)
            .await?;
        let event = account.as_ref().map_or_else(
            || AfterHook::AccountUpdateMissing(id.to_owned()),
            |account| AfterHook::AccountUpdated(account.clone()),
        );
        self.pending_after.push(event).await;
        account.ok_or_else(|| alibi_core::AuthError::not_found("Account not found"))
    }
    async fn lock_sso_provider(
        &self,
        id: &str,
        provider_id: &str,
    ) -> AuthResult<Option<alibi_core::store::SsoProvider>> {
        self.store
            .lock_sso_provider_with(Exec::tx(self.tx), id, provider_id)
            .await
    }
    async fn update_sso_provider(
        &self,
        update: alibi_core::store::SsoProviderUpdate,
    ) -> AuthResult<Option<alibi_core::store::SsoProvider>> {
        self.store
            .update_sso_provider_with(Exec::tx(self.tx), update)
            .await
    }
    async fn delete_sso_provider_and_accounts(
        &self,
        id: &str,
        provider_id: &str,
    ) -> AuthResult<bool> {
        self.store
            .delete_sso_provider_with(Exec::tx(self.tx), id, provider_id)
            .await
    }
    async fn list_jwks(&self) -> AuthResult<Vec<Jwk>> {
        self.store.list_jwks_with(Exec::tx(self.tx)).await
    }
    async fn get_jwk_by_id(&self, id: &str) -> AuthResult<Option<Jwk>> {
        self.store.get_jwk_with(Exec::tx(self.tx), id).await
    }
    async fn create_jwk(&self, data: CreateJwk) -> AuthResult<Jwk> {
        self.store.create_jwk_with(Exec::tx(self.tx), data).await
    }

    async fn get_team(&self, organization_id: &str, team_id: &str) -> AuthResult<Option<Team>> {
        self.store
            .get_team_with_connection(Exec::tx(self.tx), Some(organization_id), team_id)
            .await
    }
    async fn add_team_member(
        &self,
        team_id: &str,
        user_id: &str,
        maximum: Option<f64>,
    ) -> AuthResult<AddTeamMemberResult> {
        self.store
            .add_team_member_in_tx(self.tx, team_id, user_id, maximum)
            .await
    }
    async fn create_member(&self, member: CreateMember) -> AuthResult<Member> {
        self.store
            .create_member_with_connection(Exec::tx(self.tx), member)
            .await
    }
    async fn update_session_active_team(
        &self,
        token: &str,
        team_id: Option<&str>,
    ) -> AuthResult<S::Session> {
        self.store
            .update_session_scope_with_connection(
                Exec::tx(self.tx),
                token,
                sessions::SessionScope::Team(team_id),
            )
            .await
    }
    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<S::Session> {
        self.store
            .update_session_scope_with_connection(
                Exec::tx(self.tx),
                token,
                sessions::SessionScope::Organization(organization_id),
            )
            .await
    }
    async fn native_user_output(
        &self,
        id: &str,
    ) -> AuthResult<std::collections::BTreeMap<String, alibi_core::utils::json::JsValue>> {
        users::native_user_output::<S::User>(Exec::tx(self.tx), id).await
    }

    async fn provider_verification_output(
        &self,
        id: &str,
    ) -> AuthResult<Option<serde_json::Value>> {
        users::provider_verification_output::<S::User>(Exec::tx(self.tx), id).await
    }
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<S::User>> {
        users::find_user_by_id::<S::User>(Exec::tx(self.tx), id, users::Lock::None).await
    }
    async fn get_user_by_username_value(
        &self,
        username: &alibi_core::utils::json::JsValue,
    ) -> AuthResult<Option<S::User>> {
        self.store
            .get_user_by_username_value_with_connection(Exec::tx(self.tx), username)
            .await
    }
    async fn create_passkey(&self, data: CreatePasskey) -> AuthResult<Passkey> {
        self.store
            .create_passkey_with_connection(Exec::tx(self.tx), data)
            .await
    }
    async fn create_user(&self, create_user: CreateUser) -> AuthResult<S::User> {
        let user = self.store.create_user_in_tx(self.tx, create_user).await?;
        self.pending_after
            .push(AfterHook::UserCreated(user.clone()))
            .await;
        Ok(user)
    }

    async fn create_user_prepared(&self, prepared: PreparedUserCreation) -> AuthResult<S::User> {
        let user = self
            .store
            .create_user_prepared_in_tx(self.tx, prepared)
            .await?;
        self.pending_after
            .push(AfterHook::UserCreated(user.clone()))
            .await;
        Ok(user)
    }

    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<S::Account> {
        let account = self
            .store
            .create_account_in_tx(self.tx, create_account)
            .await?;
        self.pending_after
            .push(AfterHook::AccountCreated(account.clone()))
            .await;
        Ok(account)
    }

    async fn prepare_secondary_session_update(
        &self,
        session: S::Session,
        expires_at: Option<DateTime<Utc>>,
        fields: FieldValues,
    ) -> AuthResult<Option<(S::Session, FieldValues)>> {
        self.store
            .prepare_secondary_update_with_connection(
                Exec::tx(self.tx),
                Some(self.tx),
                session,
                expires_at,
                fields,
            )
            .await
    }
    async fn complete_secondary_session_update(
        &self,
        token: &str,
        session: S::Session,
        expires_at: Option<DateTime<Utc>>,
        fields: FieldValues,
        persist: bool,
    ) -> AuthResult<Option<S::Session>> {
        let result = self
            .store
            .complete_secondary_update_with_connection(
                Exec::tx(self.tx),
                Some(self.tx),
                token,
                session,
                expires_at,
                fields,
                persist,
            )
            .await?;
        let event = result.as_ref().map_or_else(
            || AfterHook::SessionUpdateMissing(token.to_owned()),
            |model| AfterHook::SessionUpdated(model.clone()),
        );
        self.pending_after.push(event).await;
        Ok(result)
    }
    async fn queue_session_publication(
        &self,
        session_id: &str,
        publication: Arc<dyn alibi_core::session::SessionPublication>,
    ) -> AuthResult<()> {
        self.pending_after
            .attach_session_publication(session_id, publication)
            .await
    }

    async fn prepare_secondary_session_creation(
        &self,
        input: CreateSession,
        persist: bool,
    ) -> AuthResult<S::Session> {
        let session = self
            .store
            .prepare_secondary_session_in_tx(self.tx, input, persist)
            .await?;
        self.pending_after
            .push(AfterHook::SessionCreated(session.clone()))
            .await;
        Ok(session)
    }
    async fn discard_session_creation_after_hook(&self, session_id: &str) -> AuthResult<()> {
        self.pending_after
            .discard_session_creation(session_id)
            .await
    }
    async fn create_session(&self, create_session: CreateSession) -> AuthResult<S::Session> {
        let session = self
            .store
            .create_session_in_tx(self.tx, create_session)
            .await?;
        self.pending_after
            .push(AfterHook::SessionCreated(session.clone()))
            .await;
        Ok(session)
    }
    async fn create_verification_record(
        &self,
        data: VerificationCreation,
        publication: VerificationPublication,
    ) -> AuthResult<Option<VerificationSnapshot>> {
        let snapshot = self
            .store
            .create_verification_record_with_connection(
                Exec::tx(self.tx),
                Some(self.tx),
                data,
                publication,
            )
            .await?;
        if let Some(snapshot) = &snapshot {
            self.pending_after
                .push(AfterHook::VerificationRecordCreated(snapshot.clone()))
                .await;
        }
        Ok(snapshot)
    }

    async fn create_verification(
        &self,
        verification: CreateVerification,
    ) -> AuthResult<S::Verification> {
        let verification = self
            .store
            .create_verification_in_tx(self.tx, verification)
            .await?;
        self.pending_after
            .push(AfterHook::VerificationCreated(verification.clone()))
            .await;
        Ok(verification)
    }
    async fn consume_verification_snapshot(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        let consumed = self
            .store
            .consume_generation_in(self.tx, identifier, None)
            .await?;
        if let Some(verification) = &consumed {
            self.pending_after
                .push(AfterHook::VerificationDeleted(verification.clone()))
                .await;
        }
        Ok(consumed)
    }
}

#[async_trait]
impl<S> TransactionStore<S> for SqlxStore<S>
where
    S: AuthSchema,
    S::User: SqlxUserModel,
    S::Account: SqlxAccountModel,
    S::Session: SqlxSessionModel,
    S::Verification: SqlxVerificationModel,
{
    async fn transaction_boxed(
        &self,
        work: Box<TransactionWork<S>>,
    ) -> AuthResult<BoxedTransactionValue> {
        self.transaction_boxed_with_policy(
            work,
            alibi_core::store::AfterCommitErrorPolicy::Propagate,
        )
        .await
    }
    async fn transaction_boxed_with_policy(
        &self,
        work: Box<TransactionWork<S>>,
        policy: alibi_core::store::AfterCommitErrorPolicy,
    ) -> AuthResult<BoxedTransactionValue> {
        self.run_transaction(work, policy, false).await
    }
    async fn write_transaction_boxed(
        &self,
        work: Box<TransactionWork<S>>,
    ) -> AuthResult<BoxedTransactionValue> {
        self.run_transaction(
            work,
            alibi_core::store::AfterCommitErrorPolicy::Propagate,
            true,
        )
        .await
    }
}

impl<S> SqlxStore<S>
where
    S: AuthSchema,
    S::User: SqlxUserModel,
    S::Session: SqlxSessionModel,
    S::Account: SqlxAccountModel,
    S::Verification: SqlxVerificationModel,
{
    async fn run_transaction(
        &self,
        work: Box<TransactionWork<S>>,
        policy: alibi_core::store::AfterCommitErrorPolicy,
        immediate: bool,
    ) -> AuthResult<BoxedTransactionValue> {
        let tx = self.begin(immediate).await?;
        let tx_store = SqlxStoreTransaction {
            store: self,
            tx: &tx,
            pending_after: AfterHookQueue::new(),
        };
        let outcome = work(&tx_store).await;
        let pending_after = tx_store.pending_after;
        match outcome {
            Ok(value) => {
                tx.commit().await?;
                // After hooks run only once the auth writes are durable, in
                // operation order; rollback drops them.
                pending_after
                    .run_with_policy(self.hooks(), &self.hook_context(None), policy)
                    .await?;
                Ok(value)
            }
            Err(err) => {
                tx.rollback().await?;
                Err(err)
            }
        }
    }
}

/// `FOR UPDATE` on PostgreSQL; SQLite relies on its `BEGIN IMMEDIATE` writer lock.
pub(crate) fn lock_exclusive(sql: &mut Sql) {
    if sql.engine() == Engine::Postgres {
        sql.push(" FOR UPDATE");
    }
}

/// `FOR SHARE` on PostgreSQL; SQLite relies on its `BEGIN IMMEDIATE` writer lock.
pub(crate) fn lock_shared(sql: &mut Sql) {
    if sql.engine() == Engine::Postgres {
        sql.push(" FOR SHARE");
    }
}

/// Bind raw numeric `LIMIT`/`OFFSET` values; the database validates them.
pub(crate) fn bind_page(sql: &mut crate::sql::Sql, limit: Option<f64>, offset: Option<f64>) {
    for (clause, number) in [(" LIMIT ", limit), (" OFFSET ", offset)] {
        if let Some(number) = number {
            sql.push(clause);
            if sql.engine() == Engine::Postgres {
                // node-postgres sends Number parameters as text. Binding float8
                // instead lets PostgreSQL round fractional pages to bigint.
                sql.bind(ryu_js::Buffer::new().format(number).to_owned());
                sql.push("::bigint");
            } else {
                sql.bind(number);
            }
        }
    }
}

mod sso;

mod scim;
mod scim_decommission;
mod scim_groups;
mod scim_projection;
mod scim_user_create;
mod scim_user_replace;
mod scim_users;

#[cfg(all(test, feature = "sqlite"))]
mod session_publication_tests {
    use super::*;

    #[derive(crate::AuthEntity, Clone, Debug, serde::Serialize, sqlx::FromRow)]
    #[auth(role = "session", table = "mapped_session", secondary_storage)]
    struct MappedClockSession {
        id: String,
        user_id: String,
        token: String,
        expires_at: chrono::NaiveDateTime,
        #[sqlx(rename = "database_creation_clock")]
        created_at: chrono::NaiveDateTime,
        updated_at: chrono::NaiveDateTime,
        ip_address: Option<String>,
        user_agent: Option<String>,
        impersonated_by: Option<String>,
        active_organization_id: Option<String>,
        custom_label: String,
    }

    #[test]
    fn creation_codec_corrects_mapped_naive_clock_without_mutating_model_or_custom_fields() {
        let clock = chrono::DateTime::from_timestamp_millis(1_800_000_000_789).unwrap();
        let rounded = chrono::DateTime::from_timestamp_millis(1_800_000_000_000).unwrap();
        let session = MappedClockSession {
            id: "session".into(),
            user_id: "owner".into(),
            token: "credential".into(),
            expires_at: (clock + chrono::Duration::hours(1)).naive_utc(),
            created_at: rounded.naive_utc(),
            updated_at: rounded.naive_utc(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            custom_label: "retained".into(),
        };
        let snapshot = session.secondary_snapshot_for_creation(clock).unwrap();
        assert_eq!(snapshot["custom_label"], "retained");
        assert!(snapshot.get("database_creation_clock").is_none());
        let restored = MappedClockSession::from_secondary_snapshot(snapshot).unwrap();
        assert_eq!(restored.created_at(), clock);
        assert_eq!(restored.updated_at(), rounded);
        assert_eq!(session.created_at(), rounded);
        let ordinary =
            MappedClockSession::from_secondary_snapshot(session.secondary_snapshot().unwrap())
                .unwrap();
        assert_eq!(ordinary.created_at(), rounded);
    }

    #[derive(crate::AuthEntity, Clone, Debug, serde::Serialize, sqlx::FromRow)]
    #[auth(role = "session", table = "projected_session", secondary_storage)]
    struct ProjectedSession {
        id: String,
        user_id: String,
        token: String,
        expires_at: chrono::DateTime<chrono::Utc>,
        #[sqlx(rename = "renamed_clock_column")]
        created_at: chrono::DateTime<chrono::Utc>,
        updated_at: chrono::DateTime<chrono::Utc>,
        ip_address: Option<String>,
        user_agent: Option<String>,
        #[sqlx(rename = "renamed_label_column")]
        custom_label: Option<String>,
    }

    #[test]
    fn session_native_output_codec_maps_logical_fields_without_mutating_storage_authority() {
        let clock = chrono::DateTime::from_timestamp_millis(1_800_000_000_789).unwrap();
        let rounded = chrono::DateTime::from_timestamp_millis(1_800_000_000_000).unwrap();
        let session = ProjectedSession {
            id: "session".into(),
            user_id: "owner".into(),
            token: "credential".into(),
            expires_at: clock + chrono::Duration::hours(1),
            created_at: rounded,
            updated_at: rounded,
            ip_address: Some("stored-ip".into()),
            user_agent: Some("stored-agent".into()),
            custom_label: Some("stored-label".into()),
        };
        let mut native = alibi_core::AdapterOutput::default();
        native.insert("customLabel".into(), Some(serde_json::Value::Null.into()));
        native.insert("ipAddress".into(), None);
        native.insert(
            "unknownTrustedObject".into(),
            Some(serde_json::json!({"nested":[true,null]}).into()),
        );
        native.insert(
            "createdAt".into(),
            Some(serde_json::json!("2001-01-01T00:00:00.000Z").into()),
        );
        let snapshot = session
            .secondary_snapshot_with_native_output(&native)
            .unwrap();
        assert_eq!(snapshot["custom_label"], serde_json::Value::Null);
        assert!(snapshot.get("ip_address").is_none());
        assert_eq!(
            snapshot["unknownTrustedObject"],
            serde_json::json!({"nested":[true,null]})
        );
        assert!(snapshot.get("renamed_label_column").is_none());
        assert!(snapshot.get("renamed_clock_column").is_none());
        let creation = session
            .secondary_snapshot_for_creation_with_native_output(clock, &native)
            .unwrap();
        assert_eq!(creation["created_at"], serde_json::to_value(clock).unwrap());
        assert_eq!(snapshot["created_at"], "2001-01-01T00:00:00.000Z");
        let output = ProjectedSession::output_from_secondary_snapshot(snapshot.clone()).unwrap();
        assert_eq!(output.values()["customLabel"], serde_json::Value::Null);
        assert!(output.field_is_undefined("ipAddress"));
        assert_eq!(
            output.values()["unknownTrustedObject"],
            serde_json::json!({"nested":[true,null]})
        );
        assert!(!output.values().contains_key("custom_label"));
        assert!(!output.values().contains_key("renamed_label_column"));
        let decoded = ProjectedSession::from_secondary_snapshot(snapshot.clone()).unwrap();
        assert_eq!(decoded.custom_label, None);
        assert_eq!(decoded.ip_address, None);

        assert_eq!(session.created_at(), rounded);
        assert_eq!(session.custom_label.as_deref(), Some("stored-label"));
        native.insert("customLabel".into(), None);
        assert!(
            session
                .secondary_snapshot_with_native_output(&native)
                .unwrap()
                .get("custom_label")
                .is_none()
        );

        let naive = MappedClockSession {
            id: "session".into(),
            user_id: "owner".into(),
            token: "credential".into(),
            expires_at: (clock + chrono::Duration::hours(1)).naive_utc(),
            created_at: rounded.naive_utc(),
            updated_at: rounded.naive_utc(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            custom_label: "retained".into(),
        };
        let snapshot = naive
            .secondary_snapshot_for_creation_with_native_output(clock, &native)
            .unwrap();
        assert_eq!(
            snapshot["created_at"],
            serde_json::to_value(clock.naive_utc()).unwrap()
        );
        assert!(snapshot.get("database_creation_clock").is_none());
        assert_eq!(naive.created_at(), rounded);
    }

    use alibi_core::store::{SessionStore, UserStore, write_transaction};
    use alibi_core::{AuthError, AuthSession};
    use std::sync::Mutex;

    type Schema = bundled_schema::BundledSchema;

    struct Publication {
        store: Arc<SqlxStore<Schema>>,
        token: String,
        events: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl alibi_core::session::SessionPublication for Publication {
        async fn publish(&self) {
            assert!(self.store.get_session(&self.token).await.unwrap().is_some());
            self.events.lock().unwrap().push("mirror".into());
        }
    }

    struct Hooks {
        events: Arc<Mutex<Vec<String>>>,
        fail_commit: bool,
    }

    #[async_trait]
    impl DatabaseHooks<Schema, SqlxBackend> for Hooks {
        async fn before_create_session(
            &self,
            input: &mut CreateSession,
            ctx: &SqlxHookContext<'_>,
        ) -> AuthResult<crate::hooks::HookControl> {
            if self.fail_commit && input.token.as_deref() == Some("replacement") {
                use crate::hooks::SqlxHookContextExt;
                let mut connection = ctx.connection().await?;
                let db = connection.sqlite().unwrap();
                _ = sqlx::raw_sql(sqlx::AssertSqlSafe(
                    "CREATE TABLE commit_failure (id TEXT REFERENCES user(id) DEFERRABLE INITIALLY DEFERRED); INSERT INTO commit_failure VALUES ('missing-user')".to_owned()
                )).execute(db).await.unwrap();
            }
            Ok(crate::hooks::HookControl::Continue)
        }

        async fn after_create_session(
            &self,
            session: &<Schema as alibi_core::AuthSchema>::Session,
            ctx: &SqlxHookContext<'_>,
        ) -> AuthResult<()> {
            assert!(ctx.tx.is_none());
            self.events.lock().unwrap().push(session.token().to_owned());
            Ok(())
        }
    }

    fn input(user_id: &str, token: &str) -> CreateSession {
        CreateSession {
            user_id: user_id.to_owned(),
            token: Some(token.to_owned()),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
            additional_fields: Default::default(),
        }
    }

    #[tokio::test]
    async fn secondary_update_persists_by_lookup_token_not_cached_token() {
        let pool = SqlxPool::connect("sqlite::memory:").await.unwrap();
        migrator::run_migrations(&pool).await.unwrap();
        let store = SqlxStore::<Schema>::new(AuthConfig::default(), pool);
        let user = store
            .create_user(CreateUser::new().with_email("lookup@example.com"))
            .await
            .unwrap();
        let original = store
            .create_session(input(&user.id, "lookup-token"))
            .await
            .unwrap();
        for transactional in [false, true] {
            let mut cached = original.clone();
            cached.token = "unrelated-cached-token".into();
            let expiry = Utc::now() + chrono::Duration::hours(2);
            let updated = if transactional {
                write_transaction(&store, move |tx| {
                    Box::pin(async move {
                        let (staged, fields) = tx
                            .prepare_secondary_session_update(
                                cached,
                                Some(expiry),
                                Default::default(),
                            )
                            .await?
                            .unwrap();
                        tx.complete_secondary_session_update(
                            "lookup-token",
                            staged,
                            Some(expiry),
                            fields,
                            true,
                        )
                        .await
                    })
                })
                .await
                .unwrap()
                .unwrap()
            } else {
                let (staged, fields) = store
                    .prepare_secondary_session_update(cached, Some(expiry), Default::default())
                    .await
                    .unwrap()
                    .unwrap();
                store
                    .complete_secondary_session_update(
                        "lookup-token",
                        staged,
                        Some(expiry),
                        fields,
                        true,
                    )
                    .await
                    .unwrap()
                    .unwrap()
            };
            assert_eq!(updated.token(), "lookup-token");
            assert_eq!(updated.expires_at(), expiry);
            assert_eq!(
                store
                    .get_session("lookup-token")
                    .await
                    .unwrap()
                    .unwrap()
                    .expires_at(),
                expiry
            );
            assert!(
                store
                    .get_session("unrelated-cached-token")
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[tokio::test]
    async fn publication_is_committed_before_matching_create_hook_only() {
        for outcome in ["commit", "rollback", "commit-failure"] {
            let pool = SqlxPool::connect("sqlite::memory:").await.unwrap();
            migrator::run_migrations(&pool).await.unwrap();
            let events = Arc::new(Mutex::new(Vec::new()));
            let store = Arc::new(
                SqlxStore::<Schema>::new(AuthConfig::new("test-secret-min-32-chars-1234567"), pool)
                    .hook(Hooks {
                        events: events.clone(),
                        fail_commit: outcome == "commit-failure",
                    }),
            );
            let user = store
                .create_user(CreateUser::new().with_email("mirror@example.com"))
                .await
                .unwrap();
            let user_id = user.id;
            let publication = Arc::new(Publication {
                store: store.clone(),
                token: "replacement".into(),
                events: events.clone(),
            });
            let result = write_transaction(store.as_ref(), move |tx| {
                Box::pin(async move {
                    _ = tx.create_session(input(&user_id, "preceding")).await?;
                    let replacement = tx
                        .prepare_secondary_session_creation(input(&user_id, "replacement"), true)
                        .await?;
                    tx.queue_session_publication(replacement.id().as_ref(), publication)
                        .await?;
                    if outcome == "rollback" {
                        return Err(AuthError::internal("rollback"));
                    }
                    Ok(())
                })
            })
            .await;
            if outcome == "commit" {
                result.unwrap();
                assert_eq!(
                    *events.lock().unwrap(),
                    ["preceding", "mirror", "replacement"]
                );
            } else {
                assert!(result.is_err(), "{outcome}");
                assert!(events.lock().unwrap().is_empty(), "{outcome}");
                assert!(store.get_session("preceding").await.unwrap().is_none());
                assert!(store.get_session("replacement").await.unwrap().is_none());
            }
        }
    }
}
