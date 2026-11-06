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
            JsValue::Date(chrono::DateTime::from_timestamp(1_700_000_000, 123_456_789).unwrap()),
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
    let literal_json = JsValue::String(alibi_core::utils::json::JsString::from_code_units(vec![
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
    let inner =
        super::SqlxStore::<super::bundled_schema::BundledSchema>::new(AuthConfig::default(), pool);
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
