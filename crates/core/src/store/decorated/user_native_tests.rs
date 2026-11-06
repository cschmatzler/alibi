use super::*;
use crate::field_policy::FieldConfig;
use crate::store::UserStore;
use crate::test_store::{BundledSchema, MemoryStore};
use crate::{AdapterOutput, AuthContext, CreateUser, UserView};

#[tokio::test]
async fn cached_native_user_projection_preserves_values_without_database_lookup() {
    let mut config = crate::AuthConfig::default();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    config.user.additional_fields.insert(
        "cacheMarker".into(),
        FieldConfig::new(serde_json::json!({"type": "string"})).transform_output(move |_| {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async {
                Ok(Some(crate::utils::json::JsValue::String(
                    "projected".into(),
                )))
            }
        }),
    );
    let count = Arc::clone(&calls);
    config.user.additional_fields.insert(
        "emailVerified".into(),
        FieldConfig::new(serde_json::json!({"type": "boolean"})).transform_output(move |value| {
            assert_eq!(
                value,
                Some(crate::utils::json::JsValue::String("false".into()))
            );
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async {
                Ok(Some(crate::utils::json::JsValue::String(
                    "transformed false".into(),
                )))
            }
        }),
    );
    config.user.additional_fields.insert(
        "banned".into(),
        FieldConfig::new(serde_json::json!({"type": "boolean"})).transform_output(|value| {
            assert_eq!(value, None);
            async { Ok(None) }
        }),
    );
    config.user.additional_fields.insert(
        "isAnonymous".into(),
        FieldConfig::new(serde_json::json!({"type": "boolean"})).transform_output(|value| {
            assert_eq!(value, Some(crate::utils::json::JsValue::Null));
            async { Ok(Some(crate::utils::json::JsValue::Null)) }
        }),
    );
    let config = Arc::new(config);
    let inner = Arc::new(MemoryStore::new(Arc::clone(&config)));
    let cached = inner
        .create_user(CreateUser::new().with_email("cached-native@fixture.test"))
        .await
        .unwrap();
    let mut native = AdapterOutput::default();
    native.insert("emailVerified".into(), Some(serde_json::json!("false")));
    native.insert("createdAt".into(), Some(serde_json::json!(1e20)));
    native.insert("updatedAt".into(), Some(serde_json::json!(-0.5)));
    native.insert("banExpires".into(), Some(serde_json::json!(0)));
    native.insert("isAnonymous".into(), Some(serde_json::Value::Null));
    native.insert("banned".into(), None);
    let context = AuthContext::<BundledSchema>::new(config.clone(), inner.clone());
    let store = PluginStore::new(
        inner.clone(),
        config,
        UserTransforms::default(),
        SessionCreatedCallbacks::default(),
        crate::field_policy::SessionFields::default(),
        crate::field_policy::SessionAdapterFields::default(),
        context,
    );
    inner.delete_user(&cached.id).await.unwrap();
    let record = store
        .user_record_with_native_output(cached, native)
        .await
        .unwrap();
    let wire = serde_json::to_value(UserView::from(&record)).unwrap();
    assert_eq!(wire["emailVerified"], "transformed false");
    assert_eq!(wire["createdAt"], serde_json::json!(1e20));
    assert_eq!(wire["updatedAt"], serde_json::json!(-0.5));
    assert_eq!(wire["banExpires"], 0);
    assert_eq!(wire["isAnonymous"], serde_json::Value::Null);
    assert!(wire.get("banned").is_none());
    assert!(record.raw_snapshot().field_is_undefined("banned"));
    assert_eq!(record.raw_snapshot().values()["cacheMarker"], "projected");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn custom_user_codecs_reject_unsupported_native_corrections() {
    let store = MemoryStore::default();
    let user = store
        .create_user(CreateUser::new().with_email("native-unsupported@fixture.test"))
        .await
        .unwrap();
    let mut native = AdapterOutput::default();
    native.insert("createdAt".into(), Some(serde_json::json!(1e20)));
    assert!(matches!(
        user.secondary_snapshot_with_native_output(&native),
        Err(AuthError::NotImplemented(_))
    ));
    let mut undefined = AdapterOutput::default();
    undefined.insert("banned".into(), None);
    assert!(matches!(
        user.secondary_snapshot_with_native_output(&undefined),
        Err(AuthError::NotImplemented(_))
    ));
}
