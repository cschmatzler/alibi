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

#[derive(Clone, Debug, serde::Serialize)]
struct UnsupportedUser(UserView);

impl AuthUser for UnsupportedUser {
    fn id(&self) -> std::borrow::Cow<'_, str> {
        self.0.id()
    }
    fn email(&self) -> Option<&str> {
        self.0.email()
    }
    fn name(&self) -> Option<&str> {
        self.0.name()
    }
    fn email_verified(&self) -> bool {
        self.0.email_verified()
    }
    fn image(&self) -> Option<&str> {
        self.0.image()
    }
    fn created_at(&self) -> chrono::DateTime<chrono::Utc> {
        self.0.created_at()
    }
    fn updated_at(&self) -> chrono::DateTime<chrono::Utc> {
        self.0.updated_at()
    }
    fn username(&self) -> Option<&str> {
        self.0.username()
    }
    fn display_username(&self) -> Option<&str> {
        self.0.display_username()
    }
    fn two_factor_enabled(&self) -> bool {
        self.0.two_factor_enabled()
    }
    fn role(&self) -> Option<&str> {
        self.0.role()
    }
    fn banned(&self) -> bool {
        self.0.banned()
    }
    fn ban_reason(&self) -> Option<&str> {
        self.0.ban_reason()
    }
    fn ban_expires(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.0.ban_expires()
    }
    fn metadata(&self) -> &serde_json::Value {
        self.0.metadata()
    }
}

#[tokio::test]
async fn custom_user_codecs_reject_unsupported_native_corrections() {
    let store = MemoryStore::default();
    let user = store
        .create_user(CreateUser::new().with_email("native-unsupported@fixture.test"))
        .await
        .unwrap();
    let user = UnsupportedUser(user);
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

#[tokio::test]
async fn cached_user_fields_use_effective_config_without_database_or_transforms() {
    use crate::store::stateless::{StatelessSchema, StatelessStore};
    use crate::store::{CacheAdapter, SessionStore};
    use crate::{AuthSession, CreateSession};
    use chrono::{Duration, Utc};
    use serde_json::json;

    for registered in [false, true] {
        let cache = Arc::new(crate::MemoryCacheAdapter::new());
        let mut config = crate::AuthConfig::default();
        config.session.secondary_storage = Some(cache.clone());
        let configured_fields = |marker: &str| {
            [
                (
                    marker.into(),
                    FieldConfig::new(json!({"type": "json"})).transform_output(|_| async {
                        panic!("cached reads must not rerun adapter output transforms")
                    }),
                ),
                (
                    "cachedNull".into(),
                    FieldConfig::new(json!({"type": "string"})),
                ),
                (
                    "cachedMissing".into(),
                    FieldConfig::new(json!({"type": "string"})),
                ),
                (
                    "hiddenMarker".into(),
                    FieldConfig::new(json!({"type": "json"})).hidden(),
                ),
            ]
            .into_iter()
            .collect()
        };
        config.user.additional_fields = configured_fields("fallbackMarker");
        let config = Arc::new(config);
        let inner = Arc::new(StatelessStore::default());
        let user = inner
            .create_user(CreateUser::new().with_email("cached-fields@fixture.test"))
            .await
            .unwrap();
        let session = inner
            .create_session(CreateSession {
                user_id: user.id.clone(),
                token: Some(format!("cached-fields-{registered}")),
                expires_at: Utc::now() + Duration::hours(1),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
                active_team_id: None,
                additional_fields: Default::default(),
            })
            .await
            .unwrap();
        let mut snapshot = user.secondary_snapshot().unwrap();
        snapshot["fallbackMarker"] = json!({"selected": "fallback"});
        snapshot["registeredMarker"] = json!({"selected": "registered"});
        snapshot["cachedNull"] = json!(null);
        snapshot["unconfigured"] = json!({"retained": [null, true]});
        snapshot["hiddenMarker"] = json!({"secret": "retained in cache only"});
        cache
            .set(
                session.token(),
                &json!({
                    "session": session.secondary_snapshot().unwrap(),
                    "user": snapshot,
                })
                .to_string(),
                Duration::hours(1),
            )
            .await
            .unwrap();
        inner.delete_user(&user.id).await.unwrap();
        let mut context = AuthContext::<StatelessSchema>::new(config.clone(), inner.clone());
        if registered {
            context.extensions.insert(crate::field_policy::UserFields(
                crate::field_policy::SessionFields(configured_fields("registeredMarker")),
            ));
        }
        let store = PluginStore::new(
            inner.clone(),
            config,
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
            context,
        );
        let (selected, rejected) = if registered {
            ("registeredMarker", "fallbackMarker")
        } else {
            ("fallbackMarker", "registeredMarker")
        };
        for _ in 0..2 {
            let record = store
                .get_session_user_record(session.token())
                .await
                .unwrap()
                .unwrap();
            let wire = serde_json::to_value(UserView::from(&record)).unwrap();
            assert_eq!(wire[selected], snapshot[selected]);
            assert!(wire["cachedNull"].is_null());
            assert!(record.raw_snapshot().field_is_undefined("cachedMissing"));
            assert!(wire.get("cachedMissing").is_none());
            assert_eq!(wire[rejected], snapshot[rejected]);
            assert_eq!(wire["unconfigured"], snapshot["unconfigured"]);
            assert!(wire.get("hiddenMarker").is_none());
        }
        store
            .update_session_fields(session.token(), Default::default())
            .await
            .unwrap()
            .unwrap();
        let cached: serde_json::Value =
            serde_json::from_str(&cache.get(session.token()).await.unwrap().unwrap()).unwrap();
        assert_eq!(cached["user"][selected], snapshot[selected]);
        assert!(cached["user"]["cachedNull"].is_null());
        assert!(cached["user"].get("cachedMissing").is_none());
        assert_eq!(cached["user"][rejected], snapshot[rejected]);
        assert_eq!(cached["user"]["unconfigured"], snapshot["unconfigured"]);
        assert_eq!(cached["user"]["hiddenMarker"], snapshot["hiddenMarker"]);
        assert!(inner.get_user_by_id(&user.id).await.unwrap().is_none());
    }
}
