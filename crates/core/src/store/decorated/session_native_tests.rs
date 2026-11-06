use super::*;
use crate::field_policy::{FieldConfig, FieldValues, SessionAdapterFields, SessionFields};
use crate::store::stateless::{StatelessSchema, StatelessStore};
use crate::store::{CacheAdapter, MemoryCacheAdapter, SessionStore, UserStore};
use crate::test_store::{BundledSchema, MemoryStore};
use crate::utils::json::JsValue;
use crate::{AuthContext, CreateSession, CreateUser};
use chrono::{Duration, Utc};
use serde_json::{Value, json};

fn config(cache: Arc<MemoryCacheAdapter>) -> Arc<crate::AuthConfig> {
    let mut config = crate::AuthConfig::default();
    config.session.stateless = false;
    config.session.store_in_database = false;
    config.session.secondary_storage = Some(cache);
    for (name, field) in [
        ("custom", FieldConfig::new(json!({"type": "json"}))),
        ("optional", FieldConfig::new(json!({"type": "string"}))),
        (
            "nullable",
            FieldConfig::new(json!({"type": "string"})).default_value(JsValue::Null),
        ),
        (
            "activeOrganizationId",
            FieldConfig::new(json!({"type": "string"})),
        ),
        ("activeTeamId", FieldConfig::new(json!({"type": "string"}))),
        (
            "impersonatedBy",
            FieldConfig::new(json!({"type": "string"})),
        ),
    ] {
        config.session.additional_fields.insert(name.into(), field);
    }
    Arc::new(config)
}

fn decorated<S: AuthSchema>(
    inner: Arc<dyn AuthStore<S>>,
    config: Arc<crate::AuthConfig>,
) -> PluginStore<S> {
    let context = AuthContext::new(config.clone(), inner.clone());
    let fields = config.session.additional_fields.clone();
    PluginStore::new(
        inner,
        config,
        UserTransforms::default(),
        SessionCreatedCallbacks::default(),
        SessionFields(fields.clone()),
        SessionAdapterFields(Arc::new(fields)),
        context,
    )
}

fn creation(user_id: &str, token: &str) -> CreateSession {
    let mut additional_fields = FieldValues::new();
    additional_fields.insert(
        "custom".into(),
        JsValue::from(json!({"nested": [false, null, 42]})),
    );
    CreateSession {
        user_id: user_id.into(),
        token: Some(token.into()),
        expires_at: Utc::now() + Duration::hours(1),
        ip_address: None,
        user_agent: Some("native-session-test".into()),
        impersonated_by: None,
        active_organization_id: None,
        active_team_id: None,
        additional_fields,
    }
}

async fn envelope(cache: &MemoryCacheAdapter, token: &str) -> Value {
    serde_json::from_str(&cache.get(token).await.unwrap().unwrap()).unwrap()
}

#[tokio::test]
async fn stateless_secondary_session_creation_read_update_and_revocation_are_native() {
    let cache = Arc::new(MemoryCacheAdapter::new());
    let config = config(cache.clone());
    let inner = Arc::new(StatelessStore::default());
    let store = decorated::<StatelessSchema>(inner.clone(), config.clone());
    let user = store
        .create_user(CreateUser::new().with_email("session-native@fixture.test"))
        .await
        .unwrap();
    let created = store
        .create_session(creation(&user.id, "native-secondary-token"))
        .await
        .unwrap();
    assert!(inner.get_session(&created.token).await.unwrap().is_none());
    let physical = envelope(&cache, &created.token).await;
    assert_eq!(physical["session"]["id"], created.id);
    assert_eq!(physical["session"]["token"], "native-secondary-token");
    assert_eq!(physical["session"]["userId"], user.id);
    assert_eq!(physical["session"]["ipAddress"], "");
    assert_eq!(
        physical["session"]["custom"],
        json!({"nested": [false, null, 42]})
    );
    assert_eq!(physical["session"]["nullable"], Value::Null);
    assert!(physical["session"].get("optional").is_none());
    assert!(physical["session"].get("activeTeamId").is_none());

    // A new wrapper has no ephemeral sessions; reads must decode the actual cache envelope.
    let reader = decorated::<StatelessSchema>(inner.clone(), config);
    let cached = reader
        .get_session_record(&created.token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cached.id(), created.id);
    assert_eq!(cached.user_id(), user.id);
    assert_eq!(
        cached.raw_snapshot().values()["custom"],
        physical["session"]["custom"]
    );
    assert!(cached.raw_snapshot().field_is_undefined("optional"));
    assert_eq!(
        reader
            .get_session_user(&created.token)
            .await
            .unwrap()
            .unwrap()
            .id,
        user.id
    );
    assert_eq!(reader.get_user_sessions(&user.id).await.unwrap().len(), 1);
    assert_eq!(
        reader
            .get_sessions_by_tokens(&[created.token.clone()])
            .await
            .unwrap()
            .len(),
        1
    );

    let mut fields = FieldValues::new();
    fields.insert("custom".into(), JsValue::from(json!(["updated", null])));
    fields.insert("optional".into(), JsValue::Null);
    reader
        .update_session_fields_record(&created.token, fields)
        .await
        .unwrap()
        .unwrap();
    reader
        .update_session_active_team(&created.token, Some("team-native"))
        .await
        .unwrap();
    let cleared = reader
        .update_session_active_team_record(&created.token, None)
        .await
        .unwrap();
    assert_eq!(cleared.raw_snapshot().values()["activeTeamId"], Value::Null);
    let expires = Utc::now() + Duration::hours(2);
    reader
        .refresh_session(&created.token, expires)
        .await
        .unwrap()
        .unwrap();
    let updated = envelope(&cache, &created.token).await;
    assert_eq!(
        updated["session"]["createdAt"],
        physical["session"]["createdAt"]
    );
    assert_eq!(updated["session"]["custom"], json!(["updated", null]));
    assert_eq!(updated["session"]["optional"], Value::Null);
    assert_eq!(updated["session"]["activeTeamId"], Value::Null);
    assert_eq!(
        reader
            .get_session(&created.token)
            .await
            .unwrap()
            .unwrap()
            .expires_at
            .timestamp_millis(),
        expires.timestamp_millis()
    );
    assert!(inner.get_session(&created.token).await.unwrap().is_none());

    reader.delete_session(&created.token).await.unwrap();
    assert!(cache.get(&created.token).await.unwrap().is_none());
    assert!(reader.get_session(&created.token).await.unwrap().is_none());
    assert!(reader.get_user_sessions(&user.id).await.unwrap().is_empty());
    for token in ["native-bulk-one", "native-bulk-two"] {
        reader
            .create_session(creation(&user.id, token))
            .await
            .unwrap();
    }
    reader.delete_user_sessions(&user.id).await.unwrap();
    for token in ["native-bulk-one", "native-bulk-two"] {
        assert!(cache.get(token).await.unwrap().is_none());
        assert!(reader.get_session(token).await.unwrap().is_none());
    }
    assert!(
        cache
            .get(&format!("active-sessions-{}", user.id))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        cache
            .get(&format!("revoked-sessions-before-{}", user.id))
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn bundled_secondary_session_reads_full_native_memory_cache_fixture() {
    let cache = Arc::new(MemoryCacheAdapter::new());
    let config = config(cache.clone());
    let inner = Arc::new(MemoryStore::default());
    let user = inner
        .create_user(CreateUser::new().with_email("session-fixture@fixture.test"))
        .await
        .unwrap();
    let snapshot = json!({
        "session": {
            "id": "native-fixture-id",
            "token": "native-fixture-token",
            "userId": user.id,
            "expiresAt": crate::utils::datetime::json_date_millis((Utc::now() + Duration::hours(1)).timestamp_millis()),
            "createdAt": "2026-01-02T03:04:05.678Z",
            "updatedAt": "2026-02-03T04:05:06.789Z",
            "userAgent": null,
            "activeOrganizationId": null,
            "activeTeamId": "fixture-team",
            "custom": {"from": "native-envelope"},
            "nullable": null
        },
        "user": user.secondary_snapshot().unwrap()
    });
    cache
        .set(
            "native-fixture-token",
            &snapshot.to_string(),
            Duration::hours(1),
        )
        .await
        .unwrap();
    let store = decorated::<BundledSchema>(inner.clone(), config);
    let record = store
        .get_session_record("native-fixture-token")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.id(), "native-fixture-id");
    assert_eq!(record.active_team_id(), Some("fixture-team"));
    let output = record.raw_snapshot().values();
    assert!(output.get("ipAddress").is_none());
    assert_eq!(output["userAgent"], Value::Null);
    assert_eq!(output["activeOrganizationId"], Value::Null);
    assert_eq!(output["custom"], json!({"from": "native-envelope"}));
    assert_eq!(
        store
            .get_session_user("native-fixture-token")
            .await
            .unwrap()
            .unwrap()
            .id,
        user.id
    );
    assert!(
        inner
            .get_session("native-fixture-token")
            .await
            .unwrap()
            .is_none()
    );

    cache
        .set(
            &format!("revoked-sessions-before-{}", user.id),
            "1767323045679",
            Duration::hours(1),
        )
        .await
        .unwrap();
    assert!(
        store
            .get_session("native-fixture-token")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get_sessions_by_tokens(&["native-fixture-token".into()])
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn stateless_secondary_scope_updates_replace_null_and_stale_markers() {
    let cache = Arc::new(MemoryCacheAdapter::new());
    let config = config(cache.clone());
    let inner = Arc::new(StatelessStore::default());
    let store = decorated::<StatelessSchema>(inner, config);
    let user = store
        .create_user(CreateUser::new().with_email("scope-markers@fixture.test"))
        .await
        .unwrap();
    let session = store
        .create_session(creation(&user.id, "native-scope-markers"))
        .await
        .unwrap();
    for name in ["impersonatedBy", "activeOrganizationId", "activeTeamId"] {
        for value in [
            JsValue::Null,
            JsValue::String("replacement-scope".into()),
            JsValue::Null,
        ] {
            let expected = value.to_json_value().unwrap();
            let mut fields = FieldValues::new();
            fields.insert(name.into(), value);
            let updated = store
                .update_session_fields_record(&session.token, fields)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(updated.raw_snapshot().values()[name], expected);
            let physical = envelope(&cache, &session.token).await;
            assert_eq!(physical["session"][name], expected);
            let cached = store
                .get_session_record(&session.token)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(cached.raw_snapshot().values()[name], expected);
        }
    }
}

#[tokio::test]
async fn cached_session_unknown_objects_survive_and_only_declared_hidden_fields_are_removed() {
    let cache = Arc::new(MemoryCacheAdapter::new());
    let mut config = (*config(cache.clone())).clone();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = calls.clone();
    config.session.additional_fields.insert(
        "custom".into(),
        FieldConfig::new(json!({"type": "json"})).transform_output(move |_| {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async { Ok(Some(JsValue::String("should-not-rerun".into()))) }
        }),
    );
    config.session.additional_fields.insert(
        "privateCacheState".into(),
        FieldConfig::new(json!({"type": "json"})).hidden(),
    );
    let config = Arc::new(config);
    let inner = Arc::new(StatelessStore::default());
    let user = inner
        .create_user(CreateUser::new().with_email("unknown-session@fixture.test"))
        .await
        .unwrap();
    let unknown = json!({"nested": [{"enabled": true}, null, [1, 2]]});
    let snapshot = json!({
        "session": {
            "id": "unknown-cache-session", "token": "unknown-cache-token", "userId": user.id,
            "expiresAt": crate::utils::datetime::json_date_millis((Utc::now() + Duration::hours(1)).timestamp_millis()),
            "createdAt": "2026-01-02T03:04:05.678Z", "updatedAt": "2026-01-02T03:04:05.678Z",
            "unknownTrustedObject": unknown,
            "custom": {"already": "transformed"},
            "privateCacheState": {"secret": [true, null]}
        },
        "user": user.secondary_snapshot().unwrap()
    });
    cache
        .set(
            "unknown-cache-token",
            &snapshot.to_string(),
            Duration::hours(1),
        )
        .await
        .unwrap();
    let store = decorated::<StatelessSchema>(inner, config);
    let cached = store
        .get_session("unknown-cache-token")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cached.secondary_snapshot().unwrap(), snapshot["session"]);
    let trusted =
        serde_json::to_value(store.projection_context.trusted_session_view(&cached)).unwrap();
    assert_eq!(trusted["unknownTrustedObject"], unknown);
    assert_eq!(
        trusted["privateCacheState"],
        snapshot["session"]["privateCacheState"]
    );
    let public = serde_json::to_value(store.projection_context.session_view(&cached)).unwrap();
    assert_eq!(public["unknownTrustedObject"], unknown);
    assert_eq!(public["custom"], json!({"already": "transformed"}));
    assert!(public.get("privateCacheState").is_none());
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cached_session_record_must_not_rerun_adapter_output_transforms() {
    let cache = Arc::new(MemoryCacheAdapter::new());
    let mut config = (*config(cache.clone())).clone();
    config.session.additional_fields.insert(
        "custom".into(),
        FieldConfig::new(json!({"type": "json"})).transform_output(|_| async {
            panic!("cached session record reran adapter output transform")
        }),
    );
    let config = Arc::new(config);
    let inner = Arc::new(StatelessStore::default());
    let user = inner
        .create_user(CreateUser::new().with_email("record-transform@fixture.test"))
        .await
        .unwrap();
    let snapshot = json!({
        "session": {
            "id": "record-cache-session", "token": "record-cache-token", "userId": user.id,
            "expiresAt": crate::utils::datetime::json_date_millis((Utc::now() + Duration::hours(1)).timestamp_millis()),
            "createdAt": "2026-01-02T03:04:05.678Z", "updatedAt": "2026-01-02T03:04:05.678Z",
            "custom": {"already": "transformed"},
            "unknownTrustedObject": {"nested": [true, null]}
        },
        "user": user.secondary_snapshot().unwrap()
    });
    cache
        .set(
            "record-cache-token",
            &snapshot.to_string(),
            Duration::hours(1),
        )
        .await
        .unwrap();
    let store = decorated::<StatelessSchema>(inner, config);
    let cached = store
        .get_session_record("record-cache-token")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        cached.raw_snapshot().values()["custom"],
        json!({"already": "transformed"})
    );
    assert_eq!(
        cached.raw_snapshot().values()["unknownTrustedObject"],
        json!({"nested": [true, null]})
    );
}
