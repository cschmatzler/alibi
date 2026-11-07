use crate::AdapterRecord;
#[cfg(test)]
use crate::AuthUser;
use crate::store::{
    AdapterAfterHook, AdapterEvent, SessionCreatedHook, UserCreateStep, UserCreationDefaults,
    UserUpdateStep,
};
use crate::{AuthAccount, AuthSession};
use crate::{AuthError, AuthResult, AuthSchema, AuthStore};
use std::sync::Arc;
mod account;
#[cfg(test)]
mod create_hook_tests {
    use crate::store::{UserCreateHook, UserStore};
    use crate::test_store::{BundledSchema, MemoryStore};
    use crate::user_validation::{
        UserInfoValidator, UserValidationContext, UserValidationData, UserValidationRejection,
        UserValidationSource,
    };
    use crate::{
        AuthConfig, AuthContext, AuthError, AuthInitContext, AuthResult, AuthTransaction,
        CreateUser,
    };
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn raw_username_lookup_keeps_memory_scalar_equality() {
        use crate::utils::json::JsValue;
        let store = crate::store::stateless::StatelessStore::default();
        let mut raw = CreateUser::new().with_email("numeric@fixture.test");
        raw.adapter_native_fields
            .insert("username".into(), serde_json::json!(42).into());
        let numeric = store.create_user(raw).await.unwrap();
        assert!(
            store
                .get_user_by_username_value(&JsValue::String("42".into()))
                .await
                .unwrap()
                .is_none()
        );
        let mut text = CreateUser::new().with_email("text@fixture.test");
        text.username = Some("42".into());
        let string = store.create_user(text).await.unwrap();
        assert_eq!(
            store
                .get_user_by_username_value(&JsValue::Number(42.0))
                .await
                .unwrap()
                .unwrap()
                .id,
            numeric.id
        );
        assert_eq!(
            store
                .get_user_by_username_value(&JsValue::String("42".into()))
                .await
                .unwrap()
                .unwrap()
                .id,
            string.id
        );
    }

    #[tokio::test]
    async fn typed_user_create_transform_invalidates_only_unchanged_raw_shadows() {
        use crate::utils::json::JsValue;
        let config = Arc::new(AuthConfig::default());
        let physical = Arc::new(MemoryStore::new(config.clone()));
        let mut init = AuthInitContext::<BundledSchema>::new(config, physical);
        init.register_user_create_transform(|mut data| {
            data.name = Some("typed replacement".into());
            data.email = Some("typed@fixture.test".into());
            data.username = Some("typed-user".into());
            Ok(data)
        });
        init.register_user_create_transform(|data| {
            assert_eq!(data.provider_name, None);
            assert_eq!(data.provider_email, None);
            assert!(!data.adapter_native_fields.contains_key("username"));
            Ok(data)
        });
        let database = init.database_with_registered_transforms();
        let mut input = CreateUser::new().with_email("original@fixture.test");
        input.provider_name = Some(JsValue::Null);
        input.provider_email = Some(JsValue::String("original@fixture.test".into()));
        input
            .adapter_native_fields
            .insert("username".into(), serde_json::json!(42).into());
        let user = database.create_user(input).await.unwrap();
        assert_eq!(user.name.as_deref(), Some("typed replacement"));
        assert_eq!(user.email.as_deref(), Some("typed@fixture.test"));
        assert_eq!(user.username.as_deref(), Some("typed-user"));
    }

    #[test]
    fn raw_user_shadows_keep_explicit_edits_and_preserve_undefined_and_removal() {
        use crate::utils::json::{JsString, JsValue};
        let mut before = CreateUser::new().with_name("original");
        before.provider_name = Some(JsValue::String(JsString::from_code_units(vec![0xd800])));
        before.provider_email = Some(JsValue::Undefined);
        before.provider_image = Some(JsValue::Null);
        before
            .adapter_native_fields
            .insert("username".into(), serde_json::json!(42).into());

        before.id = Some("original-id".into());
        before
            .adapter_native_fields
            .insert("id".into(), serde_json::json!(42).into());
        let mut changed_id = before.clone();
        changed_id.id = Some("typed-id".into());
        changed_id.reconcile_native_shadows(&before);
        assert!(!changed_id.adapter_native_fields.contains_key("id"));
        let mut explicit_id = before.clone();
        explicit_id.id = Some("typed-id".into());
        explicit_id
            .adapter_native_fields
            .insert("id".into(), serde_json::Value::Null.into());
        explicit_id.reconcile_native_shadows(&before);
        assert_eq!(
            explicit_id.adapter_native_fields["id"],
            serde_json::Value::Null
        );

        let mut unchanged = before.clone();
        unchanged.reconcile_native_shadows(&before);
        assert_eq!(unchanged.provider_name, before.provider_name);
        assert_eq!(unchanged.provider_email, Some(JsValue::Undefined));
        assert_eq!(unchanged.provider_image, Some(JsValue::Null));

        for explicit in [Some(JsValue::Null), Some(JsValue::Undefined), None] {
            let mut edited = before.clone();
            edited.name = Some("typed replacement".into());
            edited.provider_name = explicit.clone();
            edited.username = Some("typed-user".into());
            edited
                .adapter_native_fields
                .insert("username".into(), serde_json::json!("explicit-raw").into());
            edited.reconcile_native_shadows(&before);
            assert_eq!(edited.provider_name, explicit);
            assert_eq!(
                edited.adapter_native_fields["username"],
                serde_json::json!("explicit-raw")
            );
        }
        let mut removed = before.clone();
        removed.provider_name = None;
        removed.adapter_native_fields.remove("username");
        removed.reconcile_native_shadows(&before);
        assert_eq!(removed.provider_name, None);
        assert_eq!(removed.name.as_deref(), Some("original"));
        assert!(!removed.adapter_native_fields.contains_key("username"));
    }

    #[test]
    fn update_raw_shadow_reconciliation_uses_the_same_explicit_edit_precedence() {
        use crate::utils::json::JsValue;
        let mut before = crate::UpdateUser::default();
        before.provider_name = Some(JsValue::Undefined);
        before.provider_image = Some(JsValue::Null);
        before
            .adapter_native_fields
            .insert("username".into(), serde_json::json!(42).into());

        let mut typed = before.clone();
        typed.name = Some("typed".into());
        typed.username = Some("typed-user".into());
        typed.reconcile_native_shadows(&before);
        assert_eq!(typed.provider_name, None);
        assert_eq!(typed.provider_image, Some(JsValue::Null));
        assert!(!typed.adapter_native_fields.contains_key("username"));

        for explicit in [Some(JsValue::Null), Some(JsValue::Undefined), None] {
            let mut edited = before.clone();
            edited.image = Some("typed-image".into());
            edited.provider_image = explicit.clone();
            edited.reconcile_native_shadows(&before);
            if explicit == before.provider_image {
                assert_eq!(edited.provider_image, None);
            } else {
                assert_eq!(edited.provider_image, explicit);
            }
            assert_eq!(edited.image.as_deref(), Some("typed-image"));
        }
    }

    type Events = Arc<Mutex<Vec<&'static str>>>;

    struct Identity(Events);

    #[async_trait]
    impl UserInfoValidator for Identity {
        async fn validate(
            &self,
            data: &mut UserValidationData,
            _: &UserValidationContext,
        ) -> AuthResult<Option<UserValidationRejection>> {
            self.0.lock().unwrap().push("identity");
            Ok(
                (data.user.email.as_deref() == Some("identity-denied@fixture.test")).then(|| {
                    UserValidationRejection {
                        error: "denied".into(),
                        error_description: None,
                    }
                }),
            )
        }
    }

    struct Hook(Events);

    #[async_trait]
    impl UserCreateHook<BundledSchema> for Hook {
        async fn before_create(
            &self,
            mut data: CreateUser,
            _: &AuthContext<BundledSchema>,
            transaction: Option<&dyn AuthTransaction<BundledSchema>>,
        ) -> AuthResult<CreateUser> {
            assert!(transaction.is_none());
            tokio::task::yield_now().await;
            self.0.lock().unwrap().push("async");
            assert_eq!(data.username.as_deref(), Some("before"));
            if data.email.as_deref() == Some("hook-denied@fixture.test") {
                return Err(AuthError::bad_request("hook denied"));
            }
            data.username = Some("hook".into());
            Ok(data)
        }
    }

    #[tokio::test]
    async fn ordered_user_create_hooks_follow_identity_admission_and_short_circuit() {
        let request = crate::AuthRequest::new(crate::HttpMethod::Post, "/admin/create-user");
        crate::hooks::with_request_hook_context(&request, ordered_user_create_hooks()).await;
    }

    async fn ordered_user_create_hooks() {
        let events: Events = Arc::default();
        let mut config = AuthConfig::default();
        config.user_validation = Some(Arc::new(Identity(events.clone())));
        let config = Arc::new(config);
        let physical = Arc::new(MemoryStore::new(config.clone()));
        let mut init = AuthInitContext::<BundledSchema>::new(config, physical.clone());
        let log = events.clone();
        init.register_user_create_transform(move |mut data| {
            log.lock().unwrap().push("before");
            data.username = Some("before".into());
            Ok(data)
        });
        init.register_user_create_hook(Arc::new(Hook(events.clone())));
        let log = events.clone();
        init.register_user_create_transform(move |data| {
            log.lock().unwrap().push("after");
            assert_eq!(data.username.as_deref(), Some("hook"));
            Ok(data)
        });
        let database = init.database_with_registered_transforms();
        let user = database
            .create_user_with_source(
                CreateUser::new().with_email("created@fixture.test"),
                UserValidationSource::creation("admin"),
            )
            .await
            .unwrap();
        assert_eq!(
            events.lock().unwrap().as_slice(),
            ["identity", "before", "async", "after"]
        );
        assert_eq!(
            physical
                .get_user_by_id(&user.id)
                .await
                .unwrap()
                .unwrap()
                .username
                .as_deref(),
            Some("hook")
        );
        for (email, expected) in [
            ("identity-denied@fixture.test", vec!["identity"]),
            (
                "hook-denied@fixture.test",
                vec!["identity", "before", "async"],
            ),
        ] {
            events.lock().unwrap().clear();
            assert!(
                database
                    .create_user_with_source(
                        CreateUser::new().with_email(email),
                        UserValidationSource::creation("admin"),
                    )
                    .await
                    .is_err()
            );
            assert_eq!(*events.lock().unwrap(), expected);
            assert!(
                physical
                    .get_user_by_email(&email.into())
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        events.lock().unwrap().clear();
        assert!(
            database
                .create_user(CreateUser::new().with_email("no-source@fixture.test"))
                .await
                .is_err()
        );
        assert!(events.lock().unwrap().is_empty());
    }
}

mod extensions;
mod session;
#[cfg(test)]
mod session_native_tests {
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
    async fn session_creation_distinguishes_explicit_null_from_omitted_fields() {
        let cache = Arc::new(MemoryCacheAdapter::new());
        let config = config(cache.clone());
        let inner = Arc::new(StatelessStore::default());
        let store = decorated::<StatelessSchema>(inner.clone(), config.clone());
        let user = store
            .create_user(CreateUser::new().with_email("session-null@fixture.test"))
            .await
            .unwrap();
        for explicit_null in [false, true] {
            let token = if explicit_null {
                "explicit-null"
            } else {
                "omitted"
            };
            let mut input = creation(&user.id, token);
            if explicit_null {
                input
                    .additional_fields
                    .insert("optional".into(), JsValue::Null);
                input
                    .additional_fields
                    .insert("activeTeamId".into(), JsValue::Null);
            }
            store.create_session(input).await.unwrap();
            let reader = decorated::<StatelessSchema>(inner.clone(), config.clone());
            let record = reader.get_session_record(token).await.unwrap().unwrap();
            let raw = envelope(&cache, token).await;
            for name in ["optional", "activeTeamId"] {
                if explicit_null {
                    assert_eq!(record.raw_snapshot().values()[name], Value::Null);
                    assert!(!record.raw_snapshot().field_is_undefined(name));
                    assert!(
                        !raw["absent_fields"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|field| field == name)
                    );
                } else {
                    assert!(record.raw_snapshot().field_is_undefined(name));
                }
            }
        }
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
        let trusted = serde_json::to_value(
            store
                .projection_context
                .trusted_session_view(&cached)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(trusted["unknownTrustedObject"], unknown);
        assert_eq!(
            trusted["privateCacheState"],
            snapshot["session"]["privateCacheState"]
        );
        let public =
            serde_json::to_value(store.projection_context.session_view(&cached).unwrap()).unwrap();
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

    async fn collection_fixture() -> (PluginStore<StatelessSchema>, Arc<MemoryCacheAdapter>) {
        let cache = Arc::new(MemoryCacheAdapter::new());
        let mut config = (*config(cache.clone())).clone();
        config.session.additional_fields.insert(
            "custom".into(),
            FieldConfig::new(json!({"type": "json"})).transform_output(|_| async {
                panic!("cached collection reran adapter output transform")
            }),
        );
        config.session.additional_fields.insert(
            "hidden".into(),
            FieldConfig::new(json!({"type": "string"})).hidden(),
        );
        let store =
            decorated::<StatelessSchema>(Arc::new(StatelessStore::default()), Arc::new(config));
        for (key, user) in [
            ("first", json!({"notAnOwnerModel": true})),
            ("second", Value::Null),
        ] {
            cache.set(key, &json!({
            "session": {
                "id": key, "token": "different-embedded-token", "userId": "different-owner",
                "expiresAt": crate::utils::datetime::json_date_millis((Utc::now() - Duration::hours(1)).timestamp_millis()),
                "createdAt": "2026-01-02T03:04:05.678Z", "updatedAt": "2026-01-02T03:04:05.678Z",
                "custom": {"already": "transformed"}, "hidden": "keep-for-find"
            }, "user": user
        }).to_string(), Duration::hours(1)).await.unwrap();
        }
        cache.set("active-sessions-index-owner", &json!([
        {"token": "second", "expiresAt": (Utc::now() + Duration::hours(1)).timestamp_millis()},
        {"token": "first", "expiresAt": (Utc::now() + Duration::hours(1)).timestamp_millis()},
        {"token": "second", "expiresAt": (Utc::now() + Duration::hours(1)).timestamp_millis()}
    ]).to_string(), Duration::hours(1)).await.unwrap();
        (store, cache)
    }

    #[tokio::test]
    async fn cached_session_collections_list_ignores_owner_and_only_filters_index_expiry() {
        let (store, _) = collection_fixture().await;
        let records = store.get_user_sessions_record("index-owner").await.unwrap();
        assert_eq!(
            records.iter().map(|row| row.id()).collect::<Vec<_>>(),
            ["second", "first"]
        );
        for record in &records {
            assert_eq!(
                record.raw_snapshot().values()["custom"],
                json!({"already": "transformed"})
            );
            assert!(record.raw_snapshot().values().get("hidden").is_none());
        }
        assert_eq!(
            store
                .get_active_user_sessions_record("index-owner")
                .await
                .unwrap()
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn cached_session_collections_find_preserves_hidden_fields_lookup_order_and_null_owner_distinction()
     {
        let (store, _) = collection_fixture().await;
        let records = store
            .get_sessions_by_tokens_record(&["second".into(), "first".into(), "first".into()])
            .await
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id(), "first");
        assert_eq!(
            records[0].raw_snapshot().values()["hidden"],
            "keep-for-find"
        );
        assert_eq!(
            records[0].raw_snapshot().values()["custom"],
            json!({"already": "transformed"})
        );
    }

    #[tokio::test]
    async fn secondary_only_session_writes_do_not_execute_database_adapter_transforms() {
        let cache = Arc::new(MemoryCacheAdapter::new());
        let mut config = (*config(cache.clone())).clone();
        for name in ["custom", "activeOrganizationId", "activeTeamId"] {
            config.session.additional_fields.insert(
                name.into(),
                FieldConfig::new(json!({"type":"json"}))
                    .transform_adapter_input(|_| async { panic!("cache write ran adapter input") })
                    .transform_output(|_| async { panic!("cache write ran adapter output") }),
            );
        }
        let store =
            decorated::<StatelessSchema>(Arc::new(StatelessStore::default()), Arc::new(config));
        let user = store
            .create_user(CreateUser::new().with_email("cache-writes@fixture.test"))
            .await
            .unwrap();
        let created = store
            .create_session_record(creation(&user.id, "cache-writes"))
            .await
            .unwrap();
        assert_eq!(
            created.raw_snapshot().values()["custom"],
            json!({"nested": [false, null, 42]})
        );
        let mut fields = FieldValues::new();
        fields.insert("custom".into(), JsValue::from(json!({"new": true})));
        let updated = store
            .update_session_fields_record("cache-writes", fields)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            updated.raw_snapshot().values()["custom"],
            json!({"new": true})
        );
        let refreshed = store
            .refresh_session_record("cache-writes", Utc::now() + Duration::hours(2))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            refreshed.raw_snapshot().values()["custom"],
            json!({"new": true})
        );
        for record in [
            store
                .update_session_active_organization_record("cache-writes", Some("org"))
                .await
                .unwrap(),
            store
                .update_session_active_team_record("cache-writes", Some("team"))
                .await
                .unwrap(),
        ] {
            assert_eq!(
                record.raw_snapshot().values()["custom"],
                json!({"new": true})
            );
        }
        assert_eq!(
            envelope(&cache, "cache-writes").await["session"]["custom"],
            json!({"new": true})
        );
    }

    #[tokio::test]
    async fn cached_session_updates_preserve_unread_owner_and_lookup_key() {
        let (store, cache) = collection_fixture().await;
        for key in ["first", "second"] {
            let original_owner = envelope(&cache, key).await["user"].clone();
            let record = store
                .refresh_session_record(key, Utc::now() + Duration::hours(2))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(record.token(), "different-embedded-token");
            assert_eq!(
                record.raw_snapshot().values()["custom"],
                json!({"already":"transformed"})
            );
            let cached = envelope(&cache, key).await;
            assert_eq!(cached["user"], original_owner);
            assert!(cached["session"].get("hidden").is_none());
            assert!(
                cache
                    .get("different-embedded-token")
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }
}

mod transaction;
#[cfg(test)]
mod update_hook_tests {
    use crate::store::{UserStore, UserUpdateHook, UserUpdateHookResult, UserUpdatePatch};
    use crate::test_store::{BundledSchema, MemoryStore};
    use crate::utils::json::{JsObject, JsString, JsValue};
    use crate::{
        AuthConfig, AuthContext, AuthInitContext, AuthResult, AuthTransaction, CreateUser,
        UpdateUser,
    };
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    struct Patch {
        event: &'static str,
        log: Arc<Mutex<Vec<&'static str>>>,
        patch: JsObject,
        cancel: bool,
    }
    #[async_trait]
    impl UserUpdateHook<BundledSchema> for Patch {
        async fn before_update(
            &self,
            _: &str,
            original: &JsObject,
            _: &AuthContext<BundledSchema>,
            _: Option<&dyn AuthTransaction<BundledSchema>>,
        ) -> AuthResult<UserUpdateHookResult> {
            self.log.lock().unwrap().push(self.event);
            assert_eq!(original.get("name"), Some(&JsValue::String("A".into())));
            assert!(!original.contains_key("newKey"));
            assert!(!original.contains_key("absent"));
            assert!(original.contains_key("ownUndefined"));
            assert_eq!(original.get("ownUndefined"), Some(&JsValue::Undefined));
            assert!(original.contains_key("ownNull"));
            assert_eq!(original.get("ownNull"), Some(&JsValue::Null));
            Ok(if self.cancel {
                UserUpdateHookResult::Cancel
            } else {
                UserUpdateHookResult::Data(UserUpdatePatch(self.patch.clone()))
            })
        }
    }
    fn object(values: &[(&str, JsValue)]) -> JsObject {
        values
            .iter()
            .map(|(key, value)| ((*key).into(), value.clone()))
            .collect()
    }
    fn input() -> UpdateUser {
        UpdateUser {
            name: Some("A".into()),
            additional_fields: [
                ("ownUndefined".into(), JsValue::Undefined),
                ("ownNull".into(), JsValue::Null),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn initialized_original_input_sparse_restoration_and_sync_spread() {
        let mut config = AuthConfig::default();
        for key in ["newKey", "ownNull", "ownUndefined"] {
            _ = config.user.additional_fields.insert(
                key.into(),
                crate::field_policy::FieldConfig::new(serde_json::json!({"type":"string"})),
            );
        }
        let config = Arc::new(config);
        let inner = Arc::new(MemoryStore::new(config.clone()));
        let user = inner
            .create_user(
                CreateUser::new()
                    .with_name("stored")
                    .with_email("patch@test"),
            )
            .await
            .unwrap();
        let mut init = AuthInitContext::<BundledSchema>::new(config, inner.clone());
        let log = Arc::new(Mutex::new(Vec::new()));
        init.register_user_update_hook(Arc::new(Patch {
            event: "first",
            log: log.clone(),
            cancel: false,
            patch: object(&[
                ("name", JsValue::String("B".into())),
                ("newKey", JsValue::String("survives".into())),
            ]),
        }));
        let seen = log.clone();
        init.register_user_update_transform(move |_, original| {
            seen.lock().unwrap().push("sync");
            assert_eq!(original.name.as_deref(), Some("A"));
            assert!(!original.additional_fields.contains_key("newKey"));
            Ok(original)
        });
        let seen = log.clone();
        init.register_user_update_transform(move |_, original| {
            seen.lock().unwrap().push("empty sync");
            assert_eq!(original.name.as_deref(), Some("A"));
            Ok(UpdateUser::default())
        });
        init.register_user_update_hook(Arc::new(Patch {
            event: "restore",
            log: log.clone(),
            cancel: false,
            patch: object(&[
                ("name", JsValue::String("A".into())),
                ("ownNull", JsValue::Null),
            ]),
        }));
        let db = init.database_with_registered_transforms();
        let updated = db.update_user(&user.id, input()).await.unwrap();
        assert_eq!(
            *log.lock().unwrap(),
            ["first", "sync", "empty sync", "restore"]
        );
        assert_eq!(updated.name.as_deref(), Some("A"));
        assert_eq!(
            updated.extension_fields["newKey"],
            JsValue::String("survives".into())
        );
        assert_eq!(updated.extension_fields["ownNull"], JsValue::Null);
        assert!(!updated.extension_fields.contains_key("ownUndefined"));
    }

    #[tokio::test]
    async fn cancellation_stops_binding_and_later_hooks() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut config = AuthConfig::default();
        let seen = calls.clone();
        _ = config.user.additional_fields.insert(
            "newKey".into(),
            crate::field_policy::FieldConfig::new(serde_json::json!({"type":"string"})).on_update(
                move || {
                    seen.lock().unwrap().push("binding");
                    JsValue::String("bad".into())
                },
            ),
        );
        let config = Arc::new(config);
        let inner = Arc::new(MemoryStore::new(config.clone()));
        let user = inner
            .create_user(
                CreateUser::new()
                    .with_name("stored")
                    .with_email("cancel@test"),
            )
            .await
            .unwrap();
        let mut init = AuthInitContext::<BundledSchema>::new(config, inner.clone());
        for (event, cancel) in [("first", false), ("cancel", true), ("never", false)] {
            init.register_user_update_hook(Arc::new(Patch {
                event,
                log: calls.clone(),
                cancel,
                patch: object(&[("name", JsValue::String("B".into()))]),
            }));
        }
        assert!(
            init.database_with_registered_transforms()
                .update_user(&user.id, input())
                .await
                .is_err()
        );
        assert_eq!(*calls.lock().unwrap(), ["first", "cancel"]);
        assert_eq!(
            inner
                .get_user_by_id(&user.id)
                .await
                .unwrap()
                .unwrap()
                .name
                .as_deref(),
            Some("stored")
        );
    }

    struct NullIdentity(Arc<Mutex<Vec<JsValue>>>);

    #[async_trait]
    impl UserUpdateHook<BundledSchema> for NullIdentity {
        async fn before_update(
            &self,
            _: &str,
            original: &JsObject,
            _: &AuthContext<BundledSchema>,
            _: Option<&dyn AuthTransaction<BundledSchema>>,
        ) -> AuthResult<UserUpdateHookResult> {
            self.0
                .lock()
                .unwrap()
                .push(original.get("id").unwrap().clone());
            Ok(UserUpdateHookResult::Continue)
        }
    }

    #[tokio::test]
    async fn falsy_update_ids_remain_original_hook_input_until_binding() {
        let config = Arc::new(AuthConfig::default());
        let inner = Arc::new(MemoryStore::default());
        let user = inner
            .create_user(CreateUser::new().with_email("null-id@test"))
            .await
            .unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut init = AuthInitContext::<BundledSchema>::new(config, inner);
        init.register_user_update_hook(Arc::new(NullIdentity(seen.clone())));
        let updated = init
            .database_with_registered_transforms()
            .update_user(
                &user.id,
                UpdateUser {
                    name: Some("changed".into()),
                    adapter_native_fields: [("id".into(), JsValue::Null)].into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(*seen.lock().unwrap(), [JsValue::Null]);
        assert_eq!(updated.id, user.id);
        assert_eq!(updated.name.as_deref(), Some("changed"));
    }

    struct Empty(bool);
    #[async_trait]
    impl<S: crate::AuthSchema> UserUpdateHook<S> for Empty {
        async fn before_update(
            &self,
            _: &str,
            original: &JsObject,
            _: &AuthContext<S>,
            _: Option<&dyn AuthTransaction<S>>,
        ) -> AuthResult<UserUpdateHookResult> {
            assert!(original.is_empty());
            Ok(if self.0 {
                UserUpdateHookResult::Continue
            } else {
                UserUpdateHookResult::Data(UserUpdatePatch(JsObject::new()))
            })
        }
    }
    #[tokio::test]
    async fn empty_original_empty_patches_and_sync_omission_reach_on_update_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let mut config = AuthConfig::default();
        let count = calls.clone();
        _ = config.user.additional_fields.insert(
            "marker".into(),
            crate::field_policy::FieldConfig::new(serde_json::json!({"type":"string"})).on_update(
                move || {
                    count.fetch_add(1, Ordering::SeqCst);
                    JsValue::String("updated".into())
                },
            ),
        );
        let config = Arc::new(config);
        let inner = Arc::new(MemoryStore::new(config.clone()));
        let user = inner
            .create_user(CreateUser::new().with_email("empty@test"))
            .await
            .unwrap();
        let mut init = AuthInitContext::<BundledSchema>::new(config, inner);
        init.register_user_update_hook(Arc::new(Empty(true)));
        init.register_user_update_transform(|_, original| {
            assert!(original.additional_fields.is_empty());
            Ok(UpdateUser::default())
        });
        init.register_user_update_hook(Arc::new(Empty(false)));
        let changed = init
            .database_with_registered_transforms()
            .update_user(&user.id, UpdateUser::default())
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            changed.extension_fields["marker"],
            JsValue::String("updated".into())
        );
    }

    #[tokio::test]
    async fn initialized_plugin_declarations_project_only_installed_fields() {
        for installed in [false, true] {
            let config = Arc::new(AuthConfig::default());
            let inner = Arc::new(MemoryStore::new(config.clone()));
            let user = inner
                .create_user(CreateUser::new().with_email("projection@test"))
                .await
                .unwrap();
            let mut init = AuthInitContext::<BundledSchema>::new(config, inner);
            init.register_user_update_transform(|_, original| Ok(original));
            if installed {
                init.set_metadata("two_factor.enabled", serde_json::json!(true));
            }
            let updated = init
                .database_with_registered_transforms()
                .update_user(
                    &user.id,
                    UpdateUser {
                        two_factor_enabled: Some(true),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(
                updated.two_factor_enabled,
                if installed { Some(true) } else { None }
            );
        }
    }

    #[test]
    fn explicit_reification_resolves_authority_once_and_keeps_rich_values() {
        let mut input = input();
        input.ban_reason = Some("typed".into());
        input.clear_ban_reason = true;
        input.provider_name = Some(JsValue::Undefined);
        _ = input
            .additional_fields
            .insert("name".into(), JsValue::String("lower".into()));
        let surrogate = JsValue::String(JsString::from_code_units(vec![0xd800]));
        input
            .adapter_native_fields
            .insert("image".into(), surrogate.clone());
        input
            .adapter_native_fields
            .insert("username".into(), JsValue::Number(f64::INFINITY));
        let data = crate::store::PreparedUserUpdate::from_typed(&input).data;
        assert_eq!(data["name"], JsValue::Undefined);
        assert_eq!(data["banReason"], JsValue::Null);
        assert_eq!(data["image"], surrogate);
        assert_eq!(data["username"], JsValue::Number(f64::INFINITY));
        assert!(!data.contains_key("clear_ban_reason"));
        assert!(!data.contains_key("id"));
        assert!(!data.contains_key("updatedAt"));
        let policy = crate::field_policy::SessionFields(
            [(
                "undefinedFromInput".into(),
                crate::field_policy::FieldConfig::new(serde_json::json!({"type":"string"}))
                    .transform(|_| Ok(None)),
            )]
            .into(),
        );
        let parsed = policy
            .parse_update(&indexmap::IndexMap::from([(
                "undefinedFromInput".to_owned(),
                JsValue::Null,
            )]))
            .unwrap();
        assert!(!parsed.contains_key("undefinedFromInput"));
        let reified = crate::store::PreparedUserUpdate::from_typed(&UpdateUser {
            additional_fields: parsed,
            ..Default::default()
        })
        .data;
        assert!(reified.contains_key("undefinedFromInput"));
        assert_eq!(reified["undefinedFromInput"], JsValue::Undefined);
    }
}

mod user;
#[cfg(test)]
mod user_native_tests {
    use super::*;
    use crate::field_policy::FieldConfig;
    use crate::store::UserStore;
    use crate::test_store::{BundledSchema, MemoryStore};
    use crate::{AdapterOutput, AuthContext, CreateUser, UserView};

    #[tokio::test]
    async fn memory_json_output_keeps_native_input_and_does_not_parse_callback_strings() {
        use crate::utils::json::{self, JsValue};
        let mut value = json::parse_value(
            r#"{"\ud800":"\udfff","nested":{"iso":"2020-01-01T00:00:00.123456Z"}}"#,
        )
        .unwrap();
        _ = value
            .as_object_mut()
            .unwrap()
            .insert("undefined".into(), JsValue::Undefined);
        _ = value.as_object_mut().unwrap().insert(
            "date".into(),
            JsValue::Date(chrono::DateTime::from_timestamp(1_700_000_000, 123_456_789).unwrap()),
        );
        let observed_input = value.clone();
        let observed_output = value.clone();
        let result = JsValue::String(json::to_string(&value).unwrap().into());
        let returned = result.clone();
        let mut config = crate::AuthConfig::default();
        _ = config.user.additional_fields.insert(
            "metadata".into(),
            FieldConfig::new(serde_json::json!({"type":"json"}))
                .transform_adapter_input(move |value| {
                    assert_eq!(value.as_ref(), Some(&observed_input));
                    async move { Ok(value) }
                })
                .transform_output(move |value| {
                    assert_eq!(value.as_ref(), Some(&observed_output));
                    let returned = returned.clone();
                    async move { Ok(Some(returned)) }
                }),
        );
        let config = Arc::new(config);
        let inner = Arc::new(MemoryStore::new(config.clone()));
        let store = crate::plugin::AuthInitContext::<BundledSchema>::new(config, inner.clone())
            .database_with_registered_transforms();
        let mut input = CreateUser::new().with_email("native-json-memory@fixture.test");
        _ = input
            .additional_fields
            .insert("metadata".into(), value.clone());
        let record = store.create_user_record(input).await.unwrap();
        assert_eq!(record.raw_snapshot().values()["metadata"], result);
        let stored = inner
            .get_user_by_id(record.id().as_ref())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.extension_fields["metadata"], value);
    }

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
            FieldConfig::new(serde_json::json!({"type": "boolean"})).transform_output(
                move |value| {
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
                },
            ),
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
        native.insert(
            "emailVerified".into(),
            Some(serde_json::json!("false").into()),
        );
        native.insert("createdAt".into(), Some(serde_json::json!(1e20).into()));
        native.insert("updatedAt".into(), Some(serde_json::json!(-0.5).into()));
        native.insert("banExpires".into(), Some(serde_json::json!(0).into()));
        native.insert("isAnonymous".into(), Some(serde_json::Value::Null.into()));
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
        fn metadata(&self) -> crate::utils::json::JsValue {
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
        native.insert("createdAt".into(), Some(serde_json::json!(1e20).into()));
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
            snapshot["fallbackMarker"] = json!({"selected": "fallback"}).into();
            snapshot["registeredMarker"] = json!({"selected": "registered"}).into();
            snapshot["cachedNull"] = json!(null).into();
            snapshot["unconfigured"] = json!({"retained": [null, true]}).into();
            snapshot["hiddenMarker"] = json!({"secret": "retained in cache only"}).into();
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

    async fn physical_identity_projection<S: AuthSchema<User = UserView>>(
        inner: Arc<dyn crate::AuthStore<S>>,
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let count = Arc::new(AtomicUsize::new(0));
        let calls = count.clone();
        let mut config = crate::AuthConfig::default();
        let cache = Arc::new(crate::MemoryCacheAdapter::new());
        config.session.secondary_storage = Some(cache.clone());
        config.user.additional_fields.insert(
            "emailVerified".into(),
            FieldConfig::new(serde_json::json!({"type": "boolean"})).transform_output(
                move |value| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    async move {
                        let Some(crate::utils::json::JsValue::String(value)) = value else {
                            panic!("expected actual raw verification string")
                        };
                        Ok(Some(crate::utils::json::JsValue::String(
                            format!("projected {}", value.require_str()?).into(),
                        )))
                    }
                },
            ),
        );
        let config = Arc::new(config);
        let store = PluginStore::new(
            inner.clone(),
            config.clone(),
            UserTransforms::default(),
            SessionCreatedCallbacks::default(),
            crate::field_policy::SessionFields::default(),
            crate::field_policy::SessionAdapterFields::default(),
            AuthContext::<S>::new(config, inner.clone()),
        );
        for (id, marker, created, image) in [
            (
                serde_json::json!("2"),
                "string",
                serde_json::json!(-0.5),
                serde_json::json!(42),
            ),
            (
                serde_json::json!(2),
                "number",
                serde_json::json!(1e20),
                serde_json::json!({"raw": true}),
            ),
        ] {
            let data = CreateUser {
                name: Some(marker.into()),
                email: Some(format!("{marker}@identity.test")),
                adapter_native_fields: [
                    ("id".into(), id.into()),
                    ("emailVerified".into(), serde_json::json!(marker).into()),
                    ("createdAt".into(), created.clone().into()),
                    ("image".into(), image.clone().into()),
                ]
                .into(),
                ..Default::default()
            };
            let before = count.load(Ordering::SeqCst);
            let created_record = store.create_user_record(data).await.unwrap();
            let wire = serde_json::to_value(UserView::from(&created_record)).unwrap();
            assert_eq!(wire["id"], "2");
            assert_eq!(wire["emailVerified"], format!("projected {marker}"));
            assert_eq!(wire["createdAt"], created);
            assert_eq!(wire["image"], image);
            assert_eq!(count.load(Ordering::SeqCst), before + 1);
            let physical = inner
                .get_user_by_email(&format!("{marker}@identity.test").into())
                .await
                .unwrap()
                .unwrap();
            let native = inner.native_user_record(physical.clone()).await.unwrap();
            assert_eq!(
                native.raw_snapshot().values()["emailVerified"],
                serde_json::json!(marker)
            );
            assert_eq!(native.raw_snapshot().values()["createdAt"], created);
            let before = count.load(Ordering::SeqCst);
            let record = store
                .get_user_by_email_record(&format!("{marker}@identity.test").into())
                .await
                .unwrap()
                .unwrap();
            let wire = serde_json::to_value(UserView::from(&record)).unwrap();
            assert_eq!(wire["emailVerified"], format!("projected {marker}"));
            assert_eq!(wire["createdAt"], created);
            assert_eq!(wire["image"], image);
            assert_eq!(count.load(Ordering::SeqCst), before + 1);
        }
        let before = count.load(Ordering::SeqCst);
        let (records, total) = store
            .list_users_record(crate::ListUsersParams::default())
            .await
            .unwrap();
        assert_eq!(total, 2);
        assert_eq!(count.load(Ordering::SeqCst), before + 2);
        for record in records {
            let wire = serde_json::to_value(UserView::from(&record)).unwrap();
            let marker = wire["name"].as_str().unwrap();
            assert_eq!(wire["emailVerified"], format!("projected {marker}"));
            assert_eq!(
                wire["createdAt"],
                if marker == "number" {
                    serde_json::json!(1e20)
                } else {
                    serde_json::json!(-0.5)
                }
            );
        }
        let row = store.get_user_by_id_record("2").await.unwrap().unwrap();
        assert_eq!(row.name(), Some("string"));

        use crate::store::CacheAdapter;
        let now = chrono::Utc::now();
        let expires = now + chrono::Duration::hours(1);
        let token = "physical-native-owner";
        let owner = inner.get_user_by_id("2").await.unwrap().unwrap();
        cache
            .set(
                token,
                &serde_json::json!({
                    "session": {
                        "id": "physical-session",
                        "token": token,
                        "userId": "2",
                        "expiresAt": expires,
                        "createdAt": now,
                        "updatedAt": now,
                    },
                    "user": owner.secondary_snapshot().unwrap(),
                })
                .to_string(),
                chrono::Duration::hours(1),
            )
            .await
            .unwrap();
        cache
            .set(
                "active-sessions-2",
                &serde_json::json!([{
                    "token": token,
                    "expiresAt": expires.timestamp_millis(),
                }])
                .to_string(),
                chrono::Duration::hours(1),
            )
            .await
            .unwrap();
        let numeric = inner
            .get_user_by_email(&"number@identity.test".into())
            .await
            .unwrap()
            .unwrap();
        let before = count.load(Ordering::SeqCst);
        store.refresh_cached_user(&numeric).await.unwrap();
        assert_eq!(count.load(Ordering::SeqCst), before + 1);
        let cached: serde_json::Value =
            serde_json::from_str(&cache.get(token).await.unwrap().unwrap()).unwrap();
        assert_eq!(cached["user"]["emailVerified"], "projected number");
        assert_eq!(cached["user"]["createdAt"], serde_json::json!(1e20));
        assert_eq!(cached["user"]["image"], serde_json::json!({"raw": true}));
    }

    #[tokio::test]
    async fn memory_native_projection_uses_actual_physical_user_not_public_id() {
        physical_identity_projection::<BundledSchema>(Arc::new(MemoryStore::default())).await;
    }

    #[tokio::test]
    async fn stateless_native_projection_uses_actual_physical_user_not_public_id() {
        physical_identity_projection::<crate::store::stateless::StatelessSchema>(Arc::new(
            crate::store::stateless::StatelessStore::default(),
        ))
        .await;
    }
}

mod verification;

pub(crate) struct UserTransforms<S: AuthSchema> {
    pub(crate) creates: Vec<UserCreateStep<S>>,
    pub(crate) adapter_defaults: UserCreationDefaults,
    pub(crate) updates: Vec<UserUpdateStep<S>>,
}

impl<S: AuthSchema> Default for UserTransforms<S> {
    fn default() -> Self {
        Self {
            creates: Vec::new(),
            adapter_defaults: UserCreationDefaults::default(),
            updates: Vec::new(),
        }
    }
}

impl<S: AuthSchema> Clone for UserTransforms<S> {
    fn clone(&self) -> Self {
        Self {
            creates: self.creates.clone(),
            adapter_defaults: self.adapter_defaults.clone(),
            updates: self.updates.clone(),
        }
    }
}

pub(crate) struct SessionCreatedCallbacks<S: AuthSchema> {
    pub(crate) callbacks: Vec<Arc<dyn SessionCreatedHook<S>>>,
}
impl<S: AuthSchema> Default for SessionCreatedCallbacks<S> {
    fn default() -> Self {
        Self {
            callbacks: Vec::new(),
        }
    }
}
impl<S: AuthSchema> Clone for SessionCreatedCallbacks<S> {
    fn clone(&self) -> Self {
        Self {
            callbacks: self.callbacks.clone(),
        }
    }
}

pub(crate) struct AdapterCallbacks<S: AuthSchema>(pub(crate) Vec<Arc<dyn AdapterAfterHook<S>>>);

impl<S: AuthSchema> Default for AdapterCallbacks<S> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<S: AuthSchema> Clone for AdapterCallbacks<S> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

pub(crate) struct PluginStore<S: AuthSchema> {
    pub(in crate::store) ephemeral_sessions:
        Arc<std::sync::Mutex<indexmap::IndexMap<String, S::Session>>>,
    pub(in crate::store) inner: Arc<dyn AuthStore<S>>,
    pub(in crate::store) config: Arc<crate::AuthConfig>,
    pub(in crate::store) transforms: UserTransforms<S>,
    pub(in crate::store) session_callbacks: SessionCreatedCallbacks<S>,
    pub(in crate::store) session_fields: crate::field_policy::SessionFields,
    pub(in crate::store) adapter_fields: crate::field_policy::SessionAdapterFields,
    pub(in crate::store) projection_context: Arc<crate::AuthContext<S>>,
}

impl<S: AuthSchema> PluginStore<S> {
    #[must_use]
    pub(crate) fn new(
        inner: Arc<dyn AuthStore<S>>,
        config: Arc<crate::AuthConfig>,
        transforms: UserTransforms<S>,
        session_callbacks: SessionCreatedCallbacks<S>,
        session_fields: crate::field_policy::SessionFields,
        adapter_fields: crate::field_policy::SessionAdapterFields,
        projection_context: crate::AuthContext<S>,
    ) -> Self {
        Self {
            ephemeral_sessions: Arc::new(std::sync::Mutex::new(indexmap::IndexMap::new())),
            inner,
            config,
            transforms,
            session_callbacks,
            session_fields,
            adapter_fields,
            projection_context: Arc::new(projection_context),
        }
    }

    pub(in crate::store) fn ephemeral(
        &self,
    ) -> AuthResult<std::sync::MutexGuard<'_, indexmap::IndexMap<String, S::Session>>> {
        self.ephemeral_sessions
            .lock()
            .map_err(|_| AuthError::internal("Ephemeral session state poisoned"))
    }

    pub(in crate::store) fn field_policies(&self) -> crate::field_policy::AdapterFieldPolicies {
        self.projection_context
            .extensions
            .get::<crate::field_policy::AdapterFieldPolicies>()
            .map_or_else(
                || crate::field_policy::AdapterFieldPolicies {
                    user: crate::field_policy::SessionAdapterFields(Arc::new(
                        self.config.user.additional_fields.clone(),
                    )),
                    account: crate::field_policy::SessionAdapterFields(Arc::new(
                        self.config.account.additional_fields.clone(),
                    )),
                },
                |fields| (*fields).clone(),
            )
    }

    pub(in crate::store) async fn user_record(
        &self,
        user: S::User,
    ) -> AuthResult<AdapterRecord<S::User>> {
        let scalars = self.inner.native_user_output_for(&user).await?;
        self.user_record_with_native_output(
            user,
            crate::AdapterOutput::from_js_values(
                scalars
                    .into_iter()
                    .map(|(name, value)| (name.into(), value))
                    .collect(),
            ),
        )
        .await
    }

    /// Project a cache-authoritative user without consulting the database.
    pub(in crate::store) async fn user_record_with_native_output(
        &self,
        user: S::User,
        scalars: crate::AdapterOutput,
    ) -> AuthResult<AdapterRecord<S::User>> {
        let crate::utils::json::JsValue::Object(base) = crate::utils::json::to_js_value(
            &self
                .projection_context
                .trusted_user_view_without_metadata(&user)?,
        )?
        else {
            return Err(AuthError::internal("User output must be an object"));
        };
        let mut source =
            AdapterRecord::with_output(user, crate::AdapterOutput::from_js_values(base));
        source.retain_native_output(scalars.clone());
        let projected = self.projection_context.user_adapter_record(source).await?;
        let mut output = projected.raw_snapshot().clone();
        let fields = self.field_policies();
        for field in [
            "emailVerified",
            "banned",
            "twoFactorEnabled",
            "isAnonymous",
            "phoneNumberVerified",
            "createdAt",
            "updatedAt",
            "banExpires",
        ] {
            if scalars.field_is_undefined(field)
                && !output.contains_field(field)
                && (matches!(field, "emailVerified" | "createdAt" | "updatedAt")
                    || fields.user.0.contains_key(field))
            {
                output.insert(field.into(), None);
            }
        }
        Ok(AdapterRecord::with_output(
            projected.into_stored().into_stored(),
            output,
        ))
    }

    pub(in crate::store) async fn optional_user_record(
        &self,
        user: Option<S::User>,
    ) -> AuthResult<Option<AdapterRecord<S::User>>> {
        match user {
            Some(user) => self.user_record(user).await.map(Some),
            None => Ok(None),
        }
    }

    pub(in crate::store) async fn user_records(
        &self,
        users: Vec<S::User>,
    ) -> AuthResult<Vec<AdapterRecord<S::User>>> {
        let mut records = Vec::with_capacity(users.len());
        for user in users {
            records.push(self.user_record(user).await?);
        }
        Ok(records)
    }

    pub(in crate::store) async fn optional_account_record(
        &self,
        account: Option<S::Account>,
    ) -> AuthResult<Option<AdapterRecord<S::Account>>> {
        match account {
            Some(account) => self.account_record(account).await.map(Some),
            None => Ok(None),
        }
    }

    pub(in crate::store) async fn session_record(
        &self,
        session: S::Session,
    ) -> AuthResult<AdapterRecord<S::Session>> {
        let public = crate::utils::json::to_js_value(&crate::SessionView::from(&session))?;
        let base = crate::SessionView::from(&session);
        let physical =
            crate::utils::json::to_js_value(&self.projection_context.trusted_session_view(&base)?)?;
        let supports_json = self.inner.supports_native_json();
        let additional = if supports_json {
            session.additional_js_fields()?
        } else {
            session.adapter_js_fields(&self.adapter_fields.exact_json_fields())?
        };
        let output = self
            .adapter_fields
            .record_output(public, additional, physical, supports_json)
            .await?;
        Ok(AdapterRecord::with_output(session, output))
    }

    pub(in crate::store) async fn session_records(
        &self,
        models: Vec<S::Session>,
    ) -> AuthResult<Vec<AdapterRecord<S::Session>>> {
        if models.is_empty() {
            return Ok(Vec::new());
        }
        let mut records = vec![None; models.len()];
        let store = self.clone();
        let endpoint = crate::endpoint::current_endpoint_call_context();
        let request = crate::hooks::current_request_hook_context();
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        // Like Promise.all, reject the aggregate immediately but keep every
        // launched row projection alive. Retain its actual request context.
        _ = tokio::spawn(async move {
            let project = async {
                _ = futures_util::future::join_all(models.into_iter().enumerate().map(
                    |(index, model)| {
                        let sender = &sender;
                        let store = &store;
                        async move {
                            let result = store.session_record(model).await;
                            _ = sender.send((index, result));
                        }
                    },
                ))
                .await;
            };
            if let Some(endpoint) = endpoint {
                crate::endpoint::with_endpoint_call_context(
                    endpoint,
                    crate::hooks::with_optional_request_hook_context(request, project),
                )
                .await;
            } else {
                crate::hooks::with_optional_request_hook_context(request, project).await;
            }
        });
        for _ in 0..records.len() {
            let (index, record) = receiver
                .recv()
                .await
                .ok_or_else(|| AuthError::internal("Session collection projection stopped"))?;
            let slot = records
                .get_mut(index)
                .ok_or_else(|| AuthError::internal("Invalid session projection row"))?;
            *slot = Some(record?);
        }
        Ok(records.into_iter().flatten().collect())
    }

    pub(in crate::store) async fn account_record(
        &self,
        account: S::Account,
    ) -> AuthResult<AdapterRecord<S::Account>> {
        let crate::utils::json::JsValue::Object(mut canonical) =
            crate::utils::json::to_js_value(&crate::AccountView::from(&account))?
        else {
            return Err(AuthError::internal("Account output must be an object"));
        };
        _ = canonical.insert(
            "password".into(),
            account
                .password()
                .map_or(crate::utils::json::JsValue::Null, |value| {
                    crate::utils::json::JsValue::String(value.into())
                }),
        );
        let fields = self.field_policies().account.clone();
        let supports_json = self.inner.supports_native_json();
        let additional = if supports_json {
            account.additional_js_fields()?
        } else {
            account.adapter_js_fields(&fields.exact_json_fields())?
        };
        let output = fields
            .record_output(
                crate::utils::json::JsValue::Object(canonical.clone()),
                additional,
                crate::utils::json::JsValue::Object(canonical),
                supports_json,
            )
            .await?;
        Ok(AdapterRecord::with_output(account, output))
    }

    pub(in crate::store) async fn observe(&self, event: AdapterEvent<S>) -> AuthResult<()> {
        if let Some(callbacks) = self
            .projection_context
            .extensions
            .get::<AdapterCallbacks<S>>()
        {
            for callback in &callbacks.0 {
                callback.after_write(&event, self).await?;
            }
        }
        Ok(())
    }
}
