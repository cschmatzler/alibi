use alibi_core::store::{
    AdapterAfterHook, AdapterEvent, DatabaseHookContext, DatabaseHooks, HookBackend, HookControl,
    UserUpdateHook, UserUpdateHookResult, UserUpdatePatch,
};
use alibi_core::utils::json::{JsObject, JsValue};
use alibi_core::{
    AuthConfig, AuthContext, AuthError, AuthInitContext, AuthResult, AuthSchema, AuthStore,
    AuthTransaction, AuthUser, CreateUser, UpdateUser,
};
use async_trait::async_trait;
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub(super) struct Effects {
    pub native_before: Mutex<Vec<JsObject>>,
    pub native_after: Mutex<usize>,
    pub after: Mutex<usize>,
    pub inputs: Mutex<Vec<Option<JsValue>>>,
    pub outputs: Mutex<usize>,
    pub order: Mutex<Vec<u8>>,
    pub updates: Mutex<usize>,
    pub cache_operations: Mutex<usize>,
}
struct CacheProbe {
    cache: alibi_core::store::MemoryCacheAdapter,
    effects: Arc<Effects>,
}
#[async_trait]
impl alibi_core::store::CacheAdapter for CacheProbe {
    async fn get(&self, key: &str) -> AuthResult<Option<String>> {
        *self.effects.cache_operations.lock().unwrap() += 1;
        self.cache.get(key).await
    }
    async fn set(&self, key: &str, value: &str, ttl: chrono::Duration) -> AuthResult<()> {
        *self.effects.cache_operations.lock().unwrap() += 1;
        self.cache.set(key, value, ttl).await
    }
    async fn delete(&self, key: &str) -> AuthResult<()> {
        *self.effects.cache_operations.lock().unwrap() += 1;
        self.cache.delete(key).await
    }
    async fn exists(&self, key: &str) -> AuthResult<bool> {
        self.cache.exists(key).await
    }
    async fn expire(&self, key: &str, ttl: chrono::Duration) -> AuthResult<()> {
        self.cache.expire(key, ttl).await
    }
    async fn clear(&self) -> AuthResult<()> {
        self.cache.clear().await
    }
}
pub(super) struct PhysicalHook(pub Arc<Effects>);
#[async_trait]
impl<S: AuthSchema, B: HookBackend> DatabaseHooks<S, B> for PhysicalHook {
    async fn before_update_user(
        &self,
        _: &str,
        data: &mut JsObject,
        _: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        _ = data.insert("nativeAdded".into(), text("from physical hook"));
        self.0.native_before.lock().unwrap().push(data.clone());
        Ok(HookControl::Continue)
    }
    async fn after_update_user(
        &self,
        _: &S::User,
        _: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        *self.0.native_after.lock().unwrap() += 1;
        Ok(())
    }
}
#[async_trait]
impl<S: AuthSchema> AdapterAfterHook<S> for Effects {
    async fn after_write(&self, event: &AdapterEvent<S>, _: &dyn AuthStore<S>) -> AuthResult<()> {
        if matches!(event, AdapterEvent::UserUpdated(_)) {
            *self.after.lock().unwrap() += 1;
        }
        Ok(())
    }
}

fn text(value: &str) -> JsValue {
    JsValue::String(value.into())
}
fn patch(values: &[(&str, JsValue)]) -> UserUpdateHookResult {
    UserUpdateHookResult::Data(UserUpdatePatch(
        values
            .iter()
            .map(|(key, value)| ((*key).into(), value.clone()))
            .collect(),
    ))
}
struct Step(u8, Arc<Effects>);
#[async_trait]
impl<S: AuthSchema> UserUpdateHook<S> for Step {
    async fn before_update(
        &self,
        _: &str,
        original: &JsObject,
        _: &AuthContext<S>,
        transaction: Option<&dyn AuthTransaction<S>>,
    ) -> AuthResult<UserUpdateHookResult> {
        let mode = original.get("mode").and_then(JsValue::as_str).unwrap();
        self.1.order.lock().unwrap().push(self.0);
        if self.0 == 1 {
            return Ok(patch(&[
                ("name", text("B")),
                ("newKey", text("new")),
                ("image", text("must omit")),
            ]));
        }
        assert_eq!(original["name"], text("A"));
        assert!(!original.contains_key("newKey"));
        assert!(!original.contains_key("absent"));
        assert!(original.contains_key("username"));
        assert_eq!(original["username"], JsValue::Undefined);
        assert!(original.contains_key("banReason"));
        assert_eq!(original["banReason"], JsValue::Null);
        if mode == "tx" || mode == "rollback" {
            let tx = transaction.expect("the actual SQLite transaction is supplied");
            assert!(
                tx.get_user_by_email(&"local-sentinel@test".into())
                    .await?
                    .is_some()
            );
        }
        if self.0 == 2 {
            if mode == "cancel" {
                return Ok(UserUpdateHookResult::Cancel);
            }
            if mode == "error" {
                return Err(AuthError::bad_request("hook failed"));
            }
            return Ok(patch(&[
                (
                    "name",
                    text(if mode == "rollback" {
                        "transaction only"
                    } else {
                        "A"
                    }),
                ),
                ("image", JsValue::Undefined),
                ("banReason", text("restored")),
                ("lastLoginMethod", JsValue::Null),
                (
                    "updatedAt",
                    JsValue::Date(
                        chrono::DateTime::from_timestamp_millis(1_700_000_000_123).unwrap(),
                    ),
                ),
            ]));
        }
        Ok(UserUpdateHookResult::Continue)
    }
}

pub(super) fn config(effects: &Arc<Effects>, display_column: &str) -> Arc<AuthConfig> {
    use alibi_core::field_policy::FieldConfig;
    let mut config = AuthConfig::default();
    config.session.secondary_storage = Some(Arc::new(CacheProbe {
        cache: alibi_core::store::MemoryCacheAdapter::new(),
        effects: effects.clone(),
    }));
    for key in ["banned", "banReason", "banExpires", "lastLoginMethod"] {
        _ = config.user.additional_fields.insert(
            key.into(),
            FieldConfig::new(serde_json::json!({"type":"string"})),
        );
    }
    let observed = effects.clone();
    _ = config.user.additional_fields.insert(
        "username".into(),
        FieldConfig::new(serde_json::json!({"type":"string"})).on_update(move || {
            *observed.updates.lock().unwrap() += 1;
            text("on update username")
        }),
    );
    _ = config.user.additional_fields.insert(
        "nativeAdded".into(),
        FieldConfig::new(serde_json::json!({"type":"string"})).field_name("role"),
    );
    let observed = effects.clone();
    _ = config.user.additional_fields.insert(
        "newKey".into(),
        FieldConfig::new(serde_json::json!({"type":"string"}))
            .field_name(display_column)
            .transform_adapter_input(move |value| {
                observed.inputs.lock().unwrap().push(value.clone());
                async move { Ok(value) }
            }),
    );
    let observed = effects.clone();
    _ = config.user.additional_fields.insert(
        "image".into(),
        FieldConfig::new(serde_json::json!({"type":"string"})).transform_output(move |value| {
            *observed.outputs.lock().unwrap() += 1;
            async move { Ok(value) }
        }),
    );
    Arc::new(config)
}
fn input(mode: &str) -> UpdateUser {
    UpdateUser {
        name: Some("A".into()),
        ban_reason: Some("ignored typed reason".into()),
        clear_ban_reason: true,
        additional_fields: [
            ("mode".into(), text(mode)),
            ("username".into(), JsValue::Undefined),
        ]
        .into_iter()
        .collect(),
        ..Default::default()
    }
}
fn counters(effects: &Effects) -> (usize, usize, usize, usize, usize, usize, usize) {
    (
        effects.native_before.lock().unwrap().len(),
        *effects.native_after.lock().unwrap(),
        *effects.after.lock().unwrap(),
        effects.inputs.lock().unwrap().len(),
        *effects.outputs.lock().unwrap(),
        *effects.updates.lock().unwrap(),
        *effects.cache_operations.lock().unwrap(),
    )
}

pub(super) async fn exercise<S: AuthSchema>(
    config: Arc<AuthConfig>,
    physical: Arc<dyn AuthStore<S>>,
    effects: Arc<Effects>,
) {
    let mut create = CreateUser::new()
        .with_name("stored")
        .with_email("original-update@test");
    create.image = Some("stored image".into());
    create.banned = Some(true);
    _ = create
        .adapter_native_fields
        .insert("banReason".into(), text("old"));
    _ = create.adapter_native_fields.insert(
        "banExpires".into(),
        JsValue::Date(chrono::DateTime::from_timestamp_millis(4_102_444_800_123).unwrap()),
    );
    let original = physical.create_user(create).await.unwrap();
    let id = original.id().into_owned();
    let mut init = AuthInitContext::<S>::new(config.clone(), physical.clone());
    for index in 1..=3 {
        init.register_user_update_hook(Arc::new(Step(index, effects.clone())));
    }
    init.register_adapter_after_hook(effects.clone());
    let db = init.database_with_registered_transforms();
    let record = db.update_user_record(&id, input("ordinary")).await.unwrap();
    assert_eq!(record.stored().name(), Some("A"));
    assert_eq!(record.stored().username(), Some("on update username"));
    assert_eq!(*effects.updates.lock().unwrap(), 1);
    assert_eq!(record.stored().image(), Some("stored image"));
    assert_eq!(record.stored().ban_reason(), Some("restored"));
    assert_eq!(record.stored().banned(), true);
    assert_eq!(record.stored().ban_expires(), original.ban_expires());
    assert_eq!(
        record.stored().updated_at().timestamp_millis(),
        1_700_000_000_123
    );
    assert_eq!(record.raw_snapshot().values()["newKey"], text("new"));
    assert_eq!(
        record.raw_snapshot().values()["nativeAdded"],
        text("from physical hook")
    );
    let before = effects.native_before.lock().unwrap();
    assert_eq!(before.len(), 1);
    assert_eq!(before[0]["image"], JsValue::Undefined);
    assert_eq!(before[0]["username"], JsValue::Undefined);
    assert_eq!(before[0]["lastLoginMethod"], JsValue::Null);
    assert!(!before[0].contains_key("clear_ban_reason"));
    drop(before);
    assert_eq!(*effects.inputs.lock().unwrap(), [Some(text("new"))]);
    assert_eq!(*effects.order.lock().unwrap(), [1, 2, 3]);
    assert_eq!(*effects.native_after.lock().unwrap(), 1);
    assert_eq!(*effects.after.lock().unwrap(), 1);
    assert!(*effects.cache_operations.lock().unwrap() > 0);

    for mode in ["cancel", "error"] {
        let before = counters(&effects);
        effects.order.lock().unwrap().clear();
        assert!(db.update_user_record(&id, input(mode)).await.is_err());
        assert_eq!(counters(&effects), before);
        assert_eq!(*effects.order.lock().unwrap(), [1, 2]);
    }
    for mode in ["tx", "rollback", "cancel", "error"] {
        let target_id = id.clone();
        let before = counters(&effects);
        let trace = effects.clone();
        let result = alibi_core::store::transaction(db.as_ref(), move |tx| {
            Box::pin(async move {
                let _sentinel = tx
                    .create_user(CreateUser::new().with_email("local-sentinel@test"))
                    .await?;
                let before_update = counters(&trace);
                let result = tx.update_user_record(&target_id, input(mode)).await;
                if mode == "cancel" || mode == "error" {
                    assert!(result.is_err());
                    assert_eq!(counters(&trace), before_update);
                }
                let record = result?;
                assert_eq!(
                    record.stored().name(),
                    Some(if mode == "rollback" {
                        "transaction only"
                    } else {
                        "A"
                    })
                );
                assert_eq!(*trace.after.lock().unwrap(), before.2);
                assert_eq!(*trace.native_after.lock().unwrap(), before.1);
                if mode == "rollback" {
                    return Err(AuthError::bad_request("forced rollback"));
                }
                Ok(())
            })
        })
        .await;
        if mode == "tx" {
            result.unwrap();
            assert_eq!(*effects.after.lock().unwrap(), before.2 + 1);
            assert_eq!(*effects.native_after.lock().unwrap(), before.1 + 1);
            physical
                .delete_user(
                    &physical
                        .get_user_by_email(&"local-sentinel@test".into())
                        .await
                        .unwrap()
                        .unwrap()
                        .id(),
                )
                .await
                .unwrap();
        } else {
            assert!(result.is_err());
            assert_eq!(*effects.after.lock().unwrap(), before.2);
            assert_eq!(*effects.native_after.lock().unwrap(), before.1);
            assert!(
                physical
                    .get_user_by_email(&"local-sentinel@test".into())
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        if mode == "cancel" || mode == "error" {
            // The earlier sentinel CREATE legitimately ran its own input callback.
            assert_eq!(
                counters(&effects),
                (
                    before.0,
                    before.1,
                    before.2,
                    before.3 + 1,
                    before.4,
                    before.5,
                    before.6
                )
            );
        }
        assert_eq!(
            physical.get_user_by_id(&id).await.unwrap().unwrap().name(),
            Some("A")
        );
    }

    let plain = AuthInitContext::<S>::new(config.clone(), physical.clone())
        .database_with_registered_transforms();
    let before = *effects.updates.lock().unwrap();
    let _updated = plain.update_user(&id, UpdateUser::default()).await.unwrap();
    assert_eq!(*effects.updates.lock().unwrap(), before + 1);
    let cleared = plain
        .update_user(
            &id,
            UpdateUser {
                clear_ban_reason: true,
                ban_reason: Some("must lose to clear".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(cleared.ban_reason().is_none());
    assert!(cleared.banned());
    assert_eq!(cleared.ban_expires(), original.ban_expires());
    let mut omit_config = (*config).clone();
    _ = omit_config.user.additional_fields.insert(
        "updatedAt".into(),
        alibi_core::field_policy::FieldConfig::new(serde_json::json!({"type":"date"}))
            .on_update(|| JsValue::Undefined),
    );
    let omit = AuthInitContext::<S>::new(Arc::new(omit_config), physical.clone())
        .database_with_registered_transforms();
    let omitted = omit.update_user(&id, UpdateUser::default()).await.unwrap();
    assert_eq!(omitted.updated_at(), cleared.updated_at());

    let mut missing_config = (*config).clone();
    _ = missing_config.user.additional_fields.insert(
        "missingBinding".into(),
        alibi_core::field_policy::FieldConfig::new(serde_json::json!({"type":"string"})),
    );
    let missing = AuthInitContext::<S>::new(Arc::new(missing_config), physical.clone())
        .database_with_registered_transforms();
    let mut missing_input = UpdateUser::default();
    _ = missing_input
        .additional_fields
        .insert("missingBinding".into(), text("must not silently drop"));
    let error = missing.update_user(&id, missing_input).await.unwrap_err();
    assert!(error.to_string().contains("no model column"), "{error}");

    // The post-hook boundary also admits core scalar and primary-key assignments.
    let mut update = alibi_core::store::PreparedUserUpdate::default();
    update.data = [
        ("id".into(), text("renamed-user")),
        ("name".into(), JsValue::Number(42.0)),
        ("email".into(), text("CASE@TEST")),
        ("createdAt".into(), JsValue::Number(0.0)),
        ("image".into(), JsValue::Null),
    ]
    .into();
    let renamed = db.update_user_prepared(&id, update).await.unwrap();
    assert_eq!(renamed.id(), "renamed-user");
    assert_eq!(renamed.name(), Some("42"));
    assert_eq!(renamed.email(), Some("CASE@TEST"));
    assert_eq!(renamed.created_at().timestamp_millis(), 0);
    assert_eq!(
        physical.native_user_output_for(&renamed).await.unwrap()["createdAt"],
        JsValue::Number(0.0)
    );
    assert!(renamed.image().is_none());
    assert!(physical.get_user_by_id(&id).await.unwrap().is_none());
    let mut invalid = alibi_core::store::PreparedUserUpdate::default();
    invalid.data = [("name".into(), JsValue::Null)].into();
    assert!(
        db.update_user_prepared("renamed-user", invalid)
            .await
            .is_err()
    );
    assert_eq!(
        physical
            .get_user_by_id("renamed-user")
            .await
            .unwrap()
            .unwrap()
            .name(),
        Some("42")
    );
    let surrogate = JsValue::String(alibi_core::utils::json::JsString::from_code_units(vec![
        0xd800,
    ]));
    let mut utf16 = alibi_core::store::PreparedUserUpdate::default();
    utf16.data = [("image".into(), surrogate.clone())].into();
    let bound = db
        .update_user_prepared("renamed-user", utf16)
        .await
        .unwrap();
    assert_eq!(
        effects.native_before.lock().unwrap().last().unwrap()["image"],
        surrogate
    );
    assert_eq!(bound.image(), Some("\u{fffd}"));

    let mut zero = alibi_core::store::PreparedUserUpdate::default();
    zero.data = [("id".into(), JsValue::Number(0.0))].into();
    let zero = db.update_user_prepared("renamed-user", zero).await.unwrap();
    assert_eq!(zero.id(), "0");
    assert!(
        physical
            .get_user_by_id("renamed-user")
            .await
            .unwrap()
            .is_none()
    );
    let mut collision = CreateUser::new().with_email("collision@test");
    collision.id = Some("collision".into());
    let _collision = physical.create_user(collision).await.unwrap();
    let mut duplicate = alibi_core::store::PreparedUserUpdate::default();
    duplicate.data = [("id".into(), text("collision"))].into();
    assert!(db.update_user_prepared("0", duplicate).await.is_err());
    assert!(physical.get_user_by_id("0").await.unwrap().is_some());
    let mut nonfinite = alibi_core::store::PreparedUserUpdate::default();
    nonfinite.data = [("name".into(), JsValue::Number(f64::INFINITY))].into();
    let infinity = db.update_user_prepared("0", nonfinite).await.unwrap();
    assert_eq!(
        effects.native_before.lock().unwrap().last().unwrap()["name"],
        JsValue::Number(f64::INFINITY)
    );
    assert_eq!(infinity.name(), Some("Inf"));
}
