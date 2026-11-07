use crate::store::{UserStore, UserUpdateHook, UserUpdateHookResult, UserUpdatePatch};
use crate::test_store::{BundledSchema, MemoryStore};
use crate::utils::json::{JsObject, JsString, JsValue};
use crate::{
    AuthConfig, AuthContext, AuthInitContext, AuthResult, AuthTransaction, CreateUser, UpdateUser,
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
