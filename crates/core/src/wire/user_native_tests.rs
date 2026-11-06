use crate::store::{
    UserStore,
    stateless::{StatelessSchema, StatelessStore},
};
use crate::test_store::{BundledSchema, MemoryStore};
use crate::{AuthSchema, AuthUser, CreateUser, UpdateUser, UserView};
use crate::{CacheAdapter, MemoryCacheAdapter};
use serde_json::{Value, json};

async fn native_state_roundtrip<S: AuthSchema<User = UserView>>(store: &impl UserStore<S>) {
    let raw = json!({
        "image": 42, "emailVerified": "false", "banned": true,
        "twoFactorEnabled": 2, "isAnonymous": null, "phoneNumberVerified": "pending",
        "createdAt": 1e20, "updatedAt": -0.5, "banExpires": 0, "banReason": 7,
        "notDeclared": "must not be trusted"
    })
    .as_object()
    .unwrap()
    .clone()
    .into_iter()
    .map(|(key, value)| (key, value.into()))
    .collect();
    let user = store
        .create_user(CreateUser {
            email: Some("native-memory@example.test".into()),
            name: Some("Original".into()),
            adapter_native_fields: raw,
            ..Default::default()
        })
        .await
        .unwrap();
    let id = user.id.clone();
    assert!(user.email_verified);
    assert_eq!(user.two_factor_enabled, Some(true));
    let wire = serde_json::to_value(&user).unwrap();
    for (name, expected) in [
        ("image", json!(42)),
        ("emailVerified", json!("false")),
        ("twoFactorEnabled", json!(2)),
        ("isAnonymous", Value::Null),
        ("phoneNumberVerified", json!("pending")),
        ("createdAt", json!(1e20)),
        ("updatedAt", json!(-0.5)),
        ("banExpires", json!(0)),
        ("banReason", json!(7)),
    ] {
        assert_eq!(wire[name], expected, "{name}");
    }
    assert!(wire.get("notDeclared").is_none());
    assert_eq!(serde_json::to_value(UserView::from(&user)).unwrap(), wire);
    assert_eq!(
        serde_json::to_value(store.get_user_by_id(&id).await.unwrap().unwrap()).unwrap(),
        wire
    );
    assert_eq!(
        serde_json::to_value(UserView::from(
            &store.get_user_by_id_record(&id).await.unwrap().unwrap()
        ))
        .unwrap(),
        wire
    );

    assert!(
        store
            .update_user(
                &id,
                UpdateUser {
                    name: Some("Must not persist".into()),
                    adapter_native_fields: [("image".into(), json!(42).into())].into(),
                    ..Default::default()
                }
            )
            .await
            .is_err()
    );
    assert_eq!(
        store
            .get_user_by_id(&id)
            .await
            .unwrap()
            .unwrap()
            .name
            .as_deref(),
        Some("Original")
    );
    store
        .update_user(
            &id,
            UpdateUser {
                name: Some("Changed".into()),
                additional_fields: [("registeredMarker".into(), json!("kept").into())]
                    .into_iter()
                    .collect(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let changed = store.get_user_by_id(&id).await.unwrap().unwrap();
    let wire = serde_json::to_value(&changed).unwrap();
    assert_eq!(wire["name"], "Changed");
    assert_eq!(wire["createdAt"], json!(1e20));
    assert_eq!(wire["image"], 42);
    assert_eq!(wire["banExpires"], 0);
    assert!(wire["updatedAt"].is_string());
    assert_eq!(wire["registeredMarker"], "kept");
    let patched = store
        .update_user(
            &id,
            UpdateUser {
                image: Some("replacement".into()),
                email_verified: Some(false),
                clear_ban_reason: true,
                banned: Some(false),
                adapter_native_fields: [("banExpires".into(), json!(-0.5).into())].into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let wire = serde_json::to_value(&patched).unwrap();
    assert_eq!(wire["image"], "replacement");
    assert_eq!(wire["emailVerified"], false);
    assert_eq!(wire["banned"], false);
    assert!(wire["banReason"].is_null());
    assert_eq!(wire["banExpires"], json!(-0.5));
    assert_eq!(wire["registeredMarker"], "kept");
    assert_eq!(
        store.native_user_output(&id).await.unwrap()["banExpires"],
        json!(-0.5)
    );
    let record = store.get_user_by_id_record(&id).await.unwrap().unwrap();
    let snapshot = record.secondary_snapshot().unwrap();
    let cache = MemoryCacheAdapter::new();
    cache
        .set(
            "mirrored-user",
            &serde_json::to_string(&snapshot).unwrap(),
            chrono::Duration::minutes(1),
        )
        .await
        .unwrap();
    store.delete_user(&id).await.unwrap();
    assert!(store.get_user_by_id(&id).await.unwrap().is_none());
    let snapshot =
        serde_json::from_str(&cache.get("mirrored-user").await.unwrap().unwrap()).unwrap();
    let restored = UserView::from_secondary_snapshot_record(snapshot).unwrap();
    let wire = serde_json::to_value(UserView::from(&restored)).unwrap();
    assert_eq!(wire["createdAt"], json!(1e20));
    assert_eq!(wire["banExpires"], json!(-0.5));
    assert_eq!(wire["image"], "replacement");
    assert_eq!(wire["twoFactorEnabled"], 2);
    assert_eq!(wire["registeredMarker"], "kept");
    assert_eq!(restored.secondary_snapshot().unwrap(), wire);
}

#[tokio::test]
async fn stateless_native_fields_survive_create_update_record_and_user_cache() {
    native_state_roundtrip::<StatelessSchema>(&StatelessStore::default()).await;
}

#[tokio::test]
async fn memory_native_fields_survive_create_update_record_and_user_cache() {
    native_state_roundtrip::<BundledSchema>(&MemoryStore::default()).await;
}

#[test]
fn user_view_secondary_preserves_known_presence_and_rejects_nonstring_identity() {
    let source = json!({
        "id": "cached-id", "name": 42, "email": null, "image": {"raw": true},
        "emailVerified": null, "createdAt": 1e20, "updatedAt": -0.5,
        "isAnonymous": null, "unknown": "ignored"
    });
    let record = UserView::from_secondary_snapshot_record(source.clone().into()).unwrap();
    let wire = serde_json::to_value(UserView::from(&record)).unwrap();
    assert_eq!(wire["name"], 42);
    assert!(wire["email"].is_null());
    assert_eq!(wire["image"], json!({"raw": true}));
    assert!(wire["emailVerified"].is_null());
    assert_eq!(wire["createdAt"], json!(1e20));
    assert_eq!(wire["updatedAt"], json!(-0.5));
    assert!(record.raw_snapshot().field_is_undefined("username"));
    assert!(wire.get("username").is_none());
    assert_eq!(wire["unknown"], source["unknown"]);
    assert_eq!(record.secondary_snapshot().unwrap(), wire);
    for id in [Value::Null, json!(42), json!({})] {
        let mut source = source.clone();
        source["id"] = id;
        assert!(UserView::from_secondary_snapshot_record(source.into()).is_err());
    }
}

#[test]
fn configured_user_cache_fields_keep_values_and_presence_without_rerunning_policy() {
    use crate::field_policy::{FieldConfig, FieldConfigs};
    let allowed: FieldConfigs = [
        (
            "customNull".into(),
            FieldConfig::new(json!({"type": "string"})),
        ),
        (
            "customMissing".into(),
            FieldConfig::new(json!({"type": "string"})),
        ),
        (
            "customValue".into(),
            FieldConfig::new(json!({"type": "json"})).transform_output(|_| async {
                panic!("cache hydration must not run database output transforms")
            }),
        ),
        ("image".into(), FieldConfig::new(json!({"type": "string"}))),
        ("id".into(), FieldConfig::new(json!({"type": "string"}))),
    ]
    .into();
    let source = json!({
        "id": "real-owner", "name": 42, "emailVerified": "false",
        "createdAt": 1e20, "updatedAt": -0.5,
        "customNull": null, "customValue": {"retained": [1, false]}, "unknown": true,
        "image": {"retained": true}
    });
    let record =
        UserView::from_secondary_snapshot_record_with_fields(source.clone().into(), &allowed)
            .unwrap();
    let wire = serde_json::to_value(UserView::from(&record)).unwrap();
    assert_eq!(wire["id"], "real-owner");
    assert_eq!(wire["name"], 42);
    assert_eq!(wire["image"], source["image"]);
    assert_eq!(wire["emailVerified"], "false");
    assert_eq!(wire["createdAt"], json!(1e20));
    assert!(wire["customNull"].is_null());
    assert_eq!(wire["customValue"], source["customValue"]);
    assert!(record.raw_snapshot().field_is_undefined("customMissing"));
    assert!(wire.get("customMissing").is_none());
    assert_eq!(wire["unknown"], source["unknown"]);
    assert_eq!(record.secondary_snapshot().unwrap(), wire);
    let mut invalid_identity = source;
    invalid_identity["id"] = Value::Null;
    assert!(
        UserView::from_secondary_snapshot_record_with_fields(invalid_identity.into(), &allowed)
            .is_err()
    );
}

async fn memory_username_updates<S: AuthSchema<User = UserView>>(store: &impl UserStore<S>) {
    let created = store
        .create_user(CreateUser::new().with_email("native-username-update@fixture.test"))
        .await
        .unwrap();
    for raw in [
        json!("KeEpCaSe"),
        json!(42),
        json!(false),
        Value::Null,
        json!(""),
    ] {
        let updated = store
            .update_user(
                &created.id,
                UpdateUser {
                    adapter_native_fields: [
                        ("username".into(), raw.clone().into()),
                        ("displayUsername".into(), json!(false).into()),
                    ]
                    .into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let wire = serde_json::to_value(&updated).unwrap();
        assert_eq!(wire["username"], raw);
        assert_eq!(wire["displayUsername"], false);
        let record = store
            .get_user_by_id_record(&created.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::to_value(UserView::from(&record)).unwrap()["username"],
            raw
        );
    }
    let updated = store
        .update_user(
            &created.id,
            UpdateUser {
                username: Some("NotLowered".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.username(), Some("NotLowered"));
    assert_eq!(
        serde_json::to_value(&updated).unwrap()["username"],
        "NotLowered"
    );
}

#[tokio::test]
async fn stateless_native_username_updates_keep_scalars_and_case() {
    memory_username_updates::<StatelessSchema>(&StatelessStore::default()).await;
}

#[tokio::test]
async fn memory_native_username_updates_keep_scalars_and_case() {
    memory_username_updates::<BundledSchema>(&MemoryStore::new(std::sync::Arc::new(
        crate::AuthConfig::default(),
    )))
    .await;
}
