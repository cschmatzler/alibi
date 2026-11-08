//! Concrete auth types for API responses and framework callbacks.
//!
//! These types decouple JSON response shapes from app-owned `SeaORM` entities.
//! Each view implements its corresponding `Auth*` entity trait, allowing it
//! to be used in trait-generic framework code (hooks, helpers).
mod account;
mod plugins;
mod session;
#[cfg(test)]
mod session_native_tests {
    use crate::{AuthSession, SessionView};
    use chrono::{TimeZone, Utc};
    use serde_json::{Value, json};

    fn snapshot() -> Value {
        json!({
            "id": "session-physical",
            "token": "issued-token",
            "userId": "user-physical",
            "expiresAt": "2030-04-05T06:07:08.901Z",
            "createdAt": "2026-01-02T03:04:05.678Z",
            "updatedAt": "2026-02-03T04:05:06.789Z",
            "ipAddress": null,
            "userAgent": "native-agent",
            "activeOrganizationId": "org-physical",
            "custom": {"nested": [null, false, 42, "value"]},
            "nullable": null
        })
    }

    #[test]
    fn session_secondary_codec_round_trips_physical_camel_case_fields() {
        let physical = snapshot();
        let session = SessionView::from_secondary_snapshot(physical.clone().into()).unwrap();
        assert_eq!(session.id(), "session-physical");
        assert_eq!(session.token(), "issued-token");
        assert_eq!(session.user_id(), "user-physical");
        assert_eq!(session.created_at().timestamp_millis(), 1_767_323_045_678);
        assert_eq!(session.active_organization_id(), Some("org-physical"));
        assert_eq!(session.secondary_snapshot().unwrap(), physical);
        assert_eq!(
            session.additional_js_fields().unwrap()["custom"],
            physical["custom"]
        );
        assert_eq!(SessionView::from(&session), session);
    }

    #[test]
    fn session_secondary_codec_distinguishes_optional_absence_and_null() {
        for name in [
            "ipAddress",
            "userAgent",
            "impersonatedBy",
            "activeOrganizationId",
            "activeTeamId",
            "nullable",
        ] {
            let mut absent = snapshot();
            absent.as_object_mut().unwrap().remove(name);
            let session = SessionView::from_secondary_snapshot(absent.clone().into()).unwrap();
            assert_eq!(
                session.secondary_snapshot().unwrap(),
                absent,
                "{name} absent"
            );
            assert_eq!(
                serde_json::to_value(SessionView::from(&session)).unwrap(),
                absent
            );

            let mut null = absent;
            null[name] = Value::Null;
            let session = SessionView::from_secondary_snapshot(null.clone().into()).unwrap();
            assert_eq!(session.secondary_snapshot().unwrap(), null, "{name} null");
            assert_eq!(
                serde_json::to_value(SessionView::from(&session)).unwrap(),
                null
            );
        }
    }

    #[test]
    fn session_secondary_creation_clock_correction_does_not_mutate_model() {
        let physical = snapshot();
        let session = SessionView::from_secondary_snapshot(physical.clone().into()).unwrap();
        for (clock, literal) in [
            (
                Utc.timestamp_millis_opt(1_767_323_045_999).unwrap(),
                "2026-01-02T03:04:05.999Z",
            ),
            (
                Utc.timestamp_millis_opt(1_767_323_045_000).unwrap(),
                "2026-01-02T03:04:05.000Z",
            ),
            (
                Utc.timestamp_millis_opt(1_767_323_045_000).unwrap()
                    + chrono::Duration::microseconds(987),
                "2026-01-02T03:04:05.000Z",
            ),
        ] {
            let corrected = session.secondary_snapshot_for_creation(clock).unwrap();
            let mut expected = physical.clone();
            expected["createdAt"] = json!(literal);
            assert_eq!(corrected, expected);
            let native = session
                .secondary_snapshot_for_creation_with_native_output(
                    clock,
                    &crate::AdapterOutput::default(),
                )
                .unwrap();
            assert_eq!(native, expected);
            assert_eq!(session.secondary_snapshot().unwrap(), physical);
        }
    }

    #[test]
    fn session_secondary_codec_rejects_unrepresentable_required_values_without_fabrication() {
        for name in ["id", "token", "userId"] {
            for invalid in [None, Some(Value::Null), Some(json!({})), Some(json!(42))] {
                let mut physical = snapshot();
                match invalid {
                    Some(value) => physical[name] = value,
                    None => {
                        physical.as_object_mut().unwrap().remove(name);
                    }
                }
                assert!(
                    SessionView::from_secondary_snapshot(physical.into()).is_err(),
                    "{name}"
                );
            }
        }
        for name in ["expiresAt", "createdAt", "updatedAt"] {
            for invalid in [
                None,
                Some(json!("invalid date")),
                Some(json!({})),
                Some(json!(8_640_000_000_000_000_i64)),
                Some(json!(-8_640_000_000_000_000_i64)),
                Some(json!(1e20)),
            ] {
                let mut physical = snapshot();
                match invalid {
                    Some(value) => physical[name] = value,
                    None => {
                        physical.as_object_mut().unwrap().remove(name);
                    }
                }
                assert!(
                    SessionView::from_secondary_snapshot(physical.into()).is_err(),
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn session_secondary_codec_revives_representable_javascript_dates() {
        for name in ["expiresAt", "createdAt", "updatedAt"] {
            for (input, expected) in [
                (json!(null), "1970-01-01T00:00:00.000Z"),
                (json!(false), "1970-01-01T00:00:00.000Z"),
                (json!(true), "1970-01-01T00:00:00.001Z"),
                (json!(1.9), "1970-01-01T00:00:00.001Z"),
                (json!(-1.9), "1969-12-31T23:59:59.999Z"),
                (json!(-0.5), "1970-01-01T00:00:00.000Z"),
                (json!(1767323045678_i64), "2026-01-02T03:04:05.678Z"),
                (
                    json!(["2026-01-02T03:04:05.678Z"]),
                    "2026-01-02T03:04:05.678Z",
                ),
                (
                    json!("2026-01-02T04:04:05.678+01:00"),
                    "2026-01-02T03:04:05.678Z",
                ),
            ] {
                let mut physical = snapshot();
                physical[name] = input;
                let session =
                    SessionView::from_secondary_snapshot(physical.clone().into()).unwrap();
                physical[name] = json!(expected);
                assert_eq!(session.secondary_snapshot().unwrap(), physical);
            }
        }
    }

    #[test]
    fn session_secondary_codec_retains_configured_scope_extension_values() {
        let mut session = SessionView::from_secondary_snapshot(snapshot().into()).unwrap();
        for name in ["impersonatedBy", "activeOrganizationId", "activeTeamId"] {
            session
                .extension_fields
                .insert(name.into(), json!("configured-scope").into());
        }
        let encoded = session.secondary_snapshot().unwrap();
        for name in ["impersonatedBy", "activeOrganizationId", "activeTeamId"] {
            assert_eq!(encoded[name], "configured-scope");
        }
    }

    #[test]
    fn session_secondary_creation_clock_replaces_raw_shadow_without_mutation() {
        let mut session = SessionView::from_secondary_snapshot(snapshot().into()).unwrap();
        session
            .extension_fields
            .insert("createdAt".into(), json!("1999-01-01T00:00:00.000Z").into());
        let before = session.clone();
        let corrected = session
            .secondary_snapshot_for_creation(Utc.timestamp_millis_opt(1_767_323_045_999).unwrap())
            .unwrap();
        assert_eq!(corrected["createdAt"], "2026-01-02T03:04:05.999Z");
        assert_eq!(session, before);
        assert_eq!(
            session.secondary_snapshot().unwrap()["createdAt"],
            "1999-01-01T00:00:00.000Z"
        );
    }

    #[test]
    fn session_native_output_overlay_keeps_null_undefined_extras_and_original_creation_clock() {
        let session = SessionView::from_secondary_snapshot(snapshot().into()).unwrap();
        let clock = chrono::DateTime::from_timestamp_millis(1_800_000_000_789).unwrap();
        let mut native = crate::AdapterOutput::default();
        native.insert("custom".into(), Some(serde_json::Value::Null.into()));
        native.insert("ipAddress".into(), None);
        native.insert(
            "unknownTrustedObject".into(),
            Some(serde_json::json!({"nested":[true,null]}).into()),
        );
        native.insert(
            "createdAt".into(),
            Some(serde_json::json!("2001-01-01T00:00:00.000Z").into()),
        );
        let projected = session
            .secondary_snapshot_with_native_output(&native)
            .unwrap();
        assert_eq!(projected["custom"], serde_json::Value::Null);
        assert!(projected.get("ipAddress").is_none());
        assert_eq!(
            projected["unknownTrustedObject"],
            serde_json::json!({"nested":[true,null]})
        );
        assert_eq!(projected["createdAt"], "2001-01-01T00:00:00.000Z");
        let creation = session
            .secondary_snapshot_for_creation_with_native_output(clock, &native)
            .unwrap();
        assert_eq!(
            creation["createdAt"],
            crate::utils::datetime::json_date_millis(clock.timestamp_millis())
        );
        native.insert("createdAt".into(), None);
        assert_eq!(
            session
                .secondary_snapshot_for_creation_with_native_output(clock, &native)
                .unwrap()["createdAt"],
            creation["createdAt"]
        );
        assert_ne!(session.created_at(), clock);
        assert_ne!(
            session.secondary_snapshot().unwrap()["custom"],
            serde_json::Value::Null
        );
    }
}

mod user;
mod user_native;
#[cfg(test)]
mod user_native_tests {
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

        // factory.ts projects declared image scalars, not a three-field native allowlist.
        let admitted = store
            .update_user(
                &id,
                UpdateUser {
                    name: Some("Now persists".into()),
                    adapter_native_fields: [("image".into(), json!(42).into())].into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(admitted.name.as_deref(), Some("Now persists"));
        assert_eq!(serde_json::to_value(&admitted).unwrap()["image"], 42);
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
}

mod verification;

pub use account::AccountView;
pub use plugins::{ApiKeyView, InvitationView, OrganizationView, PasskeyView};
pub use session::SessionView;
pub use user::UserView;
pub use verification::VerificationView;

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn user_view_serializes_camel_case() {
        let user = UserView {
            omitted_fields: std::collections::BTreeSet::default(),
            id: "user-1".to_owned(),
            name: Some("Ada".to_owned()),
            email: Some("ada@example.com".to_owned()),
            email_verified: true,
            image: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            username: Some("ada".to_owned()),
            display_username: Some("Ada".to_owned()),
            two_factor_enabled: Some(true),
            role: Some("admin".to_owned()),
            banned: Some(false),
            ban_reason: None,
            ban_expires: None,
            is_anonymous: None,
            phone_number: None,
            phone_number_verified: None,
            last_login_method: None,
            extension_fields: Default::default(),
            metadata: serde_json::json!({}).into(),
        };

        let json = serde_json::to_value(UserView::from(&user)).expect("serialize user view");
        assert_eq!(
            (*(json)
                .get("emailVerified")
                .unwrap_or(&serde_json::Value::Null)),
            true
        );
        assert_eq!(
            (*(json)
                .get("displayUsername")
                .unwrap_or(&serde_json::Value::Null)),
            "Ada"
        );
        assert_eq!(
            (*(json)
                .get("twoFactorEnabled")
                .unwrap_or(&serde_json::Value::Null)),
            true
        );
    }

    #[test]
    fn session_view_serializes_camel_case() {
        let session = SessionView {
            omitted_fields: std::collections::BTreeSet::default(),
            id: "session-1".to_owned(),
            expires_at: Utc::now(),
            token: "token".to_owned(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            ip_address: Some("127.0.0.1".to_owned()),
            user_agent: Some("agent".to_owned()),
            user_id: "user-1".to_owned(),
            impersonated_by: Some("admin-1".to_owned()),
            active_organization_id: Some("org-1".to_owned()),
            active_team_id: None,
            extension_fields: Default::default(),
        };

        let json =
            serde_json::to_value(SessionView::from(&session)).expect("serialize session view");
        assert!((*(json).get("expiresAt").unwrap_or(&serde_json::Value::Null)).is_string());
        assert_eq!(
            (*(json).get("ipAddress").unwrap_or(&serde_json::Value::Null)),
            "127.0.0.1"
        );
        assert_eq!(
            (*(json)
                .get("activeOrganizationId")
                .unwrap_or(&serde_json::Value::Null)),
            "org-1"
        );
    }

    #[test]
    fn account_view_omits_password_on_serialize() {
        let account = AccountView {
            id: "acc-1".to_owned(),
            account_id: "account-id".to_owned().into(),
            provider_id: "credential".to_owned(),
            user_id: "user-1".to_owned(),
            access_token: None,
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
            password: Some("$2a$hash".to_owned()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let json = serde_json::to_value(&account).expect("serialize account view");
        assert!(
            json.get("password").is_none(),
            "password field must not appear in serialized output"
        );
    }
}
// LCOV_EXCL_STOP
