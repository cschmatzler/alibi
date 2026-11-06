use super::SqlxStore;
use super::bundled_schema::BundledSchema;
use alibi_core::store::UserStore;
use alibi_core::{AuthUser, CreateUser};
use serde_json::json;

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
    let record = OptionalNativeUser::from_secondary_snapshot_record(source).unwrap();
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
    assert_eq!(encoded.get("name"), Some(&serde_json::Value::Null));
    assert!(encoded.get("image").is_none());
    assert!(encoded.get("absent_marker").is_none());
    assert_eq!(
        encoded.get("favorite_color"),
        Some(&serde_json::Value::Null)
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
        let record = OptionalNativeUser::from_secondary_snapshot_record(source.clone()).unwrap();
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
    let record = OptionalNativeUser::from_secondary_snapshot_record(source).unwrap();
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
    let store = SqlxStore::<BundledSchema>::new(alibi_core::AuthConfig::default(), pool.clone());
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
    .map(|(name, value)| (name.to_owned(), value))
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
    let store = SqlxStore::<BundledSchema>::new(alibi_core::AuthConfig::default(), pool.clone());
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
                .insert(field.to_owned(), value.clone());
        }
        let created = store.create_user_record(input).await.unwrap();
        let expected = if value.is_boolean() { json!(1) } else { value };
        let response = serde_json::to_value(alibi_core::wire::UserView::from(&created)).unwrap();
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
    let store = SqlxStore::<BundledSchema>::new(alibi_core::AuthConfig::default(), pool.clone());
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
            .insert(field.to_owned(), json!({"unsupported": true}));
        assert!(store.create_user(input).await.is_err());
        assert!(store.get_user_by_email(&email).await.unwrap().is_none());
    }
}

#[tokio::test]
async fn unrelated_user_update_retains_native_sqlite_scalars() {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let store = SqlxStore::<BundledSchema>::new(alibi_core::AuthConfig::default(), pool.clone());
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
    .map(|(key, value)| (key.to_owned(), value))
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
