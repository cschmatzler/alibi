use super::SqlxStore;
use super::bundled_schema::BundledSchema;
use alibi_core::store::UserStore;
use alibi_core::{AuthUser, CreateUser};
use serde_json::json;

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
