use super::*;
use chrono::Datelike;

#[tokio::test]
async fn admin_creation_native_scalar_affinity_and_nulls_are_persisted() {
    let (mut ctx, _, _, _, _) = create_admin_context().await;
    let init = alibi_core::plugin::AuthInitContext::new(
        Arc::clone(&ctx.config),
        Arc::clone(&ctx.database),
    );
    ctx.database = init.database_with_registered_transforms();
    let mut input = types::CreateUserRequest::new("raw-native@fixture.test", "Outer name");
    input.data = Some(
        serde_json::json!({
            "id": {"ignored": true},
            "image": 42, "emailVerified": "not-a-boolean",
            "displayUsername": false, "phoneNumber": 12345,
            "lastLoginMethod": null, "banned": 2,
            "twoFactorEnabled": "false", "isAnonymous": null,
            "phoneNumberVerified": 1, "banReason": 7,
            "banExpires": "2099-01-01", "createdAt": "2020-01-01"
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    let created = handlers::create_user_core(&input, &AdminConfig::default(), &ctx)
        .await
        .unwrap();
    let response = serde_json::to_value(&created).unwrap();
    assert_eq!(response["user"]["twoFactorEnabled"], "false");
    assert_eq!(response["user"]["banned"], false);
    assert_eq!(response["user"]["isAnonymous"], serde_json::Value::Null);
    let stored = ctx
        .database
        .get_user_by_id_record(&created.user.id)
        .await
        .unwrap()
        .unwrap();
    use alibi_core::entity::AuthUser as _;
    assert_eq!(stored.image(), Some("42"));
    assert_eq!(stored.display_username(), Some("0"));
    assert_eq!(stored.phone_number(), Some("12345"));
    assert_eq!(stored.ban_reason(), Some("7"));
    assert!(!stored.banned());
    assert_eq!(stored.created_at().year(), 2020);
    assert_eq!(stored.ban_expires().unwrap().year(), 2099);
    let values = stored.raw_snapshot().values();
    assert_eq!(values["emailVerified"], "not-a-boolean");
    assert_eq!(values["banned"], false);
    assert_eq!(values["twoFactorEnabled"], "false");
    assert_eq!(values["isAnonymous"], serde_json::Value::Null);
    assert_eq!(values["phoneNumberVerified"], true);

    let mut defaults = types::CreateUserRequest::new("raw-defaults@fixture.test", "Defaults");
    defaults.data = Some(
        serde_json::json!({
            "emailVerified": null, "createdAt": null, "updatedAt": null,
            "image": null, "banned": null, "twoFactorEnabled": null
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    let created = handlers::create_user_core(&defaults, &AdminConfig::default(), &ctx)
        .await
        .unwrap();
    let stored = ctx
        .database
        .get_user_by_id_record(&created.user.id)
        .await
        .unwrap()
        .unwrap();
    assert!(!stored.email_verified());
    assert_eq!(stored.image(), None);
    assert_eq!(
        stored.raw_snapshot().values()["banned"],
        serde_json::Value::Null
    );
}

#[tokio::test]
async fn admin_creation_numeric_dates_keep_sqlite_date_affinity_and_raw_wire_values() {
    use alibi_seaorm::sea_orm::{ConnectionTrait, Database, DbBackend, Statement};
    let database = Database::connect("sqlite::memory:").await.unwrap();
    alibi_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap();
    let store = Arc::new(alibi_seaorm::SeaOrmStore::<TestSchema>::new(
        test_helpers::create_test_config(),
        database.clone(),
    ));
    let ctx = AuthContext::new(Arc::new(test_helpers::create_test_config()), store);
    for (index, value) in [
        serde_json::json!(0),
        serde_json::json!(-1),
        serde_json::json!(1.9),
        serde_json::json!(true),
        serde_json::json!(1e20),
    ]
    .into_iter()
    .enumerate()
    {
        let mut input =
            types::CreateUserRequest::new(format!("numeric-date-{index}@fixture.test"), "Date");
        input.data = Some(
            serde_json::json!({
                "createdAt": value, "updatedAt": value, "banExpires": value
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        let created = handlers::create_user_core(&input, &AdminConfig::default(), &ctx)
            .await
            .unwrap();
        let expected = if value.is_boolean() {
            serde_json::json!(1)
        } else {
            value
        };
        let response = serde_json::to_value(&created).unwrap();
        for field in ["createdAt", "updatedAt", "banExpires"] {
            assert_eq!(response["user"][field], expected, "{field}");
        }
        let retained = ctx
            .database
            .get_user_by_id_record(&created.user.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retained.raw_snapshot().values()["createdAt"], expected);
        let row = database.query_one_raw(Statement::from_sql_and_values(DbBackend::Sqlite,
            "SELECT typeof(\"createdAt\") AS storage_type, CAST(\"createdAt\" AS REAL) AS stored FROM user WHERE id = ?",
            [created.user.id.into()]
        )).await.unwrap().unwrap();
        let kind: String = row.try_get("", "storage_type").unwrap();
        assert!(matches!(kind.as_str(), "integer" | "real"), "{kind}");
        let stored: f64 = row.try_get("", "stored").unwrap();
        assert_eq!(stored, expected.as_f64().unwrap());
    }
}

#[tokio::test]
async fn numeric_native_ban_expiry_uses_truthiness_and_date_timeclip() {
    use alibi_core::store::SessionCreatedHook;
    let (ctx, _, _, _, _) = create_admin_context().await;
    for (index, (expiry, expired)) in [
        (serde_json::json!(0), false),
        (serde_json::json!(-1), true),
        (serde_json::json!(1.9), true),
        (serde_json::json!(-0.5), true),
        (serde_json::json!(1e20), false),
        (serde_json::json!(-1e20), false),
    ]
    .into_iter()
    .enumerate()
    {
        let mut input =
            types::CreateUserRequest::new(format!("numeric-ban-{index}@fixture.test"), "Ban");
        input.data = Some(
            serde_json::json!({"banned": true, "banExpires": expiry})
                .as_object()
                .unwrap()
                .clone(),
        );
        let created = handlers::create_user_core(&input, &AdminConfig::default(), &ctx)
            .await
            .unwrap();
        let result = AdminSessionGuard
            .before_create(
                &CreateSession {
                    user_id: created.user.id.clone(),
                    expires_at: Utc::now() + Duration::hours(1),
                    token: None,
                    ip_address: None,
                    user_agent: None,
                    impersonated_by: None,
                    active_organization_id: None,
                    active_team_id: None,
                    additional_fields: Default::default(),
                },
                &ctx,
                None,
            )
            .await;
        assert_eq!(result.is_ok(), expired, "{expiry}: {result:?}");
        let stored = ctx
            .database
            .get_user_by_id_record(&created.user.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.banned(), !expired);
    }
}

#[tokio::test]
async fn admin_creation_malformed_native_fields_reach_storage_failure() {
    let (ctx, _, _, _, _) = create_admin_context().await;
    for (index, data) in [
        serde_json::json!({"image": {"not": "a scalar"}}),
        serde_json::json!({"banned": []}),
        serde_json::json!({"createdAt": "definitely not a date"}),
        serde_json::json!({"banExpires": "invalid"}),
    ]
    .into_iter()
    .enumerate()
    {
        let email = format!("raw-malformed-{index}@fixture.test");
        let mut input = types::CreateUserRequest::new(&email, "Malformed");
        input.data = Some(data.as_object().unwrap().clone());
        let error = handlers::create_user_core(&input, &AdminConfig::default(), &ctx)
            .await
            .unwrap_err();
        assert_eq!(error.status_code(), 500, "{error:?}");
        assert!(
            ctx.database
                .get_user_by_email(&email)
                .await
                .unwrap()
                .is_none()
        );
    }
}
