use super::*;
use alibi_core::UpdateUser;
use chrono::Datelike;

#[tokio::test]
async fn false_ban_patch_preserves_omissions_and_honors_explicit_values() {
    let (ctx, admin, _, user, _) = create_admin_context().await;
    let expiry = Utc::now() + Duration::hours(1);
    ctx.database
        .update_user_record(
            &user.id,
            UpdateUser {
                banned: Some(true),
                ban_reason: Some("preserved".into()),
                ban_expires: Some(Some(expiry)),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    for (data, reason, expected_expiry) in [
        (
            serde_json::json!({"banned": false}),
            Some("preserved"),
            Some(expiry),
        ),
        (
            serde_json::json!({"banned": false, "banReason": "replacement", "banExpires": "2099-01-01T00:00:00Z"}),
            Some("replacement"),
            Some(
                chrono::DateTime::parse_from_rfc3339("2099-01-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
        ),
        (
            serde_json::json!({"banned": false, "banReason": null, "banExpires": null}),
            None,
            None,
        ),
    ] {
        handlers::update_user_core(
            &types::AdminUpdateUserRequest::new(&user.id, data.as_object().unwrap().clone()),
            &admin,
            &AdminConfig::default(),
            &ctx,
        )
        .await
        .unwrap();
        let stored = ctx
            .database
            .get_user_by_id_record(&user.id)
            .await
            .unwrap()
            .unwrap();
        assert!(!stored.banned());
        assert_eq!(stored.ban_reason(), reason);
        assert_eq!(stored.ban_expires(), expected_expiry);
    }
}

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
            serde_json::json!({"banned": true, "banExpires": expiry, "banReason": "expired reason"})
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
        assert_eq!(
            stored.ban_reason(),
            if expired {
                None
            } else {
                Some("expired reason")
            }
        );
        assert_eq!(stored.ban_expires().is_none(), expired);
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

#[tokio::test]
async fn native_secondary_user_roundtrip_retains_raw_dates_and_boolean_presence() {
    use alibi_core::{AuthSchema, AuthUser, CacheAdapter};
    let (ctx, _, _, user, _) = create_admin_context().await;
    let user = ctx
        .database
        .get_user_by_id_record(&user.id)
        .await
        .unwrap()
        .unwrap();
    let cache = alibi_core::MemoryCacheAdapter::new();
    type User = <TestSchema as AuthSchema>::User;
    for (index, created_at) in [
        serde_json::json!(1e20),
        serde_json::json!(-1),
        serde_json::json!(1.9),
        serde_json::json!("2099-01-01T00:00:00.000Z"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut snapshot = user.secondary_snapshot().unwrap();
        snapshot["created_at"] = created_at.clone();
        snapshot["updated_at"] = serde_json::json!(-1e20);
        snapshot["ban_expires"] = serde_json::json!(-0.5);
        snapshot["email_verified"] = serde_json::json!("false");
        snapshot["two_factor_enabled"] = serde_json::json!("false");
        snapshot["banned"] = serde_json::json!(false);
        snapshot["is_anonymous"] = serde_json::Value::Null;
        snapshot
            .as_object_mut()
            .unwrap()
            .remove("phone_number_verified");
        snapshot.as_object_mut().unwrap().remove("image");
        snapshot["username"] = serde_json::Value::Null;
        snapshot["unknownNative"] = serde_json::json!("must not retain");
        cache
            .set(
                &format!("native-user-{index}"),
                &snapshot.to_string(),
                Duration::seconds(60),
            )
            .await
            .unwrap();
    }
    ctx.database.delete_user(&user.id()).await.unwrap();
    for index in 0..4 {
        let source: serde_json::Value = serde_json::from_str(
            &cache
                .get(&format!("native-user-{index}"))
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let decoded = User::from_secondary_snapshot_record(source.clone()).unwrap();
        let wire = serde_json::to_value(alibi_core::UserView::from(&decoded)).unwrap();
        assert_eq!(wire["createdAt"], source["created_at"]);
        assert_eq!(wire["updatedAt"], source["updated_at"]);
        assert_eq!(wire["banExpires"], source["ban_expires"]);
        assert_eq!(wire["emailVerified"], "false");
        assert_eq!(wire["twoFactorEnabled"], "false");
        assert_eq!(wire["isAnonymous"], serde_json::Value::Null);
        assert!(wire.get("phoneNumberVerified").is_none());
        assert!(wire.get("image").is_none());
        assert_eq!(wire.get("username"), Some(&serde_json::Value::Null));
        assert!(decoded.email_verified());
        assert!(decoded.two_factor_enabled());
        assert!(!decoded.banned());
        assert!(
            decoded
                .raw_snapshot()
                .field_is_undefined("phoneNumberVerified")
        );
        assert!(!decoded.raw_snapshot().contains_field("unknownNative"));
        let encoded = decoded.secondary_snapshot().unwrap();
        for field in [
            "created_at",
            "updated_at",
            "ban_expires",
            "email_verified",
            "two_factor_enabled",
            "is_anonymous",
        ] {
            assert_eq!(encoded[field], source[field], "{field}");
        }
        assert!(encoded.get("phone_number_verified").is_none());
        assert!(encoded.get("image").is_none());
        assert_eq!(encoded.get("username"), Some(&serde_json::Value::Null));
    }
}
