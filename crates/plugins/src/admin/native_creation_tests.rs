use super::*;
use alibi_core::UpdateUser;
use chrono::Datelike;

#[tokio::test]
async fn native_username_lookup_observes_sqlite_affinity_and_current_transaction() {
    let (ctx, _, _, _, _) = create_admin_context().await;
    let mut input = alibi_core::CreateUser::new().with_email("raw-username@fixture.test");
    input
        .adapter_native_fields
        .insert("username".into(), serde_json::json!(42).into());
    let user = ctx.database.create_user(input).await.unwrap();
    let found = ctx
        .database
        .get_user_by_username_value(&alibi_core::utils::json::JsValue::Number(42.0))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        alibi_core::AuthUser::id(&found),
        alibi_core::AuthUser::id(&user)
    );
    for raw in [serde_json::json!([]), serde_json::json!({})] {
        assert!(
            ctx.database
                .get_user_by_username_value(&raw.into())
                .await
                .is_err()
        );
    }
    alibi_core::store::transaction(ctx.database.as_ref(), |tx| {
        Box::pin(async move {
            let mut input =
                alibi_core::CreateUser::new().with_email("transaction-username@fixture.test");
            input
                .adapter_native_fields
                .insert("username".into(), serde_json::json!(73).into());
            let created = tx.create_user(input).await?;
            let found = tx
                .get_user_by_username_value(&alibi_core::utils::json::JsValue::Number(73.0))
                .await?
                .unwrap();
            assert_eq!(
                alibi_core::AuthUser::id(&found),
                alibi_core::AuthUser::id(&created)
            );
            Ok(())
        })
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn false_ban_patch_preserves_omissions_and_honors_explicit_values() {
    let (ctx, admin, _, user, _) = create_admin_context().await;
    let expiry = chrono::DateTime::from_timestamp_millis(4_102_444_800_123).unwrap();
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
            "id": "native-affinity-user",
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
    assert_eq!(response["user"]["id"], "native-affinity-user");
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
                .get_user_by_email(&alibi_core::utils::json::JsString::from(&email))
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
        snapshot["created_at"] = created_at.clone().into();
        snapshot["updated_at"] = serde_json::json!(-1e20).into();
        snapshot["ban_expires"] = serde_json::json!(-0.5).into();
        snapshot["email_verified"] = serde_json::json!("false").into();
        snapshot["two_factor_enabled"] = serde_json::json!("false").into();
        snapshot["banned"] = serde_json::json!(false).into();
        snapshot["is_anonymous"] = serde_json::Value::Null.into();
        snapshot
            .as_object_mut()
            .unwrap()
            .shift_remove("phone_number_verified");
        snapshot.as_object_mut().unwrap().shift_remove("image");
        snapshot["username"] = serde_json::Value::Null.into();
        snapshot["name"] = serde_json::Value::Null.into();
        snapshot["unknownNative"] = serde_json::json!("must not retain").into();
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
        let decoded = User::from_secondary_snapshot_record(source.clone().into()).unwrap();
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
        assert_eq!(wire.get("name"), Some(&serde_json::Value::Null));
        assert_eq!(decoded.name(), Some(""));
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
        assert_eq!(
            encoded.get("username"),
            Some(&alibi_core::utils::json::JsValue::Null)
        );
        assert_eq!(
            encoded.get("name"),
            Some(&alibi_core::utils::json::JsValue::Null)
        );
    }
}

#[tokio::test]
async fn unrelated_user_update_retains_native_sqlite_scalars() {
    use alibi_core::AuthUser;
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
    let mut input = types::CreateUserRequest::new("update-native@fixture.test", "Native");
    input.data = Some(
        serde_json::json!({
            "emailVerified": 2, "banned": 0.5, "twoFactorEnabled": -1,
            "isAnonymous": "pending", "phoneNumberVerified": -2,
            "createdAt": 1e20, "banExpires": -0.5
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    let created = handlers::create_user_core(&input, &AdminConfig::default(), &ctx)
        .await
        .unwrap();
    let updated = ctx
        .database
        .update_user_record(
            &created.user.id,
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
    assert_eq!(wire["createdAt"], serde_json::json!(1e20));
    assert_eq!(wire["banExpires"], serde_json::json!(-0.5));
    let row = database
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT typeof(banned) AS kind, banned, createdAt, banExpires FROM user WHERE id = ?",
            [created.user.id.into()],
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.try_get::<String>("", "kind").unwrap(), "real");
    assert_eq!(row.try_get::<f64>("", "banned").unwrap(), 0.5);
    assert_eq!(row.try_get::<f64>("", "createdAt").unwrap(), 1e20);
    assert_eq!(row.try_get::<f64>("", "banExpires").unwrap(), -0.5);
}

#[tokio::test]
async fn admin_update_ban_expiry_accepts_javascript_dates_and_invalid_date_fails_before_write() {
    use alibi_core::AuthUser;
    let (ctx, admin, _, user, _) = create_admin_context().await;
    for (input, expected) in [
        ("2099-01-01", "2099-01-01T00:00:00.000Z"),
        ("January 2, 2099", "2099-01-02T00:00:00.000Z"),
    ] {
        let data = serde_json::json!({"banExpires": input});
        let response = handlers::update_user_core(
            &types::AdminUpdateUserRequest::new(&user.id, data.as_object().unwrap().clone()),
            &admin,
            &AdminConfig::default(),
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(
            serde_json::to_value(&response).unwrap()["banExpires"],
            expected
        );
        let stored = ctx
            .database
            .get_user_by_id_record(&user.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.ban_expires().unwrap().timestamp_millis(),
            alibi_core::utils::datetime::parse_date_millis(expected).unwrap()
        );
    }
    let before = ctx
        .database
        .get_user_by_id_record(&user.id)
        .await
        .unwrap()
        .unwrap();
    let data = serde_json::json!({"name": "Must not write", "banExpires": "not a date"});
    let error = handlers::update_user_core(
        &types::AdminUpdateUserRequest::new(&user.id, data.as_object().unwrap().clone()),
        &admin,
        &AdminConfig::default(),
        &ctx,
    )
    .await
    .unwrap_err();
    assert_eq!(error.status_code(), 500);
    assert!(error.to_string().contains("Invalid time value"));
    let after = ctx
        .database
        .get_user_by_id_record(&user.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before.name(), after.name());
    assert_eq!(before.ban_expires(), after.ban_expires());
}

#[tokio::test]
async fn native_secondary_nonidentity_texts_keep_raw_cache_values() {
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
    let mut source = user.secondary_snapshot().unwrap();
    source["name"] = serde_json::json!(42).into();
    source["email"] = serde_json::Value::Null.into();
    source["image"] = serde_json::json!({"cached": true}).into();
    source["display_username"] = serde_json::json!(false).into();
    source["unknownText"] = serde_json::json!("not declared").into();
    cache
        .set(
            "native-text-user",
            &source.to_string(),
            Duration::seconds(60),
        )
        .await
        .unwrap();
    ctx.database.delete_user(&user.id()).await.unwrap();
    let cached =
        serde_json::from_str(&cache.get("native-text-user").await.unwrap().unwrap()).unwrap();
    let record = User::from_secondary_snapshot_record(cached).unwrap();
    assert_eq!(record.name(), Some(""));
    assert_eq!(record.email(), Some(""));
    assert_eq!(record.image(), None);
    assert_eq!(record.display_username(), None);
    let wire = serde_json::to_value(alibi_core::UserView::from(&record)).unwrap();
    assert_eq!(wire["name"], 42);
    assert_eq!(wire["email"], serde_json::Value::Null);
    assert_eq!(wire["image"], source["image"]);
    assert_eq!(wire["displayUsername"], false);
    assert!(wire.get("unknownText").is_none());
    let encoded = record.secondary_snapshot().unwrap();
    for field in ["name", "email", "image", "display_username"] {
        assert_eq!(encoded[field], source[field]);
    }
    assert!(encoded.get("unknownText").is_none());
}

#[tokio::test]
async fn native_ban_expiry_updates_preserve_scalars_and_expanded_dates() {
    use alibi_seaorm::sea_orm::{ConnectionTrait, Database, DbBackend, Statement};
    let database = Database::connect("sqlite::memory:").await.unwrap();
    alibi_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap();
    let (_, acting_admin, _, _, _) = create_admin_context().await;
    let store = Arc::new(alibi_seaorm::SeaOrmStore::<TestSchema>::new(
        test_helpers::create_test_config(),
        database.clone(),
    ));
    let ctx = AuthContext::new(Arc::new(test_helpers::create_test_config()), store);
    let expanded = "+275760-09-13T00:00:00.000Z";
    let mut input = types::CreateUserRequest::new("expanded-date@fixture.test", "Date");
    input.data = Some(
        serde_json::json!({
            "createdAt": expanded, "updatedAt": expanded, "banExpires": expanded
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    let created = handlers::create_user_core(&input, &AdminConfig::default(), &ctx)
        .await
        .unwrap();
    let wire = serde_json::to_value(&created).unwrap();
    for field in ["createdAt", "updatedAt", "banExpires"] {
        assert_eq!(wire["user"][field], expanded);
    }
    let row = database
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT createdAt AS value, typeof(createdAt) AS kind FROM user WHERE id = ?",
            [created.user.id.clone().into()],
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.try_get::<String>("", "value").unwrap(), expanded);
    assert_eq!(row.try_get::<String>("", "kind").unwrap(), "text");
    for value in [
        serde_json::json!(0),
        serde_json::json!(-0.5),
        serde_json::json!(1.9),
        serde_json::json!(true),
        serde_json::json!(1e20),
        serde_json::json!(-1e20),
        serde_json::json!(expanded),
        serde_json::Value::Null,
    ] {
        let response = handlers::update_user_core(
            &types::AdminUpdateUserRequest::new(
                &created.user.id,
                serde_json::json!({"banExpires": value})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
            &acting_admin,
            &AdminConfig::default(),
            &ctx,
        )
        .await
        .unwrap();
        let expected = if value.is_boolean() {
            serde_json::json!(1)
        } else {
            value.clone()
        };
        let wire = serde_json::to_value(response).unwrap();
        assert_eq!(wire["banExpires"], expected);
        let retained = ctx
            .database
            .get_user_by_id_record(&created.user.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retained.raw_snapshot().values()["banExpires"], expected);
        let row = database.query_one_raw(Statement::from_sql_and_values(DbBackend::Sqlite,
            "SELECT json_quote(banExpires) AS value, typeof(banExpires) AS kind FROM user WHERE id = ?",
            [created.user.id.clone().into()])).await.unwrap().unwrap();
        let physical: serde_json::Value =
            serde_json::from_str(&row.try_get::<String>("", "value").unwrap()).unwrap();
        assert_eq!(physical, expected);
        let expected_kind = if expected.is_null() {
            "null"
        } else if expected.is_string() {
            "text"
        } else if expected.as_f64().unwrap().fract() == 0.0
            && expected.as_f64().unwrap().abs() < i64::MAX as f64
        {
            "integer"
        } else {
            "real"
        };
        assert_eq!(row.try_get::<String>("", "kind").unwrap(), expected_kind);
    }
}

#[tokio::test]
async fn stateless_ban_expiry_comparisons_keep_native_truthiness_and_timeclip() {
    use alibi_core::store::UserStore;
    let store = alibi_core::store::stateless::StatelessStore::default();
    for (index, (expiry, expired)) in [
        (serde_json::json!(0), false),
        (serde_json::json!(-0.5), true),
        (serde_json::json!(1.9), true),
        (serde_json::json!(1e20), false),
        (serde_json::json!(-1e20), false),
    ]
    .into_iter()
    .enumerate()
    {
        let user = store
            .create_user(alibi_core::CreateUser {
                email: Some(format!("stateless-ban-{index}@fixture.test")),
                banned: Some(true),
                adapter_native_fields: [("banExpires".into(), expiry.clone().into())].into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            super::super::ban_expired_at(&user, Utc::now()).unwrap(),
            expired,
            "{expiry}"
        );
        let stored = store.get_user_by_id(&user.id).await.unwrap().unwrap();
        assert_eq!(serde_json::to_value(stored).unwrap()["banExpires"], expiry);
    }
}

#[tokio::test]
async fn stateless_structured_ban_expiry_uses_date_primitive_conversion_and_errors() {
    use alibi_core::store::SessionCreatedHook;
    let ctx = AuthContext::new(
        Arc::new(crate::test_helpers::create_test_config()),
        Arc::new(alibi_core::store::stateless::StatelessStore::default()),
    );
    for (index, (expiry, expired)) in [
        (serde_json::json!(["2000-01-01"]), Some(true)),
        (serde_json::json!([0]), Some(true)),
        (serde_json::json!([["2000-01-01"]]), Some(true)),
        (serde_json::json!([]), Some(false)),
        (serde_json::json!({}), Some(false)),
        (serde_json::json!({"toString": null}), None),
        (serde_json::json!({"toString": 1}), None),
    ]
    .into_iter()
    .enumerate()
    {
        let user = ctx
            .database
            .create_user_record(alibi_core::CreateUser {
                email: Some(format!("structured-expiry-{index}@fixture.test")),
                banned: Some(true),
                adapter_native_fields: [
                    ("banExpires".into(), expiry.clone().into()),
                    ("banReason".into(), serde_json::json!("retained").into()),
                ]
                .into(),
                ..Default::default()
            })
            .await
            .unwrap();
        let result = AdminSessionGuard
            .before_create(
                &CreateSession {
                    user_id: user.id().to_string(),
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
        if let Some(expired) = expired {
            assert_eq!(result.is_ok(), expired, "{expiry}: {result:?}");
        } else {
            let error = result.unwrap_err();
            assert_eq!(error.status_code(), 500);
            assert!(
                error
                    .to_string()
                    .contains("Cannot convert object to primitive value")
            );
        }
        let stored = ctx
            .database
            .get_user_by_id_record(user.id().as_ref())
            .await
            .unwrap()
            .unwrap();
        let wire = serde_json::to_value(UserView::from(&stored)).unwrap();
        assert_eq!(stored.banned(), expired != Some(true));
        assert_eq!(
            wire["banExpires"],
            if expired == Some(true) {
                serde_json::Value::Null
            } else {
                expiry
            }
        );
        assert_eq!(
            wire["banReason"],
            if expired == Some(true) {
                serde_json::Value::Null
            } else {
                serde_json::json!("retained")
            }
        );
    }
}
