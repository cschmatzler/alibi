#![allow(
    unreachable_pub,
    reason = "SeaORM derives public associated entities inside private test fixtures"
)]
use super::*;
use alibi::store::{AuthStore, CacheAdapter, MemoryCacheAdapter};
use chrono::{DateTime, Utc};

macro_rules! model {
    (sqlx, $module:ident, $role:literal, {$($fields:tt)*}) => {
        mod $module {
            use super::*;
            #[derive(alibi::sqlx::AuthEntity, Clone, Debug, serde::Serialize, sqlx::FromRow)]
            #[auth(role = $role, table = $role, secondary_storage)]
            #[sqlx(rename_all = "camelCase")]
            pub struct Model { pub id: String, $($fields)* }
        }
    };
    (seaorm, $module:ident, $role:literal, {$($fields:tt)*}) => {
        mod $module {
            use super::*;
            use alibi::seaorm::sea_orm::{self, entity::prelude::*};
            use chrono::DateTime;
            #[derive(alibi::seaorm::AuthEntity, Clone, Debug, serde::Serialize, DeriveEntityModel)]
            #[auth(role = $role, secondary_storage)]
            #[sea_orm(table_name = $role, rename_all = "camelCase")]
            pub struct Model {
                #[sea_orm(primary_key, auto_increment = false)]
                pub id: String,
                $($fields)*
            }
            #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
            pub enum Relation {}
            impl ActiveModelBehavior for ActiveModel {}
        }
    };
}

macro_rules! models {
    ($backend:ident, $attr:ident, $column:ident, $bundled:ty) => {
        model!($backend, user, "user", {
            pub name: Option<String>, pub email: Option<String>, pub email_verified: bool, pub image: Option<String>,
            pub created_at: DateTime<Utc>, pub updated_at: DateTime<Utc>,
            #[$attr($column = "wire_label")] pub wire_storage: String,
            #[$attr($column = "wire_null")] pub null_storage: Option<String>,
            #[$attr($column = "wire_omitted")] pub omitted_storage: Option<String>,
            #[$attr($column = "wire_hidden")] pub hidden_storage: Option<String>,
        });
        model!($backend, session, "session", {
            pub expires_at: DateTime<Utc>, pub token: String, pub created_at: DateTime<Utc>, pub updated_at: DateTime<Utc>,
            pub ip_address: Option<String>, pub user_agent: Option<String>, pub user_id: String,
            #[$attr($column = "wire_label")] pub wire_storage: String,
            #[$attr($column = "wire_null")] pub null_storage: Option<String>,
            #[$attr($column = "wire_omitted")] pub omitted_storage: Option<String>,
            #[$attr($column = "wire_hidden")] pub hidden_storage: Option<String>,
        });
        struct Schema;
        impl AuthSchema for Schema {
            type User = user::Model;
            type Session = session::Model;
            type Account = <$bundled as AuthSchema>::Account;
            type Verification = <$bundled as AuthSchema>::Verification;
        }
    };
}

fn config(cache: Arc<MemoryCacheAdapter>) -> AuthConfig {
    use alibi::field_policy::FieldConfig;
    let mut config = AuthConfig::new("session-timestamp-hooks-secret-at-least-32");
    config.session.secondary_storage = Some(cache);
    config.session.store_in_database = true;
    let mut label = FieldConfig::new(json!({"type":"string"}))
        .field_name("wire_label")
        .default_value(json!("original"));
    label.required = true;
    let fields = alibi::field_policy::FieldConfigs::from([
        ("wireLabel".into(), label),
        (
            "wireNull".into(),
            FieldConfig::new(json!({"type":"string"}))
                .field_name("wire_null")
                .default_value(JsValue::Null),
        ),
        (
            "wireOmitted".into(),
            FieldConfig::new(json!({"type":"string"}))
                .field_name("wire_omitted")
                .transform_output(|_| async { Ok(None) }),
        ),
        (
            "wireHidden".into(),
            FieldConfig::new(json!({"type":"string"}))
                .field_name("wire_hidden")
                .default_value(json!("secret"))
                .hidden(),
        ),
    ]);
    config.user.additional_fields = fields.clone();
    config.session.additional_fields = fields;
    _ = config.session.additional_fields.insert(
        "expiresAt".into(),
        FieldConfig::new(json!({"type":"date"})).transform_adapter_input(|value| async move {
            match value {
                Some(JsValue::Date(date)) => {
                    Ok(Some(JsValue::Date(date + chrono::Duration::seconds(1))))
                }
                _ => Err(alibi::AuthError::internal("expected expiry Date")),
            }
        }),
    );
    config
}

async fn install(db: &Db) -> TestResult {
    for table in ["user", "session"] {
        for (column, definition) in [
            ("wire_label", "TEXT NOT NULL DEFAULT 'original'"),
            ("wire_null", "TEXT"),
            ("wire_omitted", "TEXT"),
            ("wire_hidden", "TEXT DEFAULT 'secret'"),
        ] {
            _ = db
                .execute(
                    &format!("ALTER TABLE \"{table}\" ADD COLUMN {column} {definition}"),
                    &[],
                )
                .await?;
        }
    }
    Ok(())
}

async fn exercise<S: AuthSchema>(
    db: &Db,
    store: Arc<dyn AuthStore<S>>,
    cache: Arc<MemoryCacheAdapter>,
    operation: &str,
    unknown: bool,
) -> TestResult {
    let owner_update = operation == "owner";
    let operation = if owner_update { "create" } else { operation };
    let fixture: Value = serde_json::from_str(if owner_update {
        include_str!("../../../fixtures/session-timestamp-hooks-secondary-wire-owner.json")
    } else if unknown {
        include_str!("../../../fixtures/session-timestamp-hooks-secondary-wire-unknown.json")
    } else {
        include_str!("../../../fixtures/session-timestamp-hooks-secondary-wire-fields.json")
    })?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let backend = if db.is_postgres() {
        "postgres"
    } else {
        "sqlite"
    };
    let cases = fixture["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|profile| profile["backend"] == backend)
        .unwrap()["cases"]
        .as_array()
        .unwrap();
    assert_eq!(cases.len(), 2);
    let case = cases
        .iter()
        .find(|case| case["operation"] == operation)
        .unwrap();
    let owner = store
        .create_user(
            CreateUser::new()
                .with_name("Timestamp")
                .with_email("session-timestamp@example.com"),
        )
        .await?;
    let token = format!("timestamp-{operation}-date");
    let input: DateTime<Utc> = case["input"].as_str().unwrap().parse()?;
    let session = store
        .create_session(CreateSession {
            additional_fields: Default::default(),
            user_id: owner.id().into_owned(),
            token: Some(token.clone()),
            expires_at: if operation == "create" {
                input
            } else {
                "2030-01-01T00:00:00.123Z".parse()?
            },
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
        })
        .await?;
    if operation == "update" {
        if unknown {
            let raw = cache
                .get(&token)
                .await?
                .ok_or("original aliased cache missing")?;
            let mut payload = native::parse_value(&raw)?;
            payload["session"]["trustedUnknown"] = json!({"exact":true}).into();
            payload["user"]["trustedUnknown"] = json!({"owner":true}).into();
            cache
                .set(
                    &token,
                    &native::to_string(&payload)?,
                    chrono::Duration::hours(1),
                )
                .await?;
        }
        let mut fields = alibi::field_policy::FieldValues::new();
        _ = fields.insert("expiresAt".into(), JsValue::Date(input));
        _ = fields.insert("wireLabel".into(), JsValue::String("changed".into()));
        _ = fields.insert("wireNull".into(), JsValue::Null);
        let updated = store
            .update_session_fields(&token, fields)
            .await?
            .ok_or("aliased update missing")?;
        assert_eq!(updated.id(), session.id());
    }
    if owner_update {
        let mut update = alibi::UpdateUser::default();
        update.name = Some("Changed Owner".into());
        _ = update
            .additional_fields
            .insert("wireLabel".into(), JsValue::String("owner-changed".into()));
        _ = store.update_user(owner.id().as_ref(), update).await?;
    }
    let raw = cache.get(&token).await?.ok_or("aliased cache missing")?;
    super::wire::assert_payload(&raw, case["wire"].as_str().unwrap(), backend, operation)?;
    // A database miss must not hide a broken required-field cache decoder.
    _ = db
        .execute("DELETE FROM session WHERE token = $1", &[&token])
        .await?;
    let readback = store
        .get_session(&token)
        .await?
        .ok_or("aliased cache decoding failed")?;
    let owner_record = store
        .get_session_user_record(&token)
        .await?
        .ok_or("aliased cache owner decoding failed")?;
    assert_eq!(readback.id(), session.id());
    assert_eq!(owner_record.id(), owner.id());
    assert_eq!(
        owner_record.name(),
        Some(if owner_update {
            "Changed Owner"
        } else {
            "Timestamp"
        })
    );
    let public_owner = native::to_js_value(&owner_record)?;
    let expected = native::parse_value(case["wire"].as_str().unwrap())?;
    let expected_keys = expected["user"]
        .as_object()
        .unwrap()
        .keys()
        .filter(|name| name.as_str() != Some("wireHidden"))
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        public_owner
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        expected_keys,
        "{backend}/{operation} public cached owner properties"
    );
    assert_eq!(public_owner["wireNull"], JsValue::Null);
    assert_eq!(public_owner.get("wireOmitted"), None);
    assert_eq!(public_owner.get("wireHidden"), None);
    if unknown {
        assert_eq!(public_owner["trustedUnknown"], json!({"owner":true}));
    }
    let session_fields = readback.additional_js_fields()?;
    assert_eq!(
        session_fields["wireStorage"],
        if operation == "update" {
            json!("changed")
        } else {
            json!("original")
        }
    );
    assert_eq!(
        owner_record.additional_js_fields()?["wireStorage"],
        if owner_update {
            json!("owner-changed")
        } else {
            json!("original")
        }
    );
    Ok(())
}

mod on_sqlx {
    use super::super::super::Sqlx;
    use super::*;
    models!(sqlx, sqlx, rename, <Sqlx as Backend>::Schema);
    async fn run(db: Db, operation: &str, unknown: bool) -> TestResult {
        let (connection, _) = db
            .migrated::<Sqlx>("session-timestamp-hooks-secret-at-least-32")
            .await?;
        install(&db).await?;
        let cache = Arc::new(MemoryCacheAdapter::new());
        let config = config(cache.clone());
        let store = alibi::sqlx::SqlxStore::<Schema>::new(config.clone(), connection.clone());
        let auth = AuthBuilder::new(config).store(store).build().await?;
        exercise(&db, auth.store().clone(), cache, operation, unknown).await?;
        drop(auth);
        Sqlx::close(connection).await
    }
    #[tokio::test]
    async fn sqlite_creation_alias_wire_and_readback() -> TestResult {
        run(Db::sqlite().await?, "create", false).await
    }
    #[tokio::test]
    async fn sqlite_refresh_alias_wire_and_readback() -> TestResult {
        run(Db::sqlite().await?, "update", false).await
    }
    #[tokio::test]
    async fn sqlite_refresh_preserves_unknown_cache_properties() -> TestResult {
        run(Db::sqlite().await?, "update", true).await
    }
    #[tokio::test]
    async fn sqlite_owner_refresh_preserves_logical_wire() -> TestResult {
        run(Db::sqlite().await?, "owner", false).await
    }
    #[tokio::test]
    #[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
    async fn postgres_owner_refresh_preserves_logical_wire() -> TestResult {
        run(Db::postgres().await?, "owner", false).await
    }
    #[tokio::test]
    #[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
    async fn postgres_creation_alias_wire_and_readback() -> TestResult {
        run(Db::postgres().await?, "create", false).await
    }
    #[tokio::test]
    #[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
    async fn postgres_refresh_alias_wire_and_readback() -> TestResult {
        run(Db::postgres().await?, "update", false).await
    }
    #[tokio::test]
    #[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
    async fn postgres_refresh_preserves_unknown_cache_properties() -> TestResult {
        run(Db::postgres().await?, "update", true).await
    }
}

mod on_seaorm {
    use super::super::super::SeaOrm;
    use super::*;
    models!(seaorm, sea_orm, column_name, <SeaOrm as Backend>::Schema);
    async fn run(db: Db, operation: &str, unknown: bool) -> TestResult {
        let (connection, _) = db
            .migrated::<SeaOrm>("session-timestamp-hooks-secret-at-least-32")
            .await?;
        install(&db).await?;
        let cache = Arc::new(MemoryCacheAdapter::new());
        let config = config(cache.clone());
        let store =
            alibi::seaorm::SeaOrmStore::<Schema>::new(Arc::new(config.clone()), connection.clone());
        let auth = AuthBuilder::new(config).store(store).build().await?;
        exercise(&db, auth.store().clone(), cache, operation, unknown).await?;
        drop(auth);
        SeaOrm::close(connection).await
    }
    #[tokio::test]
    async fn sqlite_creation_alias_wire_and_readback() -> TestResult {
        run(Db::sqlite().await?, "create", false).await
    }
    #[tokio::test]
    async fn sqlite_refresh_alias_wire_and_readback() -> TestResult {
        run(Db::sqlite().await?, "update", false).await
    }
    #[tokio::test]
    async fn sqlite_refresh_preserves_unknown_cache_properties() -> TestResult {
        run(Db::sqlite().await?, "update", true).await
    }
    #[tokio::test]
    async fn sqlite_owner_refresh_preserves_logical_wire() -> TestResult {
        run(Db::sqlite().await?, "owner", false).await
    }
    #[tokio::test]
    #[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
    async fn postgres_owner_refresh_preserves_logical_wire() -> TestResult {
        run(Db::postgres().await?, "owner", false).await
    }
    #[tokio::test]
    #[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
    async fn postgres_creation_alias_wire_and_readback() -> TestResult {
        run(Db::postgres().await?, "create", false).await
    }
    #[tokio::test]
    #[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
    async fn postgres_refresh_alias_wire_and_readback() -> TestResult {
        run(Db::postgres().await?, "update", false).await
    }
    #[tokio::test]
    #[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
    async fn postgres_refresh_preserves_unknown_cache_properties() -> TestResult {
        run(Db::postgres().await?, "update", true).await
    }
}
