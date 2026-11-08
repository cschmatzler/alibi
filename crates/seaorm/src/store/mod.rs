//! SeaORM-backed persistence implementation for built-in auth tables.

#[cfg(test)]
mod json_metadata_tests {
    mod rich {
        use sea_orm::entity::prelude::*;
        #[derive(
            crate::AuthEntity, Clone, Debug, PartialEq, DeriveEntityModel, serde::Serialize,
        )]
        #[sea_orm(table_name = "user")]
        #[auth(role = "user", secondary_storage)]
        pub(super) struct Model {
            #[sea_orm(primary_key, auto_increment = false)]
            pub id: String,
            pub name: String,
            pub email: String,
            #[sea_orm(column_name = "emailVerified")]
            pub email_verified: bool,
            pub image: Option<String>,
            #[sea_orm(column_name = "createdAt")]
            pub created_at: DateTimeUtc,
            #[sea_orm(column_name = "updatedAt")]
            pub updated_at: DateTimeUtc,
            #[sea_orm(column_type = "Json")]
            pub metadata: crate::JsonMetadata,
        }
        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub(super) enum Relation {}
        impl ActiveModelBehavior for ActiveModel {}
    }

    struct Schema;
    impl alibi_core::AuthSchema for Schema {
        type User = rich::Model;
        type Session = <super::bundled_schema::BundledSchema as alibi_core::AuthSchema>::Session;
        type Account = <super::bundled_schema::BundledSchema as alibi_core::AuthSchema>::Account;
        type Verification =
            <super::bundled_schema::BundledSchema as alibi_core::AuthSchema>::Verification;
    }

    use alibi_core::utils::json::{self, JsValue};
    use alibi_core::{AuthConfig, AuthError, AuthUser, CreateUser};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    #[tokio::test]
    async fn adapter_input_undefined_defaults_and_updates_reach_actual_sqlite_cells() {
        use alibi_core::UpdateUser;
        use alibi_core::store::UserStore;
        use sea_orm::ConnectionTrait;
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        super::migrator::run_migrations(&db).await.unwrap();
        _ = db
            .execute_unprepared("ALTER TABLE user ADD COLUMN metadata TEXT NOT NULL DEFAULT '{}'")
            .await
            .unwrap();

        for (label, on_update) in [("enabled", true), ("disabled", false)] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let inputs = Arc::new(Mutex::new(Vec::new()));
            let mut config = AuthConfig::default();
            let default_events = events.clone();
            let mut field =
                alibi_core::field_policy::FieldConfig::new(serde_json::json!({"type":"string"}))
                    .default_callback(move || {
                        default_events.lock().unwrap().push("default");
                        JsValue::String("default".into())
                    });
            if on_update {
                let update_events = events.clone();
                field = field.on_update(move || {
                    update_events.lock().unwrap().push("update");
                    JsValue::String("updated".into())
                });
            }
            let transform_events = events.clone();
            let transform_inputs = inputs.clone();
            field = field.transform_adapter_input(move |value| {
                transform_events.lock().unwrap().push("input");
                transform_inputs.lock().unwrap().push(value.clone());
                async move { Ok(value) }
            });
            _ = config.user.additional_fields.insert("image".into(), field);
            let config = Arc::new(config);
            let inner = Arc::new(super::SeaOrmStore::<Schema>::new(
                (*config).clone(),
                db.clone(),
            ));
            let store = alibi_core::AuthInitContext::new(config, inner.clone())
                .database_with_registered_transforms();
            let mut input = CreateUser::new()
                .with_email(format!("{label}@fixture.test"))
                .with_name("fixture");
            _ = input
                .additional_fields
                .insert("image".into(), JsValue::Undefined);
            let user = store.create_user(input).await.unwrap();
            let id = user.id().into_owned();
            assert_eq!(user.image(), Some("default"));
            assert_eq!(*events.lock().unwrap(), ["default", "input"]);
            assert_eq!(
                *inputs.lock().unwrap(),
                [Some(JsValue::String("default".into()))]
            );

            for (value, expected) in [
                (
                    None,
                    if on_update {
                        Some("updated")
                    } else {
                        Some("default")
                    },
                ),
                (
                    Some(JsValue::Undefined),
                    if on_update {
                        Some("updated")
                    } else {
                        Some("default")
                    },
                ),
                (Some(JsValue::Null), None),
                (Some(JsValue::String("".into())), Some("")),
                (Some(JsValue::String("supplied".into())), Some("supplied")),
            ] {
                events.lock().unwrap().clear();
                inputs.lock().unwrap().clear();
                let mut update = UpdateUser::default();
                if let Some(value) = value.clone() {
                    _ = update.additional_fields.insert("image".into(), value);
                }
                let user = store.update_user(&id, update).await.unwrap();
                assert_eq!(user.image(), expected);
                assert_eq!(
                    inner.get_user_by_id(&id).await.unwrap().unwrap().image(),
                    expected,
                );
                let missing = value.as_ref().is_none_or(JsValue::is_undefined);
                let expected_events: &[&str] = if missing {
                    if on_update { &["update", "input"] } else { &[] }
                } else {
                    &["input"]
                };
                assert_eq!(*events.lock().unwrap(), expected_events);
                let expected_inputs: Vec<_> = if missing {
                    if on_update {
                        vec![Some(JsValue::String("updated".into()))]
                    } else {
                        vec![]
                    }
                } else {
                    vec![value]
                };
                assert_eq!(*inputs.lock().unwrap(), expected_inputs);
            }
        }
    }

    #[tokio::test]
    async fn initialized_json_output_observes_physical_cell_before_read_codec() {
        let original = {
            let mut value = json::parse_value(r#"{"\ud800":"\udfff","null":null,"$serde_json::private::Number":"literal","alibi::JsValue/v1":"literal"}"#).unwrap();
            let object = value.as_object_mut().unwrap();
            _ = object.insert("nested".into(), json::parse_value(r#"{"iso":"2020-01-01T00:00:00.123456Z","2020-01-01T00:00:00.123456Z":"key stays text"}"#).unwrap());
            _ = object.insert("undefined".into(), JsValue::Undefined);
            _ = object.insert(
                "array".into(),
                JsValue::Array(vec![JsValue::Undefined, JsValue::Null]),
            );
            _ = object.insert(
                "date".into(),
                JsValue::Date(
                    chrono::DateTime::from_timestamp(1_700_000_000, 123_456_789).unwrap(),
                ),
            );
            value
        };
        let physical = json::to_string(&original).unwrap();
        let returned_object = {
            let mut value = original.clone();
            _ = value.as_object_mut().unwrap().insert(
                "literalDate".into(),
                JsValue::String("2020-01-01T00:00:00.123456Z".into()),
            );
            value
        };
        let literal_json =
            JsValue::String(alibi_core::utils::json::JsString::from_code_units(vec![
                34, 0xd800, 34,
            ]));
        let outputs = Arc::new(vec![
            Some(JsValue::String(physical.clone().into())),
            Some(returned_object.clone()),
            Some(literal_json.clone()),
            Some(JsValue::Undefined),
            Some(JsValue::Null),
            Some(JsValue::String("not JSON".into())),
        ]);
        let expected = [
            json::parse_adapter_value(&physical),
            returned_object.clone(),
            json::parse_adapter_string(literal_json.as_js_string().unwrap()),
            JsValue::Undefined,
            JsValue::Null,
            JsValue::Null,
        ];
        let mode = Arc::new(AtomicUsize::new(0));
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut config = AuthConfig::default();
        let cache = Arc::new(alibi_core::store::MemoryCacheAdapter::new());
        config.session.secondary_storage = Some(cache.clone());
        config.session.store_in_database = true;
        let input_events = events.clone();
        let input_mode = mode.clone();
        let input_original = original.clone();
        let output_events = events.clone();
        let output_mode = mode.clone();
        let output_physical = physical.clone();
        _ = config.user.additional_fields.insert(
            "metadata".into(),
            alibi_core::field_policy::FieldConfig::new(serde_json::json!({"type":"json"}))
                .transform_adapter_input(move |value| {
                    if input_mode.load(Ordering::SeqCst) == 6 {
                        assert_eq!(value.as_ref().and_then(JsValue::as_str), Some("not JSON"));
                    } else {
                        assert_eq!(value.as_ref(), Some(&input_original));
                    }
                    input_events.lock().unwrap().push("input");
                    async move { Ok(value) }
                })
                .transform_output(move |value| {
                    output_events.lock().unwrap().push("output");
                    let index = output_mode.load(Ordering::SeqCst);
                    let expected = if index == 6 {
                        "not JSON"
                    } else {
                        &output_physical
                    };
                    assert_eq!(value.as_ref().and_then(JsValue::as_str), Some(expected));
                    if index < 6 {
                        assert!(expected.contains("\\ud800"));
                    }
                    let result = if index == 6 {
                        Err(AuthError::internal("json-output-marker"))
                    } else {
                        Ok(outputs[index].clone())
                    };
                    async move { result }
                }),
        );

        use sea_orm::{ConnectionTrait, Statement};
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        super::migrator::run_migrations(&db).await.unwrap();
        let inner = Arc::new(super::SeaOrmStore::<Schema>::new(config.clone(), db));
        _ = inner
            .scoped_connection()
            .execute_unprepared("ALTER TABLE user ADD COLUMN metadata TEXT NOT NULL DEFAULT '{}'")
            .await
            .unwrap();
        type User = rich::Model;
        let allowed = config.user.additional_fields.clone();
        let config = Arc::new(config);
        let initialized = alibi_core::plugin::AuthInitContext::new(config.clone(), inner.clone())
            .database_with_registered_transforms();
        for index in 0..=6 {
            mode.store(index, Ordering::SeqCst);
            events.lock().unwrap().clear();
            let mut input = CreateUser::new().with_email(format!("json-{index}@fixture.test"));
            _ = input.additional_fields.insert(
                "metadata".into(),
                if index == 6 {
                    JsValue::String("not JSON".into())
                } else {
                    original.clone()
                },
            );
            let result = initialized.create_user_record(input).await;
            assert_eq!(*events.lock().unwrap(), ["input", "output"]);
            if index == 6 {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("json-output-marker")
                );
                continue;
            }
            let record = result.unwrap();
            let metadata = &record.raw_snapshot().values()["metadata"];
            assert_eq!(metadata, &expected[index]);
            if index == 0 {
                assert!(matches!(metadata["nested"]["iso"], JsValue::Date(_)));
            } else if index == 1 {
                assert_eq!(
                    metadata["nested"]["iso"].as_str(),
                    Some("2020-01-01T00:00:00.123456Z")
                );
                assert_eq!(
                    metadata["literalDate"].as_str(),
                    Some("2020-01-01T00:00:00.123456Z")
                );
                assert_eq!(metadata["date"], returned_object["date"]);
            }
            // The authority getter is logical stored JSON, not the mapped public value or an encoded cell.
            assert_eq!(
                record.stored().metadata(),
                json::parse_adapter_value(&physical)
            );

            let row = inner
                .scoped_connection()
                .query_one_raw(Statement::from_sql_and_values(
                    sea_orm::DbBackend::Sqlite,
                    "SELECT metadata FROM user WHERE id = ?",
                    [record.id().into_owned().into()],
                ))
                .await
                .unwrap()
                .unwrap();
            let stored: String = row.try_get("", "metadata").unwrap();
            assert_eq!(stored, physical);
            let response = alibi_core::endpoint::EndpointResponse::json(&record).unwrap();
            assert_eq!(
                response.result().as_ref().unwrap().get("metadata"),
                Some(metadata)
            );
            let http = response.to_response().unwrap();
            let wire = json::parse_value(std::str::from_utf8(&http.body).unwrap()).unwrap();
            if metadata.is_undefined() {
                assert!(wire.get("metadata").is_none());
            } else {
                let expected_wire = json::parse_value(&json::to_string(metadata).unwrap()).unwrap();
                assert_eq!(wire["metadata"], expected_wire);
            }
            let snapshot = record.secondary_snapshot().unwrap();
            let cache_text = json::to_string(&snapshot).unwrap();
            let cached = json::parse_adapter_value(&cache_text);
            let restored =
                <User as AuthUser>::from_secondary_snapshot_record_with_fields(cached, &allowed)
                    .unwrap();
            let cached_value = restored.raw_snapshot().values().get("metadata").unwrap();
            if metadata.is_undefined() {
                assert!(cached_value.is_undefined());
            } else {
                let mut expected_cache =
                    json::parse_value(&json::to_string(metadata).unwrap()).unwrap();
                json::revive_json_dates(&mut expected_cache);
                assert_eq!(*cached_value, expected_cache);
            }
            let token = format!("json-cache-{index}");
            _ = initialized
                .create_session(alibi_core::CreateSession {
                    user_id: record.id().into_owned(),
                    token: Some(token.clone()),
                    expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
                    ip_address: None,
                    user_agent: None,
                    impersonated_by: None,
                    active_organization_id: None,
                    active_team_id: None,
                    additional_fields: Default::default(),
                })
                .await
                .unwrap();
            let callbacks = events.lock().unwrap().len();
            let reader = alibi_core::plugin::AuthInitContext::new(config.clone(), inner.clone())
                .database_with_registered_transforms();
            let cached = reader
                .get_session_user_record(&token)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                events.lock().unwrap().len(),
                callbacks,
                "cache read replayed output transform"
            );
            let actual = &cached.raw_snapshot().values()["metadata"];
            let normalized = if metadata.is_undefined() {
                JsValue::Undefined
            } else {
                json::parse_adapter_value(&json::to_string(metadata).unwrap())
            };
            assert_eq!(actual, &normalized);
            if index < 2 {
                assert!(matches!(actual["nested"]["iso"], JsValue::Date(_)));
                assert!(matches!(actual["date"], JsValue::Date(_)));
                assert_eq!(
                    actual["nested"]["2020-01-01T00:00:00.123456Z"].as_str(),
                    Some("key stays text")
                );
            }
            let JsValue::Date(created) = json::parse_adapter_value(
                &json::to_string(&record.raw_snapshot().values()["createdAt"]).unwrap(),
            ) else {
                panic!("expected public creation date");
            };
            assert_eq!(
                cached.created_at().timestamp_millis(),
                created.timestamp_millis()
            );
            assert_eq!(
                cached.raw_snapshot().values()["createdAt"],
                JsValue::Date(created)
            );
        }
    }

    #[tokio::test]
    async fn non_policy_metadata_getters_decode_logically_without_leaking_sqlite_text() {
        use alibi_core::AuthOrganization;
        use alibi_core::store::OrganizationStore;
        use sea_orm::{ConnectionTrait, FromQueryResult, Statement};
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        super::migrator::run_migrations(&db).await.unwrap();
        let inner = super::SeaOrmStore::<super::bundled_schema::BundledSchema>::new(
            AuthConfig::default(),
            db,
        );
        let physical = r#"{"\ud800":"\udfff","nested":{"iso":"2020-01-01T00:00:00.123456Z"},"alibi::JsValue/v1":"literal","null":null}"#.to_owned();
        let expected = json::parse_adapter_value(&physical);
        let org = inner
            .create_organization(alibi_core::types::CreateOrganization::new(
                "Metadata",
                "logical-metadata",
            ))
            .await
            .unwrap();

        _ = inner
            .scoped_connection()
            .execute_raw(Statement::from_sql_and_values(
                sea_orm::DbBackend::Sqlite,
                "UPDATE organization SET metadata = ? WHERE id = ?",
                [physical.clone().into(), org.id.clone().into()],
            ))
            .await
            .unwrap();
        let row = inner.scoped_connection().query_one_raw(Statement::from_sql_and_values(sea_orm::DbBackend::Sqlite,
        "SELECT 'r' AS id, 'c' AS \"clientId\", 'resource' AS \"resourceId\", ? AS metadata, NULL AS \"createdAt\"", [physical.clone().into()])).await.unwrap().unwrap();
        let model =
            super::entities::oauth_client_resource::Model::from_query_result(&row, "").unwrap();
        let resource = alibi_core::store::OAuthClientResource::try_from(model).unwrap();
        assert_eq!(resource.metadata, expected);
        let org = inner
            .get_organization_by_id(&org.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(org.metadata(), Some(expected.clone()));
        let response = alibi_core::endpoint::EndpointResponse::json(&org).unwrap();
        assert_eq!(
            response.result().as_ref().unwrap()["metadata"].as_str(),
            Some(json::to_string(&expected).unwrap().as_str())
        );
        assert!(matches!(
            org.metadata().unwrap()["nested"]["iso"],
            JsValue::Date(_)
        ));
        let decoded: alibi_core::types::Organization =
            json::from_value(response.result().as_ref().unwrap().clone()).unwrap();
        assert_eq!(
            decoded.metadata,
            Some(JsValue::String(json::to_string(&expected).unwrap().into()))
        );
    }
}

#[cfg(test)]
mod update_hook_tests {
    mod cases {
        include!("../../../../tests/integration/storage/plugin_flows/user_update_patch_cases.rs");
    }

    mod falsy_id_cases {
        include!(
            "../../../../tests/integration/storage/plugin_flows/user_update_falsy_id_cases.rs"
        );
    }

    #[tokio::test]
    async fn falsy_update_ids_bind_on_real_sqlite() {
        let config = std::sync::Arc::new(alibi_core::AuthConfig::default());
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        super::migrator::run_migrations(&db).await.unwrap();
        let store = super::SeaOrmStore::<super::bundled_schema::BundledSchema>::new(config, db);
        falsy_id_cases::exercise(&store).await;
    }

    mod renamed {
        use sea_orm::entity::prelude::*;
        #[derive(
            crate::AuthEntity, Clone, Debug, PartialEq, DeriveEntityModel, serde::Serialize,
        )]
        #[sea_orm(table_name = "renamed_user")]
        #[auth(role = "user", secondary_storage)]
        pub(super) struct Model {
            #[sea_orm(primary_key, auto_increment = false, column_name = "pk")]
            pub id: String,
            #[sea_orm(column_name = "full_name")]
            pub name: String,
            pub email: String,
            #[sea_orm(column_name = "verified")]
            pub email_verified: bool,
            #[sea_orm(column_name = "avatar")]
            pub image: Option<String>,
            pub username: Option<String>,
            #[sea_orm(column_name = "display_name")]
            pub display_username: Option<String>,
            pub role: Option<String>,
            pub banned: Option<bool>,
            #[sea_orm(column_name = "reason")]
            pub ban_reason: Option<String>,
            #[sea_orm(column_name = "expiry")]
            pub ban_expires: Option<DateTimeUtc>,
            #[sea_orm(column_name = "login_method")]
            pub last_login_method: Option<String>,
            #[sea_orm(column_name = "created")]
            pub created_at: DateTimeUtc,
            #[sea_orm(column_name = "updated")]
            pub updated_at: DateTimeUtc,
        }
        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub(super) enum Relation {}
        impl ActiveModelBehavior for ActiveModel {}
    }
    struct RenamedSchema;
    impl alibi_core::AuthSchema for RenamedSchema {
        type User = renamed::Model;
        type Session = <super::bundled_schema::BundledSchema as alibi_core::AuthSchema>::Session;
        type Account = <super::bundled_schema::BundledSchema as alibi_core::AuthSchema>::Account;
        type Verification =
            <super::bundled_schema::BundledSchema as alibi_core::AuthSchema>::Verification;
    }
    #[tokio::test]
    async fn original_input_update_patches_renamed_model_sqlite() {
        use sea_orm::ConnectionTrait;
        let effects = std::sync::Arc::new(cases::Effects::default());
        let config = cases::config(&effects, "display_name");
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        super::migrator::run_migrations(&db).await.unwrap();
        _ = db.execute_unprepared("CREATE TABLE renamed_user (pk TEXT PRIMARY KEY, full_name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, verified BOOLEAN NOT NULL, avatar TEXT, username TEXT, display_name TEXT, role TEXT, banned BOOLEAN, reason TEXT, expiry DATE, login_method TEXT, created DATE NOT NULL, updated DATE NOT NULL)").await.unwrap();
        let store = super::SeaOrmStore::<RenamedSchema>::new(config.clone(), db);
        cases::exercise(
            config,
            std::sync::Arc::new(
                store.with_hooks(vec![std::sync::Arc::new(cases::PhysicalHook(
                    effects.clone(),
                ))]),
            ),
            effects,
        )
        .await;
    }
    #[tokio::test]
    async fn original_input_update_patches_bind_and_rollback_on_real_sqlite() {
        let effects = std::sync::Arc::new(cases::Effects::default());
        let config = cases::config(&effects, "displayUsername");
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        super::migrator::run_migrations(&db).await.unwrap();
        let store =
            super::SeaOrmStore::<super::bundled_schema::BundledSchema>::new(config.clone(), db);
        let store = store.with_hooks(vec![std::sync::Arc::new(cases::PhysicalHook(
            effects.clone(),
        ))]);
        cases::exercise(config, std::sync::Arc::new(store), effects).await;
    }
}

mod accounts;
mod api_key_usage_phases;
mod api_keys;
mod bundled_schema;
mod device_codes;
pub mod entities;
mod invitations;
mod jwks;
mod members;
mod migrator;
mod mysql_snapshot;
mod oauth_clients;
mod organization_roles;
mod organizations;
mod passkeys;
mod scoped_connection;
mod sessions;
mod teams;
mod two_factor;
mod users;
mod verifications;
mod wallets;

#[doc(hidden)]
pub mod __private_test_support {
    pub mod bundled_schema {
        pub use super::super::bundled_schema::BundledSchema;
    }

    pub mod migrator {
        pub use super::super::migrator::{AuthMigrator, run_migrations};
    }
}

use crate::hooks::{DatabaseHooks, SeaOrmBackend, SeaOrmHookContext, current_request_hook_context};
use crate::schema::{
    AuthSchema, SeaOrmAccountModel, SeaOrmSessionModel, SeaOrmUserModel, SeaOrmVerificationModel,
};
use alibi_core::config::AuthConfig;
use alibi_core::error::{AuthError, AuthResult, DatabaseError};
use alibi_core::field_policy::FieldValues;
use alibi_core::store::SchemaMigrator;
use alibi_core::store::adapter::{AfterHook, AfterHookQueue};
use alibi_core::store::{
    AuthTransaction, BoxedTransactionValue, TransactionStore, TransactionWork,
};
use alibi_core::types::{AddTeamMemberResult, CreateJwk, Jwk, Member, Team};
use alibi_core::user_validation::PreparedUserCreation;
use alibi_core::verification::{
    VerificationCreation, VerificationPublication, VerificationSnapshot,
};
use alibi_core::{
    CreateAccount, CreateMember, CreatePasskey, CreateSession, CreateUser, CreateVerification,
    Passkey,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use scoped_connection::{ScopedConnection, ScopedTransaction};
use sea_orm::{DatabaseConnection, DbErr, EntityTrait, SqlErr, TransactionTrait};
use std::marker::PhantomData;
use std::sync::Arc;

#[derive(Clone)]
pub struct SeaOrmStore<S: AuthSchema> {
    config: Arc<AuthConfig>,
    db: ScopedConnection,
    hooks: Vec<Arc<dyn DatabaseHooks<S, SeaOrmBackend>>>,
    _schema: PhantomData<S>,
}

impl<S: AuthSchema> std::fmt::Debug for SeaOrmStore<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeaOrmStore").finish_non_exhaustive()
    }
}

impl<S: AuthSchema> SeaOrmStore<S> {
    pub(crate) async fn generated_id<C: sea_orm::ConnectionTrait>(
        &self,
        db: &C,
        model: &str,
        table: &str,
        column: &str,
    ) -> AuthResult<Option<String>> {
        let policy = &self.config.advanced.database;
        if !policy.serial_ids() {
            return policy.generated_id(model);
        }
        let backend = db.get_database_backend();
        let [ddl, allocate] = alibi_core::config::serial_id_statements(
            table,
            column,
            backend == sea_orm::DbBackend::Postgres,
        );
        _ = db.execute_unprepared(&ddl).await.map_err(map_db_err)?;
        let row = db
            .query_one_raw(sea_orm::Statement::from_string(backend, allocate))
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| AuthError::internal("ID allocation returned no value"))?;
        let value: i64 = row.try_get("", "value").map_err(map_db_err)?;
        Ok(Some(value.to_string()))
    }

    /// `generated_id` for a model entity, naming its table and ID column.
    pub(crate) async fn generated_entity_id<E: EntityTrait, C: sea_orm::ConnectionTrait>(
        &self,
        db: &C,
        model: &str,
        id_column: impl sea_orm::Iden,
    ) -> AuthResult<Option<String>> {
        let table = E::default().table_name().to_owned();
        self.generated_id(db, model, &table, &id_column.to_string())
            .await
    }

    #[must_use]
    pub fn new(config: impl Into<Arc<AuthConfig>>, db: DatabaseConnection) -> Self {
        let config = config.into();
        let schema = config.advanced.database.schema_name.clone();
        let factor = config.advanced.database.two_factor.clone();
        let sso_provider = config.advanced.database.sso_provider.clone();
        Self {
            config,
            db: ScopedConnection {
                inner: db,
                schema,
                factor,
                sso_provider,
            },
            hooks: Vec::new(),
            _schema: PhantomData,
        }
    }

    #[must_use]
    pub fn with_hooks(mut self, hooks: Vec<Arc<dyn DatabaseHooks<S, SeaOrmBackend>>>) -> Self {
        self.hooks = hooks;
        self
    }

    #[must_use]
    pub fn hook<H: DatabaseHooks<S, SeaOrmBackend> + 'static>(mut self, hook: H) -> Self {
        self.hooks.push(Arc::new(hook));
        self
    }

    #[must_use]
    pub(super) const fn scoped_connection(&self) -> &ScopedConnection {
        &self.db
    }

    pub const fn connection(&self) -> &DatabaseConnection {
        &self.db.inner
    }

    #[must_use]
    pub const fn config(&self) -> &Arc<AuthConfig> {
        &self.config
    }

    pub(crate) fn hooks(&self) -> &[Arc<dyn DatabaseHooks<S, SeaOrmBackend>>] {
        &self.hooks
    }

    pub(crate) fn hook_context<'a>(
        &'a self,
        tx: Option<&'a ScopedTransaction>,
    ) -> SeaOrmHookContext<'a> {
        SeaOrmHookContext {
            config: self.config.as_ref(),
            db: &self.db.inner,
            tx: tx.map(|tx| &tx.inner),
            request: current_request_hook_context(),
        }
    }
}

impl<S: AuthSchema> SeaOrmStore<S> {
    async fn migrate_bundled_schema(&self) -> AuthResult<()> {
        if self.db.get_database_backend() == sea_orm::DbBackend::Postgres
            && let Some(schema) = &self.db.schema
        {
            use sea_orm::{ConnectionTrait, Statement};
            use sea_orm_migration::MigratorTrait;
            let quoted = format!("\"{}\"", schema.replace('"', "\"\""));
            _ = self
                .db
                .inner
                .execute_unprepared(&format!("CREATE SCHEMA IF NOT EXISTS {quoted}"))
                .await
                .map_err(map_db_err)?;
            // Only the migration transaction has a local DDL namespace.
            // Runtime connections and statements retain statement qualification.
            let transaction = self.db.inner.begin().await.map_err(map_db_err)?;
            _ = transaction
                .execute_raw(Statement::from_string(
                    sea_orm::DbBackend::Postgres,
                    format!("SET LOCAL search_path TO {quoted}"),
                ))
                .await
                .map_err(map_db_err)?;
            migrator::AuthMigrator::up(&transaction, None)
                .await
                .map_err(map_db_err)?;
            return transaction.commit().await.map_err(map_db_err);
        }
        migrator::run_migrations(&self.db.inner)
            .await
            .map_err(map_db_err)
    }
}

#[async_trait]
impl<S: AuthSchema> SchemaMigrator for SeaOrmStore<S> {
    async fn migrate(&self) -> AuthResult<()> {
        self.migrate_bundled_schema().await?;
        if self.config.advanced.database.serial_ids() {
            use sea_orm::ConnectionTrait;
            let [ddl, _] = alibi_core::config::serial_id_statements("", "", false);
            _ = self.db.execute_unprepared(&ddl).await.map_err(map_db_err)?;
        }
        if let Some(mapping) = &self.config.advanced.database.two_factor {
            use sea_orm::ConnectionTrait;
            let commands = mapping.migration_statements()?;
            let transaction = self.db.begin().await.map_err(map_db_err)?;
            if transaction
                .has_table("twoFactor")
                .await
                .map_err(map_db_err)?
            {
                for command in commands {
                    _ = transaction
                        .execute_unprepared(&command)
                        .await
                        .map_err(map_db_err)?;
                }
            }
            transaction.commit().await.map_err(map_db_err)?;
        }
        if let Some(mapping) = &self.config.advanced.database.sso_provider {
            use sea_orm::ConnectionTrait;
            let commands = mapping.migration_statements()?;
            let transaction = self.db.begin().await.map_err(map_db_err)?;
            if transaction
                .has_table("ssoProvider")
                .await
                .map_err(map_db_err)?
            {
                for command in commands {
                    _ = transaction
                        .execute_unprepared(&command)
                        .await
                        .map_err(map_db_err)?;
                }
            }
            transaction.commit().await.map_err(map_db_err)?;
        }

        let storage = &self.config.advanced.database;
        alibi_core::store::validate_sso_fields(storage)?;
        if !storage.sso_provider_fields.0.is_empty() {
            use sea_orm::ConnectionTrait;
            let table = storage
                .sso_provider
                .as_ref()
                .map_or("ssoProvider", |mapping| mapping.table_name.as_str());
            let transaction = self.db.begin().await.map_err(map_db_err)?;
            for (name, field) in &storage.sso_provider_fields.0 {
                let column = alibi_core::store::sso_field_column(name, field);
                if !transaction
                    .has_column(table, column)
                    .await
                    .map_err(map_db_err)?
                {
                    let definition = alibi_core::store::sso_field_definition(
                        name,
                        field,
                        transaction.get_database_backend() == sea_orm::DbBackend::Postgres,
                    )?;
                    let table = format!("\"{}\"", table.replace('"', "\"\""));
                    _ = transaction
                        .execute_unprepared(&format!("ALTER TABLE {table} ADD COLUMN {definition}"))
                        .await
                        .map_err(map_db_err)?;
                }
            }
            transaction.commit().await.map_err(map_db_err)?;
        }

        Ok(())
    }
}

struct SeaOrmStoreTransaction<'a, S: AuthSchema> {
    store: &'a SeaOrmStore<S>,
    tx: &'a ScopedTransaction,
    pending_after: AfterHookQueue<S>,
}

#[async_trait]
impl<S> AuthTransaction<S> for SeaOrmStoreTransaction<'_, S>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
    S::Account: SeaOrmAccountModel,
    S::Session: SeaOrmSessionModel,
    S::Verification: SeaOrmVerificationModel,
{
    async fn get_scim_connection_binding(
        &self,
        id: &str,
    ) -> AuthResult<Option<alibi_core::store::ScimConnectionBinding>> {
        self.store
            .get_scim_connection_binding_with_connection(self.tx, id)
            .await
    }
    async fn scim_projection_candidates(
        &self,
        domain: &str,
        cursor: Option<&str>,
    ) -> AuthResult<Vec<alibi_core::store::ScimProjectionCandidate>> {
        self.store
            .scim_projection_candidates_with_connection(self.tx, domain, cursor)
            .await
    }
    async fn renew_scim_decommission_lease(
        &self,
        binding: &alibi_core::store::ScimConnectionBinding,
        lease: &str,
    ) -> AuthResult<bool> {
        self.store
            .renew_scim_decommission_lease_with_connection(self.tx, binding, lease)
            .await
    }
    async fn advance_scim_decommission(
        &self,
        binding: &alibi_core::store::ScimConnectionBinding,
        lease: &str,
        cursor: Option<&str>,
        count: usize,
        more: bool,
    ) -> AuthResult<Option<alibi_core::store::ScimConnectionBinding>> {
        self.store
            .advance_scim_decommission_with_connection(self.tx, binding, lease, cursor, count, more)
            .await
    }
    async fn reconcile_scim_identity(
        &self,
        user_id: &str,
    ) -> AuthResult<alibi_core::store::ScimIdentityState> {
        self.store
            .reconcile_scim_identity_with_connection(self.tx, user_id)
            .await
    }
    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
        use sea_orm::{ColumnTrait, QueryFilter};
        let sessions = self.get_user_sessions(user_id).await?;
        let context = self.store.hook_context(Some(self.tx));
        for session in &sessions {
            for hook in self.store.hooks() {
                if hook
                    .before_delete_session(session, &context)
                    .await?
                    .is_cancelled()
                {
                    return Ok(());
                }
            }
        }
        _ = <S::Session as SeaOrmSessionModel>::Entity::delete_many()
            .filter(
                S::Session::user_id_column()
                    .eq(<S::Session as SeaOrmSessionModel>::parse_user_id(user_id)?),
            )
            .exec(self.tx)
            .await
            .map_err(map_db_err)?;
        for session in sessions {
            self.pending_after
                .push(AfterHook::SessionDeleted(session))
                .await;
        }
        Ok(())
    }
    async fn queue_session_revocation(
        &self,
        session_ids: &[String],
        revocation: Arc<dyn alibi_core::store::SessionRevocation>,
    ) -> AuthResult<()> {
        self.pending_after
            .attach_session_revocation(session_ids, revocation)
            .await;
        Ok(())
    }
    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<S::Session>> {
        use sea_orm::{ColumnTrait, QueryFilter, QuerySelect};
        <S::Session as SeaOrmSessionModel>::Entity::find()
            .filter(S::Session::user_id_column().eq(S::Session::parse_user_id(user_id)?))
            .limit(
                u64::try_from(
                    self.store
                        .config()
                        .advanced
                        .database
                        .default_find_many_limit,
                )
                .unwrap_or(u64::MAX),
            )
            .all(self.tx)
            .await
            .map_err(map_db_err)
    }
    async fn list_oauth_tokens_for_session(
        &self,
        kind: alibi_core::store::OAuthTokenKind,
        session_id: &str,
    ) -> AuthResult<Vec<alibi_core::store::OAuthToken>> {
        self.store
            .session_oauth_tokens(self.tx, kind, session_id)
            .await
    }
    async fn get_oauth_client(
        &self,
        client_id: &str,
    ) -> AuthResult<Option<alibi_core::store::OAuthClient>> {
        self.store
            .oauth_client_with_connection(self.tx, client_id)
            .await
    }
    async fn queue_session_deletion_work(
        &self,
        session_id: &str,
        works: Vec<Box<dyn alibi_core::store::SessionDeletionWork<S>>>,
        context: Arc<alibi_core::AuthContext<S>>,
    ) -> AuthResult<()> {
        self.pending_after
            .attach_session_retirement(session_id, works, context)
            .await;
        Ok(())
    }
    async fn check_scim_user_attributes(
        &self,
        id: &str,
        connection: &str,
        attributes: &alibi_core::store::ScimUserAttributes,
    ) -> AuthResult<()> {
        self.store
            .assert_scim_user_keys_with_connection(
                self.tx,
                connection,
                &attributes.user_name_key,
                attributes.external_id_key.as_deref(),
                None,
                Some(id),
            )
            .await
    }
    async fn lock_scim_user(
        &self,
        id: &str,
        connection: &str,
        domain: &str,
        attributes: Option<&alibi_core::store::ScimUserAttributes>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<alibi_core::store::ScimUserMutationContext> {
        self.store
            .lock_scim_user_with_connection(self.tx, id, connection, domain, attributes, now)
            .await
    }
    async fn replace_scim_user(
        &self,
        id: &str,
        data: alibi_core::store::ReplaceScimUser,
        roles: bool,
    ) -> AuthResult<(
        alibi_core::store::ScimUserRecord,
        Vec<alibi_core::store::ScimProjectionPreparedUser>,
    )> {
        self.store
            .replace_scim_user_with_connection(self.tx, id, data, roles)
            .await
    }
    async fn create_scim_user(
        &self,
        data: alibi_core::store::CreateScimUser,
        roles: bool,
    ) -> AuthResult<(
        alibi_core::store::ScimUserRecord,
        Vec<alibi_core::store::ScimProjectionPreparedUser>,
    )> {
        self.store
            .create_scim_user_with_connection(self.tx, data, roles)
            .await
    }
    async fn delete_scim_user(
        &self,
        id: &str,
        connection: &str,
        domain: &str,
        roles: bool,
    ) -> AuthResult<(String, Vec<alibi_core::store::ScimProjectionPreparedUser>)> {
        self.store
            .delete_scim_user_with_connection(self.tx, id, connection, domain, roles)
            .await
    }
    async fn patch_scim_group(
        &self,
        id: &str,
        connection: &str,
        domain: &str,
        patch: alibi_core::store::ScimGroupPatch,
        roles: bool,
    ) -> AuthResult<(
        alibi_core::store::ScimGroupRecord,
        Vec<alibi_core::store::ScimProjectionPreparedUser>,
    )> {
        self.store
            .patch_scim_group_with_connection(self.tx, id, connection, domain, patch, roles)
            .await
    }
    async fn replace_scim_group(
        &self,
        id: &str,
        data: alibi_core::store::ReplaceScimGroup,
        roles: bool,
    ) -> AuthResult<(
        alibi_core::store::ScimGroupRecord,
        Vec<alibi_core::store::ScimProjectionPreparedUser>,
    )> {
        self.store
            .replace_scim_group_with_connection(self.tx, id, data, roles)
            .await
    }
    async fn delete_scim_group(
        &self,
        id: &str,
        connection: &str,
        domain: &str,
        roles: bool,
    ) -> AuthResult<Vec<alibi_core::store::ScimProjectionPreparedUser>> {
        self.store
            .delete_scim_group_with_connection(self.tx, id, connection, domain, roles)
            .await
    }
    async fn create_scim_group(
        &self,
        data: alibi_core::store::CreateScimGroup,
        roles: bool,
    ) -> AuthResult<(
        alibi_core::store::ScimGroupRecord,
        Vec<alibi_core::store::ScimProjectionPreparedUser>,
    )> {
        self.store
            .create_scim_group_with_connection(self.tx, data, roles)
            .await
    }
    async fn fence_scim_connection(&self, id: &str, key: &str) -> AuthResult<()> {
        self.store
            .fence_scim_connection_with_connection(self.tx, id, key)
            .await
    }
    async fn prepare_scim_projection(
        &self,
        domain: &str,
        ids: &[String],
        roles: bool,
    ) -> AuthResult<Vec<alibi_core::store::ScimProjectionPreparedUser>> {
        self.store
            .prepare_scim_projection_with_connection(self.tx, domain, ids, roles)
            .await
    }
    async fn create_scim_projection_grant(
        &self,
        data: alibi_core::store::CreateScimProjectionGrant,
    ) -> AuthResult<()> {
        self.store
            .create_scim_projection_grant_with_connection(self.tx, data)
            .await
    }
    async fn remove_scim_projection_grants(
        &self,
        domain: &str,
        user_id: &str,
        ids: &[String],
    ) -> AuthResult<()> {
        self.store
            .remove_scim_projection_grants_with_connection(self.tx, domain, user_id, ids)
            .await
    }
    async fn get_user_by_email(
        &self,
        email: &alibi_core::utils::json::JsString,
    ) -> AuthResult<Option<S::User>> {
        self.store
            .get_user_by_email_with_connection(self.tx, email)
            .await
    }
    async fn get_account(
        &self,
        provider: &str,
        account_id: &alibi_core::utils::json::JsString,
    ) -> AuthResult<Option<S::Account>> {
        self.store
            .get_account_with_connection(self.tx, provider, account_id)
            .await
    }
    async fn update_user(&self, id: &str, update: alibi_core::UpdateUser) -> AuthResult<S::User> {
        self.update_user_prepared(
            id,
            alibi_core::store::PreparedUserUpdate::from_typed(&update),
        )
        .await
    }
    async fn update_user_prepared(
        &self,
        id: &str,
        update: alibi_core::store::PreparedUserUpdate,
    ) -> AuthResult<S::User> {
        let user = self
            .store
            .update_user_prepared_with_connection(self.tx, Some(self.tx), id, update)
            .await?;
        self.pending_after
            .push(AfterHook::UserUpdated(user.clone()))
            .await;
        Ok(user)
    }
    async fn update_account(
        &self,
        id: &str,
        update: alibi_core::UpdateAccount,
    ) -> AuthResult<S::Account> {
        let account = self
            .store
            .update_account_with_connection(self.tx, Some(self.tx), id, update)
            .await?;
        self.pending_after
            .push(AfterHook::AccountUpdated(account.clone()))
            .await;
        Ok(account)
    }
    async fn lock_sso_provider(
        &self,
        id: &str,
        provider_id: &str,
    ) -> AuthResult<Option<alibi_core::store::SsoProvider>> {
        self.store
            .lock_sso_provider_with(self.tx, id, provider_id)
            .await
    }
    async fn update_sso_provider(
        &self,
        update: alibi_core::store::SsoProviderUpdate,
    ) -> AuthResult<Option<alibi_core::store::SsoProvider>> {
        self.store.update_sso_provider_with(self.tx, update).await
    }
    async fn delete_sso_provider_and_accounts(
        &self,
        id: &str,
        provider_id: &str,
    ) -> AuthResult<bool> {
        self.store
            .delete_sso_provider_with(self.tx, id, provider_id)
            .await
    }
    async fn list_jwks(&self) -> AuthResult<Vec<Jwk>> {
        self.store.list_jwks_with_connection(self.tx).await
    }
    async fn get_jwk_by_id(&self, id: &str) -> AuthResult<Option<Jwk>> {
        self.store.get_jwk_with_connection(self.tx, id).await
    }
    async fn create_jwk(&self, data: CreateJwk) -> AuthResult<Jwk> {
        self.store.create_jwk_with_connection(self.tx, data).await
    }

    async fn get_team(&self, organization_id: &str, team_id: &str) -> AuthResult<Option<Team>> {
        self.store
            .get_team_with_connection(self.tx, Some(organization_id), team_id)
            .await
    }
    async fn add_team_member(
        &self,
        team_id: &str,
        user_id: &str,
        maximum: Option<f64>,
    ) -> AuthResult<AddTeamMemberResult> {
        self.store
            .add_team_member_in_tx(self.tx, team_id, user_id, maximum)
            .await
    }
    async fn create_member(&self, member: CreateMember) -> AuthResult<Member> {
        self.store
            .create_member_with_connection(self.tx, member)
            .await
    }
    async fn update_session_active_team(
        &self,
        token: &str,
        team_id: Option<&str>,
    ) -> AuthResult<S::Session> {
        self.store
            .update_session_scope_with_connection(
                self.tx,
                token,
                sessions::SessionScope::Team(team_id),
            )
            .await
    }
    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<S::Session> {
        self.store
            .update_session_scope_with_connection(
                self.tx,
                token,
                sessions::SessionScope::Organization(organization_id),
            )
            .await
    }
    async fn native_user_output(
        &self,
        id: &str,
    ) -> AuthResult<std::collections::BTreeMap<String, alibi_core::utils::json::JsValue>> {
        users::native_user_output::<S::User, _>(self.tx, id).await
    }

    async fn provider_verification_output(
        &self,
        id: &str,
    ) -> AuthResult<Option<serde_json::Value>> {
        users::provider_verification_output::<S::User, _>(self.tx, id).await
    }
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<S::User>> {
        use sea_orm::{ColumnTrait, QueryFilter};
        let id = S::User::parse_id(id)?;
        users::user_query::<S::User>(self.tx.get_database_backend())
            .filter(S::User::id_column().eq(id))
            .one(self.tx)
            .await
            .map_err(map_db_err)
    }
    async fn get_user_by_username_value(
        &self,
        username: &alibi_core::utils::json::JsValue,
    ) -> AuthResult<Option<S::User>> {
        self.store
            .get_user_by_username_value_with_connection(self.tx, username)
            .await
    }
    async fn create_passkey(&self, data: CreatePasskey) -> AuthResult<Passkey> {
        self.store
            .create_passkey_with_connection(self.tx, data)
            .await
    }
    async fn create_user(&self, create_user: CreateUser) -> AuthResult<S::User> {
        let user = self.store.create_user_in_tx(self.tx, create_user).await?;
        self.pending_after
            .push(AfterHook::UserCreated(user.clone()))
            .await;
        Ok(user)
    }

    async fn create_user_prepared(&self, prepared: PreparedUserCreation) -> AuthResult<S::User> {
        let user = self
            .store
            .create_user_prepared_in_tx(self.tx, prepared)
            .await?;
        self.pending_after
            .push(AfterHook::UserCreated(user.clone()))
            .await;
        Ok(user)
    }

    async fn create_account(&self, create_account: CreateAccount) -> AuthResult<S::Account> {
        let account = self
            .store
            .create_account_in_tx(self.tx, create_account)
            .await?;
        self.pending_after
            .push(AfterHook::AccountCreated(account.clone()))
            .await;
        Ok(account)
    }

    async fn prepare_secondary_session_update(
        &self,
        session: S::Session,
        expires_at: Option<DateTime<Utc>>,
        fields: FieldValues,
    ) -> AuthResult<Option<(S::Session, FieldValues)>> {
        self.store
            .prepare_secondary_update_with_connection(
                self.tx,
                Some(self.tx),
                session,
                expires_at,
                fields,
            )
            .await
    }
    async fn complete_secondary_session_update(
        &self,
        token: &str,
        session: S::Session,
        expires_at: Option<DateTime<Utc>>,
        fields: FieldValues,
        persist: bool,
    ) -> AuthResult<Option<S::Session>> {
        let result = self
            .store
            .complete_secondary_update_with_connection(
                self.tx,
                Some(self.tx),
                token,
                session,
                expires_at,
                fields,
                persist,
            )
            .await?;
        let event = result.as_ref().map_or_else(
            || AfterHook::SessionUpdateMissing(token.to_owned()),
            |model| AfterHook::SessionUpdated(model.clone()),
        );
        self.pending_after.push(event).await;
        Ok(result)
    }
    async fn queue_session_publication(
        &self,
        session_id: &str,
        publication: Arc<dyn alibi_core::session::SessionPublication>,
    ) -> AuthResult<()> {
        self.pending_after
            .attach_session_publication(session_id, publication)
            .await
    }

    async fn prepare_secondary_session_creation(
        &self,
        input: CreateSession,
        persist: bool,
    ) -> AuthResult<S::Session> {
        let session = self
            .store
            .prepare_secondary_session_in_tx(self.tx, input, persist)
            .await?;
        self.pending_after
            .push(AfterHook::SessionCreated(session.clone()))
            .await;
        Ok(session)
    }
    async fn create_session(&self, create_session: CreateSession) -> AuthResult<S::Session> {
        let session = self
            .store
            .create_session_in_tx(self.tx, create_session)
            .await?;
        self.pending_after
            .push(AfterHook::SessionCreated(session.clone()))
            .await;
        Ok(session)
    }
    async fn create_verification_record(
        &self,
        data: VerificationCreation,
        publication: VerificationPublication,
    ) -> AuthResult<Option<VerificationSnapshot>> {
        let snapshot = self
            .store
            .create_verification_record_with_connection(self.tx, Some(self.tx), data, publication)
            .await?;
        if let Some(snapshot) = &snapshot {
            self.pending_after
                .push(AfterHook::VerificationRecordCreated(snapshot.clone()))
                .await;
        }
        Ok(snapshot)
    }

    async fn create_verification(
        &self,
        verification: CreateVerification,
    ) -> AuthResult<S::Verification> {
        let verification = self
            .store
            .create_verification_in_tx(self.tx, verification)
            .await?;
        self.pending_after
            .push(AfterHook::VerificationCreated(verification.clone()))
            .await;
        Ok(verification)
    }
    async fn consume_verification_snapshot(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        let consumed = self
            .store
            .consume_generation_in(self.tx, identifier, None)
            .await?;
        if let Some(verification) = &consumed {
            self.pending_after
                .push(AfterHook::VerificationDeleted(verification.clone()))
                .await;
        }
        Ok(consumed)
    }
}

#[async_trait]
impl<S> TransactionStore<S> for SeaOrmStore<S>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
    S::Account: SeaOrmAccountModel,
    S::Session: SeaOrmSessionModel,
    S::Verification: SeaOrmVerificationModel,
{
    async fn transaction_boxed(
        &self,
        work: Box<TransactionWork<S>>,
    ) -> AuthResult<BoxedTransactionValue> {
        self.transaction_boxed_with_policy(
            work,
            alibi_core::store::AfterCommitErrorPolicy::Propagate,
        )
        .await
    }
    async fn transaction_boxed_with_policy(
        &self,
        work: Box<TransactionWork<S>>,
        policy: alibi_core::store::AfterCommitErrorPolicy,
    ) -> AuthResult<BoxedTransactionValue> {
        let tx = self.db.begin().await.map_err(map_db_err)?;
        self.run_transaction(tx, work, policy).await
    }
    async fn write_transaction_boxed(
        &self,
        work: Box<TransactionWork<S>>,
    ) -> AuthResult<BoxedTransactionValue> {
        let tx = self.db.begin_immediate().await?;
        self.run_transaction(
            tx,
            work,
            alibi_core::store::AfterCommitErrorPolicy::Propagate,
        )
        .await
    }
}

impl<S> SeaOrmStore<S>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
    S::Account: SeaOrmAccountModel,
    S::Session: SeaOrmSessionModel,
    S::Verification: SeaOrmVerificationModel,
{
    async fn run_transaction(
        &self,
        tx: ScopedTransaction,
        work: Box<TransactionWork<S>>,
        policy: alibi_core::store::AfterCommitErrorPolicy,
    ) -> AuthResult<BoxedTransactionValue> {
        let tx_store = SeaOrmStoreTransaction {
            store: self,
            tx: &tx,
            pending_after: AfterHookQueue::new(),
        };
        let outcome = work(&tx_store).await;
        let pending_after = tx_store.pending_after;
        match outcome {
            Ok(value) => {
                tx.commit().await.map_err(map_db_err)?;
                // After hooks run only once the auth writes are durable, in
                // operation order; rollback drops them.
                pending_after
                    .run_with_policy(self.hooks(), &self.hook_context(None), policy)
                    .await?;
                Ok(value)
            }
            Err(err) => {
                tx.rollback().await.map_err(map_db_err)?;
                Err(err)
            }
        }
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "Result::map_err transfers ownership to this error-boundary adapter"
)]
pub(crate) fn map_db_err(err: DbErr) -> AuthError {
    match err.sql_err() {
        Some(
            SqlErr::UniqueConstraintViolation(message)
            | SqlErr::ForeignKeyConstraintViolation(message),
        ) => AuthError::Database(DatabaseError::Constraint(message)),
        Some(_) | None => AuthError::Database(DatabaseError::Query(err.to_string())),
    }
}

/// Preserve backend validation of raw numeric `LIMIT`/`OFFSET` values.
pub(crate) fn bind_page(
    mut statement: sea_orm::Statement,
    limit: Option<f64>,
    offset: Option<f64>,
) -> AuthResult<sea_orm::Statement> {
    use sea_orm::{DbBackend, Value, Values};
    use std::fmt::Write;
    for (clause, number) in [("LIMIT", limit), ("OFFSET", offset)] {
        if let Some(number) = number {
            if statement.db_backend == DbBackend::MySql {
                // mysql2 interpolates Number parameters; prepared doubles are
                // rejected even for integral pages. Fractional literals must fail.
                _ = write!(
                    statement.sql,
                    " {clause} {}",
                    ryu_js::Buffer::new().format(number)
                );
                continue;
            }
            let values = statement.values.get_or_insert_with(|| Values(Vec::new()));
            let placeholder = match statement.db_backend {
                DbBackend::Postgres => format!("${}", values.0.len() + 1),
                DbBackend::Sqlite => "?".into(),
                _ => {
                    return Err(AuthError::not_implemented(
                        "Raw numeric pages are not supported by this database backend",
                    ));
                }
            };
            _ = write!(statement.sql, " {clause} {placeholder}");
            if statement.db_backend == DbBackend::Postgres {
                // node-postgres sends Number parameters as text. Binding float8
                // instead lets PostgreSQL round fractional pages to bigint.
                statement.sql.push_str("::bigint");
                values.0.push(Value::String(Some(
                    ryu_js::Buffer::new().format(number).to_owned(),
                )));
            } else {
                values.0.push(Value::Double(Some(number)));
            }
        }
    }
    Ok(statement)
}

mod sso;

mod scim;
mod scim_decommission;
mod scim_groups;
mod scim_projection;
mod scim_user_create;
mod scim_user_replace;
mod scim_users;
