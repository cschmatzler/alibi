//! Native user metadata persistence must preserve valid application JSON keys.

#[cfg(feature = "seaorm2")]
#[expect(unreachable_pub, reason = "SeaORM derive requires public model fields")]
mod custom_user {
    use better_auth_seaorm::sea_orm::entity::prelude::*;
    use better_auth_seaorm::{AuthEntity, sea_orm};
    #[derive(Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "user")]
    #[sea_orm(table_name = "custom_metadata_users")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: Option<String>,
        pub email: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        pub metadata: better_auth_seaorm::JsonMetadata,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
        pub tenant: Option<String>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

use better_auth::{AuthBuilder, AuthConfig};
use better_auth_core::{AuthUser, CreateUser, UpdateUser};
use better_auth_seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};
use better_auth_seaorm::{Database, SeaOrmStore};

type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

struct MetadataHook;

#[async_trait::async_trait]
impl better_auth_seaorm::DatabaseHooks<Schema, better_auth_seaorm::SeaOrm> for MetadataHook {
    async fn before_create_user(
        &self,
        user: &mut CreateUser,
        _ctx: &better_auth_seaorm::SeaOrmHookContext<'_>,
    ) -> better_auth_core::AuthResult<better_auth_seaorm::HookControl> {
        user.metadata.as_mut().unwrap()["hookRounded"] =
            serde_json::Value::from(9_007_199_254_740_993_u64);
        Ok(better_auth_seaorm::HookControl::Continue)
    }
    async fn before_update_user(
        &self,
        _id: &str,
        update: &mut UpdateUser,
        _ctx: &better_auth_seaorm::SeaOrmHookContext<'_>,
    ) -> better_auth_core::AuthResult<better_auth_seaorm::HookControl> {
        if let Some(metadata) = &mut update.metadata {
            metadata["hookRounded"] = serde_json::Value::from(9_007_199_254_740_993_u64);
        }
        Ok(better_auth_seaorm::HookControl::Continue)
    }
}

#[cfg(feature = "seaorm2")]
struct CustomSchema;

#[cfg(feature = "seaorm2")]
impl better_auth_core::AuthSchema for CustomSchema {
    type User = custom_user::Model;
    type Session = better_auth_seaorm::store::entities::session::Model;
    type Account = better_auth_seaorm::store::entities::account::Model;
    type Verification = better_auth_seaorm::store::entities::verification::Model;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn prepared_metadata_replacement_persists_the_edited_value() {
        use better_auth_seaorm::sea_orm::{ActiveModelTrait, ActiveValue::Set, IntoActiveModel};
        use better_auth_seaorm::store::entities::organization;
        use better_auth_seaorm::{JsonMetadata, json_metadata::prepare_metadata_value};
        let db = Database::connect("sqlite::memory:").await.unwrap();
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&db)
            .await
            .unwrap();
        let prepared: JsonMetadata = prepare_metadata_value(
            JsonMetadata::from(serde_json::json!({"version":"old","fixed":1e20})),
            DbBackend::Sqlite,
        )
        .unwrap();
        let mut value: serde_json::Value = prepared.into();
        drop(
            value
                .as_object_mut()
                .expect("metadata is an object")
                .insert("version".to_owned(), serde_json::json!("edited")),
        );
        let prepared_2 =
            prepare_metadata_value(JsonMetadata::from(value), DbBackend::Sqlite).unwrap();
        let inserted = organization::ActiveModel {
            id: Set("prepared-metadata".into()),
            name: Set("Prepared".into()),
            slug: Set("prepared-metadata".into()),
            logo: Set(None),
            metadata: Set(Some(prepared_2)),
            created_at: Set(chrono::Utc::now()),
            updated_at: Set(chrono::Utc::now()),
        }
        .insert(&db)
        .await
        .unwrap();
        assert_eq!(inserted.metadata.as_ref().unwrap()["version"], "edited");
        let mut value_2: serde_json::Value = inserted.metadata.clone().unwrap().into();
        drop(
            value_2
                .as_object_mut()
                .expect("metadata is an object")
                .insert("version".to_owned(), serde_json::json!("updated")),
        );
        let mut active = inserted.into_active_model();
        active.metadata = Set(Some(
            prepare_metadata_value(JsonMetadata::from(value_2), DbBackend::Sqlite).unwrap(),
        ));
        let updated = active.update(&db).await.unwrap();
        assert_eq!(updated.metadata.as_ref().unwrap()["version"], "updated");
        let row = db
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT metadata FROM organization WHERE id = ?",
                ["prepared-metadata".into()],
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row.try_get::<String>("", "metadata").unwrap(),
            r#"{"version":"updated","fixed":100000000000000000000}"#
        );
    }

    // Real user store + SQLx model decode detects the private marker collision.
    // SQL text and native number bits additionally catch response-only/pre-normalized fixes.
    #[tokio::test]
    async fn native_user_metadata_survives_storage_lookup_and_partial_update() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&db)
            .await
            .unwrap();
        let config = AuthConfig::new("user-json-persistence-secret-minimum-32-characters");
        let auth = AuthBuilder::new(config.clone())
            .store(SeaOrmStore::<Schema>::new(config, db.clone()).hook(MetadataHook))
            .build()
            .await
            .unwrap();
        let metadata = serde_json::json!({"private":[{"$serde_json::private::Number":"1e400"},{"$serde_json::private::RawValue":"hello"}],"rounded":9_007_199_254_740_993_u64,"fixed":1e20,"tiny":3.873_063_935_476_172_6e-71,"zero":-0.0,"id":"9007199254740993"});
        let user = auth
            .store()
            .create_user(
                CreateUser::new()
                    .with_email("metadata@user-json.fixture.test")
                    .with_metadata(metadata),
            )
            .await
            .unwrap();
        let id = user.id().into_owned();
        assert_eq!(user.metadata()["rounded"], 9_007_199_254_740_992_u64);
        assert_eq!(user.metadata()["hookRounded"], 9_007_199_254_740_992_u64);
        assert_eq!(
            user.metadata()["tiny"].as_f64().unwrap().to_bits(),
            0x3151_1b97_697f_234c
        );
        assert_eq!(
            (*(*(*(user.metadata())
                .get("private")
                .unwrap_or(&serde_json::Value::Null))
            .get(1)
            .unwrap_or(&serde_json::Value::Null))
            .get("$serde_json::private::RawValue")
            .unwrap_or(&serde_json::Value::Null)),
            "hello"
        );
        let read = auth.store().get_user_by_id(&id).await.unwrap().unwrap();
        assert_eq!(read.metadata(), user.metadata());
        let renamed = auth
            .store()
            .update_user(
                &id,
                UpdateUser {
                    name: Some("Readback".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(renamed.metadata(), user.metadata());
        let row = db
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT metadata FROM users WHERE id = ?",
                [id.clone().into()],
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row.try_get::<String>("", "metadata").unwrap(),
            r#"{"private":[{"$serde_json::private::Number":"1e400"},{"$serde_json::private::RawValue":"hello"}],"rounded":9007199254740992,"fixed":100000000000000000000,"tiny":3.8730639354761726e-71,"zero":0,"id":"9007199254740993","hookRounded":9007199254740992}"#
        );
        let replacement = serde_json::json!({"updated":{"$serde_json::private::RawValue":"hello"},"rounded":9_007_199_254_740_993_u64,"fixed":1e20});
        let updated = auth
            .store()
            .update_user(
                &id,
                UpdateUser {
                    metadata: Some(replacement),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.id().as_ref(), id);
        assert_eq!(updated.metadata()["rounded"], 9_007_199_254_740_992_u64);
        assert_eq!(
            auth.store()
                .get_user_by_email("metadata@user-json.fixture.test")
                .await
                .unwrap()
                .unwrap()
                .metadata(),
            updated.metadata()
        );
        let row_2 = db
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT metadata FROM users WHERE id = ?",
                [id.into()],
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row_2.try_get::<String>("", "metadata").unwrap(),
            r#"{"updated":{"$serde_json::private::RawValue":"hello"},"rounded":9007199254740992,"fixed":100000000000000000000,"hookRounded":9007199254740992}"#
        );
    }

    // Custom model/derive support is a separate public integration contract: the
    // bundled entity alone cannot prove the macro supplies backend-aware bindings.
    #[cfg(feature = "seaorm2")]
    #[tokio::test]
    async fn custom_user_metadata_derive_prepares_json_without_changing_extra_fields() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        let schema = better_auth_seaorm::sea_orm::Schema::new(DbBackend::Sqlite);
        _ = db
            .execute(&schema.create_table_from_entity(custom_user::Entity))
            .await
            .unwrap();
        let config = AuthConfig::new("custom-json-persistence-secret-minimum-32-characters");
        let auth = AuthBuilder::new(config.clone())
            .store(SeaOrmStore::<CustomSchema>::new(config, db.clone()))
            .build()
            .await
            .unwrap();
        let input = serde_json::json!({"$serde_json::private::RawValue":"hello","rounded":9_007_199_254_740_993_u64,"fixed":1e20,"tiny":3.873_063_935_476_172_6e-71});
        let user = auth
            .store()
            .create_user(
                CreateUser::new()
                    .with_email("custom@user-json.fixture.test")
                    .with_metadata(input),
            )
            .await
            .unwrap();
        assert!(user.tenant.is_none());
        assert_eq!(user.metadata()["$serde_json::private::RawValue"], "hello");
        assert_eq!(user.metadata()["rounded"], 9_007_199_254_740_992_u64);
        assert_eq!(
            user.metadata()["tiny"].as_f64().unwrap().to_bits(),
            0x3151_1b97_697f_234c
        );
        let id = user.id().into_owned();
        let read = auth.store().get_user_by_id(&id).await.unwrap().unwrap();
        assert_eq!(read.metadata(), user.metadata());
        let update = serde_json::json!({"$serde_json::private::Number":"1e400","$serde_json::private::RawValue":"hello","fixed":1e20,"rounded":9_007_199_254_740_993_u64});
        let updated = auth
            .store()
            .update_user(
                &id,
                UpdateUser {
                    metadata: Some(update),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(updated.tenant.is_none());
        assert_eq!(updated.metadata()["$serde_json::private::Number"], "1e400");
        assert_eq!(
            updated.metadata()["$serde_json::private::RawValue"],
            "hello"
        );
        assert_eq!(updated.metadata()["rounded"], 9_007_199_254_740_992_u64);
        let row = db
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT metadata, tenant FROM custom_metadata_users WHERE id = ?",
                [id.into()],
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row.try_get::<String>("", "metadata").unwrap(),
            r#"{"$serde_json::private::Number":"1e400","$serde_json::private::RawValue":"hello","fixed":100000000000000000000,"rounded":9007199254740992}"#
        );
        assert!(
            row.try_get::<Option<String>>("", "tenant")
                .unwrap()
                .is_none()
        );
        assert!(
            (*(serde_json::to_value(&updated).unwrap())
                .get("metadata")
                .unwrap_or(&serde_json::Value::Null))
            .is_object()
        );
    }
}
