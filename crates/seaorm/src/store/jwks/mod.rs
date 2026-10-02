use super::entities::jwk::{ActiveModel, Entity};
use super::{SeaOrmStore, map_db_err};
use crate::schema::AuthSchema;
use async_trait::async_trait;
use better_auth_core::error::AuthResult;
use better_auth_core::store::JwkStore;
use better_auth_core::types::{CreateJwk, Jwk};
use sea_orm::{ActiveModelTrait, EntityTrait, QuerySelect, Set};
use sea_orm_migration::prelude::*;

#[async_trait]
impl<S: AuthSchema> JwkStore for SeaOrmStore<S> {
    async fn list_jwks(&self) -> AuthResult<Vec<Jwk>> {
        Entity::find()
            .limit(self.config().advanced.database.default_find_many_limit as u64)
            .all(self.connection())
            .await
            .map(|rows| rows.into_iter().map(Into::into).collect())
            .map_err(map_db_err)
    }
    async fn get_jwk_by_id(&self, id: &str) -> AuthResult<Option<Jwk>> {
        Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map(|row| row.map(Into::into))
            .map_err(map_db_err)
    }
    async fn create_jwk(&self, data: CreateJwk) -> AuthResult<Jwk> {
        ActiveModel {
            id: Set(data.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string())),
            public_key: Set(data.public_key),
            private_key: Set(data.private_key),
            created_at: Set(data.created_at),
            expires_at: Set(data.expires_at),
            alg: Set(data.alg),
            crv: Set(data.crv),
        }
        .insert(self.connection())
        .await
        .map(Into::into)
        .map_err(map_db_err)
    }
}

pub(super) struct JwkKeys;

impl MigrationName for JwkKeys {
    fn name(&self) -> &'static str {
        "m20260930_000004_jwk_keys"
    }
}

#[async_trait]
impl MigrationTrait for JwkKeys {
    #[expect(
        elided_lifetimes_in_paths,
        reason = "SeaORM MigrationTrait requires its implicit manager lifetime to remain late-bound"
    )]
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let schema = sea_orm::Schema::new(manager.get_connection().get_database_backend());
        manager
            .create_table(
                schema
                    .create_table_from_entity(Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{bundled_schema::BundledSchema, migrator::run_migrations};
    use chrono::{Duration, Utc};
    use sea_orm::Database;
    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    async fn persists_private_key_material_and_lists_expired_legacy_keys()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect("sqlite::memory:").await?;
        run_migrations(&database).await?;
        let store = SeaOrmStore::<BundledSchema>::new(
            better_auth_core::AuthConfig::new("keyring-local-test-secret-long-enough"),
            database,
        );
        let now = Utc::now();
        for (id, created_at, expires_at, alg, crv) in [
            (
                "legacy",
                now - Duration::days(3),
                Some(now - Duration::days(1)),
                None,
                None,
            ),
            (
                "current",
                now,
                None,
                Some("ES256".to_owned()),
                Some("P-256".to_owned()),
            ),
        ] {
            drop(
                store
                    .create_jwk(CreateJwk {
                        id: Some(id.to_owned()),
                        public_key: "public JSON".to_owned(),
                        private_key: "encrypted private JSON".to_owned(),
                        created_at,
                        expires_at,
                        alg,
                        crv,
                    })
                    .await?,
            );
        }
        let keys = store.list_jwks().await?;
        assert_eq!(
            keys.iter().map(|key| key.id.as_str()).collect::<Vec<_>>(),
            vec!["legacy", "current"]
        );
        let mut config = store.config().as_ref().clone();
        config.advanced.database.default_find_many_limit = 1;
        let limited = SeaOrmStore::<BundledSchema>::new(config, store.connection().clone());
        assert_eq!(
            limited
                .list_jwks()
                .await?
                .iter()
                .map(|row| row.id.as_str())
                .collect::<Vec<_>>(),
            vec!["legacy"]
        );
        let legacy = store
            .get_jwk_by_id("legacy")
            .await?
            .ok_or_else(|| std::io::Error::other("missing legacy key"))?;
        assert_eq!(legacy.private_key, "encrypted private JSON");
        assert!(legacy.expires_at.is_some_and(|expiry| expiry < now));
        assert!(legacy.alg.is_none());
        assert!(legacy.crv.is_none());
        assert!(store.get_jwk_by_id("unknown").await?.is_none());
        Ok(())
    }
}
// LCOV_EXCL_STOP
