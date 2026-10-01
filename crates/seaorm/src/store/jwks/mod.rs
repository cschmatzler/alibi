#[cfg(test)]
mod tests;

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
