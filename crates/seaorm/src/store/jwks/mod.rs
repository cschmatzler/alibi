use super::entities::jwk::{ActiveModel, Entity};
use super::{SeaOrmStore, map_db_err};
use crate::schema::AuthSchema;
use alibi_core::error::AuthResult;
use alibi_core::store::JwkStore;
use alibi_core::types::{CreateJwk, Jwk};
use async_trait::async_trait;
use sea_orm::{ActiveModelTrait, ConnectionTrait, EntityTrait, QuerySelect, Set};

impl<S: AuthSchema> SeaOrmStore<S> {
    pub(super) async fn list_jwks_with_connection<C: ConnectionTrait>(
        &self,
        connection: &C,
    ) -> AuthResult<Vec<Jwk>> {
        let limit =
            <u64 as TryFrom<_>>::try_from(self.config().advanced.database.default_find_many_limit)
                .map_err(|_error| alibi_core::AuthError::config("Invalid keyring result limit"))?;
        Entity::find()
            .limit(limit)
            .all(connection)
            .await
            .map(|rows| rows.into_iter().map(Into::into).collect())
            .map_err(map_db_err)
    }
    pub(super) async fn get_jwk_with_connection<C: ConnectionTrait>(
        &self,
        connection: &C,
        id: &str,
    ) -> AuthResult<Option<Jwk>> {
        Entity::find_by_id(id.to_owned())
            .one(connection)
            .await
            .map(|row| row.map(Into::into))
            .map_err(map_db_err)
    }
    pub(super) async fn create_jwk_with_connection<C: ConnectionTrait>(
        &self,
        connection: &C,
        data: CreateJwk,
    ) -> AuthResult<Jwk> {
        ActiveModel {
            id: Set(data.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string())),
            public_key: Set(data.public_key),
            private_key: Set(data.private_key),
            created_at: Set(data.created_at),
            expires_at: Set(data.expires_at),
            alg: Set(data.alg),
            crv: Set(data.crv),
        }
        .insert(connection)
        .await
        .map(Into::into)
        .map_err(map_db_err)
    }
}
#[async_trait]
impl<S: AuthSchema> JwkStore for SeaOrmStore<S> {
    async fn list_jwks(&self) -> AuthResult<Vec<Jwk>> {
        self.list_jwks_with_connection(self.connection()).await
    }
    async fn get_jwk_by_id(&self, id: &str) -> AuthResult<Option<Jwk>> {
        self.get_jwk_with_connection(self.connection(), id).await
    }
    async fn create_jwk(&self, data: CreateJwk) -> AuthResult<Jwk> {
        self.create_jwk_with_connection(self.connection(), data)
            .await
    }
}
