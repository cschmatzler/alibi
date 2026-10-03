use super::SqlxStore;
use super::entities::jwk::Model;
use crate::model::{self, ActiveRow};
use crate::pool::Exec;
use crate::schema::AuthSchema;
use async_trait::async_trait;
use better_auth_core::error::AuthResult;
use better_auth_core::store::JwkStore;
use better_auth_core::types::{CreateJwk, Jwk};

impl<S: AuthSchema> SqlxStore<S> {
    pub(super) async fn list_jwks_with(&self, exec: Exec<'_>) -> AuthResult<Vec<Jwk>> {
        let mut sql = model::select_model::<Model>(exec);
        sql.push(" LIMIT ");
        sql.bind(self.find_many_limit());
        Ok(exec
            .fetch_all::<Model>(sql)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub(super) async fn get_jwk_with(&self, exec: Exec<'_>, id: &str) -> AuthResult<Option<Jwk>> {
        let mut sql = model::by_id::<Model>(exec, id);
        model::limit_one(&mut sql);
        Ok(exec.fetch_optional::<Model>(sql).await?.map(Into::into))
    }

    pub(super) async fn create_jwk_with(&self, exec: Exec<'_>, data: CreateJwk) -> AuthResult<Jwk> {
        let mut active = ActiveRow::new();
        active.set(
            "id",
            data.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        );
        active.set("public_key", data.public_key);
        active.set("private_key", data.private_key);
        active.set("created_at", data.created_at);
        active.set("expires_at", data.expires_at);
        active.set("alg", data.alg);
        active.set("crv", data.crv);
        model::insert::<Model>(exec, &active).await.map(Into::into)
    }
}

#[async_trait]
impl<S: AuthSchema> JwkStore for SqlxStore<S> {
    async fn list_jwks(&self) -> AuthResult<Vec<Jwk>> {
        self.list_jwks_with(self.exec()).await
    }
    async fn get_jwk_by_id(&self, id: &str) -> AuthResult<Option<Jwk>> {
        self.get_jwk_with(self.exec(), id).await
    }
    async fn create_jwk(&self, data: CreateJwk) -> AuthResult<Jwk> {
        self.create_jwk_with(self.exec(), data).await
    }
}
