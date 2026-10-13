use super::{SqlxStore, entities::oauth_client::Model};
use crate::{
    model::{self, ActiveRow, SqlxModel},
    schema::AuthSchema,
};
use alibi_core::{
    AuthResult,
    store::{CreateOAuthClient, OAuthClient, OAuthClientStore},
};
use async_trait::async_trait;
#[async_trait]
impl<S: AuthSchema> OAuthClientStore for SqlxStore<S> {
    async fn create_oauth_client(&self, data: CreateOAuthClient) -> AuthResult<OAuthClient> {
        let mut active = ActiveRow::new();
        active.set(
            "id",
            self.generated_id(self.exec(), "oauthClient", "oauth_client", "id")
                .await?
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        );
        active.set("client_id", data.client_id);
        active.set("user_id", data.user_id);
        active.set("client_secret", data.client_secret);
        active.set("metadata", serde_json::to_string(&data.metadata)?);
        active.set("created_at", data.created_at);
        active.set("updated_at", data.created_at);
        model::insert::<Model>(self.exec(), &active)
            .await?
            .try_into()
    }
    async fn get_oauth_client(&self, client_id: &str) -> AuthResult<Option<OAuthClient>> {
        let mut sql = model::select_model::<Model>(self.exec());
        sql.push(" WHERE ");
        sql.compare(Model::TABLE, "client_id", " = ", client_id);
        model::limit_one(&mut sql);
        self.exec()
            .fetch_optional::<Model>(sql)
            .await?
            .map(TryInto::try_into)
            .transpose()
    }
    async fn list_oauth_clients_by_user(&self, user_id: &str) -> AuthResult<Vec<OAuthClient>> {
        let mut sql = model::select_model::<Model>(self.exec());
        sql.push(" WHERE ");
        sql.compare(Model::TABLE, "user_id", " = ", user_id);
        sql.push(" LIMIT ");
        sql.bind(self.find_many_limit());
        self.exec()
            .fetch_all::<Model>(sql)
            .await?
            .into_iter()
            .map(TryInto::try_into)
            .collect()
    }
}
