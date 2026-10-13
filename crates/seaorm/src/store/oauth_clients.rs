use super::{
    SeaOrmStore,
    entities::oauth_client::{self, Column, Entity},
    map_db_err,
};
use crate::schema::AuthSchema;
use alibi_core::{
    AuthResult,
    store::{CreateOAuthClient, OAuthClient, OAuthClientStore},
};
use async_trait::async_trait;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
#[async_trait]
impl<S: AuthSchema> OAuthClientStore for SeaOrmStore<S> {
    async fn create_oauth_client(&self, data: CreateOAuthClient) -> AuthResult<OAuthClient> {
        oauth_client::ActiveModel {
            id: Set(self
                .generated_id(&self.db, "oauthClient", "oauth_client", "id")
                .await?
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())),
            client_id: Set(data.client_id),
            user_id: Set(data.user_id),
            client_secret: Set(data.client_secret),
            metadata: Set(serde_json::to_string(&data.metadata)?),
            created_at: Set(data.created_at),
            updated_at: Set(data.created_at),
        }
        .insert(self.scoped_connection())
        .await
        .map_err(map_db_err)?
        .try_into()
    }
    async fn get_oauth_client(&self, client_id: &str) -> AuthResult<Option<OAuthClient>> {
        Entity::find()
            .filter(Column::ClientId.eq(client_id))
            .one(self.scoped_connection())
            .await
            .map_err(map_db_err)?
            .map(TryInto::try_into)
            .transpose()
    }
}
