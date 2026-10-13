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
            self.generated_id(self.exec(), "oauthClient", "oauthClient", "id")
                .await?
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        );
        active.set("clientId", data.client_id);
        active.set("userId", data.user_id);
        active.set("clientSecret", data.client_secret);
        let fields = Model::columns_from_metadata(data.metadata)?.into_active();
        for (column, value) in fields.present() {
            if ![
                "id",
                "clientId",
                "userId",
                "clientSecret",
                "createdAt",
                "updatedAt",
            ]
            .contains(&column)
            {
                active.set(column, value.clone());
            }
        }
        active.set("createdAt", data.created_at);
        active.set("updatedAt", data.created_at);
        model::insert::<Model>(self.exec(), &active)
            .await?
            .try_into()
    }
    async fn get_oauth_client(&self, client_id: &str) -> AuthResult<Option<OAuthClient>> {
        let mut sql = model::select_model::<Model>(self.exec());
        sql.push(" WHERE ");
        sql.compare(Model::TABLE, "clientId", " = ", client_id);
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
        sql.compare(Model::TABLE, "userId", " = ", user_id);
        sql.push(" LIMIT ");
        sql.bind(self.find_many_limit());
        self.exec()
            .fetch_all::<Model>(sql)
            .await?
            .into_iter()
            .map(TryInto::try_into)
            .collect()
    }
    async fn delete_oauth_client(&self, client_id: &str) -> AuthResult<()> {
        let mut sql = crate::sql::Sql::with(self.exec().engine(), "DELETE FROM ");
        sql.ident(Model::TABLE);
        sql.push(" WHERE ");
        sql.compare(Model::TABLE, "clientId", " = ", client_id);
        self.exec().execute(sql).await.map(|_| ())
    }
    async fn update_oauth_client_secret(
        &self,
        client_id: &str,
        secret: String,
        updated_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<Option<OAuthClient>> {
        let Some(client) = self.get_oauth_client(client_id).await? else {
            return Ok(None);
        };
        let mut active = ActiveRow::new();
        active.set("id", client.id);
        active.set("clientSecret", Some(secret));
        active.set("updatedAt", updated_at);
        model::update::<Model>(self.exec(), &active)
            .await?
            .map(TryInto::try_into)
            .transpose()
    }
    async fn update_oauth_client_metadata(
        &self,
        client_id: &str,
        metadata: serde_json::Value,
        updated_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<Option<OAuthClient>> {
        let Some(client) = self.get_oauth_client(client_id).await? else {
            return Ok(None);
        };
        let mut active = ActiveRow::new();
        active.set("id", client.id);
        let fields = Model::columns_from_metadata(metadata)?.into_active();
        for (column, value) in fields.present() {
            if ![
                "id",
                "clientId",
                "userId",
                "clientSecret",
                "createdAt",
                "updatedAt",
            ]
            .contains(&column)
            {
                active.set(column, value.clone());
            }
        }
        active.set("updatedAt", updated_at);
        model::update::<Model>(self.exec(), &active)
            .await?
            .map(TryInto::try_into)
            .transpose()
    }
}
