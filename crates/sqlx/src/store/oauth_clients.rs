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
    async fn create_oauth_consent(
        &self,
        data: alibi_core::store::CreateOAuthConsent,
    ) -> AuthResult<alibi_core::store::OAuthConsent> {
        let mut active = ActiveRow::new();
        active.set(
            "id",
            self.generated_id(self.exec(), "oauthConsent", "oauth_consent", "id")
                .await?
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        );
        active.set("client_id", data.client_id);
        active.set("user_id", data.user_id);
        active.set("metadata", serde_json::to_string(&data.metadata)?);
        active.set("created_at", data.created_at);
        active.set("updated_at", data.created_at);
        model::insert::<super::entities::oauth_consent::Model>(self.exec(), &active)
            .await?
            .try_into()
    }
    async fn list_oauth_consents_by_user(
        &self,
        user_id: &str,
    ) -> AuthResult<Vec<alibi_core::store::OAuthConsent>> {
        let mut sql = model::select_model::<super::entities::oauth_consent::Model>(self.exec());
        sql.push(" WHERE ");
        sql.compare(
            super::entities::oauth_consent::Model::TABLE,
            "user_id",
            " = ",
            user_id,
        );
        sql.push(" LIMIT ");
        sql.bind(self.find_many_limit());
        self.exec()
            .fetch_all::<super::entities::oauth_consent::Model>(sql)
            .await?
            .into_iter()
            .map(TryInto::try_into)
            .collect()
    }
    async fn update_oauth_consent_metadata(
        &self,
        id: &str,
        metadata: serde_json::Value,
        updated_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<Option<alibi_core::store::OAuthConsent>> {
        let mut active = ActiveRow::new();
        active.set("id", id.to_owned());
        active.set("metadata", serde_json::to_string(&metadata)?);
        active.set("updated_at", updated_at);
        model::update::<super::entities::oauth_consent::Model>(self.exec(), &active)
            .await?
            .map(TryInto::try_into)
            .transpose()
    }
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
    async fn delete_oauth_client(&self, client_id: &str) -> AuthResult<()> {
        let mut sql = crate::sql::Sql::with(self.exec().engine(), "DELETE FROM ");
        sql.ident(Model::TABLE);
        sql.push(" WHERE ");
        sql.compare(Model::TABLE, "client_id", " = ", client_id);
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
        active.set("client_secret", Some(secret));
        active.set("updated_at", updated_at);
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
        active.set("metadata", serde_json::to_string(&metadata)?);
        active.set("updated_at", updated_at);
        model::update::<Model>(self.exec(), &active)
            .await?
            .map(TryInto::try_into)
            .transpose()
    }
}
