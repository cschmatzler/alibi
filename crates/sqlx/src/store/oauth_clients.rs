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
    async fn create_oauth_token(
        &self,
        kind: alibi_core::store::OAuthTokenKind,
        data: alibi_core::store::CreateOAuthToken,
    ) -> AuthResult<alibi_core::store::OAuthToken> {
        match kind {
            alibi_core::store::OAuthTokenKind::Access => {
                let mut active = ActiveRow::new();
                active.set(
                    "id",
                    self.generated_id(self.exec(), "oauthAccessToken", "oauth_access_token", "id")
                        .await?
                        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                );
                active.set("token", data.token);
                active.set("client_id", data.client_id);
                active.set("user_id", data.user_id);
                active.set("session_id", data.session_id);
                active.set("authorization_code_id", data.authorization_code_id);
                active.set("created_at", data.created_at);
                active.set("expires_at", data.expires_at);
                active.set("metadata", serde_json::to_string(&data.metadata)?);
                model::insert::<super::entities::oauth_access_token::Model>(self.exec(), &active)
                    .await?
                    .try_into()
            }
            alibi_core::store::OAuthTokenKind::Refresh => {
                let mut active = ActiveRow::new();
                active.set(
                    "id",
                    self.generated_id(
                        self.exec(),
                        "oauthRefreshToken",
                        "oauth_refresh_token",
                        "id",
                    )
                    .await?
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                );
                active.set("token", data.token);
                active.set("client_id", data.client_id);
                active.set("user_id", data.user_id);
                active.set("session_id", data.session_id);
                active.set("authorization_code_id", data.authorization_code_id);
                active.set("created_at", data.created_at);
                active.set("expires_at", data.expires_at);
                active.set("metadata", serde_json::to_string(&data.metadata)?);
                model::insert::<super::entities::oauth_refresh_token::Model>(self.exec(), &active)
                    .await?
                    .try_into()
            }
        }
    }
    async fn get_oauth_token(
        &self,
        kind: alibi_core::store::OAuthTokenKind,
        token: &str,
    ) -> AuthResult<Option<alibi_core::store::OAuthToken>> {
        match kind {
            alibi_core::store::OAuthTokenKind::Access => {
                let mut sql =
                    model::select_model::<super::entities::oauth_access_token::Model>(self.exec());
                sql.push(" WHERE ");
                sql.compare(
                    super::entities::oauth_access_token::Model::TABLE,
                    "token",
                    " = ",
                    token,
                );
                self.exec()
                    .fetch_optional::<super::entities::oauth_access_token::Model>(sql)
                    .await?
                    .map(TryInto::try_into)
                    .transpose()
            }
            alibi_core::store::OAuthTokenKind::Refresh => {
                let mut sql =
                    model::select_model::<super::entities::oauth_refresh_token::Model>(self.exec());
                sql.push(" WHERE ");
                sql.compare(
                    super::entities::oauth_refresh_token::Model::TABLE,
                    "token",
                    " = ",
                    token,
                );
                self.exec()
                    .fetch_optional::<super::entities::oauth_refresh_token::Model>(sql)
                    .await?
                    .map(TryInto::try_into)
                    .transpose()
            }
        }
    }
    async fn delete_oauth_tokens_for_code(&self, code: &str) -> AuthResult<()> {
        {
            let mut sql = crate::sql::Sql::with(self.exec().engine(), "DELETE FROM ");
            sql.ident(super::entities::oauth_access_token::Model::TABLE);
            sql.push(" WHERE ");
            sql.compare(
                super::entities::oauth_access_token::Model::TABLE,
                "authorization_code_id",
                " = ",
                code,
            );
            _ = self.exec().execute(sql).await?;
        }
        {
            let mut sql = crate::sql::Sql::with(self.exec().engine(), "DELETE FROM ");
            sql.ident(super::entities::oauth_refresh_token::Model::TABLE);
            sql.push(" WHERE ");
            sql.compare(
                super::entities::oauth_refresh_token::Model::TABLE,
                "authorization_code_id",
                " = ",
                code,
            );
            _ = self.exec().execute(sql).await?;
        }
        Ok(())
    }
    async fn delete_oauth_client_resource(
        &self,
        client_id: &str,
        resource_id: &str,
    ) -> AuthResult<()> {
        let mut sql = crate::sql::Sql::with(self.exec().engine(), "DELETE FROM ");
        sql.ident(super::entities::oauth_client_resource::Model::TABLE);
        sql.push(" WHERE ");
        sql.compare(
            super::entities::oauth_client_resource::Model::TABLE,
            "client_id",
            " = ",
            client_id,
        );
        sql.push(" AND ");
        sql.compare(
            super::entities::oauth_client_resource::Model::TABLE,
            "resource_id",
            " = ",
            resource_id,
        );
        self.exec().execute(sql).await.map(|_| ())
    }
    async fn create_oauth_client_resource(
        &self,
        data: alibi_core::store::CreateOAuthClientResource,
    ) -> AuthResult<alibi_core::store::OAuthClientResource> {
        let mut active = ActiveRow::new();
        active.set(
            "id",
            self.generated_id(
                self.exec(),
                "oauthClientResource",
                "oauth_client_resource",
                "id",
            )
            .await?
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        );
        active.set("client_id", data.client_id);
        active.set("resource_id", data.resource_id);
        active.set("metadata", Option::<String>::None);
        active.set("created_at", Some(data.created_at));
        model::insert::<super::entities::oauth_client_resource::Model>(self.exec(), &active)
            .await?
            .try_into()
    }
    async fn delete_oauth_resource(&self, identifier: &str) -> AuthResult<()> {
        let mut sql = crate::sql::Sql::with(self.exec().engine(), "DELETE FROM ");
        sql.ident(super::entities::oauth_resource::Model::TABLE);
        sql.push(" WHERE ");
        sql.compare(
            super::entities::oauth_resource::Model::TABLE,
            "identifier",
            " = ",
            identifier,
        );
        self.exec().execute(sql).await.map(|_| ())
    }
    async fn update_oauth_resource(
        &self,
        identifier: &str,
        metadata: serde_json::Value,
        updated_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<Option<alibi_core::store::OAuthResource>> {
        let Some(row) = self.get_oauth_resource(identifier).await? else {
            return Ok(None);
        };
        let mut active = ActiveRow::new();
        active.set("id", row.id);
        active.set("metadata", serde_json::to_string(&metadata)?);
        active.set("updated_at", updated_at);
        model::update::<super::entities::oauth_resource::Model>(self.exec(), &active)
            .await?
            .map(TryInto::try_into)
            .transpose()
    }
    async fn list_oauth_resources(&self) -> AuthResult<Vec<alibi_core::store::OAuthResource>> {
        let mut sql = model::select_model::<super::entities::oauth_resource::Model>(self.exec());
        sql.push(" LIMIT ");
        sql.bind(self.find_many_limit());
        self.exec()
            .fetch_all::<super::entities::oauth_resource::Model>(sql)
            .await?
            .into_iter()
            .map(TryInto::try_into)
            .collect()
    }
    async fn list_oauth_client_resources(
        &self,
        client_id: &str,
    ) -> AuthResult<Vec<alibi_core::store::OAuthClientResource>> {
        let mut sql =
            model::select_model::<super::entities::oauth_client_resource::Model>(self.exec());
        sql.push(" WHERE ");
        sql.compare(
            super::entities::oauth_client_resource::Model::TABLE,
            "client_id",
            " = ",
            client_id,
        );
        sql.push(" LIMIT ");
        sql.bind(self.find_many_limit());
        self.exec()
            .fetch_all::<super::entities::oauth_client_resource::Model>(sql)
            .await?
            .into_iter()
            .map(TryInto::try_into)
            .collect()
    }
    async fn create_oauth_resource(
        &self,
        data: alibi_core::store::CreateOAuthResource,
    ) -> AuthResult<alibi_core::store::OAuthResource> {
        let mut active = ActiveRow::new();
        active.set(
            "id",
            self.generated_id(self.exec(), "oauthResource", "oauth_resource", "id")
                .await?
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        );
        active.set("identifier", data.identifier);
        active.set("metadata", serde_json::to_string(&data.metadata)?);
        active.set("created_at", data.created_at);
        active.set("updated_at", data.created_at);
        model::insert::<super::entities::oauth_resource::Model>(self.exec(), &active)
            .await?
            .try_into()
    }
    async fn get_oauth_resource(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<alibi_core::store::OAuthResource>> {
        let mut sql = model::select_model::<super::entities::oauth_resource::Model>(self.exec());
        sql.push(" WHERE ");
        sql.compare(
            super::entities::oauth_resource::Model::TABLE,
            "identifier",
            " = ",
            identifier,
        );
        model::limit_one(&mut sql);
        self.exec()
            .fetch_optional::<super::entities::oauth_resource::Model>(sql)
            .await?
            .map(TryInto::try_into)
            .transpose()
    }
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
    async fn get_oauth_consent(
        &self,
        id: &str,
    ) -> AuthResult<Option<alibi_core::store::OAuthConsent>> {
        let mut sql = model::select_model::<super::entities::oauth_consent::Model>(self.exec());
        sql.push(" WHERE ");
        sql.compare(
            super::entities::oauth_consent::Model::TABLE,
            "id",
            " = ",
            id,
        );
        model::limit_one(&mut sql);
        self.exec()
            .fetch_optional::<super::entities::oauth_consent::Model>(sql)
            .await?
            .map(TryInto::try_into)
            .transpose()
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
    async fn delete_oauth_consent(&self, id: &str) -> AuthResult<()> {
        let mut sql = crate::sql::Sql::with(self.exec().engine(), "DELETE FROM ");
        sql.ident(super::entities::oauth_consent::Model::TABLE);
        sql.push(" WHERE ");
        sql.compare(
            super::entities::oauth_consent::Model::TABLE,
            "id",
            " = ",
            id,
        );
        self.exec().execute(sql).await.map(|_| ())
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
