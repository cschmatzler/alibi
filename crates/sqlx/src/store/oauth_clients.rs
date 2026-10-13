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
    async fn claim_oauth_refresh_rotation(
        &self,
        token: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<bool> {
        let mut sql = crate::sql::Sql::with(self.exec().engine(), "UPDATE ");
        sql.ident("oauthRefreshToken");
        sql.push(" SET ");
        sql.assign("revoked", at);
        sql.push(", ");
        sql.assign("rotatedAt", at);
        sql.push(" WHERE ");
        sql.compare("oauthRefreshToken", "token", " = ", token);
        sql.push(" AND ");
        sql.ident("revoked");
        sql.push(" IS NULL");
        Ok(self.exec().execute(sql).await? > 0)
    }

    async fn mark_oauth_token_revoked(
        &self,
        kind: alibi_core::store::OAuthTokenKind,
        id: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<()> {
        let table = match kind {
            alibi_core::store::OAuthTokenKind::Access => "oauthAccessToken",
            alibi_core::store::OAuthTokenKind::Refresh => "oauthRefreshToken",
        };
        let mut sql = crate::sql::Sql::with(self.exec().engine(), "UPDATE ");
        sql.ident(table);
        sql.push(" SET ");
        sql.assign("revoked", at);
        sql.push(" WHERE ");
        sql.compare(table, "id", " = ", id);
        _ = self.exec().execute(sql).await?;
        Ok(())
    }
    async fn list_oauth_tokens_for_session(
        &self,
        kind: alibi_core::store::OAuthTokenKind,
        session_id: &str,
    ) -> AuthResult<Vec<alibi_core::store::OAuthToken>> {
        match kind {
            alibi_core::store::OAuthTokenKind::Access => {
                let mut sql =
                    model::select_model::<super::entities::oauth_access_token::Model>(self.exec());
                sql.push(" WHERE ");
                sql.compare(
                    super::entities::oauth_access_token::Model::TABLE,
                    "sessionId",
                    " = ",
                    session_id,
                );
                sql.push(" LIMIT ");
                sql.bind(self.find_many_limit());
                self.exec()
                    .fetch_all::<super::entities::oauth_access_token::Model>(sql)
                    .await?
                    .into_iter()
                    .map(TryInto::try_into)
                    .collect()
            }
            alibi_core::store::OAuthTokenKind::Refresh => {
                let mut sql =
                    model::select_model::<super::entities::oauth_refresh_token::Model>(self.exec());
                sql.push(" WHERE ");
                sql.compare(
                    super::entities::oauth_refresh_token::Model::TABLE,
                    "sessionId",
                    " = ",
                    session_id,
                );
                sql.push(" LIMIT ");
                sql.bind(self.find_many_limit());
                self.exec()
                    .fetch_all::<super::entities::oauth_refresh_token::Model>(sql)
                    .await?
                    .into_iter()
                    .map(TryInto::try_into)
                    .collect()
            }
        }
    }

    async fn delete_oauth_token(
        &self,
        kind: alibi_core::store::OAuthTokenKind,
        token: &str,
    ) -> AuthResult<()> {
        match kind {
            alibi_core::store::OAuthTokenKind::Access => {
                let mut sql = crate::sql::Sql::with(self.exec().engine(), "DELETE FROM ");
                sql.ident(super::entities::oauth_access_token::Model::TABLE);
                sql.push(" WHERE ");
                sql.compare(
                    super::entities::oauth_access_token::Model::TABLE,
                    "token",
                    " = ",
                    token,
                );
                _ = self.exec().execute(sql).await?;
            }
            alibi_core::store::OAuthTokenKind::Refresh => {
                let mut sql = crate::sql::Sql::with(self.exec().engine(), "DELETE FROM ");
                sql.ident(super::entities::oauth_refresh_token::Model::TABLE);
                sql.push(" WHERE ");
                sql.compare(
                    super::entities::oauth_refresh_token::Model::TABLE,
                    "token",
                    " = ",
                    token,
                );
                _ = self.exec().execute(sql).await?;
            }
        }
        Ok(())
    }
    async fn revoke_oauth_refresh_token(
        &self,
        token: &str,
        revoked_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<bool> {
        let mut lookup =
            model::select_model::<super::entities::oauth_refresh_token::Model>(self.exec());
        lookup.push(" WHERE ");
        lookup.compare("oauthRefreshToken", "token", " = ", token);
        let Some(row) = self
            .exec()
            .fetch_optional::<super::entities::oauth_refresh_token::Model>(lookup)
            .await?
        else {
            return Ok(false);
        };
        if row.revoked.is_some() {
            return Ok(false);
        }
        let mut sql = crate::sql::Sql::with(self.exec().engine(), "UPDATE ");
        sql.ident("oauthRefreshToken");
        sql.push(" SET ");
        sql.assign("revoked", revoked_at);
        sql.push(" WHERE ");
        sql.compare("oauthRefreshToken", "token", " = ", token);
        sql.push(" AND ");
        sql.ident("revoked");
        sql.push(" IS NULL");
        Ok(self.exec().execute(sql).await? > 0)
    }
    async fn delete_oauth_access_tokens_for_refresh(&self, refresh_id: &str) -> AuthResult<()> {
        let mut sql = crate::sql::Sql::with(self.exec().engine(), "DELETE FROM ");
        sql.ident("oauthAccessToken");
        sql.push(" WHERE ");
        sql.compare("oauthAccessToken", "refreshId", " = ", refresh_id);
        _ = self.exec().execute(sql).await?;
        Ok(())
    }
    async fn delete_oauth_refresh_family(&self, client_id: &str, user_id: &str) -> AuthResult<()> {
        let mut sql = crate::sql::Sql::with(self.exec().engine(), "DELETE FROM ");
        sql.ident("oauthAccessToken");
        sql.push(" WHERE ");
        sql.ident("refreshId");
        sql.push(" IN (SELECT id FROM ");
        sql.ident("oauthRefreshToken");
        sql.push(" WHERE ");
        sql.compare("oauthRefreshToken", "clientId", " = ", client_id);
        sql.push(" AND ");
        sql.compare("oauthRefreshToken", "userId", " = ", user_id);
        sql.push(" LIMIT ");
        sql.bind(
            i64::try_from(self.config().advanced.database.default_find_many_limit)
                .unwrap_or(i64::MAX),
        );
        sql.push(")");
        _ = self.exec().execute(sql).await?;
        let mut sql = crate::sql::Sql::with(self.exec().engine(), "DELETE FROM ");
        sql.ident("oauthRefreshToken");
        sql.push(" WHERE ");
        sql.compare("oauthRefreshToken", "clientId", " = ", client_id);
        sql.push(" AND ");
        sql.compare("oauthRefreshToken", "userId", " = ", user_id);
        _ = self.exec().execute(sql).await?;
        Ok(())
    }
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
                    self.generated_id(self.exec(), "oauthAccessToken", "oauthAccessToken", "id")
                        .await?
                        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                );
                active.set("token", data.token);
                active.set("clientId", data.client_id);
                active.set("userId", data.user_id);
                active.set("sessionId", data.session_id);
                active.set("authorizationCodeId", data.authorization_code_id);
                active.set("createdAt", data.created_at);
                active.set("expiresAt", data.expires_at);
                let fields = super::entities::oauth_access_token::Model::columns_from_metadata(
                    data.metadata,
                )?
                .into_active();
                for (column, value) in fields.present() {
                    if ![
                        "id",
                        "token",
                        "clientId",
                        "sessionId",
                        "userId",
                        "authorizationCodeId",
                        "createdAt",
                        "expiresAt",
                    ]
                    .contains(&column)
                    {
                        active.set(column, value.clone());
                    }
                }
                model::insert::<super::entities::oauth_access_token::Model>(self.exec(), &active)
                    .await?
                    .try_into()
            }
            alibi_core::store::OAuthTokenKind::Refresh => {
                let mut active = ActiveRow::new();
                active.set(
                    "id",
                    self.generated_id(self.exec(), "oauthRefreshToken", "oauthRefreshToken", "id")
                        .await?
                        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                );
                active.set("token", data.token);
                active.set("clientId", data.client_id);
                active.set("userId", data.user_id);
                active.set("sessionId", data.session_id);
                active.set("authorizationCodeId", data.authorization_code_id);
                active.set("createdAt", data.created_at);
                active.set("expiresAt", data.expires_at);
                let fields = super::entities::oauth_refresh_token::Model::columns_from_metadata(
                    data.metadata,
                )?
                .into_active();
                for (column, value) in fields.present() {
                    if ![
                        "id",
                        "token",
                        "clientId",
                        "sessionId",
                        "userId",
                        "authorizationCodeId",
                        "createdAt",
                        "expiresAt",
                    ]
                    .contains(&column)
                    {
                        active.set(column, value.clone());
                    }
                }
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
                "authorizationCodeId",
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
                "authorizationCodeId",
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
            "clientId",
            " = ",
            client_id,
        );
        sql.push(" AND ");
        sql.compare(
            super::entities::oauth_client_resource::Model::TABLE,
            "resourceId",
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
                "oauthClientResource",
                "id",
            )
            .await?
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        );
        active.set("clientId", data.client_id);
        active.set("resourceId", data.resource_id);
        active.set("metadata", Option::<String>::None);
        active.set("createdAt", Some(data.created_at));
        model::insert::<super::entities::oauth_client_resource::Model>(self.exec(), &active)
            .await?
            .try_into()
    }
    async fn delete_oauth_resource(&self, identifier: &str) -> AuthResult<()> {
        let mut links = crate::sql::Sql::with(self.exec().engine(), "DELETE FROM ");
        links.ident(super::entities::oauth_client_resource::Model::TABLE);
        links.push(" WHERE ");
        links.compare(
            super::entities::oauth_client_resource::Model::TABLE,
            "resourceId",
            " = ",
            identifier,
        );
        _ = self.exec().execute(links).await?;
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
        let fields =
            super::entities::oauth_resource::Model::columns_from_metadata(metadata)?.into_active();
        for (column, value) in fields.present() {
            if !["id", "identifier", "createdAt", "updatedAt"].contains(&column) {
                active.set(column, value.clone());
            }
        }
        active.set("updatedAt", updated_at);
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
            "clientId",
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
            self.generated_id(self.exec(), "oauthResource", "oauthResource", "id")
                .await?
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        );
        active.set("identifier", data.identifier);
        let fields = super::entities::oauth_resource::Model::columns_from_metadata(data.metadata)?
            .into_active();
        for (column, value) in fields.present() {
            if !["id", "identifier", "createdAt", "updatedAt"].contains(&column) {
                active.set(column, value.clone());
            }
        }
        active.set("createdAt", data.created_at);
        active.set("updatedAt", data.created_at);
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
            self.generated_id(self.exec(), "oauthConsent", "oauthConsent", "id")
                .await?
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        );
        active.set("clientId", data.client_id);
        active.set("userId", data.user_id);
        let fields = super::entities::oauth_consent::Model::columns_from_metadata(data.metadata)?
            .into_active();
        for (column, value) in fields.present() {
            if !["id", "clientId", "userId", "createdAt", "updatedAt"].contains(&column) {
                active.set(column, value.clone());
            }
        }
        active.set("createdAt", data.created_at);
        active.set("updatedAt", data.created_at);
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
            "userId",
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
        let fields =
            super::entities::oauth_consent::Model::columns_from_metadata(metadata)?.into_active();
        for (column, value) in fields.present() {
            if !["id", "clientId", "userId", "createdAt", "updatedAt"].contains(&column) {
                active.set(column, value.clone());
            }
        }
        active.set("updatedAt", updated_at);
        model::update::<super::entities::oauth_consent::Model>(self.exec(), &active)
            .await?
            .map(TryInto::try_into)
            .transpose()
    }
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
