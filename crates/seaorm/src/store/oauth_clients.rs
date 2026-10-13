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
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, QuerySelect, Set,
};
#[async_trait]
impl<S: AuthSchema> OAuthClientStore for SeaOrmStore<S> {
    async fn delete_oauth_token(
        &self,
        kind: alibi_core::store::OAuthTokenKind,
        token: &str,
    ) -> AuthResult<()> {
        match kind {
            alibi_core::store::OAuthTokenKind::Access => {
                _ = super::entities::oauth_access_token::Entity::delete_many()
                    .filter(super::entities::oauth_access_token::Column::Token.eq(token))
                    .exec(self.scoped_connection())
                    .await
                    .map_err(map_db_err)?;
            }
            alibi_core::store::OAuthTokenKind::Refresh => {
                _ = super::entities::oauth_refresh_token::Entity::delete_many()
                    .filter(super::entities::oauth_refresh_token::Column::Token.eq(token))
                    .exec(self.scoped_connection())
                    .await
                    .map_err(map_db_err)?;
            }
        }
        Ok(())
    }
    async fn revoke_oauth_refresh_token(
        &self,
        token: &str,
        revoked_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<bool> {
        let Some(row) = super::entities::oauth_refresh_token::Entity::find()
            .filter(super::entities::oauth_refresh_token::Column::Token.eq(token))
            .one(self.scoped_connection())
            .await
            .map_err(map_db_err)?
        else {
            return Ok(false);
        };
        if row.revoked.is_some() {
            return Ok(false);
        }
        let result = super::entities::oauth_refresh_token::Entity::update_many()
            .col_expr(
                super::entities::oauth_refresh_token::Column::Revoked,
                sea_orm::sea_query::Expr::value(revoked_at),
            )
            .filter(super::entities::oauth_refresh_token::Column::Token.eq(token))
            .filter(super::entities::oauth_refresh_token::Column::Revoked.is_null())
            .exec(self.scoped_connection())
            .await
            .map_err(map_db_err)?;
        Ok(result.rows_affected > 0)
    }
    async fn delete_oauth_access_tokens_for_refresh(&self, refresh_id: &str) -> AuthResult<()> {
        _ = super::entities::oauth_access_token::Entity::delete_many()
            .filter(super::entities::oauth_access_token::Column::RefreshId.eq(refresh_id))
            .exec(self.scoped_connection())
            .await
            .map_err(map_db_err)?;
        Ok(())
    }
    async fn delete_oauth_refresh_family(&self, client_id: &str, user_id: &str) -> AuthResult<()> {
        use super::entities::{oauth_access_token, oauth_refresh_token};
        use sea_orm::sea_query::{Expr, ExprTrait, Query};
        let query = Query::select()
            .column(oauth_refresh_token::Column::Id)
            .from(oauth_refresh_token::Entity)
            .and_where(Expr::col(oauth_refresh_token::Column::ClientId).eq(client_id))
            .and_where(Expr::col(oauth_refresh_token::Column::UserId).eq(user_id))
            .limit(
                u64::try_from(self.config().advanced.database.default_find_many_limit)
                    .unwrap_or(u64::MAX),
            )
            .to_owned();
        _ = oauth_access_token::Entity::delete_many()
            .filter(oauth_access_token::Column::RefreshId.in_subquery(query))
            .exec(self.scoped_connection())
            .await
            .map_err(map_db_err)?;
        _ = oauth_refresh_token::Entity::delete_many()
            .filter(oauth_refresh_token::Column::ClientId.eq(client_id))
            .filter(oauth_refresh_token::Column::UserId.eq(user_id))
            .exec(self.scoped_connection())
            .await
            .map_err(map_db_err)?;
        Ok(())
    }
    async fn create_oauth_token(
        &self,
        kind: alibi_core::store::OAuthTokenKind,
        data: alibi_core::store::CreateOAuthToken,
    ) -> AuthResult<alibi_core::store::OAuthToken> {
        match kind {
            alibi_core::store::OAuthTokenKind::Access => {
                let fields = super::entities::oauth_access_token::Model::columns_from_metadata(
                    data.metadata,
                )?;
                let mut active = super::entities::oauth_access_token::ActiveModel {
                    id: Set(self
                        .generated_id(&self.db, "oauthAccessToken", "oauthAccessToken", "id")
                        .await?
                        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())),
                    token: Set(data.token),
                    client_id: Set(data.client_id),
                    user_id: Set(data.user_id),
                    session_id: Set(data.session_id),
                    authorization_code_id: Set(data.authorization_code_id),
                    created_at: Set(data.created_at),
                    expires_at: Set(data.expires_at),
                    ..Default::default()
                };
                fields.stage_metadata(&mut active);
                active
                    .insert(self.scoped_connection())
                    .await
                    .map_err(map_db_err)?
                    .try_into()
            }
            alibi_core::store::OAuthTokenKind::Refresh => {
                let fields = super::entities::oauth_refresh_token::Model::columns_from_metadata(
                    data.metadata,
                )?;
                let mut active = super::entities::oauth_refresh_token::ActiveModel {
                    id: Set(self
                        .generated_id(&self.db, "oauthRefreshToken", "oauthRefreshToken", "id")
                        .await?
                        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())),
                    token: Set(data.token),
                    client_id: Set(data.client_id),
                    user_id: Set(data.user_id.ok_or_else(|| {
                        alibi_core::AuthError::bad_request("Refresh token userId is required")
                    })?),
                    session_id: Set(data.session_id),
                    authorization_code_id: Set(data.authorization_code_id),
                    created_at: Set(data.created_at),
                    expires_at: Set(data.expires_at),
                    ..Default::default()
                };
                fields.stage_metadata(&mut active);
                active
                    .insert(self.scoped_connection())
                    .await
                    .map_err(map_db_err)?
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
                super::entities::oauth_access_token::Entity::find()
                    .filter(super::entities::oauth_access_token::Column::Token.eq(token))
                    .one(self.scoped_connection())
                    .await
                    .map_err(map_db_err)?
                    .map(TryInto::try_into)
                    .transpose()
            }
            alibi_core::store::OAuthTokenKind::Refresh => {
                super::entities::oauth_refresh_token::Entity::find()
                    .filter(super::entities::oauth_refresh_token::Column::Token.eq(token))
                    .one(self.scoped_connection())
                    .await
                    .map_err(map_db_err)?
                    .map(TryInto::try_into)
                    .transpose()
            }
        }
    }
    async fn delete_oauth_tokens_for_code(&self, code: &str) -> AuthResult<()> {
        _ = super::entities::oauth_access_token::Entity::delete_many()
            .filter(super::entities::oauth_access_token::Column::AuthorizationCodeId.eq(code))
            .exec(self.scoped_connection())
            .await
            .map_err(map_db_err)?;
        _ = super::entities::oauth_refresh_token::Entity::delete_many()
            .filter(super::entities::oauth_refresh_token::Column::AuthorizationCodeId.eq(code))
            .exec(self.scoped_connection())
            .await
            .map_err(map_db_err)?;
        Ok(())
    }
    async fn delete_oauth_client_resource(
        &self,
        client_id: &str,
        resource_id: &str,
    ) -> AuthResult<()> {
        super::entities::oauth_client_resource::Entity::delete_many()
            .filter(super::entities::oauth_client_resource::Column::ClientId.eq(client_id))
            .filter(super::entities::oauth_client_resource::Column::ResourceId.eq(resource_id))
            .exec(self.scoped_connection())
            .await
            .map_err(map_db_err)
            .map(|_| ())
    }
    async fn create_oauth_client_resource(
        &self,
        data: alibi_core::store::CreateOAuthClientResource,
    ) -> AuthResult<alibi_core::store::OAuthClientResource> {
        super::entities::oauth_client_resource::ActiveModel {
            id: Set(self
                .generated_id(&self.db, "oauthClientResource", "oauthClientResource", "id")
                .await?
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())),
            client_id: Set(data.client_id),
            resource_id: Set(data.resource_id),
            metadata: Set(None),
            created_at: Set(Some(data.created_at)),
        }
        .insert(self.scoped_connection())
        .await
        .map_err(map_db_err)?
        .try_into()
    }
    async fn delete_oauth_resource(&self, identifier: &str) -> AuthResult<()> {
        _ = super::entities::oauth_client_resource::Entity::delete_many()
            .filter(super::entities::oauth_client_resource::Column::ResourceId.eq(identifier))
            .exec(self.scoped_connection())
            .await
            .map_err(map_db_err)?;
        super::entities::oauth_resource::Entity::delete_many()
            .filter(super::entities::oauth_resource::Column::Identifier.eq(identifier))
            .exec(self.scoped_connection())
            .await
            .map_err(map_db_err)
            .map(|_| ())
    }
    async fn update_oauth_resource(
        &self,
        identifier: &str,
        metadata: serde_json::Value,
        updated_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<Option<alibi_core::store::OAuthResource>> {
        let Some(model) = super::entities::oauth_resource::Entity::find()
            .filter(super::entities::oauth_resource::Column::Identifier.eq(identifier))
            .one(self.scoped_connection())
            .await
            .map_err(map_db_err)?
        else {
            return Ok(None);
        };
        let mut active = model.into_active_model();
        super::entities::oauth_resource::Model::columns_from_metadata(metadata)?
            .stage_metadata(&mut active);
        active.updated_at = Set(Some(updated_at));
        active
            .update(self.scoped_connection())
            .await
            .map_err(map_db_err)?
            .try_into()
            .map(Some)
    }
    async fn list_oauth_resources(&self) -> AuthResult<Vec<alibi_core::store::OAuthResource>> {
        super::entities::oauth_resource::Entity::find()
            .limit(
                u64::try_from(self.config().advanced.database.default_find_many_limit)
                    .unwrap_or(u64::MAX),
            )
            .all(self.scoped_connection())
            .await
            .map_err(map_db_err)?
            .into_iter()
            .map(TryInto::try_into)
            .collect()
    }
    async fn list_oauth_client_resources(
        &self,
        client_id: &str,
    ) -> AuthResult<Vec<alibi_core::store::OAuthClientResource>> {
        super::entities::oauth_client_resource::Entity::find()
            .filter(super::entities::oauth_client_resource::Column::ClientId.eq(client_id))
            .limit(
                u64::try_from(self.config().advanced.database.default_find_many_limit)
                    .unwrap_or(u64::MAX),
            )
            .all(self.scoped_connection())
            .await
            .map_err(map_db_err)?
            .into_iter()
            .map(TryInto::try_into)
            .collect()
    }
    async fn create_oauth_resource(
        &self,
        data: alibi_core::store::CreateOAuthResource,
    ) -> AuthResult<alibi_core::store::OAuthResource> {
        let fields = super::entities::oauth_resource::Model::columns_from_metadata(data.metadata)?;
        let mut active = super::entities::oauth_resource::ActiveModel {
            id: Set(self
                .generated_id(&self.db, "oauthResource", "oauthResource", "id")
                .await?
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())),
            identifier: Set(data.identifier),
            created_at: Set(Some(data.created_at)),
            updated_at: Set(Some(data.created_at)),
            ..Default::default()
        };
        fields.stage_metadata(&mut active);
        active
            .insert(self.scoped_connection())
            .await
            .map_err(map_db_err)?
            .try_into()
    }
    async fn get_oauth_resource(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<alibi_core::store::OAuthResource>> {
        super::entities::oauth_resource::Entity::find()
            .filter(super::entities::oauth_resource::Column::Identifier.eq(identifier))
            .one(self.scoped_connection())
            .await
            .map_err(map_db_err)?
            .map(TryInto::try_into)
            .transpose()
    }
    async fn create_oauth_consent(
        &self,
        data: alibi_core::store::CreateOAuthConsent,
    ) -> AuthResult<alibi_core::store::OAuthConsent> {
        let fields = super::entities::oauth_consent::Model::columns_from_metadata(data.metadata)?;
        let mut active = super::entities::oauth_consent::ActiveModel {
            id: Set(self
                .generated_id(&self.db, "oauthConsent", "oauthConsent", "id")
                .await?
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())),
            client_id: Set(data.client_id),
            user_id: Set(data.user_id),
            created_at: Set(data.created_at),
            updated_at: Set(data.created_at),
            ..Default::default()
        };
        fields.stage_metadata(&mut active);
        active
            .insert(self.scoped_connection())
            .await
            .map_err(map_db_err)?
            .try_into()
    }
    async fn list_oauth_consents_by_user(
        &self,
        user_id: &str,
    ) -> AuthResult<Vec<alibi_core::store::OAuthConsent>> {
        super::entities::oauth_consent::Entity::find()
            .filter(super::entities::oauth_consent::Column::UserId.eq(user_id))
            .limit(
                u64::try_from(self.config().advanced.database.default_find_many_limit)
                    .unwrap_or(u64::MAX),
            )
            .all(self.scoped_connection())
            .await
            .map_err(map_db_err)?
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
        let Some(model) = super::entities::oauth_consent::Entity::find_by_id(id)
            .one(self.scoped_connection())
            .await
            .map_err(map_db_err)?
        else {
            return Ok(None);
        };
        let mut active = model.into_active_model();
        super::entities::oauth_consent::Model::columns_from_metadata(metadata)?
            .stage_metadata(&mut active);
        active.updated_at = Set(updated_at);
        active
            .update(self.scoped_connection())
            .await
            .map_err(map_db_err)?
            .try_into()
            .map(Some)
    }
    async fn create_oauth_client(&self, data: CreateOAuthClient) -> AuthResult<OAuthClient> {
        let fields = oauth_client::Model::columns_from_metadata(data.metadata)?;
        let mut active = oauth_client::ActiveModel {
            id: Set(self
                .generated_id(&self.db, "oauthClient", "oauthClient", "id")
                .await?
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())),
            client_id: Set(data.client_id),
            user_id: Set(data.user_id),
            client_secret: Set(data.client_secret),
            created_at: Set(Some(data.created_at)),
            updated_at: Set(Some(data.created_at)),
            ..Default::default()
        };
        fields.stage_metadata(&mut active);
        active
            .insert(self.scoped_connection())
            .await
            .map_err(map_db_err)?
            .try_into()
    }
    async fn get_oauth_consent(
        &self,
        id: &str,
    ) -> AuthResult<Option<alibi_core::store::OAuthConsent>> {
        super::entities::oauth_consent::Entity::find()
            .filter(super::entities::oauth_consent::Column::Id.eq(id))
            .one(self.scoped_connection())
            .await
            .map_err(map_db_err)?
            .map(TryInto::try_into)
            .transpose()
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
    async fn list_oauth_clients_by_user(&self, user_id: &str) -> AuthResult<Vec<OAuthClient>> {
        Entity::find()
            .filter(Column::UserId.eq(user_id))
            .limit(
                u64::try_from(self.config().advanced.database.default_find_many_limit)
                    .unwrap_or(u64::MAX),
            )
            .all(self.scoped_connection())
            .await
            .map_err(map_db_err)?
            .into_iter()
            .map(TryInto::try_into)
            .collect()
    }
    async fn delete_oauth_consent(&self, id: &str) -> AuthResult<()> {
        super::entities::oauth_consent::Entity::delete_many()
            .filter(super::entities::oauth_consent::Column::Id.eq(id))
            .exec(self.scoped_connection())
            .await
            .map_err(map_db_err)
            .map(|_| ())
    }
    async fn delete_oauth_client(&self, client_id: &str) -> AuthResult<()> {
        Entity::delete_many()
            .filter(Column::ClientId.eq(client_id))
            .exec(self.scoped_connection())
            .await
            .map_err(map_db_err)
            .map(|_| ())
    }
    async fn update_oauth_client_secret(
        &self,
        client_id: &str,
        secret: String,
        updated_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<Option<OAuthClient>> {
        let Some(model) = Entity::find()
            .filter(Column::ClientId.eq(client_id))
            .one(self.scoped_connection())
            .await
            .map_err(map_db_err)?
        else {
            return Ok(None);
        };
        let mut active = model.into_active_model();
        active.client_secret = Set(Some(secret));
        active.updated_at = Set(Some(updated_at));
        active
            .update(self.scoped_connection())
            .await
            .map_err(map_db_err)?
            .try_into()
            .map(Some)
    }
    async fn update_oauth_client_metadata(
        &self,
        client_id: &str,
        metadata: serde_json::Value,
        updated_at: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<Option<OAuthClient>> {
        let Some(model) = Entity::find()
            .filter(Column::ClientId.eq(client_id))
            .one(self.scoped_connection())
            .await
            .map_err(map_db_err)?
        else {
            return Ok(None);
        };
        let mut active = model.into_active_model();
        oauth_client::Model::columns_from_metadata(metadata)?.stage_metadata(&mut active);
        active.updated_at = Set(Some(updated_at));
        active
            .update(self.scoped_connection())
            .await
            .map_err(map_db_err)?
            .try_into()
            .map(Some)
    }
}
