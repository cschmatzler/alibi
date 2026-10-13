//! Durable OAuth provider clients, grants, and resource policy.
use crate::{AuthError, AuthResult};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
#[derive(Clone, Debug)]
pub struct OAuthClient {
    pub id: String,
    pub client_id: String,
    pub user_id: Option<String>,
    pub client_secret: Option<String>,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
#[derive(Clone, Debug)]
pub struct CreateOAuthClient {
    pub client_id: String,
    pub user_id: Option<String>,
    pub client_secret: Option<String>,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
}
#[async_trait]
pub trait OAuthClientStore: Send + Sync {
    async fn delete_oauth_resource(&self, _identifier: &str) -> AuthResult<()> {
        Err(AuthError::config(
            "OAuth resource persistence is not supported by this store",
        ))
    }
    async fn update_oauth_resource(
        &self,
        _identifier: &str,
        _metadata: Value,
        _updated_at: DateTime<Utc>,
    ) -> AuthResult<Option<OAuthResource>> {
        Err(AuthError::config(
            "OAuth resource persistence is not supported by this store",
        ))
    }
    async fn list_oauth_resources(&self) -> AuthResult<Vec<OAuthResource>> {
        Err(AuthError::config(
            "OAuth resource persistence is not supported by this store",
        ))
    }
    async fn list_oauth_client_resources(
        &self,
        _client_id: &str,
    ) -> AuthResult<Vec<OAuthClientResource>> {
        Err(AuthError::config(
            "OAuth resource linkage is not supported by this store",
        ))
    }
    async fn create_oauth_resource(&self, _data: CreateOAuthResource) -> AuthResult<OAuthResource> {
        Err(AuthError::config(
            "OAuth resource persistence is not supported by this store",
        ))
    }
    async fn get_oauth_resource(&self, _identifier: &str) -> AuthResult<Option<OAuthResource>> {
        Err(AuthError::config(
            "OAuth resource persistence is not supported by this store",
        ))
    }
    async fn delete_oauth_consent(&self, _id: &str) -> AuthResult<()> {
        Err(AuthError::config(
            "OAuth consent persistence is not supported by this store",
        ))
    }
    async fn get_oauth_consent(&self, _id: &str) -> AuthResult<Option<OAuthConsent>> {
        Err(AuthError::config(
            "OAuth consent persistence is not supported by this store",
        ))
    }
    async fn create_oauth_consent(&self, _data: CreateOAuthConsent) -> AuthResult<OAuthConsent> {
        Err(AuthError::config(
            "OAuth consent persistence is not supported by this store",
        ))
    }
    async fn list_oauth_consents_by_user(&self, _user_id: &str) -> AuthResult<Vec<OAuthConsent>> {
        Err(AuthError::config(
            "OAuth consent persistence is not supported by this store",
        ))
    }
    async fn update_oauth_consent_metadata(
        &self,
        _id: &str,
        _metadata: Value,
        _updated_at: DateTime<Utc>,
    ) -> AuthResult<Option<OAuthConsent>> {
        Err(AuthError::config(
            "OAuth consent persistence is not supported by this store",
        ))
    }
    async fn create_oauth_client(&self, _data: CreateOAuthClient) -> AuthResult<OAuthClient> {
        Err(AuthError::config(
            "OAuth client persistence is not supported by this store",
        ))
    }
    async fn get_oauth_client(&self, _client_id: &str) -> AuthResult<Option<OAuthClient>> {
        Err(AuthError::config(
            "OAuth client persistence is not supported by this store",
        ))
    }
    async fn list_oauth_clients_by_user(&self, _user_id: &str) -> AuthResult<Vec<OAuthClient>> {
        Err(AuthError::config(
            "OAuth client persistence is not supported by this store",
        ))
    }
    async fn delete_oauth_client(&self, _client_id: &str) -> AuthResult<()> {
        Err(AuthError::config(
            "OAuth client persistence is not supported by this store",
        ))
    }
    async fn update_oauth_client_secret(
        &self,
        _client_id: &str,
        _secret: String,
        _updated_at: DateTime<Utc>,
    ) -> AuthResult<Option<OAuthClient>> {
        Err(AuthError::config(
            "OAuth client persistence is not supported by this store",
        ))
    }
    async fn update_oauth_client_metadata(
        &self,
        _client_id: &str,
        _metadata: Value,
        _updated_at: DateTime<Utc>,
    ) -> AuthResult<Option<OAuthClient>> {
        Err(AuthError::config(
            "OAuth client persistence is not supported by this store",
        ))
    }
}

/// Durable consent attached to the client and consenting user.
#[derive(Clone, Debug)]
pub struct OAuthConsent {
    pub id: String,
    pub client_id: String,
    pub user_id: Option<String>,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
#[derive(Clone, Debug)]
pub struct CreateOAuthConsent {
    pub client_id: String,
    pub user_id: Option<String>,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct OAuthResource {
    pub id: String,
    pub identifier: String,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
#[derive(Clone, Debug)]
pub struct CreateOAuthResource {
    pub identifier: String,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct OAuthClientResource {
    pub id: String,
    pub client_id: String,
    pub resource_id: String,
    pub metadata: Value,
    pub created_at: Option<DateTime<Utc>>,
}
