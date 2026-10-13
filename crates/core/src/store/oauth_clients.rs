//! Durable OAuth clients; plaintext registration secrets never belong in metadata.
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
