use crate::{JsonMetadata, SqlxModel};
use chrono::{DateTime, Utc};
#[derive(Clone, Debug, PartialEq, serde::Serialize, sqlx::FromRow, SqlxModel)]
#[auth(table = "oauthConsent")]
pub struct Model {
    pub id: String,
    #[sqlx(rename = "clientId")]
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[sqlx(rename = "userId")]
    #[serde(rename = "userId")]
    pub user_id: Option<String>,
    #[sqlx(rename = "referenceId")]
    #[serde(rename = "referenceId")]
    pub reference_id: Option<String>,
    #[serde(rename = "resources")]
    pub resources: Option<JsonMetadata>,
    #[sqlx(rename = "requestedUserInfoClaims")]
    #[serde(rename = "requestedUserInfoClaims")]
    pub requested_user_info_claims: Option<JsonMetadata>,
    #[serde(rename = "scopes")]
    pub scopes: JsonMetadata,
    #[sqlx(rename = "createdAt")]
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[sqlx(rename = "updatedAt")]
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}
