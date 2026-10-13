use crate::JsonMetadata;
use sea_orm::entity::prelude::*;
#[derive(Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel)]
#[sea_orm(table_name = "oauthRefreshToken")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[serde(rename = "token")]
    pub token: String,
    #[sea_orm(column_name = "clientId")]
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[sea_orm(column_name = "sessionId")]
    #[serde(rename = "sessionId")]
    pub session_id: Option<String>,
    #[sea_orm(column_name = "userId")]
    #[serde(rename = "userId")]
    pub user_id: String,
    #[sea_orm(column_name = "referenceId")]
    #[serde(rename = "referenceId")]
    pub reference_id: Option<String>,
    #[sea_orm(column_name = "authorizationCodeId")]
    #[serde(rename = "authorizationCodeId")]
    pub authorization_code_id: Option<String>,
    #[serde(rename = "resources")]
    pub resources: Option<JsonMetadata>,
    #[sea_orm(column_name = "requestedUserInfoClaims")]
    #[serde(rename = "requestedUserInfoClaims")]
    pub requested_user_info_claims: Option<JsonMetadata>,
    #[sea_orm(column_name = "expiresAt")]
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTimeUtc,
    #[sea_orm(column_name = "createdAt")]
    #[serde(rename = "createdAt")]
    pub created_at: DateTimeUtc,
    #[serde(rename = "revoked")]
    pub revoked: Option<DateTimeUtc>,
    #[sea_orm(column_name = "rotatedAt")]
    #[serde(rename = "rotatedAt")]
    pub rotated_at: Option<DateTimeUtc>,
    #[sea_orm(column_name = "rotationReplayResponse")]
    #[serde(rename = "rotationReplayResponse")]
    pub rotation_replay_response: Option<String>,
    #[sea_orm(column_name = "rotationReplayExpiresAt")]
    #[serde(rename = "rotationReplayExpiresAt")]
    pub rotation_replay_expires_at: Option<DateTimeUtc>,
    #[sea_orm(column_name = "authTime")]
    #[serde(rename = "authTime")]
    pub auth_time: Option<DateTimeUtc>,
    #[serde(rename = "confirmation")]
    pub confirmation: Option<JsonMetadata>,
    #[serde(rename = "scopes")]
    pub scopes: JsonMetadata,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}
