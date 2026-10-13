use crate::JsonMetadata;
use sea_orm::entity::prelude::*;
#[derive(Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel)]
#[sea_orm(table_name = "oauthResource")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[serde(rename = "identifier")]
    pub identifier: String,
    #[serde(rename = "name")]
    pub name: String,
    #[sea_orm(column_name = "accessTokenTtl")]
    #[serde(rename = "accessTokenTtl")]
    pub access_token_ttl: Option<i32>,
    #[sea_orm(column_name = "refreshTokenTtl")]
    #[serde(rename = "refreshTokenTtl")]
    pub refresh_token_ttl: Option<i32>,
    #[sea_orm(column_name = "signingAlgorithm")]
    #[serde(rename = "signingAlgorithm")]
    pub signing_algorithm: Option<String>,
    #[sea_orm(column_name = "signingKeyId")]
    #[serde(rename = "signingKeyId")]
    pub signing_key_id: Option<String>,
    #[sea_orm(column_name = "allowedScopes")]
    #[serde(rename = "allowedScopes")]
    pub allowed_scopes: Option<JsonMetadata>,
    #[sea_orm(column_name = "customClaims")]
    #[serde(rename = "customClaims")]
    pub custom_claims: Option<JsonMetadata>,
    #[sea_orm(column_name = "dpopBoundAccessTokensRequired")]
    #[serde(rename = "dpopBoundAccessTokensRequired")]
    pub dpop_bound_access_tokens_required: Option<bool>,
    #[serde(rename = "disabled")]
    pub disabled: Option<bool>,
    #[sea_orm(column_name = "createdAt")]
    #[serde(rename = "createdAt")]
    pub created_at: Option<DateTimeUtc>,
    #[sea_orm(column_name = "updatedAt")]
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<DateTimeUtc>,
    #[sea_orm(column_name = "policyVersion")]
    #[serde(rename = "policyVersion")]
    pub policy_version: Option<i32>,
    #[serde(rename = "metadata")]
    pub metadata: Option<JsonMetadata>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}
