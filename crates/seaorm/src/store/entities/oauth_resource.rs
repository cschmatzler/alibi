use crate::JsonMetadata;
use sea_orm::entity::prelude::*;
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
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

impl TryFrom<Model> for alibi_core::store::OAuthResource {
    type Error = alibi_core::AuthError;
    fn try_from(model: Model) -> Result<Self, Self::Error> {
        let mut metadata = serde_json::to_value(&model)?;
        let object = metadata
            .as_object_mut()
            .ok_or_else(|| alibi_core::AuthError::internal("OAuth fields must be an object"))?;
        for name in ["id", "identifier", "createdAt", "updatedAt"] {
            _ = object.remove(name);
        }
        Ok(Self {
            id: model.id,
            identifier: model.identifier.clone(),
            metadata,
            created_at: model.created_at,
            updated_at: model.updated_at,
        })
    }
}
impl Model {
    pub(crate) fn columns_from_metadata(
        mut fields: serde_json::Value,
    ) -> alibi_core::AuthResult<Self> {
        let object = fields
            .as_object_mut()
            .ok_or_else(|| alibi_core::AuthError::bad_request("OAuth fields must be an object"))?;
        for (key, value) in [("id", ""), ("identifier", "")] {
            _ = object.insert(key.into(), serde_json::Value::String(value.into()));
        }
        Ok(serde_json::from_value(fields)?)
    }
}

impl Model {
    pub(crate) fn stage_metadata(self, active: &mut ActiveModel) {
        active.name = sea_orm::Set(self.name);
        active.access_token_ttl = sea_orm::Set(self.access_token_ttl);
        active.refresh_token_ttl = sea_orm::Set(self.refresh_token_ttl);
        active.signing_algorithm = sea_orm::Set(self.signing_algorithm);
        active.signing_key_id = sea_orm::Set(self.signing_key_id);
        active.allowed_scopes = sea_orm::Set(self.allowed_scopes);
        active.custom_claims = sea_orm::Set(self.custom_claims);
        active.dpop_bound_access_tokens_required =
            sea_orm::Set(self.dpop_bound_access_tokens_required);
        active.disabled = sea_orm::Set(self.disabled);
        active.policy_version = sea_orm::Set(self.policy_version);
        active.metadata = sea_orm::Set(self.metadata);
    }
}
