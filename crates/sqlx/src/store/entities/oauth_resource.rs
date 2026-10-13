use crate::{JsonMetadata, SqlxModel};
use chrono::{DateTime, Utc};
#[derive(
    Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, sqlx::FromRow, SqlxModel,
)]
#[auth(table = "oauthResource")]
pub struct Model {
    pub id: String,
    #[serde(rename = "identifier")]
    pub identifier: String,
    #[serde(rename = "name")]
    pub name: String,
    #[sqlx(rename = "accessTokenTtl")]
    #[serde(rename = "accessTokenTtl")]
    pub access_token_ttl: Option<i32>,
    #[sqlx(rename = "refreshTokenTtl")]
    #[serde(rename = "refreshTokenTtl")]
    pub refresh_token_ttl: Option<i32>,
    #[sqlx(rename = "signingAlgorithm")]
    #[serde(rename = "signingAlgorithm")]
    pub signing_algorithm: Option<String>,
    #[sqlx(rename = "signingKeyId")]
    #[serde(rename = "signingKeyId")]
    pub signing_key_id: Option<String>,
    #[sqlx(rename = "allowedScopes")]
    #[serde(rename = "allowedScopes")]
    pub allowed_scopes: Option<JsonMetadata>,
    #[sqlx(rename = "customClaims")]
    #[serde(rename = "customClaims")]
    pub custom_claims: Option<JsonMetadata>,
    #[sqlx(rename = "dpopBoundAccessTokensRequired")]
    #[serde(rename = "dpopBoundAccessTokensRequired")]
    pub dpop_bound_access_tokens_required: Option<bool>,
    #[serde(rename = "disabled")]
    pub disabled: Option<bool>,
    #[sqlx(rename = "createdAt")]
    #[serde(rename = "createdAt")]
    pub created_at: Option<DateTime<Utc>>,
    #[sqlx(rename = "updatedAt")]
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<DateTime<Utc>>,
    #[sqlx(rename = "policyVersion")]
    #[serde(rename = "policyVersion")]
    pub policy_version: Option<i32>,
    #[serde(rename = "metadata")]
    pub metadata: Option<JsonMetadata>,
}

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
