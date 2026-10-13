use crate::{JsonMetadata, SqlxModel};
use chrono::{DateTime, Utc};
#[derive(
    Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, sqlx::FromRow, SqlxModel,
)]
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

impl TryFrom<Model> for alibi_core::store::OAuthConsent {
    type Error = alibi_core::AuthError;
    fn try_from(model: Model) -> Result<Self, Self::Error> {
        let mut metadata = serde_json::to_value(&model)?;
        let object = metadata
            .as_object_mut()
            .ok_or_else(|| alibi_core::AuthError::internal("OAuth fields must be an object"))?;
        for name in ["id", "clientId", "userId", "createdAt", "updatedAt"] {
            _ = object.remove(name);
        }
        Ok(Self {
            id: model.id,
            client_id: model.client_id.clone(),
            user_id: model.user_id.clone(),
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
        for (key, value) in [
            ("id", ""),
            ("clientId", ""),
            ("createdAt", "1970-01-01T00:00:00Z"),
            ("updatedAt", "1970-01-01T00:00:00Z"),
        ] {
            _ = object.insert(key.into(), serde_json::Value::String(value.into()));
        }
        Ok(serde_json::from_value(fields)?)
    }
}
