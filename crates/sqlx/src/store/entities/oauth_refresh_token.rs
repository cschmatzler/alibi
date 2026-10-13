use crate::{JsonMetadata, SqlxModel};
use chrono::{DateTime, Utc};
#[derive(
    Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, sqlx::FromRow, SqlxModel,
)]
#[auth(table = "oauthRefreshToken")]
pub struct Model {
    pub id: String,
    #[serde(rename = "token")]
    pub token: String,
    #[sqlx(rename = "clientId")]
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[sqlx(rename = "sessionId")]
    #[serde(rename = "sessionId")]
    pub session_id: Option<String>,
    #[sqlx(rename = "userId")]
    #[serde(rename = "userId")]
    pub user_id: String,
    #[sqlx(rename = "referenceId")]
    #[serde(rename = "referenceId")]
    pub reference_id: Option<String>,
    #[sqlx(rename = "authorizationCodeId")]
    #[serde(rename = "authorizationCodeId")]
    pub authorization_code_id: Option<String>,
    #[serde(rename = "resources")]
    pub resources: Option<JsonMetadata>,
    #[sqlx(rename = "requestedUserInfoClaims")]
    #[serde(rename = "requestedUserInfoClaims")]
    pub requested_user_info_claims: Option<JsonMetadata>,
    #[sqlx(rename = "expiresAt")]
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
    #[sqlx(rename = "createdAt")]
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "revoked")]
    pub revoked: Option<DateTime<Utc>>,
    #[sqlx(rename = "rotatedAt")]
    #[serde(rename = "rotatedAt")]
    pub rotated_at: Option<DateTime<Utc>>,
    #[sqlx(rename = "rotationReplayResponse")]
    #[serde(rename = "rotationReplayResponse")]
    pub rotation_replay_response: Option<String>,
    #[sqlx(rename = "rotationReplayExpiresAt")]
    #[serde(rename = "rotationReplayExpiresAt")]
    pub rotation_replay_expires_at: Option<DateTime<Utc>>,
    #[sqlx(rename = "authTime")]
    #[serde(rename = "authTime")]
    pub auth_time: Option<DateTime<Utc>>,
    #[serde(rename = "confirmation")]
    pub confirmation: Option<JsonMetadata>,
    #[serde(rename = "scopes")]
    pub scopes: JsonMetadata,
}

impl TryFrom<Model> for alibi_core::store::OAuthToken {
    type Error = alibi_core::AuthError;
    fn try_from(model: Model) -> Result<Self, Self::Error> {
        let mut metadata = serde_json::to_value(&model)?;
        let object = metadata
            .as_object_mut()
            .ok_or_else(|| alibi_core::AuthError::internal("OAuth token must be an object"))?;
        for name in [
            "id",
            "token",
            "clientId",
            "sessionId",
            "userId",
            "authorizationCodeId",
            "createdAt",
            "expiresAt",
        ] {
            _ = object.remove(name);
        }
        Ok(Self {
            id: model.id,
            token: model.token,
            client_id: model.client_id,
            user_id: Some(model.user_id.clone()),
            session_id: model.session_id,
            authorization_code_id: model.authorization_code_id,
            metadata,
            created_at: model.created_at,
            expires_at: model.expires_at,
        })
    }
}
impl Model {
    pub(crate) fn columns_from_metadata(
        mut fields: serde_json::Value,
    ) -> alibi_core::AuthResult<Self> {
        let object = fields.as_object_mut().ok_or_else(|| {
            alibi_core::AuthError::bad_request("OAuth token metadata must be an object")
        })?;
        for name in ["id", "token", "clientId", "userId"] {
            _ = object.insert(name.into(), serde_json::Value::String(String::new()));
        }
        for name in ["createdAt", "expiresAt"] {
            _ = object.insert(
                name.into(),
                serde_json::Value::String("1970-01-01T00:00:00Z".into()),
            );
        }
        Ok(serde_json::from_value(fields)?)
    }
}
