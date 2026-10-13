use crate::JsonMetadata;
use sea_orm::entity::prelude::*;
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
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
impl Model {
    pub(crate) fn stage_metadata(self, active: &mut ActiveModel) {
        active.reference_id = sea_orm::Set(self.reference_id);
        active.resources = sea_orm::Set(self.resources);
        active.requested_user_info_claims = sea_orm::Set(self.requested_user_info_claims);
        active.revoked = sea_orm::Set(self.revoked);
        active.rotated_at = sea_orm::Set(self.rotated_at);
        active.rotation_replay_response = sea_orm::Set(self.rotation_replay_response);
        active.rotation_replay_expires_at = sea_orm::Set(self.rotation_replay_expires_at);
        active.auth_time = sea_orm::Set(self.auth_time);
        active.confirmation = sea_orm::Set(self.confirmation);
        active.scopes = sea_orm::Set(self.scopes);
    }
}
