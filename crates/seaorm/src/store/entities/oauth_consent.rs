use crate::JsonMetadata;
use sea_orm::entity::prelude::*;
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "oauthConsent")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(column_name = "clientId")]
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[sea_orm(column_name = "userId")]
    #[serde(rename = "userId")]
    pub user_id: Option<String>,
    #[sea_orm(column_name = "referenceId")]
    #[serde(rename = "referenceId")]
    pub reference_id: Option<String>,
    #[serde(rename = "resources")]
    pub resources: Option<JsonMetadata>,
    #[sea_orm(column_name = "requestedUserInfoClaims")]
    #[serde(rename = "requestedUserInfoClaims")]
    pub requested_user_info_claims: Option<JsonMetadata>,
    #[serde(rename = "scopes")]
    pub scopes: JsonMetadata,
    #[sea_orm(column_name = "createdAt")]
    #[serde(rename = "createdAt")]
    pub created_at: DateTimeUtc,
    #[sea_orm(column_name = "updatedAt")]
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}

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

impl Model {
    pub(crate) fn stage_metadata(self, active: &mut ActiveModel) {
        active.reference_id = sea_orm::Set(self.reference_id);
        active.resources = sea_orm::Set(self.resources);
        active.requested_user_info_claims = sea_orm::Set(self.requested_user_info_claims);
        active.scopes = sea_orm::Set(self.scopes);
    }
}
