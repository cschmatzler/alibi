use crate::SqlxModel;
use chrono::{DateTime, Utc};
#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow, SqlxModel)]
#[auth(table = "oauth_client")]
pub struct Model {
    pub id: String,
    pub client_id: String,
    pub user_id: Option<String>,
    pub client_secret: Option<String>,
    pub metadata: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
impl TryFrom<Model> for alibi_core::store::OAuthClient {
    type Error = alibi_core::AuthError;
    fn try_from(model: Model) -> Result<Self, Self::Error> {
        Ok(Self {
            id: model.id,
            client_id: model.client_id,
            user_id: model.user_id,
            client_secret: model.client_secret,
            metadata: serde_json::from_str(&model.metadata)?,
            created_at: model.created_at,
            updated_at: model.updated_at,
        })
    }
}
