use sea_orm::entity::prelude::*;
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "oauth_refresh_token")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub token: String,
    pub client_id: String,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub authorization_code_id: Option<String>,
    pub metadata: String,
    pub created_at: DateTimeUtc,
    pub expires_at: DateTimeUtc,
}
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}
impl TryFrom<Model> for alibi_core::store::OAuthToken {
    type Error = alibi_core::AuthError;
    fn try_from(model: Model) -> Result<Self, Self::Error> {
        Ok(Self {
            id: model.id,
            token: model.token,
            client_id: model.client_id,
            user_id: model.user_id,
            session_id: model.session_id,
            authorization_code_id: model.authorization_code_id,
            metadata: serde_json::from_str(&model.metadata)?,
            created_at: model.created_at,
            expires_at: model.expires_at,
        })
    }
}
