use alibi_core::types::Jwk;
use sea_orm::entity::prelude::*;
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "jwks")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(column_name = "publicKey")]
    pub public_key: String,
    #[sea_orm(column_name = "privateKey")]
    pub private_key: String,
    #[sea_orm(column_name = "createdAt")]
    pub created_at: DateTimeUtc,
    #[sea_orm(column_name = "expiresAt")]
    pub expires_at: Option<DateTimeUtc>,
    pub alg: Option<String>,
    pub crv: Option<String>,
}
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}
impl From<Model> for Jwk {
    fn from(row: Model) -> Self {
        Self {
            id: row.id,
            public_key: row.public_key,
            private_key: row.private_key,
            created_at: row.created_at,
            expires_at: row.expires_at,
            alg: row.alg,
            crv: row.crv,
        }
    }
}
