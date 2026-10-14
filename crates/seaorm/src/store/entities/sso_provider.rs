#[derive(
    Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, sea_orm::DeriveEntityModel,
)]
#[sea_orm(table_name = "ssoProvider")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub issuer: String,
    pub domain: String,
    #[sea_orm(column_name = "providerId")]
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[sea_orm(column_name = "userId")]
    #[serde(rename = "userId")]
    pub user_id: Option<String>,
    #[sea_orm(column_name = "organizationId")]
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
    #[sea_orm(column_name = "oidcConfig")]
    #[serde(rename = "oidcConfig")]
    pub oidc_config: Option<String>,
    #[sea_orm(column_name = "samlConfig")]
    #[serde(rename = "samlConfig")]
    pub saml_config: Option<String>,
    #[sea_orm(column_name = "domainVerified")]
    #[serde(rename = "domainVerified")]
    pub domain_verified: Option<bool>,
}
use sea_orm::entity::prelude::*;
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}
impl From<Model> for alibi_core::store::SsoProvider {
    fn from(row: Model) -> Self {
        Self {
            id: row.id,
            issuer: row.issuer,
            domain: row.domain,
            provider_id: row.provider_id,
            user_id: row.user_id,
            organization_id: row.organization_id,
            oidc_config: row.oidc_config,
            saml_config: row.saml_config,
            domain_verified: row.domain_verified,
            additional_fields: serde_json::Map::new(),
        }
    }
}
