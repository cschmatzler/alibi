#[derive(
    Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, sqlx::FromRow, crate::SqlxModel,
)]
#[auth(table = "ssoProvider")]
pub struct Model {
    pub id: String,
    pub issuer: String,
    pub domain: String,
    #[sqlx(rename = "providerId")]
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[sqlx(rename = "userId")]
    #[serde(rename = "userId")]
    pub user_id: Option<String>,
    #[sqlx(rename = "organizationId")]
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
    #[sqlx(rename = "oidcConfig")]
    #[serde(rename = "oidcConfig")]
    pub oidc_config: Option<String>,
    #[sqlx(rename = "samlConfig")]
    #[serde(rename = "samlConfig")]
    pub saml_config: Option<String>,
    #[sqlx(rename = "domainVerified")]
    #[serde(rename = "domainVerified")]
    pub domain_verified: Option<bool>,
}
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
