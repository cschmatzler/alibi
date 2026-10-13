use crate::{JsonMetadata, SqlxModel};
use chrono::{DateTime, Utc};
#[derive(
    Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, sqlx::FromRow, SqlxModel,
)]
#[auth(table = "oauthClient")]
pub struct Model {
    pub id: String,
    #[sqlx(rename = "clientId")]
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[sqlx(rename = "clientSecret")]
    #[serde(rename = "clientSecret")]
    pub client_secret: Option<String>,
    #[sqlx(rename = "clientDiscoveryId")]
    #[serde(rename = "clientDiscoveryId")]
    pub client_discovery_id: Option<String>,
    #[serde(rename = "disabled")]
    pub disabled: Option<bool>,
    #[sqlx(rename = "skipConsent")]
    #[serde(rename = "skipConsent")]
    pub skip_consent: Option<bool>,
    #[sqlx(rename = "enableEndSession")]
    #[serde(rename = "enableEndSession")]
    pub enable_end_session: Option<bool>,
    #[sqlx(rename = "subjectType")]
    #[serde(rename = "subjectType")]
    pub subject_type: Option<String>,
    #[serde(rename = "scopes")]
    pub scopes: Option<JsonMetadata>,
    #[sqlx(rename = "clientCredentialsScopes")]
    #[serde(rename = "clientCredentialsScopes")]
    pub client_credentials_scopes: Option<JsonMetadata>,
    #[sqlx(rename = "userId")]
    #[serde(rename = "userId")]
    pub user_id: Option<String>,
    #[sqlx(rename = "createdAt")]
    #[serde(rename = "createdAt")]
    pub created_at: Option<DateTime<Utc>>,
    #[sqlx(rename = "updatedAt")]
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(rename = "name")]
    pub name: Option<String>,
    #[serde(rename = "uri")]
    pub uri: Option<String>,
    #[serde(rename = "icon")]
    pub icon: Option<String>,
    #[serde(rename = "contacts")]
    pub contacts: Option<JsonMetadata>,
    #[serde(rename = "tos")]
    pub tos: Option<String>,
    #[serde(rename = "policy")]
    pub policy: Option<String>,
    #[sqlx(rename = "softwareId")]
    #[serde(rename = "softwareId")]
    pub software_id: Option<String>,
    #[sqlx(rename = "softwareVersion")]
    #[serde(rename = "softwareVersion")]
    pub software_version: Option<String>,
    #[sqlx(rename = "softwareStatement")]
    #[serde(rename = "softwareStatement")]
    pub software_statement: Option<String>,
    #[sqlx(rename = "redirectUris")]
    #[serde(rename = "redirectUris")]
    pub redirect_uris: JsonMetadata,
    #[sqlx(rename = "postLogoutRedirectUris")]
    #[serde(rename = "postLogoutRedirectUris")]
    pub post_logout_redirect_uris: Option<JsonMetadata>,
    #[sqlx(rename = "backchannelLogoutUri")]
    #[serde(rename = "backchannelLogoutUri")]
    pub backchannel_logout_uri: Option<String>,
    #[sqlx(rename = "backchannelLogoutSessionRequired")]
    #[serde(rename = "backchannelLogoutSessionRequired")]
    pub backchannel_logout_session_required: Option<bool>,
    #[sqlx(rename = "tokenEndpointAuthMethod")]
    #[serde(rename = "tokenEndpointAuthMethod")]
    pub token_endpoint_auth_method: Option<String>,
    #[sqlx(rename = "applicationType")]
    #[serde(rename = "applicationType")]
    pub application_type: Option<String>,
    #[serde(rename = "jwks")]
    pub jwks: Option<String>,
    #[sqlx(rename = "jwksUri")]
    #[serde(rename = "jwksUri")]
    pub jwks_uri: Option<String>,
    #[sqlx(rename = "grantTypes")]
    #[serde(rename = "grantTypes")]
    pub grant_types: Option<JsonMetadata>,
    #[sqlx(rename = "responseTypes")]
    #[serde(rename = "responseTypes")]
    pub response_types: Option<JsonMetadata>,
    #[sqlx(rename = "requirePKCE")]
    #[serde(rename = "requirePKCE")]
    pub require_pkce: Option<bool>,
    #[sqlx(rename = "dpopBoundAccessTokens")]
    #[serde(rename = "dpopBoundAccessTokens")]
    pub dpop_bound_access_tokens: Option<bool>,
    #[sqlx(rename = "referenceId")]
    #[serde(rename = "referenceId")]
    pub reference_id: Option<String>,
    #[serde(rename = "metadata")]
    pub metadata: Option<JsonMetadata>,
}

impl TryFrom<Model> for alibi_core::store::OAuthClient {
    type Error = alibi_core::AuthError;
    fn try_from(model: Model) -> Result<Self, Self::Error> {
        let metadata = alibi_core::store::oauth_clients::metadata_from_columns(
            &serde_json::to_value(&model)?,
        )?;
        Ok(Self {
            id: model.id,
            client_id: model.client_id,
            user_id: model.user_id,
            client_secret: model.client_secret,
            metadata,
            created_at: model.created_at,
            updated_at: model.updated_at,
        })
    }
}
impl Model {
    pub(crate) fn columns_from_metadata(
        metadata: serde_json::Value,
    ) -> alibi_core::AuthResult<Self> {
        let mut fields = alibi_core::store::oauth_clients::metadata_to_columns(metadata)?;
        let object = fields.as_object_mut().ok_or_else(|| {
            alibi_core::AuthError::internal("OAuth client fields must be an object")
        })?;
        _ = object.insert("id".into(), serde_json::Value::String(String::new()));
        _ = object.insert("clientId".into(), serde_json::Value::String(String::new()));
        Ok(serde_json::from_value(fields)?)
    }
}
