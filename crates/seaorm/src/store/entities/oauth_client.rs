use crate::JsonMetadata;
use sea_orm::entity::prelude::*;
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, DeriveEntityModel)]
#[sea_orm(table_name = "oauthClient")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(column_name = "clientId")]
    #[serde(rename = "clientId")]
    pub client_id: String,
    #[sea_orm(column_name = "clientSecret")]
    #[serde(rename = "clientSecret")]
    pub client_secret: Option<String>,
    #[sea_orm(column_name = "clientDiscoveryId")]
    #[serde(rename = "clientDiscoveryId")]
    pub client_discovery_id: Option<String>,
    #[serde(rename = "disabled")]
    pub disabled: Option<bool>,
    #[sea_orm(column_name = "skipConsent")]
    #[serde(rename = "skipConsent")]
    pub skip_consent: Option<bool>,
    #[sea_orm(column_name = "enableEndSession")]
    #[serde(rename = "enableEndSession")]
    pub enable_end_session: Option<bool>,
    #[sea_orm(column_name = "subjectType")]
    #[serde(rename = "subjectType")]
    pub subject_type: Option<String>,
    #[serde(rename = "scopes")]
    pub scopes: Option<JsonMetadata>,
    #[sea_orm(column_name = "clientCredentialsScopes")]
    #[serde(rename = "clientCredentialsScopes")]
    pub client_credentials_scopes: Option<JsonMetadata>,
    #[sea_orm(column_name = "userId")]
    #[serde(rename = "userId")]
    pub user_id: Option<String>,
    #[sea_orm(column_name = "createdAt")]
    #[serde(rename = "createdAt")]
    pub created_at: Option<DateTimeUtc>,
    #[sea_orm(column_name = "updatedAt")]
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<DateTimeUtc>,
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
    #[sea_orm(column_name = "softwareId")]
    #[serde(rename = "softwareId")]
    pub software_id: Option<String>,
    #[sea_orm(column_name = "softwareVersion")]
    #[serde(rename = "softwareVersion")]
    pub software_version: Option<String>,
    #[sea_orm(column_name = "softwareStatement")]
    #[serde(rename = "softwareStatement")]
    pub software_statement: Option<String>,
    #[sea_orm(column_name = "redirectUris")]
    #[serde(rename = "redirectUris")]
    pub redirect_uris: JsonMetadata,
    #[sea_orm(column_name = "postLogoutRedirectUris")]
    #[serde(rename = "postLogoutRedirectUris")]
    pub post_logout_redirect_uris: Option<JsonMetadata>,
    #[sea_orm(column_name = "backchannelLogoutUri")]
    #[serde(rename = "backchannelLogoutUri")]
    pub backchannel_logout_uri: Option<String>,
    #[sea_orm(column_name = "backchannelLogoutSessionRequired")]
    #[serde(rename = "backchannelLogoutSessionRequired")]
    pub backchannel_logout_session_required: Option<bool>,
    #[sea_orm(column_name = "tokenEndpointAuthMethod")]
    #[serde(rename = "tokenEndpointAuthMethod")]
    pub token_endpoint_auth_method: Option<String>,
    #[sea_orm(column_name = "applicationType")]
    #[serde(rename = "applicationType")]
    pub application_type: Option<String>,
    #[serde(rename = "jwks")]
    pub jwks: Option<String>,
    #[sea_orm(column_name = "jwksUri")]
    #[serde(rename = "jwksUri")]
    pub jwks_uri: Option<String>,
    #[sea_orm(column_name = "grantTypes")]
    #[serde(rename = "grantTypes")]
    pub grant_types: Option<JsonMetadata>,
    #[sea_orm(column_name = "responseTypes")]
    #[serde(rename = "responseTypes")]
    pub response_types: Option<JsonMetadata>,
    #[sea_orm(column_name = "requirePKCE")]
    #[serde(rename = "requirePKCE")]
    pub require_pkce: Option<bool>,
    #[sea_orm(column_name = "dpopBoundAccessTokens")]
    #[serde(rename = "dpopBoundAccessTokens")]
    pub dpop_bound_access_tokens: Option<bool>,
    #[sea_orm(column_name = "referenceId")]
    #[serde(rename = "referenceId")]
    pub reference_id: Option<String>,
    #[serde(rename = "metadata")]
    pub metadata: Option<JsonMetadata>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}

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
impl Model {
    pub(crate) fn stage_metadata(self, active: &mut ActiveModel) {
        active.client_discovery_id = sea_orm::Set(self.client_discovery_id);
        active.disabled = sea_orm::Set(self.disabled);
        active.skip_consent = sea_orm::Set(self.skip_consent);
        active.enable_end_session = sea_orm::Set(self.enable_end_session);
        active.subject_type = sea_orm::Set(self.subject_type);
        active.scopes = sea_orm::Set(self.scopes);
        active.client_credentials_scopes = sea_orm::Set(self.client_credentials_scopes);
        active.name = sea_orm::Set(self.name);
        active.uri = sea_orm::Set(self.uri);
        active.icon = sea_orm::Set(self.icon);
        active.contacts = sea_orm::Set(self.contacts);
        active.tos = sea_orm::Set(self.tos);
        active.policy = sea_orm::Set(self.policy);
        active.software_id = sea_orm::Set(self.software_id);
        active.software_version = sea_orm::Set(self.software_version);
        active.software_statement = sea_orm::Set(self.software_statement);
        active.redirect_uris = sea_orm::Set(self.redirect_uris);
        active.post_logout_redirect_uris = sea_orm::Set(self.post_logout_redirect_uris);
        active.backchannel_logout_uri = sea_orm::Set(self.backchannel_logout_uri);
        active.backchannel_logout_session_required =
            sea_orm::Set(self.backchannel_logout_session_required);
        active.token_endpoint_auth_method = sea_orm::Set(self.token_endpoint_auth_method);
        active.application_type = sea_orm::Set(self.application_type);
        active.jwks = sea_orm::Set(self.jwks);
        active.jwks_uri = sea_orm::Set(self.jwks_uri);
        active.grant_types = sea_orm::Set(self.grant_types);
        active.response_types = sea_orm::Set(self.response_types);
        active.require_pkce = sea_orm::Set(self.require_pkce);
        active.dpop_bound_access_tokens = sea_orm::Set(self.dpop_bound_access_tokens);
        active.reference_id = sea_orm::Set(self.reference_id);
        active.metadata = sea_orm::Set(self.metadata);
    }
}
