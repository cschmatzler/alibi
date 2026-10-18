//! Durable OAuth provider clients, grants, and resource policy.
use crate::{AuthError, AuthResult};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
#[derive(Clone, Debug)]
pub struct OAuthClient {
    pub id: String,
    pub client_id: String,
    pub user_id: Option<String>,
    pub client_secret: Option<String>,
    pub metadata: Value,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}
#[derive(Clone, Debug)]
pub struct CreateOAuthClient {
    pub client_id: String,
    pub user_id: Option<String>,
    pub client_secret: Option<String>,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
}
/// One atomic client row write and additive server-default resource linkage.
/// Replacement metadata is a patch: omitted model fields survive, explicit nulls clear.
#[derive(Clone, Debug)]
pub struct PersistOAuthClientRegistration {
    pub client: CreateOAuthClient,
    pub discovery_id: String,
    pub replace: bool,
    /// Replacement snapshot timestamp; absence is filtered out like an undefined adapter field.
    pub existing_created_at: Option<DateTime<Utc>>,
    pub resources: Vec<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum OAuthClientRegistrationWriteError {
    #[error(transparent)]
    Failure(#[from] AuthError),
    #[error("client registration collision: {cause}")]
    Collision {
        cause: AuthError,
        resource_id: Option<String>,
    },
}
impl OAuthClientRegistrationWriteError {
    /// Bundled adapters retain unique diagnostics in their constraint contract.
    #[must_use]
    pub fn classify(cause: AuthError, resource_id: Option<String>) -> Self {
        if matches!(&cause, AuthError::Database(crate::error::DatabaseError::Constraint(message)) if message.to_ascii_lowercase().contains("unique"))
        {
            Self::Collision { cause, resource_id }
        } else {
            Self::Failure(cause)
        }
    }
}
/// Durable token kind; refresh and opaque access tokens have distinct lifecycles.
#[derive(Clone, Copy, Debug)]
pub enum OAuthTokenKind {
    Access,
    Refresh,
}
#[derive(Clone, Debug)]
pub struct OAuthToken {
    pub id: String,
    pub token: String,
    pub client_id: String,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub authorization_code_id: Option<String>,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}
#[derive(Clone, Debug)]
pub struct CreateOAuthToken {
    pub token: String,
    pub client_id: String,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub authorization_code_id: Option<String>,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}
#[async_trait]
pub trait OAuthClientStore: Send + Sync {
    /// Exact relation lookup, independent of the configured list page limit.
    async fn has_oauth_client_resource(
        &self,
        _client_id: &str,
        _resource_id: &str,
    ) -> AuthResult<bool> {
        Err(AuthError::config(
            "OAuth resource linkage is not supported by this store",
        ))
    }
    /// Atomically insert or conditionally update a discovery-owned client and ensure
    /// its resource links. `None` means the replacement ownership predicate lost.
    /// Existing links (including their metadata/timestamps) are never replaced.
    async fn persist_oauth_client_registration(
        &self,
        _data: PersistOAuthClientRegistration,
    ) -> Result<Option<OAuthClient>, OAuthClientRegistrationWriteError> {
        Err(
            AuthError::config("Atomic OAuth client registration is not supported by this store")
                .into(),
        )
    }
    /// Atomically claim a caller-supplied assertion digest; false means it already exists.
    async fn claim_oauth_client_assertion(
        &self,
        id: &str,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<bool> {
        let _ = (id, expires_at);
        Err(AuthError::config(
            "OAuth assertion persistence is not supported by this store",
        ))
    }

    /// Claim default refresh rotation with both revocation and rotation timestamps.
    async fn store_oauth_refresh_replay(&self, id: &str, ciphertext: &str) -> AuthResult<()> {
        let _ = (id, ciphertext);
        Err(AuthError::config(
            "OAuth token persistence is not supported by this store",
        ))
    }
    /// Atomically rotate the retained row supplied to a trusted grant handler.
    async fn claim_oauth_refresh_rotation_by_id(
        &self,
        id: &str,
        at: DateTime<Utc>,
        replay_expires: Option<DateTime<Utc>>,
    ) -> AuthResult<bool> {
        let _ = (id, at, replay_expires);
        Err(AuthError::config(
            "OAuth refresh rotation by ID is not supported by this store",
        ))
    }
    async fn claim_oauth_refresh_rotation(
        &self,
        _token: &str,
        _at: DateTime<Utc>,
        _replay_expires: Option<DateTime<Utc>>,
    ) -> AuthResult<bool> {
        Err(AuthError::config(
            "OAuth token persistence is not supported by this store",
        ))
    }

    async fn list_oauth_tokens_for_session(
        &self,
        _kind: OAuthTokenKind,
        _session_id: &str,
    ) -> AuthResult<Vec<OAuthToken>> {
        Err(AuthError::config(
            "OAuth token persistence is not supported by this store",
        ))
    }
    async fn mark_oauth_token_revoked(
        &self,
        _kind: OAuthTokenKind,
        _id: &str,
        _at: DateTime<Utc>,
    ) -> AuthResult<()> {
        Err(AuthError::config(
            "OAuth token persistence is not supported by this store",
        ))
    }

    async fn delete_oauth_token(&self, _kind: OAuthTokenKind, _token: &str) -> AuthResult<()> {
        Err(AuthError::config(
            "OAuth token persistence is not supported by this store",
        ))
    }
    /// Atomically claim an unrevoked refresh token; concurrent claimants lose.
    async fn revoke_oauth_refresh_token(
        &self,
        _token: &str,
        _revoked_at: DateTime<Utc>,
    ) -> AuthResult<bool> {
        Err(AuthError::config(
            "OAuth token persistence is not supported by this store",
        ))
    }
    async fn delete_oauth_access_tokens_for_refresh(&self, _refresh_id: &str) -> AuthResult<()> {
        Err(AuthError::config(
            "OAuth token persistence is not supported by this store",
        ))
    }
    async fn delete_oauth_refresh_family(
        &self,
        _client_id: &str,
        _user_id: &str,
    ) -> AuthResult<()> {
        Err(AuthError::config(
            "OAuth token persistence is not supported by this store",
        ))
    }
    async fn create_oauth_token(
        &self,
        _kind: OAuthTokenKind,
        _data: CreateOAuthToken,
    ) -> AuthResult<OAuthToken> {
        Err(AuthError::config(
            "OAuth token persistence is not supported by this store",
        ))
    }
    async fn get_oauth_token(
        &self,
        _kind: OAuthTokenKind,
        _token: &str,
    ) -> AuthResult<Option<OAuthToken>> {
        Err(AuthError::config(
            "OAuth token persistence is not supported by this store",
        ))
    }
    async fn delete_oauth_tokens_for_code(&self, _code: &str) -> AuthResult<()> {
        Err(AuthError::config(
            "OAuth token persistence is not supported by this store",
        ))
    }

    async fn delete_oauth_client_resource(
        &self,
        _client_id: &str,
        _resource_id: &str,
    ) -> AuthResult<()> {
        Err(AuthError::config(
            "OAuth resource linkage is not supported by this store",
        ))
    }
    async fn create_oauth_client_resource(
        &self,
        _data: CreateOAuthClientResource,
    ) -> AuthResult<OAuthClientResource> {
        Err(AuthError::config(
            "OAuth resource linkage is not supported by this store",
        ))
    }
    async fn delete_oauth_resource(&self, _identifier: &str) -> AuthResult<()> {
        Err(AuthError::config(
            "OAuth resource persistence is not supported by this store",
        ))
    }
    async fn update_oauth_resource(
        &self,
        _identifier: &str,
        _metadata: Value,
        _updated_at: DateTime<Utc>,
    ) -> AuthResult<Option<OAuthResource>> {
        Err(AuthError::config(
            "OAuth resource persistence is not supported by this store",
        ))
    }
    async fn list_oauth_resources(&self) -> AuthResult<Vec<OAuthResource>> {
        Err(AuthError::config(
            "OAuth resource persistence is not supported by this store",
        ))
    }
    async fn list_oauth_client_resources(
        &self,
        _client_id: &str,
    ) -> AuthResult<Vec<OAuthClientResource>> {
        Err(AuthError::config(
            "OAuth resource linkage is not supported by this store",
        ))
    }
    async fn create_oauth_resource(&self, _data: CreateOAuthResource) -> AuthResult<OAuthResource> {
        Err(AuthError::config(
            "OAuth resource persistence is not supported by this store",
        ))
    }
    async fn get_oauth_resource(&self, _identifier: &str) -> AuthResult<Option<OAuthResource>> {
        Err(AuthError::config(
            "OAuth resource persistence is not supported by this store",
        ))
    }
    async fn delete_oauth_consent(&self, _id: &str) -> AuthResult<()> {
        Err(AuthError::config(
            "OAuth consent persistence is not supported by this store",
        ))
    }
    async fn get_oauth_consent(&self, _id: &str) -> AuthResult<Option<OAuthConsent>> {
        Err(AuthError::config(
            "OAuth consent persistence is not supported by this store",
        ))
    }
    async fn create_oauth_consent(&self, _data: CreateOAuthConsent) -> AuthResult<OAuthConsent> {
        Err(AuthError::config(
            "OAuth consent persistence is not supported by this store",
        ))
    }
    async fn list_oauth_consents_by_user(&self, _user_id: &str) -> AuthResult<Vec<OAuthConsent>> {
        Err(AuthError::config(
            "OAuth consent persistence is not supported by this store",
        ))
    }
    async fn update_oauth_consent_metadata(
        &self,
        _id: &str,
        _metadata: Value,
        _updated_at: DateTime<Utc>,
    ) -> AuthResult<Option<OAuthConsent>> {
        Err(AuthError::config(
            "OAuth consent persistence is not supported by this store",
        ))
    }
    async fn create_oauth_client(&self, _data: CreateOAuthClient) -> AuthResult<OAuthClient> {
        Err(AuthError::config(
            "OAuth client persistence is not supported by this store",
        ))
    }
    async fn get_oauth_client(&self, _client_id: &str) -> AuthResult<Option<OAuthClient>> {
        Err(AuthError::config(
            "OAuth client persistence is not supported by this store",
        ))
    }
    async fn list_oauth_clients_by_user(&self, _user_id: &str) -> AuthResult<Vec<OAuthClient>> {
        Err(AuthError::config(
            "OAuth client persistence is not supported by this store",
        ))
    }
    async fn delete_oauth_client(&self, _client_id: &str) -> AuthResult<()> {
        Err(AuthError::config(
            "OAuth client persistence is not supported by this store",
        ))
    }
    async fn update_oauth_client_secret(
        &self,
        _client_id: &str,
        _secret: String,
        _updated_at: DateTime<Utc>,
    ) -> AuthResult<Option<OAuthClient>> {
        Err(AuthError::config(
            "OAuth client persistence is not supported by this store",
        ))
    }
    async fn update_oauth_client_metadata(
        &self,
        _client_id: &str,
        _metadata: Value,
        _updated_at: DateTime<Utc>,
    ) -> AuthResult<Option<OAuthClient>> {
        Err(AuthError::config(
            "OAuth client persistence is not supported by this store",
        ))
    }
}

/// RFC client metadata names mapped to the TypeScript persistence schema.
const CLIENT_FIELDS: &[(&str, &str)] = &[
    ("client_discovery_id", "clientDiscoveryId"),
    ("disabled", "disabled"),
    ("skip_consent", "skipConsent"),
    ("enable_end_session", "enableEndSession"),
    ("subject_type", "subjectType"),
    ("client_credentials_scopes", "clientCredentialsScopes"),
    ("contacts", "contacts"),
    ("software_id", "softwareId"),
    ("software_version", "softwareVersion"),
    ("software_statement", "softwareStatement"),
    ("redirect_uris", "redirectUris"),
    ("post_logout_redirect_uris", "postLogoutRedirectUris"),
    ("backchannel_logout_uri", "backchannelLogoutUri"),
    (
        "backchannel_logout_session_required",
        "backchannelLogoutSessionRequired",
    ),
    ("token_endpoint_auth_method", "tokenEndpointAuthMethod"),
    ("application_type", "applicationType"),
    ("jwks", "jwks"),
    ("jwks_uri", "jwksUri"),
    ("grant_types", "grantTypes"),
    ("response_types", "responseTypes"),
    ("require_pkce", "requirePKCE"),
    ("dpop_bound_access_tokens", "dpopBoundAccessTokens"),
    ("reference_id", "referenceId"),
    ("client_name", "name"),
    ("client_uri", "uri"),
    ("logo_uri", "icon"),
    ("tos_uri", "tos"),
    ("policy_uri", "policy"),
    ("scope", "scopes"),
];

/// Separate registration fields from application metadata for physical persistence.
/// # Errors
/// Rejects metadata that is not an object.
pub fn metadata_to_columns(metadata: Value) -> AuthResult<Value> {
    let Value::Object(mut metadata) = metadata else {
        return Err(AuthError::bad_request(
            "OAuth client metadata must be an object",
        ));
    };
    let mut fields = serde_json::Map::new();
    // A protocol metadata envelope stays opaque even when a safe extension name
    // coincides with a native projection key (for example client_discovery_id).
    let extensions = metadata.remove("metadata");
    for (rfc, column) in CLIENT_FIELDS {
        if let Some(mut value) = metadata.remove(*rfc) {
            if *rfc == "scope"
                && let Some(scope) = value.as_str()
            {
                value = Value::Array(
                    // oauthToSchema uses JavaScript split(" "), including the empty scope sentinel.
                    scope
                        .split(' ')
                        .map(|scope| Value::String(scope.into()))
                        .collect(),
                );
            }
            if *rfc == "jwks" && value.is_object() {
                value = Value::String(serde_json::to_string(&value)?);
            }
            _ = fields.insert((*column).into(), value);
        }
    }
    if !fields.contains_key("redirectUris") {
        _ = fields.insert("redirectUris".into(), serde_json::json!([]));
    }
    if let Some(Value::Object(extensions)) = extensions {
        metadata.extend(extensions);
    }
    _ = fields.insert(
        "metadata".into(),
        if metadata.is_empty() {
            Value::Null
        } else {
            Value::Object(metadata)
        },
    );
    Ok(Value::Object(fields))
}

/// Rebuild the registration projection from the TypeScript client columns.
/// # Errors
/// Returns an error when a stored client is malformed.
pub fn metadata_from_columns(fields: &Value) -> AuthResult<Value> {
    let fields = fields
        .as_object()
        .ok_or_else(|| AuthError::internal("Stored OAuth client must be an object"))?;
    let mut metadata = fields
        .get("metadata")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for (rfc, column) in CLIENT_FIELDS {
        if let Some(mut value) = fields
            .get(*column)
            .filter(|value| !value.is_null())
            .cloned()
        {
            if *rfc == "scope"
                && let Some(scopes) = value.as_array()
            {
                value = Value::String(
                    scopes
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(" "),
                );
            }
            if *rfc == "jwks"
                && let Some(jwks) = value.as_str()
            {
                value = serde_json::from_str(jwks)?;
            }
            _ = metadata.insert((*rfc).into(), value);
        }
    }
    Ok(Value::Object(metadata))
}

/// Durable consent attached to the client and consenting user.
#[derive(Clone, Debug)]
pub struct OAuthConsent {
    pub id: String,
    pub client_id: String,
    pub user_id: Option<String>,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
#[derive(Clone, Debug)]
pub struct CreateOAuthConsent {
    pub client_id: String,
    pub user_id: Option<String>,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct OAuthResource {
    pub id: String,
    pub identifier: String,
    pub metadata: Value,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}
#[derive(Clone, Debug)]
pub struct CreateOAuthResource {
    pub identifier: String,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct OAuthClientResource {
    pub id: String,
    pub client_id: String,
    pub resource_id: String,
    pub metadata: Value,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub struct CreateOAuthClientResource {
    pub client_id: String,
    pub resource_id: String,
    pub created_at: DateTime<Utc>,
}
