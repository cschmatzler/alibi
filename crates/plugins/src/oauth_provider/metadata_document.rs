//! Trusted persistence for an already validated Client ID Metadata Document; no fetching.
use super::{CreateOAuthClientInput, OAuthProviderPlugin};
use alibi_core::AuthError;
use alibi_core::endpoint::EndpointError;
use alibi_core::store::oauth_clients::{
    OAuthClientRegistrationReplacement, OAuthClientRegistrationWriteError,
    PersistOAuthClientRegistration,
};
use alibi_core::store::{CreateOAuthClient, OAuthClient};
use alibi_core::{AuthContext, AuthSchema};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// OAuth metadata supplied by the first-party document validator, not a discovery callback.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OAuthClientMetadata {
    #[serde(flatten)]
    pub metadata: CreateOAuthClientInput,
    /// Opaque protocol metadata, distinct from the flattened standard client fields.
    /// Reserved record/wire keys are stripped before persistence.
    #[serde(rename = "metadata", skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Map<String, Value>>,
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_expires_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id_issued_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_consent: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_end_session: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_pkce: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct RegisterClientMetadataDocumentInput {
    pub metadata: OAuthClientMetadata,
    pub client_id: String,
    pub client_discovery_id: String,
    pub existing_client: Option<OAuthClient>,
}

/// Durable registration result, rather than an HTTP registration response.
#[derive(Clone, Debug)]
pub struct OAuthClientRegistrationResult {
    pub client: OAuthClient,
    pub client_secret: Option<String>,
    pub resources: Vec<String>,
    pub created: bool,
}

impl OAuthProviderPlugin {
    /// Persist a validated document under its discovery owner. This does not fetch or discover it.
    pub async fn register_client_metadata_document<S: AuthSchema>(
        &self,
        input: RegisterClientMetadataDocumentInput,
        ctx: &AuthContext<S>,
    ) -> Result<OAuthClientRegistrationResult, EndpointError> {
        if input.existing_client.as_ref().is_some_and(|client| {
            client
                .metadata
                .get("client_discovery_id")
                .and_then(Value::as_str)
                != Some(&input.client_discovery_id)
        }) {
            return Err(document_error(
                "invalid_client",
                "client_id is already owned by a different registration source",
            ));
        }
        if input.metadata.metadata.backchannel_logout_uri.is_some()
            || input
                .metadata
                .metadata
                .backchannel_logout_session_required
                .is_some()
        {
            return Err(document_error(
                "invalid_client_metadata",
                "Client ID Metadata Documents cannot register a back-channel logout target",
            ));
        }
        if !["none", "private_key_jwt"].contains(
            &input
                .metadata
                .metadata
                .token_endpoint_auth_method
                .as_deref()
                .unwrap_or("none"),
        ) {
            return Err(document_error(
                "invalid_client_metadata",
                "Client ID Metadata Document clients cannot use a shared secret",
            ));
        }
        let (cause, resource_id) = match self
            .persist_metadata_document(&input, input.existing_client.as_ref(), ctx)
            .await
        {
            Ok(result) => return Ok(result),
            Err(DocumentWriteError::Store(OAuthClientRegistrationWriteError::Collision {
                cause,
                resource_id,
            })) => (cause, resource_id),
            Err(error) => return Err(error.into_endpoint()),
        };
        let current = ctx.database.get_oauth_client(&input.client_id).await?;
        let Some(current) = current.filter(|client| {
            client
                .metadata
                .get("client_discovery_id")
                .and_then(Value::as_str)
                == Some(&input.client_discovery_id)
        }) else {
            return Err(cause.into());
        };
        if let Some(resource_id) = resource_id
            && !ctx
                .database
                .has_oauth_client_resource(&input.client_id, &resource_id)
                .await?
        {
            return Err(cause.into());
        }
        self.persist_metadata_document(&input, Some(&current), ctx)
            .await
            .map_err(DocumentWriteError::into_endpoint)
    }

    async fn persist_metadata_document<S: AuthSchema>(
        &self,
        input: &RegisterClientMetadataDocumentInput,
        existing: Option<&OAuthClient>,
        ctx: &AuthContext<S>,
    ) -> Result<OAuthClientRegistrationResult, DocumentWriteError> {
        let mut metadata = serde_json::to_value(&input.metadata)
            .map_err(AuthError::from)?
            .as_object()
            .cloned()
            .ok_or_else(|| AuthError::internal("Invalid OAuth metadata"))?;
        _ = metadata.remove("client_secret");
        _ = metadata.remove("client_secret_expires_at");
        if let Some(Value::Object(extensions)) = metadata.get_mut("metadata") {
            extensions.retain(|name, _| {
                !super::clients::RESERVED_METADATA_FIELDS.contains(&name.as_str())
            });
        }
        _ = metadata
            .entry("token_endpoint_auth_method")
            .or_insert_with(|| json!("none"));
        let scopes = super::unique(
            self.config
                .client_registration_default_scopes
                .as_ref()
                .unwrap_or(&self.config.scopes)
                .iter()
                .chain(
                    self.config
                        .client_registration_allowed_scopes
                        .iter()
                        .flatten(),
                )
                .cloned()
                .collect(),
        );
        let mut metadata = match self.admit_metadata_for_source(metadata, &scopes, ctx, true)? {
            Ok(metadata) => metadata,
            Err(response) => match response.into_output::<Value>() {
                Err(error) => return Err(DocumentWriteError::Endpoint(error)),
                Ok(_) => {
                    return Err(AuthError::internal(
                        "OAuth metadata admission returned an invalid error response",
                    )
                    .into());
                }
            },
        };
        for name in [
            "client_id",
            "user_id",
            "reference_id",
            "client_id_issued_at",
            "disabled",
        ] {
            _ = metadata.remove(name);
        }
        _ = metadata.insert("scope".into(), json!(scopes.join(" ")));
        _ = metadata.insert(
            "client_discovery_id".into(),
            json!(input.client_discovery_id),
        );
        // Canonical persistence explicitly clears applicationType; other absent
        // remote fields stay undefined and the initialized adapter filters them out.
        _ = metadata.entry("application_type").or_insert(Value::Null);
        if existing.is_some() {
            // Server-owned fields (disabled, consent and logout settings, the
            // client_credentials ceiling) can change while a refresh fetches
            // metadata, so the refresh never writes them.
            for name in [
                "client_credentials_scopes",
                "disabled",
                "skip_consent",
                "enable_end_session",
            ] {
                _ = metadata.remove(name);
            }
        } else {
            _ = metadata.insert("client_credentials_scopes".into(), json!([]));
            _ = metadata.insert("disabled".into(), json!(false));
            _ = metadata
                .entry("dpop_bound_access_tokens")
                .or_insert_with(|| json!(false));
        }
        let resources = super::unique(
            self.config
                .client_registration_default_resources
                .clone()
                .unwrap_or_default(),
        );
        for identifier in &resources {
            let resource = self.get_resource(ctx, identifier).await?;
            if resource.is_none() {
                return Err(DocumentWriteError::Endpoint(document_error(
                    "invalid_target",
                    &format!("requested resource {identifier} does not exist"),
                )));
            }
            if resource
                .is_some_and(|resource| resource.metadata.get("disabled") == Some(&json!(true)))
            {
                return Err(DocumentWriteError::Endpoint(document_error(
                    "invalid_target",
                    &format!("requested resource {identifier} is disabled"),
                )));
            }
        }
        let now = chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0)
            .ok_or_else(|| AuthError::internal("Invalid OAuth registration timestamp"))?;
        let client = ctx
            .database
            .persist_oauth_client_registration(PersistOAuthClientRegistration {
                client: CreateOAuthClient {
                    client_id: input.client_id.clone(),
                    user_id: None,
                    client_secret: None,
                    metadata: Value::Object(metadata),
                    created_at: existing.and_then(|client| client.created_at).unwrap_or(now),
                },
                replacement: existing.map(|client| OAuthClientRegistrationReplacement {
                    discovery_id: input.client_discovery_id.clone(),
                    existing_created_at: client.created_at,
                }),
                resources: resources.clone(),
                updated_at: now,
            })
            .await
            .map_err(DocumentWriteError::Store)?
            .ok_or_else(|| {
                DocumentWriteError::Endpoint(document_error(
                    "invalid_client",
                    "client no longer exists",
                ))
            })?;
        Ok(OAuthClientRegistrationResult {
            client,
            client_secret: None,
            resources,
            created: existing.is_none(),
        })
    }
}

enum DocumentWriteError {
    Endpoint(EndpointError),
    Store(OAuthClientRegistrationWriteError),
}
impl DocumentWriteError {
    fn into_endpoint(self) -> EndpointError {
        match self {
            Self::Endpoint(error) => error,
            Self::Store(
                OAuthClientRegistrationWriteError::Failure(error)
                | OAuthClientRegistrationWriteError::Collision { cause: error, .. },
            ) => error.into(),
        }
    }
}
impl From<AuthError> for DocumentWriteError {
    fn from(error: AuthError) -> Self {
        Self::Endpoint(error.into())
    }
}
fn document_error(error: &str, description: &str) -> EndpointError {
    EndpointError {
        error: AuthError::Api {
            status: 400,
            code: None,
            message: String::new(),
        },
        headers: None,
        body: Some(Box::new(
            json!({"error":error,"error_description":description}).into(),
        )),
        body_absent: false,
    }
}
