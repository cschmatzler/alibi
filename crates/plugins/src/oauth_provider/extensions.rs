//! Configured extension grants and schema-erased, grant-bound provider capabilities.
use super::{
    OAuthAuthenticatedClient, OAuthClientAuthenticationOptions, OAuthProviderConfig,
    OAuthProviderPlugin, OAuthTokenIssueParams,
};
use alibi_core::endpoint::{
    EndpointCall, EndpointContextPatch, EndpointDefinition, EndpointError, EndpointOptions,
    EndpointResponse, with_endpoint_call_context,
};
use alibi_core::session::SessionRequest;
use alibi_core::store::OAuthClient;
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema, CallbackContext, HttpMethod};
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;

/// One configured extension. Dispatched URI keys must be disjoint across extensions.
#[derive(Clone, Debug, Default)]
pub struct OAuthProviderExtension {
    pub grants: indexmap::IndexMap<String, Arc<dyn OAuthExtensionGrantHandler>>,
    pub metadata: Option<Arc<dyn OAuthMetadataContributor>>,
    pub claims: super::OAuthExtensionClaims,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthMetadataType {
    OAuthAuthorizationServer,
    OpenIdConfiguration,
}
impl OAuthMetadataType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OAuthAuthorizationServer => "oauth-authorization-server",
            Self::OpenIdConfiguration => "openid-configuration",
        }
    }
}
pub struct OAuthMetadataExtensionInput<'a> {
    pub context: &'a CallbackContext,
    pub options: &'a OAuthProviderConfig,
    pub metadata_type: OAuthMetadataType,
    /// Provider and client-discovery document, before any metadata callback contribution.
    pub document: &'a mut Value,
}
pub trait OAuthMetadataContributor: Send + Sync + std::fmt::Debug {
    fn contribute(
        &self,
        input: &mut OAuthMetadataExtensionInput<'_>,
    ) -> AuthResult<serde_json::Map<String, Value>>;
}
pub struct OAuthExtensionGrantInput<'a> {
    pub context: CallbackContext,
    pub call: &'a EndpointCall,
    pub options: &'a OAuthProviderConfig,
    pub grant_type: &'a str,
    pub provider: &'a dyn OAuthProviderApi,
}
/// A trusted companion owns grant-specific admission; no client is fabricated or pre-authorized.
#[async_trait]
pub trait OAuthExtensionGrantHandler: Send + Sync + std::fmt::Debug {
    async fn handle(&self, input: OAuthExtensionGrantInput<'_>) -> Result<Value, EndpointError>;
}
/// Live provider capabilities bound to the actual call and its optional grant.
#[async_trait]
pub trait OAuthProviderApi: Send + Sync {
    async fn get_client(&self, client_id: &str) -> AuthResult<Option<OAuthClient>>;
    async fn authenticate_client(
        &self,
        options: &OAuthClientAuthenticationOptions,
    ) -> Result<OAuthAuthenticatedClient, EndpointError>;
    async fn hash_token(&self, token: &str, kind: &str) -> AuthResult<String>;
    async fn issue_tokens(&self, params: &OAuthTokenIssueParams) -> Result<Value, EndpointError>;
    async fn validate_access_token(
        &self,
        token: &str,
        client_id: Option<&str>,
    ) -> Result<Value, EndpointError>;
    async fn require_active_access_token(
        &self,
        token: &str,
        client_id: Option<&str>,
    ) -> Result<Value, EndpointError>;
}
struct ProviderApi<'a, S: AuthSchema> {
    provider: &'a OAuthProviderPlugin,
    context: &'a AuthContext<S>,
    call: &'a EndpointCall,
    grant_type: Option<&'a str>,
}
#[async_trait]
impl<S: AuthSchema> OAuthProviderApi for ProviderApi<'_, S> {
    async fn get_client(&self, id: &str) -> AuthResult<Option<OAuthClient>> {
        self.provider.get_client(self.context, id).await
    }
    async fn authenticate_client(
        &self,
        options: &OAuthClientAuthenticationOptions,
    ) -> Result<OAuthAuthenticatedClient, EndpointError> {
        self.provider
            .authenticate_client(self.context, self.call, self.grant_type, options)
            .await
    }
    async fn hash_token(&self, token: &str, kind: &str) -> AuthResult<String> {
        self.provider.hash_token(token, kind).await
    }
    async fn issue_tokens(&self, params: &OAuthTokenIssueParams) -> Result<Value, EndpointError> {
        self.provider
            .issue_tokens(self.context, self.call, self.grant_type, params)
            .await
    }
    async fn validate_access_token(
        &self,
        token: &str,
        id: Option<&str>,
    ) -> Result<Value, EndpointError> {
        self.provider
            .validate_access_token(self.context, token, id)
            .await
    }
    async fn require_active_access_token(
        &self,
        token: &str,
        id: Option<&str>,
    ) -> Result<Value, EndpointError> {
        self.provider
            .require_active_access_token(self.context, token, id)
            .await
    }
}
impl OAuthProviderPlugin {
    pub(super) fn apply_metadata_extensions<S: AuthSchema>(
        &self,
        context: &AuthContext<S>,
        mut document: Value,
    ) -> AuthResult<Value> {
        let mut next = document
            .as_object()
            .cloned()
            .ok_or_else(|| AuthError::internal("OAuth metadata must be an object"))?;
        let callback = CallbackContext::new(context, None);
        let metadata_type = if self.config.scopes.iter().any(|scope| scope == "openid") {
            OAuthMetadataType::OpenIdConfiguration
        } else {
            OAuthMetadataType::OAuthAuthorizationServer
        };
        for extension in &self.config.extensions {
            if let Some(contributor) = &extension.metadata {
                let mut input = OAuthMetadataExtensionInput {
                    context: &callback,
                    options: &self.config,
                    metadata_type,
                    document: &mut document,
                };
                for (key, value) in contributor.contribute(&mut input)? {
                    // Reference `key in next` also protects inherited Object.prototype keys.
                    if !next.contains_key(&key)
                        && !matches!(
                            key.as_str(),
                            "__proto__"
                                | "constructor"
                                | "toString"
                                | "toLocaleString"
                                | "valueOf"
                                | "hasOwnProperty"
                                | "isPrototypeOf"
                                | "propertyIsEnumerable"
                                | "__defineGetter__"
                                | "__defineSetter__"
                                | "__lookupGetter__"
                                | "__lookupSetter__"
                        )
                    {
                        _ = next.insert(key, value);
                    }
                }
            }
        }
        Ok(Value::Object(next))
    }
    /// Obtain live capabilities for an extension or a trusted companion endpoint.
    /// Issuance without a bound grant is rejected by the shared issuance owner.
    pub fn get_oauth_provider_api<'a, S: AuthSchema>(
        &'a self,
        context: &'a AuthContext<S>,
        call: &'a EndpointCall,
        grant_type: Option<&'a str>,
    ) -> impl OAuthProviderApi + 'a {
        ProviderApi {
            provider: self,
            context,
            call,
            grant_type,
        }
    }
    pub(super) fn supported_grant_types(&self) -> Vec<String> {
        super::unique(
            self.config
                .grant_types
                .iter()
                .cloned()
                .chain(
                    self.config
                        .extensions
                        .iter()
                        .flat_map(|extension| extension.grants.keys().cloned()),
                )
                .collect(),
        )
    }
    pub(super) fn validate_extensions(&self) -> AuthResult<()> {
        let mut seen = std::collections::HashSet::new();
        for extension in &self.config.extensions {
            for grant in extension.grants.keys() {
                if alibi_core::utils::javascript::trim(grant).is_empty() {
                    return Err(AuthError::config(
                        "OAuth Provider extension grant type cannot be empty",
                    ));
                }
                if url::Url::parse(grant).is_err() {
                    return Err(AuthError::config(format!(
                        "OAuth Provider extension grant type must be an absolute URI: {grant}"
                    )));
                }
                if !seen.insert(grant) {
                    return Err(AuthError::config(format!(
                        "OAuth Provider extensions register grant type \"{grant}\" more than once. Extension contributions must be disjoint."
                    )));
                }
            }
        }
        Ok(())
    }
    pub(super) async fn extension_grant<S: AuthSchema>(
        &self,
        grant: &str,
        input: Option<&JsValue>,
        request: &impl SessionRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<EndpointResponse>> {
        let Some(handler) = self
            .config
            .extensions
            .iter()
            .find_map(|extension| extension.grants.get(grant))
            .cloned()
        else {
            return Ok(None);
        };
        let mut call = request.endpoint_call().cloned().unwrap_or_else(|| {
            EndpointCall::new(
                &EndpointDefinition {
                    name: "oauth2Token",
                    operation_id: "oauth2Token",
                    path: Some("/oauth2/token".into()),
                    method: HttpMethod::Post,
                },
                input.cloned(),
                None,
                EndpointOptions {
                    method: Some(request.session_method().clone()),
                    headers: Some(request.session_headers().clone()),
                    request: request.physical_request().cloned(),
                },
            )
        });
        EndpointContextPatch {
            body: Some(JsValue::Object(
                [("grant_type".into(), JsValue::String(grant.into()))]
                    .into_iter()
                    .collect(),
            )),
            ..Default::default()
        }
        .apply(&mut call);
        let api = self.get_oauth_provider_api(context, &call, Some(grant));
        let result = with_endpoint_call_context(call.clone(), async {
            handler
                .handle(OAuthExtensionGrantInput {
                    context: CallbackContext::new(context, request.physical_request()),
                    call: &call,
                    options: &self.config,
                    grant_type: grant,
                    provider: &api,
                })
                .await
        })
        .await;
        let response = match result {
            Ok(value) => EndpointResponse::json(&value)?,
            Err(error) => {
                let mut response = EndpointResponse::error(error.error);
                if let Some(body) = error.body {
                    response = response.with_error_body(*body);
                }
                if error.body_absent {
                    response = response.without_error_body();
                }
                if let Some(headers) = error.headers {
                    response.merge_headers(headers);
                }
                response
            }
        };
        Ok(Some(
            response
                .with_header("Cache-Control", "no-store")
                .with_header("Pragma", "no-cache"),
        ))
    }
}
