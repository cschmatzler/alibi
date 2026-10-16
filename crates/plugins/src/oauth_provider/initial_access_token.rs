//! Operator authorization for RFC 7591 initial access tokens.
use alibi_core::endpoint::{EndpointError, is_endpoint_api_error};
use alibi_core::{AuthError, Headers};
use async_trait::async_trait;
use serde_json::{Map, Value};

/// The actual credential, caller headers and parsed registration request, before defaults.
#[derive(Debug)]
pub struct OAuthInitialAccessTokenInput<'a> {
    pub initial_access_token: &'a str,
    pub headers: &'a Headers,
    /// Unknown/server-assigned fields are stripped; effective registration defaults are not applied.
    pub client_metadata: &'a Map<String, Value>,
}

/// Admission independent of a user session. An optional application reference owns the client.
#[derive(Debug, Clone, Default)]
pub struct OAuthInitialAccessTokenAuthorization {
    pub reference_id: Option<String>,
}

/// Explicit endpoint failures retain their status, body and headers. Ordinary application
/// failures are deliberately hidden behind the registration endpoint's OAuth server error.
#[derive(Debug)]
pub enum OAuthInitialAccessTokenError {
    Endpoint(EndpointError),
    Application(AuthError),
}

impl From<EndpointError> for OAuthInitialAccessTokenError {
    fn from(error: EndpointError) -> Self {
        Self::Endpoint(error)
    }
}

impl From<AuthError> for OAuthInitialAccessTokenError {
    fn from(error: AuthError) -> Self {
        if is_endpoint_api_error(&error) {
            Self::Endpoint(error.into())
        } else {
            Self::Application(error)
        }
    }
}

impl std::fmt::Display for OAuthInitialAccessTokenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Endpoint(error) => error.fmt(formatter),
            Self::Application(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for OAuthInitialAccessTokenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Endpoint(error) => error,
            Self::Application(error) => error,
        })
    }
}

/// Application-owned async initial-access-token policy. `None` rejects the credential.
#[async_trait]
pub trait OAuthInitialAccessTokenValidator: Send + Sync + std::fmt::Debug {
    async fn validate(
        &self,
        input: OAuthInitialAccessTokenInput<'_>,
    ) -> Result<Option<OAuthInitialAccessTokenAuthorization>, OAuthInitialAccessTokenError>;
}

impl super::OAuthProviderPlugin {
    pub(super) async fn authorize_initial_access_token(
        &self,
        input: OAuthInitialAccessTokenInput<'_>,
    ) -> alibi_core::AuthResult<
        Result<OAuthInitialAccessTokenAuthorization, alibi_core::endpoint::EndpointResponse>,
    > {
        use alibi_core::endpoint::EndpointResponse;

        let validation = match &self.config.initial_access_token_validator {
            Some(validator) => validator.validate(input).await,
            None => Ok(None),
        };
        let response = match validation {
            Ok(Some(authorization)) => return Ok(Ok(authorization)),
            Ok(None) => super::clients::status_protocol_error(
                401,
                "invalid_token",
                "Invalid initial access token",
            )?
            .with_header("WWW-Authenticate", "Bearer error=\"invalid_token\""),
            Err(OAuthInitialAccessTokenError::Application(_)) => {
                super::clients::status_protocol_error(
                    500,
                    "server_error",
                    "Initial access token validation failed",
                )?
            }
            Err(OAuthInitialAccessTokenError::Endpoint(error)) => {
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
        Ok(Err(response))
    }
}
