//! Trusted server client authentication through the shared protocol credential owner.
use super::OAuthProviderPlugin;
use alibi_core::endpoint::{
    EndpointCall, EndpointError, EndpointResponse, with_endpoint_call_context,
};
use alibi_core::store::OAuthClient;
use alibi_core::utils::json::{JsValue, parse_value};
use alibi_core::{AuthContext, AuthError, AuthSchema};
use serde_json::{Value, json};

/// Caller policy for the `authenticateClient` server capability.
#[derive(Debug, Clone)]
pub struct OAuthClientAuthenticationOptions {
    pub require_credentials: bool,
    pub scopes: Option<Vec<String>>,
}
impl Default for OAuthClientAuthenticationOptions {
    fn default() -> Self {
        Self {
            require_credentials: true,
            scopes: None,
        }
    }
}
/// A client authenticated for a trusted server operation.
#[derive(Debug, Clone)]
pub struct OAuthAuthenticatedClient {
    pub client_id: String,
    pub client: OAuthClient,
    pub method: Option<String>,
    pub confirmation: Option<Value>,
}
impl OAuthProviderPlugin {
    /// Authenticate a client against this endpoint, its scopes and an optional bound grant.
    /// Equivalent to `getOAuthProviderApi(...).authenticateClient`; assertion audiences
    /// use the logical endpoint path. Public clients require an explicit caller opt-in.
    pub async fn authenticate_client<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        call: &EndpointCall,
        grant_type: Option<&str>,
        options: &OAuthClientAuthenticationOptions,
    ) -> Result<OAuthAuthenticatedClient, EndpointError> {
        with_endpoint_call_context(
            call.clone(),
            self.authenticate_client_inner(ctx, call, grant_type, options),
        )
        .await
    }
    async fn authenticate_client_inner<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
        call: &EndpointCall,
        grant_type: Option<&str>,
        options: &OAuthClientAuthenticationOptions,
    ) -> Result<OAuthAuthenticatedClient, EndpointError> {
        // Only authentication fields participate; trusted Date values remain non-strings.
        let mut body = serde_json::Map::new();
        if let Some(input) = call.body() {
            for field in [
                "client_id",
                "client_secret",
                "client_assertion",
                "client_assertion_type",
            ] {
                if let Some(value) = input.get(field) {
                    _ = body.insert(
                        field.into(),
                        match value {
                            JsValue::String(value) => Value::String(value.clone()),
                            _ => Value::Null,
                        },
                    );
                }
            }
        }
        let audience = format!(
            "{}{}{}",
            ctx.config.base_url.trim_end_matches('/'),
            ctx.config.base_path,
            call.path().unwrap_or("/oauth2/token")
        );
        let credentials = match super::credentials::extract_for_audience(
            &Value::Object(body),
            call,
            ctx,
            self,
            &audience,
        )
        .await?
        {
            Ok(credentials) => credentials,
            Err(response) => return Err(response_error(&response)?),
        };
        if credentials.client_id.is_empty() {
            return Err(failure("invalid_request", "Missing required client_id"));
        }
        if options.require_credentials && credentials.secret.is_empty() && !credentials.pre_verified
        {
            return Err(failure(
                "invalid_client",
                "Missing required client credentials",
            ));
        }
        let client = match credentials.authenticate(ctx, self).await? {
            Ok(client) => client,
            Err(response) => return Err(response_error(&response)?),
        };
        if let Some(requested) = &options.scopes {
            let allowed = client.metadata.get("scope").and_then(|scope| {
                scope
                    .as_str()
                    .map(|scope| scope.split(' ').collect::<Vec<_>>())
                    .or_else(|| {
                        scope
                            .as_array()
                            .map(|scopes| scopes.iter().filter_map(Value::as_str).collect())
                    })
            });
            if let Some(allowed) = allowed {
                for scope in requested {
                    if !allowed.contains(&scope.as_str()) {
                        return Err(failure(
                            "invalid_scope",
                            &format!("client does not allow scope {scope}"),
                        ));
                    }
                }
            }
        }
        if let Some(grant) = grant_type.filter(|grant| !grant.is_empty()) {
            let allowed = client
                .metadata
                .get("grant_types")
                .and_then(Value::as_array)
                .filter(|grants| !grants.is_empty());
            let permits = allowed.map_or(
                matches!(grant, "authorization_code" | "refresh_token"),
                |grants| {
                    grants.contains(&json!(grant))
                        || (grant == "refresh_token"
                            && grants.contains(&json!("authorization_code")))
                },
            );
            if !permits {
                return Err(failure(
                    "unauthorized_client",
                    &format!("client is not authorized to use grant type {grant}"),
                ));
            }
        }
        Ok(OAuthAuthenticatedClient {
            client_id: credentials.client_id,
            client,
            method: Some(credentials.method.into()),
            confirmation: None,
        })
    }
}
fn failure(code: &str, description: &str) -> EndpointError {
    EndpointError {
        error: AuthError::Api {
            status: 400,
            code: None,
            message: String::new(),
        },
        headers: None,
        body: Some(Box::new(JsValue::from(
            json!({"error":code,"error_description":description}),
        ))),
        body_absent: false,
    }
}
fn response_error(response: &EndpointResponse) -> Result<EndpointError, EndpointError> {
    let response = response.to_response()?;
    let body_absent = response.body.is_empty();
    let body = if body_absent {
        None
    } else {
        Some(Box::new(
            parse_value(String::from_utf8_lossy(&response.body).as_ref())
                .map_err(AuthError::from)?,
        ))
    };
    Ok(EndpointError {
        error: AuthError::Api {
            status: response.status,
            code: None,
            message: String::new(),
        },
        headers: Some(response.headers),
        body,
        body_absent,
    })
}
