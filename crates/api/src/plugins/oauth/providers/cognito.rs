//! Cognito's configured hosted domain, authenticated subject and profile fallback.
use super::{
    OAuthAuthorizationPolicy, OAuthProvider, OAuthScopeEncoding, OAuthTokenEndpointAuth,
    OAuthUserInfo, OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use crate::plugins::oauth::{
    HttpOAuthJwksSource, OAuthIdTokenConfig, OAuthJwksSelection, OAuthJwksSource,
    OAuthNonceComparison,
};
use async_trait::async_trait;
use base64::Engine;
use serde_json::Value;
use std::sync::Arc;

/// Immutable Cognito settings. Application callback and signup policies remain
/// configurable on the returned provider.
#[derive(Clone)]
pub struct CognitoOptions {
    pub client_ids: Vec<String>,
    pub client_secret: Option<String>,
    /// Forwarded only during authorization-code exchange, as the pinned helper
    /// ignores this option during refresh.
    pub client_key: Option<String>,
    pub domain: String,
    pub region: String,
    pub user_pool_id: String,
    pub require_client_secret: bool,
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    pub prompt: Option<String>,
    pub identity_provider: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub redirect_uri: Option<String>,
    /// Application-owned transport override; token claims cannot select it.
    pub jwks_source: Option<Arc<dyn OAuthJwksSource>>,
    /// Trusted user-info transport override retaining Cognito's profile mapping.
    pub user_info_endpoint: Option<String>,
    /// Receives the original profile, with the ID-token name fallback applied.
    /// Its mapped ID cannot replace the authenticated raw `sub`.
    pub map_profile_to_user: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
}
impl CognitoOptions {
    #[must_use]
    pub fn new(
        client_id: impl Into<String>,
        client_secret: Option<String>,
        domain: impl Into<String>,
        region: impl Into<String>,
        user_pool_id: impl Into<String>,
    ) -> Self {
        Self {
            client_ids: vec![client_id.into()],
            client_secret,
            client_key: None,
            domain: domain.into(),
            region: region.into(),
            user_pool_id: user_pool_id.into(),
            require_client_secret: false,
            scope: Vec::new(),
            disable_default_scope: false,
            prompt: None,
            identity_provider: None,
            authorization_endpoint: None,
            redirect_uri: None,
            jwks_source: None,
            user_info_endpoint: None,
            map_profile_to_user: None,
        }
    }
}
impl std::fmt::Debug for CognitoOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CognitoOptions")
            .field("client_ids", &self.client_ids)
            .field("domain", &self.domain)
            .field("region", &self.region)
            .field("user_pool_id", &self.user_pool_id)
            .field("scope", &self.scope)
            .field("disable_default_scope", &self.disable_default_scope)
            .field("require_client_secret", &self.require_client_secret)
            .finish_non_exhaustive()
    }
}
impl OAuthProvider {
    /// Builds the published Cognito provider from application-owned configuration.
    ///
    /// # Errors
    /// Returns an error if the domain, region or user pool is empty.
    pub fn cognito(options: CognitoOptions) -> Result<Self, String> {
        if options.domain.is_empty() || options.region.is_empty() || options.user_pool_id.is_empty()
        {
            return Err("DOMAIN_AND_REGION_REQUIRED".into());
        }
        let domain = options
            .domain
            .strip_prefix("https://")
            .or_else(|| options.domain.strip_prefix("http://"))
            .unwrap_or(&options.domain);
        let issuer = format!(
            "https://cognito-idp.{}.amazonaws.com/{}",
            options.region, options.user_pool_id
        );
        let endpoint = options
            .user_info_endpoint
            .unwrap_or_else(|| format!("https://{domain}/oauth2/userinfo"));
        let verification = OAuthIdTokenConfig {
            issuers: vec![issuer.clone()],
            audience: None,
            client_ids: Some(options.client_ids.clone()),
            jwks_source: options.jwks_source.unwrap_or_else(|| {
                Arc::new(HttpOAuthJwksSource::new(format!(
                    "{issuer}/.well-known/jwks.json"
                )))
            }),
            max_age_secs: 3600,
            algorithm: None,
            selection: OAuthJwksSelection::ExactKid,
            nonce_comparison: OAuthNonceComparison::Exact,
        };
        let mut clients = options.client_ids.into_iter();
        let token_endpoint_auth = if options
            .client_secret
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        {
            OAuthTokenEndpointAuth::ClientSecretPost
        } else {
            OAuthTokenEndpointAuth::None
        };
        Ok(Self {
            client_id: clients.next().unwrap_or_default(),
            additional_client_ids: clients.collect(),
            client_secret: options.client_secret.unwrap_or_default(),
            hosted_domain: None,
            require_email_verification: false,
            auth_url: options
                .authorization_endpoint
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| format!("https://{domain}/oauth2/authorize")),
            token_url: format!("https://{domain}/oauth2/token"),
            user_info_url: Some(endpoint.clone()),
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            authorization: Some(OAuthAuthorizationPolicy {
                configured_scopes: options.scope,
                scope_encoding: OAuthScopeEncoding::UriComponent,
                disable_default_scopes: options.disable_default_scope,
                require_client_id: true,
                require_client_secret: options.require_client_secret,
                token_endpoint_auth: Some(token_endpoint_auth),
                authorization_code_client_key: options.client_key,
                prompt: options.prompt,
                redirect_uri: options.redirect_uri,
                login_hint: false,
                ..OAuthAuthorizationPolicy::default()
            }),
            authorization_params: options
                .identity_provider
                .map(|value| vec![("identity_provider".into(), value)])
                .unwrap_or_default(),
            map_user_info: None,
            account_subject: Some(subject),
            get_user_info: Some(Arc::new(CognitoUserInfo {
                endpoint,
                mapper: options.map_profile_to_user,
            })),
            refresh_access_token: None,
            verify_id_token: None,
            id_token: Some(verification),
            disable_id_token_sign_in: false,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            override_user_info_on_sign_in: false,
        })
    }
}
struct CognitoUserInfo {
    endpoint: String,
    mapper: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
}
#[async_trait]
impl OAuthUserInfoHandler for CognitoUserInfo {
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        if let Some(token) = request.id_token.filter(|value| !value.is_empty())
            && let Ok(mut profile) = decode_profile(&token)
        {
            let name = profile_name(&profile);
            if let Some(object) = profile.as_object_mut() {
                drop(object.insert("name".into(), name));
            }
            // Only decoding or the application's mapper may select the access-token
            // fallback. An invalid raw subject remains an admission failure.
            if let Ok(mapped) = self
                .mapper
                .map(|mapper| mapper(profile.clone()))
                .transpose()
            {
                return finish_profile(profile, mapped);
            }
        }
        let access_token = request
            .access_token
            .filter(|value| !value.is_empty())
            .ok_or("Missing Cognito access token")?;
        let profile: Value = reqwest::Client::new()
            .get(&self.endpoint)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|error| error.to_string())?
            .error_for_status()
            .map_err(|error| error.to_string())?
            .json()
            .await
            .map_err(|error| error.to_string())?;
        let mapped = self
            .mapper
            .map(|mapper| mapper(profile.clone()))
            .transpose()?;
        finish_profile(profile, mapped)
    }
}
fn decode_profile(token: &str) -> Result<Value, String> {
    let parts: Vec<_> = token.split('.').collect();
    let [_, payload, _] = parts.as_slice() else {
        return Err("Invalid Cognito ID token".into());
    };
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|error| error.to_string())?;
    let profile: Value =
        better_auth_core::utils::json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if !profile.is_object() {
        return Err("Invalid Cognito ID-token claims set".into());
    }
    Ok(profile)
}
fn scalar(value: Option<&Value>) -> Result<Option<String>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(Value::Number(value)) => better_auth_core::utils::json::number_to_string(value)
            .map(Some)
            .map_err(|error| error.to_string()),
        Some(Value::Bool(value)) => Ok(Some(value.to_string())),
        Some(Value::Array(_) | Value::Object(_)) => Err("Invalid Cognito profile field".into()),
    }
}
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(false) => false,
        Value::Number(value) => value.as_f64() != Some(0.0),
        Value::String(value) => !value.is_empty(),
        Value::Bool(true) | Value::Array(_) | Value::Object(_) => true,
    }
}
fn profile_name(profile: &Value) -> Value {
    ["name", "given_name", "username"]
        .into_iter()
        .filter_map(|key| profile.get(key))
        .find(|value| truthy(value))
        .cloned()
        .unwrap_or_else(|| Value::String(String::new()))
}
fn finish_profile(
    profile: Value,
    mapped: Option<OAuthUserInfo>,
) -> Result<OAuthUserInfoResponse, String> {
    let id = scalar(profile.get("sub"))?.unwrap_or_default();
    let user = match mapped {
        Some(user) => user,
        None => OAuthUserInfo {
            id: id.clone(),
            email: profile
                .get("email")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .into(),
            name: Some(scalar(Some(&profile_name(&profile)))?.unwrap_or_default()),
            image: scalar(profile.get("picture"))?,
            email_verified: profile
                .get("email_verified")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        },
    };
    Ok(OAuthUserInfoResponse {
        user,
        data: profile,
    })
}
fn subject(profile: &Value) -> Result<String, String> {
    let id = scalar(profile.get("sub"))?.ok_or("Missing Cognito subject")?;
    if id
        .trim_matches(|character: char| {
            (character.is_whitespace() && character != '\u{85}') || character == '\u{feff}'
        })
        .is_empty()
        || id == "null"
        || id == "undefined"
    {
        return Err("Invalid Cognito subject".into());
    }
    Ok(id)
}
