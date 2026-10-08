//! Facebook Graph app-bound access tokens and signed Limited Login profiles.
use super::{
    OAuthAuthorizationPolicy, OAuthProvider, OAuthTokenEndpointAuth, OAuthUserInfo,
    OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use crate::plugins::oauth::{
    HttpOAuthJwksSource, OAuthIdTokenConfig, OAuthJwksSelection, OAuthJwksSource,
    id_token::OAuthNonceComparison,
};
use async_trait::async_trait;
use base64::Engine;
use serde_json::Value;
use std::sync::Arc;

/// Application-owned Facebook configuration. User-info/refresh callbacks and
/// signup policies remain configurable on the returned provider.
#[derive(Clone)]
pub struct FacebookOptions {
    pub client_ids: Vec<String>,
    pub client_secret: Option<String>,
    /// Sent during authorization-code exchange only.
    pub client_key: Option<String>,
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    pub fields: Vec<String>,
    pub config_id: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub redirect_uri: Option<String>,
    /// Trusted key authority for Limited Login signature verification.
    pub jwks_source: Option<Arc<dyn OAuthJwksSource>>,
    /// Trusted transport overrides retain the actual inspection and mapping.
    pub token_inspection_endpoint: Option<String>,
    pub user_info_endpoint: Option<String>,
    pub map_profile_to_user: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
}
impl FacebookOptions {
    #[must_use]
    pub fn new(client_id: impl Into<String>, client_secret: Option<String>) -> Self {
        Self {
            client_ids: vec![client_id.into()],
            client_secret,
            client_key: None,
            scope: Vec::new(),
            disable_default_scope: false,
            fields: Vec::new(),
            config_id: None,
            authorization_endpoint: None,
            redirect_uri: None,
            jwks_source: None,
            token_inspection_endpoint: None,
            user_info_endpoint: None,
            map_profile_to_user: None,
        }
    }
}
impl std::fmt::Debug for FacebookOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FacebookOptions")
            .field("client_ids", &self.client_ids)
            .field("scope", &self.scope)
            .field("disable_default_scope", &self.disable_default_scope)
            .field("fields", &self.fields)
            .field("config_id", &self.config_id)
            .field("authorization_endpoint", &self.authorization_endpoint)
            .field("redirect_uri", &self.redirect_uri)
            .finish_non_exhaustive()
    }
}
impl OAuthProvider {
    #[must_use]
    pub fn facebook(client_id: &str, client_secret: &str) -> Self {
        Self::facebook_with_options(FacebookOptions::new(client_id, Some(client_secret.into())))
    }
    #[must_use]
    pub fn facebook_with_options(options: FacebookOptions) -> Self {
        let client_id = options.client_ids.first().cloned().unwrap_or_default();
        let secret = options.client_secret.unwrap_or_default();
        let endpoint = options
            .user_info_endpoint
            .unwrap_or_else(|| "https://graph.facebook.com/me".into());
        let verification = OAuthIdTokenConfig {
            issuers: vec!["https://www.facebook.com".into()],
            audience: None,
            client_ids: Some(options.client_ids.clone()),
            jwks_source: options.jwks_source.unwrap_or_else(|| {
                Arc::new(HttpOAuthJwksSource::new(
                    "https://limited.facebook.com/.well-known/oauth/openid/jwks/",
                ))
            }),
            max_age_secs: None,
            allow_opaque_token: true,
            algorithm: Some(jsonwebtoken::Algorithm::RS256),
            selection: OAuthJwksSelection::RemoteRs256,
            nonce_comparison: OAuthNonceComparison::Exact,
            verify_claims: None,
        };
        Self {
            client_id: client_id.clone(),
            client_secret: secret.clone(),
            additional_client_ids: options.client_ids.iter().skip(1).cloned().collect(),
            hosted_domain: None,
            require_email_verification: false,
            auth_url: options
                .authorization_endpoint
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "https://www.facebook.com/v24.0/dialog/oauth".into()),
            token_url: "https://graph.facebook.com/v24.0/oauth/access_token".into(),
            user_info_url: Some(endpoint.clone()),
            scopes: vec!["email".into(), "public_profile".into()],
            authorization: Some(OAuthAuthorizationPolicy {
                configured_scopes: options.scope,
                disable_default_scopes: options.disable_default_scope,
                require_client_id: true,
                require_client_secret: true,
                token_endpoint_auth: Some(OAuthTokenEndpointAuth::ClientSecretPost),
                authorization_code_client_key: options.client_key,
                redirect_uri: options.redirect_uri,
                pkce: false,
                ..OAuthAuthorizationPolicy::default()
            }),
            authorization_params: options
                .config_id
                .filter(|value| !value.is_empty())
                .map(|value| vec![("config_id".into(), value)])
                .unwrap_or_default(),
            account_subject: Some(subject),
            map_user_info: None,
            get_user_info: Some(Arc::new(FacebookUserInfo {
                client_id,
                client_ids: options.client_ids,
                client_secret: secret,
                inspection_endpoint: options
                    .token_inspection_endpoint
                    .unwrap_or_else(|| "https://graph.facebook.com/debug_token".into()),
                endpoint,
                fields: options.fields,
                mapper: options.map_profile_to_user,
            })),
            refresh_access_token: None,
            verify_id_token: None,
            id_token: Some(verification),
            disable_id_token_sign_in: false,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            allow_idp_initiated: false,
            override_user_info_on_sign_in: false,
        }
    }
}
struct FacebookUserInfo {
    client_id: String,
    client_ids: Vec<String>,
    client_secret: String,
    inspection_endpoint: String,
    endpoint: String,
    fields: Vec<String>,
    mapper: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
}
#[async_trait]
impl OAuthUserInfoHandler for FacebookUserInfo {
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        let limited_login = request
            .id_token
            .as_deref()
            .is_some_and(|token| token.split('.').count() == 3);
        let profile = if limited_login {
            let token = request
                .id_token
                .as_deref()
                .ok_or("Missing Facebook ID token")?;
            let payload = token.split('.').nth(1).ok_or("Invalid Facebook ID token")?;
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload)
                .map_err(|error| error.to_string())?;
            let data: Value =
                alibi_core::utils::json::from_slice(&bytes).map_err(|error| error.to_string())?;
            if !data.is_object() {
                return Err("Invalid Facebook ID profile".into());
            }
            data
        } else {
            self.graph_profile(request.access_token.as_deref()).await?
        };
        let mapped = self
            .mapper
            .map(|mapper| mapper(profile.clone()))
            .transpose()?;
        let user_output = mapped.as_ref().map(|user| user.public_profile(true));
        let user = match mapped {
            Some(user) => user,
            None => OAuthUserInfo {
                additional_fields: Default::default(),
                id: scalar(profile.get("sub").or_else(|| profile.get("id")))?.unwrap_or_default(),
                name: scalar(profile.get("name"))?,
                email: profile
                    .get("email")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .into(),
                image: scalar(if limited_login {
                    profile.get("picture")
                } else {
                    profile
                        .get("picture")
                        .and_then(|picture| picture.get("data"))
                        .and_then(|data| data.get("url"))
                })?,
                email_verified: !limited_login
                    && profile
                        .get("email_verified")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
            },
        };
        Ok(OAuthUserInfoResponse {
            user_output,
            user,
            data: profile,
        })
    }
}
impl FacebookUserInfo {
    async fn graph_profile(&self, access_token: Option<&str>) -> Result<Value, String> {
        let access_token = access_token
            .filter(|token| !token.is_empty())
            .ok_or("Missing Facebook access token")?;
        if self.client_id.is_empty() || self.client_secret.is_empty() {
            return Err("Facebook client ID and secret are required".into());
        }
        let client = reqwest::Client::new();
        let app_access_token = format!("{}|{}", self.client_id, self.client_secret);
        let inspected: Value = client
            .get(&self.inspection_endpoint)
            .query(&[
                ("input_token", access_token),
                ("access_token", app_access_token.as_str()),
            ])
            .send()
            .await
            .map_err(http_error)?
            .error_for_status()
            .map_err(http_error)?
            .json()
            .await
            .map_err(http_error)?;
        let data = inspected
            .get("data")
            .ok_or("Facebook inspection returned no data")?;
        let app_valid = data
            .get("app_id")
            .and_then(Value::as_str)
            .is_some_and(|id| {
                !id.is_empty() && self.client_ids.iter().any(|configured| configured == id)
            });
        if data.get("is_valid").and_then(Value::as_bool) != Some(true) || !app_valid {
            return Err("Invalid Facebook token or configured app binding".into());
        }
        let user_id = data
            .get("user_id")
            .filter(|value| {
                matches!(value, Value::String(_) | Value::Number(_) | Value::Bool(_))
                    && truthy(value)
            })
            .ok_or("Facebook inspection returned no user")?;
        let mut fields = vec!["id", "name", "email", "picture"];
        fields.extend(self.fields.iter().map(String::as_str));
        let profile: Value = client
            .get(&self.endpoint)
            .query(&[("fields", fields.join(","))])
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(http_error)?
            .error_for_status()
            .map_err(http_error)?
            .json()
            .await
            .map_err(http_error)?;
        if profile.get("id") != Some(user_id) {
            return Err("Facebook profile does not match inspected identity".into());
        }
        Ok(profile)
    }
}
fn http_error(error: reqwest::Error) -> String {
    error.without_url().to_string()
}
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}
fn scalar(value: Option<&Value>) -> Result<Option<String>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(Value::Number(value)) => alibi_core::utils::json::number_to_string(value)
            .map(Some)
            .map_err(|error| error.to_string()),
        Some(Value::Bool(value)) => Ok(Some(value.to_string())),
        Some(Value::Array(_) | Value::Object(_)) => Err("Invalid Facebook profile field".into()),
    }
}
fn subject(profile: &Value) -> Result<String, String> {
    let id = scalar(profile.get("sub").or_else(|| profile.get("id")))?
        .ok_or("Missing Facebook account subject")?;
    if id
        .trim_matches(|character: char| {
            (character.is_whitespace() && character != '\u{85}') || character == '\u{feff}'
        })
        .is_empty()
        || id == "null"
        || id == "undefined"
    {
        return Err("Invalid Facebook account subject".into());
    }
    Ok(id)
}
