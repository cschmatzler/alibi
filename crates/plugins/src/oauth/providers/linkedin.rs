//! LinkedIn's non-PKCE grants and original subject with nullish email verification.
use super::{
    OAuthAuthorizationPolicy, OAuthProvider, OAuthTokenEndpointAuth, OAuthUserInfo,
    OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use async_trait::async_trait;
use serde_json::Map;
use serde_json::Value;

/// Application-owned LinkedIn configuration. Generic signup and asynchronous
/// user-info/refresh callbacks remain configurable on the returned provider.
#[derive(Clone)]
pub struct LinkedInOptions {
    pub client_id: String,
    pub client_secret: Option<String>,
    /// Sent only during authorization-code exchange.
    pub client_key: Option<String>,
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    pub authorization_endpoint: Option<String>,
    pub redirect_uri: Option<String>,
    /// Trusted transport override retaining LinkedIn's actual GET and mapping.
    pub user_info_endpoint: Option<String>,
    /// Receives the original profile before its raw account identity is resolved.
    pub map_profile_to_user: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
}
impl LinkedInOptions {
    #[must_use]
    pub fn new(client_id: impl Into<String>, client_secret: Option<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret,
            client_key: None,
            scope: Vec::new(),
            disable_default_scope: false,
            authorization_endpoint: None,
            redirect_uri: None,
            user_info_endpoint: None,
            map_profile_to_user: None,
        }
    }
}
impl std::fmt::Debug for LinkedInOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LinkedInOptions")
            .field("client_id", &self.client_id)
            .field("scope", &self.scope)
            .field("disable_default_scope", &self.disable_default_scope)
            .field("authorization_endpoint", &self.authorization_endpoint)
            .field("redirect_uri", &self.redirect_uri)
            .finish_non_exhaustive()
    }
}
impl OAuthProvider {
    #[must_use]
    pub fn linkedin(client_id: &str, client_secret: Option<&str>) -> Self {
        Self::linkedin_with_options(LinkedInOptions::new(
            client_id,
            client_secret.map(str::to_owned),
        ))
    }
    #[must_use]
    pub fn linkedin_with_options(options: LinkedInOptions) -> Self {
        let secret = options.client_secret.unwrap_or_default();
        let authentication = if secret.is_empty() {
            OAuthTokenEndpointAuth::None
        } else {
            OAuthTokenEndpointAuth::ClientSecretPost
        };
        let endpoint = options
            .user_info_endpoint
            .unwrap_or_else(|| "https://api.linkedin.com/v2/userinfo".into());
        Self {
            client_id: options.client_id,
            client_secret: secret,
            additional_client_ids: Vec::new(),
            hosted_domain: None,
            require_email_verification: false,
            auth_url: options
                .authorization_endpoint
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "https://www.linkedin.com/oauth/v2/authorization".into()),
            token_url: "https://www.linkedin.com/oauth/v2/accessToken".into(),
            user_info_url: Some(endpoint.clone()),
            scopes: ["profile", "email", "openid"].map(String::from).to_vec(),
            authorization: Some(OAuthAuthorizationPolicy {
                configured_scopes: options.scope,
                disable_default_scopes: options.disable_default_scope,
                require_client_id: true,
                token_endpoint_auth: Some(authentication),
                authorization_code_client_key: options.client_key,
                redirect_uri: options.redirect_uri,
                login_hint: true,
                pkce: false,
                ..OAuthAuthorizationPolicy::default()
            }),
            authorization_params: Vec::new(),
            account_subject: Some(subject),
            map_user_info: None,
            get_user_info: Some(std::sync::Arc::new(LinkedInUserInfo {
                endpoint,
                mapper: options.map_profile_to_user,
            })),
            refresh_access_token: None,
            verify_id_token: None,
            id_token: None,
            disable_id_token_sign_in: false,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            allow_idp_initiated: false,
            override_user_info_on_sign_in: false,
        }
    }
}
struct LinkedInUserInfo {
    endpoint: String,
    mapper: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
}
#[async_trait]
impl OAuthUserInfoHandler for LinkedInUserInfo {
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        let access_token = request
            .access_token
            .ok_or("Missing LinkedIn access token")?;
        let response: Value = reqwest::Client::new()
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
        let profile = response;
        let mapped = self
            .mapper
            .map(|mapper| mapper(profile.clone()))
            .transpose()?;
        // Keep the factory's original JSON publication separate from typed
        // persistence and raw account-subject admission.
        let mut output = serde_json::Map::new();
        for (source, target) in [("name", "name"), ("email", "email"), ("picture", "image")] {
            if let Some(value) = profile.get(source) {
                drop(output.insert(target.into(), value.clone()));
            }
        }
        drop(
            output.insert(
                "emailVerified".into(),
                profile
                    .get("email_verified")
                    .filter(|value| !value.is_null())
                    .cloned()
                    .unwrap_or(Value::Bool(false)),
            ),
        );
        if let Some(user) = &mapped {
            output.extend(user.public_profile(true));
        }
        let user_output = Some(output);
        let user = match mapped {
            Some(user) => user,
            None => OAuthUserInfo {
                additional_fields: Map::default(),
                id: scalar(profile.get("sub"))?.unwrap_or_default(),
                name: scalar(profile.get("name"))?,
                email: profile
                    .get("email")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .into(),
                image: scalar(profile.get("picture"))?,
                email_verified: profile
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
fn scalar(value: Option<&Value>) -> Result<Option<String>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(Value::Number(value)) => alibi_core::utils::json::number_to_string(value)
            .map(Some)
            .map_err(|error| error.to_string()),
        Some(Value::Bool(value)) => Ok(Some(value.to_string())),
        Some(Value::Array(_) | Value::Object(_)) => Err("Invalid LinkedIn profile field".into()),
    }
}
fn subject(profile: &Value) -> Result<String, String> {
    let id = scalar(profile.get("sub"))?.ok_or("Missing LinkedIn subject")?;
    if id
        .trim_matches(|character: char| {
            (character.is_whitespace() && character != '\u{85}') || character == '\u{feff}'
        })
        .is_empty()
        || id == "null"
        || id == "undefined"
    {
        return Err("Invalid LinkedIn subject".into());
    }
    Ok(id)
}
