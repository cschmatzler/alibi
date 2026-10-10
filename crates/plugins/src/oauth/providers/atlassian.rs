//! Atlassian's published scope, PKCE, fixed audience and stable account subject.
use super::{OAuthAuthorizationPolicy, OAuthProvider, OAuthUserInfo};
use serde_json::Map;
use serde_json::Value;

/// Atlassian-specific configuration; callback and persistence policies remain
/// configurable on the returned OAuth provider.
#[derive(Clone)]
pub struct AtlassianOptions {
    pub client_id: String,
    pub client_secret: String,
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    pub prompt: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub redirect_uri: Option<String>,
    /// Trusted user-info transport endpoint, retaining the Atlassian mapping.
    pub user_info_endpoint: Option<String>,
    /// Receives the original profile. Its ID cannot replace `account_id`.
    pub map_profile_to_user: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
}
impl AtlassianOptions {
    #[must_use]
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            scope: Vec::new(),
            disable_default_scope: false,
            prompt: None,
            authorization_endpoint: None,
            redirect_uri: None,
            user_info_endpoint: None,
            map_profile_to_user: None,
        }
    }
}
impl std::fmt::Debug for AtlassianOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AtlassianOptions")
            .field("client_id", &self.client_id)
            .field("scope", &self.scope)
            .field("disable_default_scope", &self.disable_default_scope)
            .field("prompt", &self.prompt)
            .field("authorization_endpoint", &self.authorization_endpoint)
            .field("redirect_uri", &self.redirect_uri)
            .finish_non_exhaustive()
    }
}
impl OAuthProvider {
    #[must_use]
    pub fn atlassian(client_id: &str, client_secret: &str) -> Self {
        Self::atlassian_with_options(AtlassianOptions::new(client_id, client_secret))
    }
    #[must_use]
    pub fn atlassian_with_options(options: AtlassianOptions) -> Self {
        let mut provider = Self {
            client_id: options.client_id,
            client_secret: options.client_secret,
            additional_client_ids: Vec::new(),
            hosted_domain: None,
            require_email_verification: false,
            auth_url: String::new(),
            token_url: String::new(),
            user_info_url: None,
            scopes: Vec::new(),
            authorization: None,
            allowed_request_params: Vec::new(),
            authorization_params: Vec::new(),
            account_subject: None,
            map_user_info: None,
            get_user_info: None,
            refresh_access_token: None,
            verify_id_token: None,
            id_token: None,
            disable_id_token_sign_in: false,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            allow_idp_initiated: false,
            override_user_info_on_sign_in: false,
        };
        provider.auth_url = options
            .authorization_endpoint
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "https://auth.atlassian.com/authorize".into());
        provider.token_url = "https://auth.atlassian.com/oauth/token".into();
        provider.user_info_url = Some(
            options
                .user_info_endpoint
                .unwrap_or_else(|| "https://api.atlassian.com/me".into()),
        );
        provider.scopes = vec!["read:jira-user".into(), "offline_access".into()];
        provider.authorization = Some(OAuthAuthorizationPolicy {
            configured_scopes: options.scope,
            disable_default_scopes: options.disable_default_scope,
            prompt: options.prompt,
            redirect_uri: options.redirect_uri,
            require_client_secret: true,
            login_hint: false,
            ..OAuthAuthorizationPolicy::default()
        });
        provider.authorization_params = vec![("audience".into(), "api.atlassian.com".into())];
        provider.map_user_info = Some(atlassian_user_info);
        if let Some(mapper) = options.map_profile_to_user {
            provider.get_user_info = Some(std::sync::Arc::new(AtlassianMappedUserInfo {
                url: provider.user_info_url.clone().unwrap_or_default(),
                mapper,
            }));
        }
        provider
    }
}
fn string(value: Option<&Value>) -> Result<Option<String>, String> {
    match value {
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(Value::Number(value)) => alibi_core::utils::json::number_to_string(value)
            .map(Some)
            .map_err(|error| error.to_string()),
        Some(Value::Bool(value)) => Ok(Some(value.to_string())),
        None | Some(Value::Null) => Ok(None),
        _ => Err("Invalid Atlassian profile field".into()),
    }
}
fn subject(profile: &Value) -> Result<String, String> {
    let value = string(profile.get("account_id"))?.ok_or("Missing Atlassian account_id")?;
    if value
        .trim_matches(|character: char| {
            (character.is_whitespace() && character != '\u{85}') || character == '\u{feff}'
        })
        .is_empty()
        || value == "null"
        || value == "undefined"
    {
        return Err("Invalid Atlassian account_id".into());
    }
    Ok(value)
}
#[expect(
    clippy::needless_pass_by_value,
    reason = "signature fixed by the map_user_info callback type"
)]
fn atlassian_user_info(profile: Value) -> Result<OAuthUserInfo, String> {
    let name = match profile.get("name") {
        Some(Value::Bool(false)) => String::new(),
        Some(Value::Number(value)) if value.as_f64() == Some(0.0) => String::new(),
        value => string(value)?.unwrap_or_default(),
    };
    Ok(OAuthUserInfo {
        additional_fields: Map::default(),
        id: subject(&profile)?,
        name: Some(name),
        email: profile
            .get("email")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .into(),
        image: string(profile.get("picture"))?,
        email_verified: false,
    })
}
struct AtlassianMappedUserInfo {
    url: String,
    mapper: fn(Value) -> Result<OAuthUserInfo, String>,
}
#[async_trait::async_trait]
impl super::OAuthUserInfoHandler for AtlassianMappedUserInfo {
    async fn get_user_info(
        &self,
        request: super::OAuthUserInfoRequest,
    ) -> Result<super::OAuthUserInfoResponse, String> {
        let access_token = request
            .access_token
            .ok_or("Missing Atlassian access token")?;
        let response = reqwest::Client::new()
            .get(&self.url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|error| error.to_string())?
            .error_for_status()
            .map_err(|error| error.to_string())?;
        let profile: Value = response.json().await.map_err(|error| error.to_string())?;
        let mut user = (self.mapper)(profile.clone())?;
        let user_output = Some(user.public_profile(true));
        user.id = subject(&profile)?;
        Ok(super::OAuthUserInfoResponse {
            user_output,
            user,
            data: profile,
        })
    }
}
