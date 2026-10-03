//! Notion's bot owner identity, versioned lookup and grant-specific credentials.
use super::{
    OAuthAuthorizationPolicy, OAuthProvider, OAuthTokenEndpointAuth, OAuthUserInfo,
    OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use async_trait::async_trait;
use serde_json::Value;

/// Application-owned Notion configuration. Generic signup and asynchronous
/// user-info/refresh callbacks remain configurable on the returned provider.
#[derive(Clone)]
pub struct NotionOptions {
    pub client_id: String,
    pub client_secret: Option<String>,
    /// Sent only during authorization-code exchange.
    pub client_key: Option<String>,
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    pub authorization_endpoint: Option<String>,
    pub redirect_uri: Option<String>,
    /// Trusted transport override retaining Notion's versioned GET and mapping.
    pub user_info_endpoint: Option<String>,
    /// Receives the original profile before its raw account identity is resolved.
    pub map_profile_to_user: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
}
impl NotionOptions {
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
impl std::fmt::Debug for NotionOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NotionOptions")
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
    pub fn notion(client_id: &str, client_secret: Option<&str>) -> Self {
        Self::notion_with_options(NotionOptions::new(
            client_id,
            client_secret.map(str::to_owned),
        ))
    }
    #[must_use]
    pub fn notion_with_options(options: NotionOptions) -> Self {
        let secret = options.client_secret.unwrap_or_default();
        let refresh_authentication = if secret.is_empty() {
            OAuthTokenEndpointAuth::None
        } else {
            OAuthTokenEndpointAuth::ClientSecretPost
        };
        let endpoint = options
            .user_info_endpoint
            .unwrap_or_else(|| "https://api.notion.com/v1/users/me".into());
        Self {
            client_id: options.client_id,
            client_secret: secret,
            additional_client_ids: Vec::new(),
            hosted_domain: None,
            require_email_verification: false,
            auth_url: options
                .authorization_endpoint
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "https://api.notion.com/v1/oauth/authorize".into()),
            token_url: "https://api.notion.com/v1/oauth/token".into(),
            user_info_url: Some(endpoint.clone()),
            scopes: Vec::new(),
            authorization: Some(OAuthAuthorizationPolicy {
                configured_scopes: options.scope,
                disable_default_scopes: options.disable_default_scope,
                require_client_id: true,
                token_endpoint_auth: Some(OAuthTokenEndpointAuth::ClientSecretBasic),
                refresh_token_endpoint_auth: Some(refresh_authentication),
                fixed_authorization_params: vec![("owner".into(), "user".into())],
                authorization_code_client_key: options.client_key,
                redirect_uri: options.redirect_uri,
                login_hint: true,
                pkce: false,
                ..OAuthAuthorizationPolicy::default()
            }),
            authorization_params: Vec::new(),
            account_subject: Some(subject),
            map_user_info: None,
            get_user_info: Some(std::sync::Arc::new(NotionUserInfo {
                endpoint,
                mapper: options.map_profile_to_user,
            })),
            refresh_access_token: None,
            verify_id_token: None,
            id_token: None,
            disable_id_token_sign_in: false,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            override_user_info_on_sign_in: false,
        }
    }
}
struct NotionUserInfo {
    endpoint: String,
    mapper: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
}
#[async_trait]
impl OAuthUserInfoHandler for NotionUserInfo {
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        let access_token = request.access_token.ok_or("Missing Notion access token")?;
        let response: Value = reqwest::Client::new()
            .get(&self.endpoint)
            .header("Notion-Version", "2022-06-28")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|error| error.to_string())?
            .error_for_status()
            .map_err(|error| error.to_string())?
            .json()
            .await
            .map_err(|error| error.to_string())?;
        let profile = response
            .get("bot")
            .and_then(|bot| bot.get("owner"))
            .and_then(|owner| owner.get("user"))
            .filter(|user| truthy(user))
            .cloned()
            .ok_or("Missing Notion profile")?;
        let mapped = self
            .mapper
            .map(|mapper| mapper(profile.clone()))
            .transpose()?;
        // Keep the published raw JSON independently from typed persistence.
        let mut output = serde_json::Map::new();
        drop(
            output.insert(
                "name".into(),
                profile
                    .get("name")
                    .filter(|v| truthy(v))
                    .cloned()
                    .unwrap_or_else(|| Value::String(String::new())),
            ),
        );
        let email = profile
            .get("person")
            .and_then(|person| person.get("email"))
            .filter(|v| truthy(v));
        drop(output.insert("email".into(), email.cloned().unwrap_or(Value::Null)));
        if let Some(image) = profile.get("avatar_url") {
            drop(output.insert("image".into(), image.clone()));
        }
        drop(output.insert("emailVerified".into(), Value::Bool(false)));
        if let Some(user) = &mapped {
            output.extend(user.public_profile(true));
        }
        let user_output = Some(output);
        let user = match mapped {
            Some(user) => user,
            None => OAuthUserInfo {
                additional_fields: Default::default(),
                id: scalar(profile.get("id"))?.unwrap_or_default(),
                name: scalar(profile.get("name").filter(|v| truthy(v)))?
                    .or_else(|| Some(String::new())),
                email: email.and_then(Value::as_str).unwrap_or_default().into(),
                image: scalar(profile.get("avatar_url"))?,
                email_verified: false,
            },
        };
        Ok(OAuthUserInfoResponse {
            user_output,
            user,
            data: profile,
        })
    }
}
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(false) => false,
        Value::Number(value) => value.as_f64() != Some(0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) | Value::Bool(true) => true,
    }
}
fn scalar(value: Option<&Value>) -> Result<Option<String>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(Value::Number(value)) => better_auth_core::utils::json::number_to_string(value)
            .map(Some)
            .map_err(|error| error.to_string()),
        Some(Value::Bool(value)) => Ok(Some(value.to_string())),
        Some(Value::Array(_) | Value::Object(_)) => Err("Invalid Notion profile field".into()),
    }
}
fn subject(profile: &Value) -> Result<String, String> {
    let id = scalar(profile.get("id"))?.ok_or("Missing Notion id")?;
    if id
        .trim_matches(|character: char| {
            (character.is_whitespace() && character != '\u{85}') || character == '\u{feff}'
        })
        .is_empty()
        || id == "null"
        || id == "undefined"
    {
        return Err("Invalid Notion id".into());
    }
    Ok(id)
}
