//! Cloudflare's API profile, scope ordering and OAuth credential transport.
use super::{OAuthAuthorizationPolicy, OAuthProvider, OAuthTokenEndpointAuth, OAuthUserInfo};
use serde_json::Value;

/// Cloudflare configuration. Generic callback/signup policies remain available
/// on the returned provider.
#[derive(Clone)]
pub struct CloudflareOptions {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    pub authorization_endpoint: Option<String>,
    pub redirect_uri: Option<String>,
    pub token_endpoint_auth_method: Option<OAuthTokenEndpointAuth>,
    /// Trusted transport override, retaining Cloudflare's API envelope mapping.
    pub user_info_endpoint: Option<String>,
    /// Receives the original API result. Its ID cannot replace the raw subject.
    pub map_profile_to_user: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
}
impl CloudflareOptions {
    #[must_use]
    pub fn new(client_id: impl Into<String>, client_secret: Option<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret,
            scope: Vec::new(),
            disable_default_scope: false,
            authorization_endpoint: None,
            redirect_uri: None,
            token_endpoint_auth_method: None,
            user_info_endpoint: None,
            map_profile_to_user: None,
        }
    }
}
impl std::fmt::Debug for CloudflareOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CloudflareOptions")
            .field("client_id", &self.client_id)
            .field("scope", &self.scope)
            .field("disable_default_scope", &self.disable_default_scope)
            .field(
                "token_endpoint_auth_method",
                &self.token_endpoint_auth_method,
            )
            .finish_non_exhaustive()
    }
}
impl OAuthProvider {
    #[must_use]
    pub fn cloudflare(client_id: &str, client_secret: Option<&str>) -> Self {
        Self::cloudflare_with_options(CloudflareOptions::new(
            client_id,
            client_secret.map(str::to_owned),
        ))
    }
    #[must_use]
    pub fn cloudflare_with_options(options: CloudflareOptions) -> Self {
        let client_secret = options.client_secret.unwrap_or_default();
        let authentication = options.token_endpoint_auth_method.unwrap_or({
            if client_secret.is_empty() {
                OAuthTokenEndpointAuth::None
            } else {
                OAuthTokenEndpointAuth::ClientSecretBasic
            }
        });
        let user_info_url = options
            .user_info_endpoint
            .unwrap_or_else(|| "https://api.cloudflare.com/client/v4/user".into());
        Self {
            client_id: options.client_id,
            client_secret,
            additional_client_ids: Vec::new(),
            hosted_domain: None,
            require_email_verification: false,
            auth_url: options
                .authorization_endpoint
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "https://dash.cloudflare.com/oauth2/auth".into()),
            token_url: "https://dash.cloudflare.com/oauth2/token".into(),
            user_info_url: Some(user_info_url.clone()),
            scopes: vec!["user-details.read".into()],
            authorization: Some(OAuthAuthorizationPolicy {
                configured_scopes: options.scope,
                disable_default_scopes: options.disable_default_scope,
                deduplicate_scopes: true,
                require_client_id: true,
                token_endpoint_auth: Some(authentication),
                redirect_uri: options.redirect_uri,
                login_hint: false,
                ..OAuthAuthorizationPolicy::default()
            }),
            authorization_params: Vec::new(),
            account_subject: None,
            map_user_info: None,
            get_user_info: Some(std::sync::Arc::new(CloudflareUserInfo {
                url: user_info_url,
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
fn scalar(value: Option<&Value>) -> Result<Option<String>, String> {
    match value {
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(Value::Number(value)) => better_auth_core::utils::json::number_to_string(value)
            .map(Some)
            .map_err(|error| error.to_string()),
        Some(Value::Bool(value)) => Ok(Some(value.to_string())),
        None | Some(Value::Null) => Ok(None),
        _ => Err("Invalid Cloudflare profile field".into()),
    }
}
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(false) => false,
        Value::Number(value) => value.as_f64() != Some(0.0),
        Value::String(value) => !value.is_empty(),
        _ => true,
    }
}
fn subject(profile: &Value) -> Result<String, String> {
    let id = scalar(profile.get("id"))?.ok_or("Missing Cloudflare ID")?;
    if id
        .trim_matches(|character: char| {
            (character.is_whitespace() && character != '\u{85}') || character == '\u{feff}'
        })
        .is_empty()
        || id == "null"
        || id == "undefined"
    {
        return Err("Invalid Cloudflare ID".into());
    }
    Ok(id)
}
struct CloudflareUserInfo {
    url: String,
    mapper: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
}
#[async_trait::async_trait]
impl super::OAuthUserInfoHandler for CloudflareUserInfo {
    async fn get_user_info(
        &self,
        request: super::OAuthUserInfoRequest,
    ) -> Result<super::OAuthUserInfoResponse, String> {
        let access_token = request
            .access_token
            .ok_or("Missing Cloudflare access token")?;
        let response = reqwest::Client::new()
            .get(&self.url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|error| error.to_string())?
            .error_for_status()
            .map_err(|error| error.to_string())?;
        let envelope: Value = response.json().await.map_err(|error| error.to_string())?;
        if !envelope.get("success").is_some_and(truthy)
            || !envelope.get("result").is_some_and(truthy)
        {
            return Err("Cloudflare API rejected user info".into());
        }
        let profile = envelope
            .get("result")
            .ok_or("Missing Cloudflare API result")?;
        let email = profile
            .get("email")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let names = ["first_name", "last_name"]
            .into_iter()
            .filter_map(|key| profile.get(key))
            .filter(|value| truthy(value))
            .map(|value| scalar(Some(value)).map(Option::unwrap_or_default))
            .collect::<Result<Vec<_>, _>>()?;
        let name = names.join(" ");
        let mapped = self
            .mapper
            .map(|mapper| mapper(profile.clone()))
            .transpose()?;
        let user_output = mapped.as_ref().map(|user| user.public_profile(true));
        let id = subject(profile)?;
        let mut user = mapped.unwrap_or_else(|| OAuthUserInfo {
            additional_fields: Default::default(),
            id: id.clone(),
            email: email.clone(),
            name: Some(if name.is_empty() { email } else { name }),
            image: None,
            email_verified: false,
        });
        user.id = id;
        Ok(super::OAuthUserInfoResponse {
            user_output,
            user,
            data: profile.clone(),
        })
    }
}
