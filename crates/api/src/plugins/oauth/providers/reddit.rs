//! Reddit's non-PKCE Basic grants and stable placeholder-email profile.
use super::{OAuthAuthorizationPolicy, OAuthProvider, OAuthTokenEndpointAuth, OAuthUserInfo,
    OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse};
use async_trait::async_trait;
use serde_json::Value;

/// Application-owned Reddit configuration. Signup policies and asynchronous
/// user-info/refresh overrides remain available on the returned native provider.
#[derive(Clone)]
pub struct RedditOptions {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    /// Forwarded when nonempty; caller additional parameters take precedence.
    pub duration: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub redirect_uri: Option<String>,
    /// Trusted application transport override preserving Reddit's mapping.
    pub user_info_endpoint: Option<String>,
    /// Receives the original profile before account identity resolution.
    pub map_profile_to_user: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
}
impl RedditOptions {
    #[must_use]
    pub fn new(client_id: impl Into<String>, client_secret: Option<String>) -> Self {
        Self { client_id: client_id.into(), client_secret, scope: Vec::new(),
            disable_default_scope: false, duration: None, authorization_endpoint: None,
            redirect_uri: None, user_info_endpoint: None, map_profile_to_user: None }
    }
}
impl std::fmt::Debug for RedditOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("RedditOptions").field("client_id", &self.client_id)
            .field("scope", &self.scope).field("disable_default_scope", &self.disable_default_scope)
            .field("duration", &self.duration).field("authorization_endpoint", &self.authorization_endpoint)
            .field("redirect_uri", &self.redirect_uri).finish_non_exhaustive()
    }
}
impl OAuthProvider {
    #[must_use]
    pub fn reddit(client_id: &str, client_secret: Option<&str>) -> Self {
        Self::reddit_with_options(RedditOptions::new(client_id, client_secret.map(str::to_owned)))
    }
    #[must_use]
    pub fn reddit_with_options(options: RedditOptions) -> Self {
        let endpoint = options.user_info_endpoint.unwrap_or_else(|| "https://oauth.reddit.com/api/v1/me".into());
        Self {
            client_id: options.client_id, client_secret: options.client_secret.unwrap_or_default(),
            additional_client_ids: Vec::new(), hosted_domain: None, require_email_verification: false,
            auth_url: options.authorization_endpoint.filter(|v| !v.is_empty()).unwrap_or_else(|| "https://www.reddit.com/api/v1/authorize".into()),
            token_url: "https://www.reddit.com/api/v1/access_token".into(), user_info_url: Some(endpoint.clone()),
            scopes: vec!["identity".into()],
            authorization: Some(OAuthAuthorizationPolicy {
                configured_scopes: options.scope, disable_default_scopes: options.disable_default_scope,
                require_client_id: true, token_endpoint_auth: Some(OAuthTokenEndpointAuth::ClientSecretBasic),
                authorization_code_headers: vec![("accept".into(), "text/plain".into()), ("user-agent".into(), "better-auth".into())],
                redirect_uri: options.redirect_uri, login_hint: false, pkce: false,
                ..OAuthAuthorizationPolicy::default()
            }),
            authorization_params: options.duration.filter(|v| !v.is_empty()).map(|v| vec![("duration".into(),v)]).unwrap_or_default(),
            account_subject: Some(subject), map_user_info: None,
            get_user_info: Some(std::sync::Arc::new(RedditUserInfo { endpoint, mapper: options.map_profile_to_user })),
            refresh_access_token: None, verify_id_token: None, id_token: None,
            disable_id_token_sign_in: false, disable_implicit_sign_up: false, disable_sign_up: false,
            override_user_info_on_sign_in: false,
        }
    }
}
struct RedditUserInfo {
    endpoint: String,
    mapper: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
}
#[async_trait]
impl OAuthUserInfoHandler for RedditUserInfo {
    async fn get_user_info(&self, request: OAuthUserInfoRequest) -> Result<OAuthUserInfoResponse, String> {
        let access_token = request.access_token.ok_or("Missing Reddit access token")?;
        let profile: Value = reqwest::Client::new().get(&self.endpoint).bearer_auth(access_token)
            .header("User-Agent", "better-auth").send().await.map_err(|e| e.to_string())?
            .error_for_status().map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
        let mapped = self.mapper.map(|mapper| mapper(profile.clone())).transpose()?;
        let mut user = mapped.unwrap_or(OAuthUserInfo {
            additional_fields: Default::default(), id: scalar(profile.get("id"))?.unwrap_or_default(),
            // Typed signup applies Source's falsy-name fallback; public output retains raw JSON.
            name: scalar(profile.get("name").filter(|v| !matches!(v, Value::Bool(false)) && v.as_f64()!=Some(0.0)))?,
            email: String::new(), image: None, email_verified: false,
        });
        if user.email.is_empty() {
            let identifier = scalar(profile.get("id"))?.unwrap_or_else(|| if profile.get("id").is_some() { "null".into() } else { "undefined".into() });
            let email = format!("{identifier}@reddit.placeholder.invalid");
            if !crate::plugins::authentication_helpers::is_valid_email(&email) { return Err("Invalid placeholder email".into()); }
            user.email = email;
        }
        let image = match profile.get("icon_img") {
            None | Some(Value::Null) => None,
            Some(Value::String(image)) => Some(image.split('?').next().unwrap_or_default().to_owned()),
            _ => return Err("Invalid Reddit icon_img".into()),
        };
        let mut output = serde_json::Map::new();
        if let Some(name) = profile.get("name") { drop(output.insert("name".into(), name.clone())); }
        if let Some(image) = &image { drop(output.insert("image".into(), Value::String(image.clone()))); }
        if self.mapper.is_some() { output.extend(user.public_profile(true)); }
        else { user.image = image; }
        drop(output.insert("email".into(), Value::String(user.email.clone())));
        drop(output.insert("emailVerified".into(), Value::Bool(user.email_verified)));
        Ok(OAuthUserInfoResponse { user_output: Some(output), user, data: profile })
    }
}
fn scalar(value: Option<&Value>) -> Result<Option<String>, String> {
    match value {
        None | Some(Value::Null) => Ok(None), Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(Value::Number(value)) => better_auth_core::utils::json::number_to_string(value).map(Some).map_err(|e| e.to_string()),
        Some(Value::Bool(value)) => Ok(Some(value.to_string())),
        Some(Value::Array(_) | Value::Object(_)) => Err("Invalid Reddit profile field".into()),
    }
}
fn subject(profile: &Value) -> Result<String, String> {
    let id = scalar(profile.get("id"))?.ok_or("Missing Reddit id")?;
    if id.trim_matches(|c:char| (c.is_whitespace() && c!='\u{85}') || c=='\u{feff}').is_empty() || id=="null" || id=="undefined" { return Err("Invalid Reddit id".into()); }
    Ok(id)
}
