//! Dedicated published Better Auth 1.7.6 Roblox factory.
use super::remaining_profile::{ProfileKind, PublishedProfile};
use super::OAuthProvider;
use alibi_core::utils::json::JsObject as Map;
use alibi_core::utils::json::{JsString, JsValue as Value};

#[derive(Clone)]
pub struct RobloxOptions {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub client_key: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub redirect_uri: Option<String>,
    /// Trusted application transport override; it does not change profile semantics.
    pub user_info_endpoint: Option<String>,
    pub map_profile_to_user: Option<fn(Value) -> Result<Map, String>>,
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    pub prompt: Option<String>,
}
impl RobloxOptions {
    #[must_use]
    pub fn new(client_id: impl Into<String>, client_secret: Option<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret,
            client_key: None,
            authorization_endpoint: None,
            redirect_uri: None,
            user_info_endpoint: None,
            map_profile_to_user: None,
            scope: Vec::new(),
            disable_default_scope: false,
            prompt: None,
        }
    }
}
impl std::fmt::Debug for RobloxOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RobloxOptions")
            .field("client_id", &self.client_id)
            .field("authorization_endpoint", &self.authorization_endpoint)
            .finish_non_exhaustive()
    }
}
impl OAuthProvider {
    #[must_use]
    pub fn roblox(client_id: &str, client_secret: Option<&str>) -> Self {
        Self::roblox_with_options(RobloxOptions::new(
            client_id,
            client_secret.map(str::to_owned),
        ))
    }
    #[must_use]
    pub fn roblox_with_options(options: RobloxOptions) -> Self {
        let mut policy = super::published_authorization_policy(
            options.scope,
            options.disable_default_scope,
            options.client_key,
            options.redirect_uri,
            super::client_secret_auth(options.client_secret.as_deref()),
            false,
        );
        let mut provider = Self {
            client_id: options.client_id,
            client_secret: options.client_secret.unwrap_or_default(),
            auth_url: "https://apis.roblox.com/oauth/v1/authorize".into(),
            token_url: "https://apis.roblox.com/oauth/v1/token".into(),
            user_info_url: Some("https://apis.roblox.com/oauth/v1/userinfo".into()),
            scopes: vec!["openid".into(), "profile".into()],
            account_subject: Some(subject),
            ..Self::default()
        };
        provider.auth_url = options
            .authorization_endpoint
            .filter(|v| !v.is_empty())
            .unwrap_or(provider.auth_url);
        provider.user_info_url = options.user_info_endpoint.or(provider.user_info_url);
        policy.prompt = options.prompt;
        policy.default_prompt = Some("select_account consent".into());
        provider.authorization = Some(policy);
        provider.get_user_info = Some(std::sync::Arc::new(PublishedProfile {
            kind: ProfileKind::Roblox,
            endpoint: provider.user_info_url.clone(),
            email_endpoint: None,
            client_id: provider.client_id.clone(),
            mapper: options.map_profile_to_user,
            application_mapper: None,
        }));
        provider
    }
}
fn subject(profile: &Value) -> Result<JsString, String> {
    super::remaining_profile::subject(ProfileKind::Roblox, profile)
}
