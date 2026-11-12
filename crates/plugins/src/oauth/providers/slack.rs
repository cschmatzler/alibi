//! Dedicated published Better Auth 1.7.6 Slack factory.
use super::remaining_profile::{ProfileKind, PublishedProfile};
use super::OAuthProvider;
use alibi_core::utils::json::JsObject as Map;
use alibi_core::utils::json::{JsString, JsValue as Value};

#[derive(Clone, Default)]
pub struct SlackOptions {
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
}
impl SlackOptions {
    #[must_use]
    pub fn new(client_id: impl Into<String>, client_secret: Option<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret,
            ..Self::default()
        }
    }
}
impl std::fmt::Debug for SlackOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlackOptions")
            .field("client_id", &self.client_id)
            .field("authorization_endpoint", &self.authorization_endpoint)
            .finish_non_exhaustive()
    }
}
impl OAuthProvider {
    #[must_use]
    pub fn slack(client_id: &str, client_secret: Option<&str>) -> Self {
        Self::slack_with_options(SlackOptions::new(
            client_id,
            client_secret.map(str::to_owned),
        ))
    }
    #[must_use]
    pub fn slack_with_options(options: SlackOptions) -> Self {
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
            auth_url: "https://slack.com/openid/connect/authorize".into(),
            token_url: "https://slack.com/api/openid.connect.token".into(),
            user_info_url: Some("https://slack.com/api/openid.connect.userInfo".into()),
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            account_subject: Some(subject),
            ..Self::default()
        };
        provider.auth_url = options
            .authorization_endpoint
            .filter(|v| !v.is_empty())
            .unwrap_or(provider.auth_url);
        provider.user_info_url = options.user_info_endpoint.or(provider.user_info_url);
        policy.scope_order = super::OAuthScopeOrder::RequestedThenConfigured;
        provider.authorization = Some(policy);
        provider.get_user_info = Some(std::sync::Arc::new(PublishedProfile {
            kind: ProfileKind::Slack,
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
    super::remaining_profile::subject(ProfileKind::Slack, profile)
}
