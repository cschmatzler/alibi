//! Dedicated published Better Auth 1.7.6 Twitch factory.
use super::remaining_profile::{ProfileKind, PublishedProfile};
use super::{OAuthAuthorizationPolicy, OAuthProvider, OAuthTokenEndpointAuth, OAuthUserInfo};
use serde_json::Value;

#[derive(Clone)]
pub struct TwitchOptions {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub client_key: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub redirect_uri: Option<String>,
    /// Trusted application transport override; it does not change profile semantics.
    pub user_info_endpoint: Option<String>,
    pub map_profile_to_user: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    pub claims: Option<Vec<String>>,
}
impl TwitchOptions {
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
            claims: None,
        }
    }
}
impl std::fmt::Debug for TwitchOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwitchOptions")
            .field("client_id", &self.client_id)
            .field("authorization_endpoint", &self.authorization_endpoint)
            .finish_non_exhaustive()
    }
}
impl OAuthProvider {
    #[must_use]
    pub fn twitch(client_id: &str, client_secret: Option<&str>) -> Self {
        Self::twitch_with_options(TwitchOptions::new(
            client_id,
            client_secret.map(str::to_owned),
        ))
    }
    #[must_use]
    pub fn twitch_with_options(options: TwitchOptions) -> Self {
        let mut policy = OAuthAuthorizationPolicy {
            preserve_raw_profile_scalars: true,
            source_profile_exceptions: true,
            require_client_id: true,
            login_hint: false,
            pkce: false,
            configured_scopes: options.scope,
            disable_default_scopes: options.disable_default_scope,
            authorization_code_client_key: options.client_key,
            redirect_uri: options.redirect_uri,
            token_endpoint_auth: Some(
                if options
                    .client_secret
                    .as_ref()
                    .is_some_and(|v| !v.is_empty())
                {
                    OAuthTokenEndpointAuth::ClientSecretPost
                } else {
                    OAuthTokenEndpointAuth::None
                },
            ),
            allow_missing_access_token: true,
            preserve_raw_email_errors: true,
            ..OAuthAuthorizationPolicy::default()
        };
        let mut provider = Self {
            client_id: options.client_id,
            client_secret: options.client_secret.unwrap_or_default(),
            additional_client_ids: Vec::new(),
            hosted_domain: None,
            require_email_verification: false,
            auth_url: "https://id.twitch.tv/oauth2/authorize".into(),
            token_url: "https://id.twitch.tv/oauth2/token".into(),
            user_info_url: None,
            scopes: vec!["user:read:email".into(), "openid".into()],
            authorization: None,
            authorization_params: Vec::new(),
            account_subject: Some(subject),
            map_user_info: None,
            get_user_info: None,
            refresh_access_token: None,
            verify_id_token: None,
            id_token: None,
            disable_id_token_sign_in: false,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            override_user_info_on_sign_in: false,
        };
        provider.auth_url = options
            .authorization_endpoint
            .filter(|v| !v.is_empty())
            .unwrap_or(provider.auth_url);
        provider.user_info_url = options.user_info_endpoint.or(provider.user_info_url);
        let mut claims = Vec::new();
        for claim in ["email", "email_verified"]
            .into_iter()
            .map(str::to_owned)
            .chain(options.claims.unwrap_or_else(|| {
                vec![
                    "email".into(),
                    "email_verified".into(),
                    "preferred_username".into(),
                    "picture".into(),
                ]
            }))
        {
            // Object assignment to __proto__ does not create an own JSON key.
            if claim != "__proto__" && !claims.iter().any(|(key, _)| key == &claim) {
                claims.push((claim, better_auth_core::utils::json::JsValue::Null));
            }
        }
        // Only string property names and null values enter this object.
        #[expect(
            clippy::expect_used,
            reason = "Claim keys and null values cannot fail JSON serialization"
        )]
        let serialized_claims = better_auth_core::utils::json::to_string(
            &better_auth_core::utils::json::JsValue::Object(
                [(
                    "id_token".into(),
                    better_auth_core::utils::json::JsValue::Object(claims.into_iter().collect()),
                )]
                .into_iter()
                .collect(),
            ),
        )
        .expect("Twitch claim names and null values are JSON serializable");
        provider
            .authorization_params
            .push(("claims".into(), serialized_claims));
        policy.propagate_grant_profile_errors = true;
        provider.authorization = Some(policy);
        provider.get_user_info = Some(std::sync::Arc::new(PublishedProfile {
            kind: ProfileKind::Twitch,
            endpoint: provider.user_info_url.clone(),
            email_endpoint: None,
            client_id: provider.client_id.clone(),
            mapper: options.map_profile_to_user,
            application_mapper: None,
        }));
        provider
    }
}
fn subject(profile: &Value) -> Result<String, String> {
    super::remaining_profile::subject(ProfileKind::Twitch, profile)
}
