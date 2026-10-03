//! TikTok's client-key grants, comma-separated scopes and nested profile.
use super::{
    OAuthAuthorizationPolicy, OAuthProvider, OAuthTokenEndpointAuth, OAuthUserInfo,
    OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use serde_json::Value;

#[derive(Clone)]
pub struct TikTokOptions {
    pub client_key: String,
    pub client_secret: String,
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    pub redirect_uri: Option<String>,
    /// Trusted transport override, preserving the published fields query.
    pub user_info_endpoint: Option<String>,
}
impl TikTokOptions {
    #[must_use]
    pub fn new(client_key: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            client_key: client_key.into(),
            client_secret: client_secret.into(),
            scope: Vec::new(),
            disable_default_scope: false,
            redirect_uri: None,
            user_info_endpoint: None,
        }
    }
}
impl std::fmt::Debug for TikTokOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TikTokOptions")
            .field("client_key", &self.client_key)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}
impl OAuthProvider {
    #[must_use]
    pub fn tiktok(client_key: &str, client_secret: &str) -> Self {
        Self::tiktok_with_options(TikTokOptions::new(client_key, client_secret))
    }
    #[must_use]
    pub fn tiktok_with_options(options: TikTokOptions) -> Self {
        let endpoint = options
            .user_info_endpoint
            .unwrap_or_else(|| "https://open.tiktokapis.com/v2/user/info/".into());
        Self {
            client_id: options.client_key,
            client_secret: options.client_secret,
            additional_client_ids: Vec::new(),
            hosted_domain: None,
            require_email_verification: false,
            auth_url: "https://www.tiktok.com/v2/auth/authorize".into(),
            token_url: "https://open.tiktokapis.com/v2/oauth/token/".into(),
            user_info_url: Some(endpoint.clone()),
            scopes: vec!["user.info.profile".into()],
            authorization: Some(OAuthAuthorizationPolicy {
                client_id_parameter: "client_key".into(),
                scope_separator: ",".into(),
                emit_empty_scope: true,
                configured_scopes: options.scope,
                disable_default_scopes: options.disable_default_scope,
                redirect_uri: options.redirect_uri,
                pkce: false,
                authorization_code_pkce: Some(true),
                login_hint: false,
                token_endpoint_auth: Some(OAuthTokenEndpointAuth::ClientKeyPost),
                allow_missing_access_token: true,
                preserve_raw_email_errors: true,
                supports_profile_mapper: false,
                ..OAuthAuthorizationPolicy::default()
            }),
            authorization_params: Vec::new(),
            account_subject: Some(subject),
            map_user_info: None,
            get_user_info: Some(std::sync::Arc::new(TikTokProfile { endpoint })),
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
fn subject(profile: &Value) -> Result<String, String> {
    let id = super::remaining_profile::scalar(profile.pointer("/data/user/open_id"))?
        .ok_or("Missing TikTok open_id")?;
    if id.trim().is_empty() || matches!(id.as_str(), "null" | "undefined") {
        return Err("Invalid TikTok subject".into());
    }
    Ok(id)
}
struct TikTokProfile {
    endpoint: String,
}
#[async_trait::async_trait]
impl OAuthUserInfoHandler for TikTokProfile {
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        let profile: Value = reqwest::Client::new()
            .get(&self.endpoint)
            .query(&[("fields", "open_id,avatar_large_url,display_name,username")])
            .bearer_auth(request.access_token.as_deref().unwrap_or("undefined"))
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        let data = profile.pointer("/data/user").ok_or("Missing TikTok user")?;
        let raw_id = super::remaining_profile::scalar(data.get("open_id"))?.unwrap_or_else(|| {
            if data.get("open_id").is_some() {
                "null".into()
            } else {
                "undefined".into()
            }
        });
        let email = match data
            .get("email")
            .filter(|value| super::remaining_profile::truthy(value))
        {
            Some(email) => email.clone(),
            None => {
                let email = format!("{raw_id}@tiktok.placeholder.invalid");
                if !crate::plugins::authentication_helpers::is_valid_email(&email) {
                    return Err("Invalid TikTok placeholder email".into());
                }
                Value::String(email)
            }
        };
        let name = data
            .get("display_name")
            .filter(|value| super::remaining_profile::truthy(value))
            .or_else(|| {
                data.get("username")
                    .filter(|value| super::remaining_profile::truthy(value))
            })
            .cloned()
            .unwrap_or_else(|| Value::String(String::new()));
        let mut output = serde_json::Map::new();
        drop(output.insert("name".into(), name.clone()));
        drop(output.insert("email".into(), email.clone()));
        drop(output.insert("emailVerified".into(), Value::Bool(false)));
        if let Some(image) = data.get("avatar_large_url") {
            drop(output.insert("image".into(), image.clone()));
        }
        let user = OAuthUserInfo {
            additional_fields: Default::default(),
            id: raw_id,
            name: super::remaining_profile::scalar(Some(&name))?,
            email: email.as_str().unwrap_or_default().into(),
            image: super::remaining_profile::scalar(data.get("avatar_large_url"))?,
            email_verified: false,
        };
        Ok(OAuthUserInfoResponse {
            user_output: Some(output),
            user,
            data: profile,
        })
    }
}
