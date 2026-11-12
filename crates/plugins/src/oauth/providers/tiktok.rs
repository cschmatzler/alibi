//! `TikTok`'s client-key grants, comma-separated scopes and nested profile.
use super::{
    OAuthAuthorizationPolicy, OAuthProvider, OAuthTokenEndpointAuth, OAuthUserInfoHandler,
    OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use alibi_core::utils::json::JsObject as Map;
use alibi_core::utils::json::{JsString, JsValue as Value};

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
            auth_url: "https://www.tiktok.com/v2/auth/authorize".into(),
            token_url: "https://open.tiktokapis.com/v2/oauth/token/".into(),
            user_info_url: Some(endpoint.clone()),
            scopes: vec!["user.info.profile".into()],
            authorization: Some(OAuthAuthorizationPolicy {
                preserve_raw_profile_scalars: true,
                source_profile_exceptions: true,
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
            account_subject: Some(subject),
            get_user_info: Some(std::sync::Arc::new(TikTokProfile { endpoint })),
            ..Self::default()
        }
    }
}
fn subject(profile: &Value) -> Result<JsString, String> {
    super::remaining_profile::raw_subject(profile.pointer("/data/user/open_id"))
}
struct TikTokProfile {
    endpoint: String,
}
#[async_trait::async_trait]
impl OAuthUserInfoHandler for TikTokProfile {
    fn errors_are_exceptions(&self) -> bool {
        false
    }

    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        let profile: Value = super::remaining_profile::send_profile_json(
            reqwest::Client::new()
                .get(&self.endpoint)
                .query(&[("fields", "open_id,avatar_large_url,display_name,username")])
                .bearer_auth(super::remaining_profile::bearer_access_token(&request)?),
        )
        .await?;
        let data = profile
            .pointer("/data/user")
            .filter(|value| !value.is_null())
            .ok_or_else(|| super::remaining_profile::profile_exception("Missing TikTok user"))?;
        let raw_id = data
            .get("open_id")
            .map(super::remaining_profile::js_string)
            .transpose()
            .map_err(super::remaining_profile::profile_exception)?
            .unwrap_or_else(|| "undefined".into());
        let email = if let Some(email) = data
            .get("email")
            .filter(|value| super::remaining_profile::truthy(value))
        {
            email.clone()
        } else {
            let email = raw_id.concat(&"@tiktok.placeholder.invalid".into());
            if !email
                .as_str()
                .is_some_and(crate::authentication_helpers::is_valid_email)
            {
                return Err(super::remaining_profile::profile_exception(
                    "Invalid TikTok placeholder email",
                ));
            }
            Value::String(email.into())
        };
        let name = data
            .get("display_name")
            .filter(|value| super::remaining_profile::truthy(value))
            .or_else(|| {
                data.get("username")
                    .filter(|value| super::remaining_profile::truthy(value))
            })
            .cloned()
            .unwrap_or_else(|| Value::String(String::new().into()));
        let mut output = Map::new();
        _ = output.insert("email".into(), email.clone());
        _ = output.insert("name".into(), name.clone());
        _ = output.insert(
            "image".into(),
            data.get("avatar_large_url")
                .cloned()
                .unwrap_or(Value::Undefined),
        );
        _ = output.insert("emailVerified".into(), Value::Bool(false));
        Ok(OAuthUserInfoResponse {
            user: output,
            data: profile,
            account_subject: None,
        })
    }
}
