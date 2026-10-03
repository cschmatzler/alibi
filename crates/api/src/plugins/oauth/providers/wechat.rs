//! WeChat website-app grants use GET and carry openid into userinfo.
use super::{
    OAuthAuthorizationCodeCallback, OAuthAuthorizationCodeContext, OAuthAuthorizationCodeHandler,
    OAuthAuthorizationPolicy, OAuthProvider, OAuthRefreshTokenHandler, OAuthTokenSet,
    OAuthUserInfo, OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use serde_json::Value;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum WeChatLanguage {
    #[default]
    Chinese,
    English,
}
#[derive(Clone)]
pub struct WeChatOptions {
    pub client_id: String,
    pub client_secret: String,
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    pub redirect_uri: Option<String>,
    pub language: WeChatLanguage,
    /// Trusted transport overrides retaining WeChat GET/query contracts.
    pub token_endpoint: Option<String>,
    pub refresh_endpoint: Option<String>,
    pub user_info_endpoint: Option<String>,
    pub map_profile_to_user: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
}
impl WeChatOptions {
    #[must_use]
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            scope: Vec::new(),
            disable_default_scope: false,
            redirect_uri: None,
            language: WeChatLanguage::Chinese,
            token_endpoint: None,
            refresh_endpoint: None,
            user_info_endpoint: None,
            map_profile_to_user: None,
        }
    }
}
impl std::fmt::Debug for WeChatOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WeChatOptions")
            .field("client_id", &self.client_id)
            .field("language", &self.language)
            .finish_non_exhaustive()
    }
}
impl OAuthProvider {
    #[must_use]
    pub fn wechat(client_id: &str, client_secret: &str) -> Self {
        Self::wechat_with_options(WeChatOptions::new(client_id, client_secret))
    }
    #[must_use]
    pub fn wechat_with_options(options: WeChatOptions) -> Self {
        let token_endpoint = options
            .token_endpoint
            .unwrap_or_else(|| "https://api.weixin.qq.com/sns/oauth2/access_token".into());
        let refresh_endpoint = options
            .refresh_endpoint
            .unwrap_or_else(|| "https://api.weixin.qq.com/sns/oauth2/refresh_token".into());
        let endpoint = options
            .user_info_endpoint
            .unwrap_or_else(|| "https://api.weixin.qq.com/sns/userinfo".into());
        let grants = Arc::new(WeChatGrants {
            client_id: options.client_id.clone(),
            client_secret: options.client_secret.clone(),
            token_endpoint: token_endpoint.clone(),
            refresh_endpoint,
        });
        Self {
            client_id: options.client_id,
            client_secret: options.client_secret,
            additional_client_ids: Vec::new(),
            hosted_domain: None,
            require_email_verification: false,
            auth_url: "https://open.weixin.qq.com/connect/qrconnect".into(),
            token_url: token_endpoint,
            user_info_url: Some(endpoint.clone()),
            scopes: vec!["snsapi_login".into()],
            authorization: Some(OAuthAuthorizationPolicy {
                authorization_code: Some(OAuthAuthorizationCodeCallback(grants.clone())),
                client_id_parameter: "appid".into(),
                scope_separator: ",".into(),
                emit_empty_scope: true,
                authorization_fragment: Some("wechat_redirect".into()),
                configured_scopes: options.scope,
                disable_default_scopes: options.disable_default_scope,
                redirect_uri: options.redirect_uri,
                pkce: false,
                login_hint: false,
                preserve_raw_email_errors: true,
                ..OAuthAuthorizationPolicy::default()
            }),
            authorization_params: vec![(
                "lang".into(),
                match options.language {
                    WeChatLanguage::Chinese => "cn",
                    WeChatLanguage::English => "en",
                }
                .into(),
            )],
            account_subject: Some(subject),
            map_user_info: None,
            get_user_info: Some(Arc::new(WeChatProfile {
                endpoint,
                mapper: options.map_profile_to_user,
            })),
            refresh_access_token: Some(grants),
            verify_id_token: None,
            id_token: None,
            disable_id_token_sign_in: false,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            override_user_info_on_sign_in: false,
        }
    }
}
struct WeChatGrants {
    client_id: String,
    client_secret: String,
    token_endpoint: String,
    refresh_endpoint: String,
}
async fn token_request(endpoint: &str, query: &[(&str, &str)]) -> Result<OAuthTokenSet, String> {
    let raw: Value = reqwest::Client::new()
        .get(endpoint)
        .query(query)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    if !super::remaining_profile::truthy(&raw)
        || raw
            .get("errcode")
            .is_some_and(super::remaining_profile::truthy)
    {
        return Err("WeChat token request failed".into());
    }
    let scope = raw
        .get("scope")
        .and_then(Value::as_str)
        .ok_or("Missing WeChat token scope")?;
    let expiry = raw
        .get("expires_in")
        .and_then(|value| super::remaining_profile::grant_expiry(value, false));
    Ok(OAuthTokenSet {
        token_type: Some("Bearer".into()),
        access_token: raw
            .get("access_token")
            .and_then(Value::as_str)
            .map(str::to_owned),
        refresh_token: raw
            .get("refresh_token")
            .and_then(Value::as_str)
            .map(str::to_owned),
        access_token_expires_at: expiry,
        refresh_token_expires_at: None,
        scopes: scope.split(',').map(str::to_owned).collect(),
        id_token: None,
        raw: Some(raw),
    })
}
#[async_trait::async_trait]
impl OAuthAuthorizationCodeHandler for WeChatGrants {
    async fn validate_authorization_code(
        &self,
        context: OAuthAuthorizationCodeContext,
    ) -> Result<OAuthTokenSet, String> {
        token_request(
            &self.token_endpoint,
            &[
                ("appid", &self.client_id),
                ("secret", &self.client_secret),
                ("code", &context.code),
                ("grant_type", "authorization_code"),
            ],
        )
        .await
    }
}
#[async_trait::async_trait]
impl OAuthRefreshTokenHandler for WeChatGrants {
    async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuthTokenSet, String> {
        token_request(
            &self.refresh_endpoint,
            &[
                ("appid", &self.client_id),
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
            ],
        )
        .await
    }
}
struct WeChatProfile {
    endpoint: String,
    mapper: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
}
#[async_trait::async_trait]
impl OAuthUserInfoHandler for WeChatProfile {
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        let openid = request
            .raw
            .as_ref()
            .and_then(|raw| raw.get("openid"))
            .filter(|value| super::remaining_profile::truthy(value))
            .ok_or("Missing WeChat token openid")?;
        let openid =
            super::remaining_profile::scalar(Some(openid))?.ok_or("Invalid WeChat token openid")?;
        let profile: Value = reqwest::Client::new()
            .get(&self.endpoint)
            .query(&[
                (
                    "access_token",
                    request.access_token.as_deref().unwrap_or_default(),
                ),
                ("openid", openid.as_str()),
                ("lang", "zh_CN"),
            ])
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        if !super::remaining_profile::truthy(&profile)
            || profile
                .get("errcode")
                .is_some_and(super::remaining_profile::truthy)
        {
            return Err("Missing WeChat profile".into());
        }
        let mapped = self
            .mapper
            .map(|mapper| mapper(profile.clone()))
            .transpose()?;
        let raw_id = profile
            .get("unionid")
            .filter(|v| super::remaining_profile::truthy(v))
            .or_else(|| {
                profile
                    .get("openid")
                    .filter(|v| super::remaining_profile::truthy(v))
            });
        let id = super::remaining_profile::scalar(raw_id)?.unwrap_or(openid);
        let email = match profile
            .get("email")
            .filter(|value| super::remaining_profile::truthy(value))
        {
            Some(value) => value.clone(),
            None => {
                let email = format!("{id}@wechat.placeholder.invalid");
                if !crate::plugins::authentication_helpers::is_valid_email(&email) {
                    return Err("Invalid WeChat placeholder email".into());
                }
                Value::String(email)
            }
        };
        let mut output = serde_json::Map::new();
        for (key, field) in [("name", "nickname"), ("image", "headimgurl")] {
            if let Some(value) = profile.get(field) {
                drop(output.insert(key.into(), value.clone()));
            }
        }
        drop(output.insert("email".into(), email.clone()));
        drop(output.insert("emailVerified".into(), Value::Bool(false)));
        if let Some(user) = &mapped {
            output.extend(user.public_profile(true));
        }
        let user = match mapped {
            Some(user) => user,
            None => OAuthUserInfo {
                additional_fields: Default::default(),
                id,
                name: super::remaining_profile::scalar(
                    profile
                        .get("nickname")
                        .filter(|v| super::remaining_profile::truthy(v)),
                )?,
                email: email.as_str().unwrap_or_default().into(),
                image: super::remaining_profile::scalar(profile.get("headimgurl"))?,
                email_verified: false,
            },
        };
        Ok(OAuthUserInfoResponse {
            user_output: Some(output),
            user,
            data: profile,
        })
    }
}
fn subject(profile: &Value) -> Result<String, String> {
    let value = profile
        .get("unionid")
        .filter(|value| super::remaining_profile::truthy(value))
        .or_else(|| profile.get("openid"));
    super::remaining_profile::raw_subject(value)
}
