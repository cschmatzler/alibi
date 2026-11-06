//! `WeChat` website-app grants use GET and carry openid into userinfo.
use super::{
    OAuthAuthorizationCodeCallback, OAuthAuthorizationCodeContext, OAuthAuthorizationCodeHandler,
    OAuthAuthorizationPolicy, OAuthProvider, OAuthRefreshTokenHandler, OAuthTokenSet,
    OAuthUserInfo, OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use serde_json::Map;
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
    /// Trusted transport overrides retaining `WeChat` GET/query contracts.
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
            client_ids: vec![options.client_id.clone()],
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
                preserve_raw_profile_scalars: true,
                source_profile_exceptions: true,
                allow_missing_access_token: true,
                authorization_code: Some(OAuthAuthorizationCodeCallback(grants.clone())),
                client_id_parameter: "appid".into(),
                token_expiry_always: true,
                token_response_omits_id_token: true,
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
            allowed_request_params: Vec::new(),
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
                application_mapper: None,
                endpoint,
                mapper: options.map_profile_to_user,
            })),
            refresh_access_token: Some(grants),
            verify_id_token: None,
            id_token: None,
            disable_id_token_sign_in: false,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            allow_idp_initiated: false,
            override_user_info_on_sign_in: false,
        }
    }
}
#[derive(Clone)]
struct WeChatGrants {
    client_ids: Vec<String>,
    client_secret: String,
    token_endpoint: String,
    refresh_endpoint: String,
}
async fn token_request(
    endpoint: &str,
    client_ids: &[String],
    query: &[(&str, &str)],
) -> Result<OAuthTokenSet, String> {
    let appid = client_ids.join(",");
    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| error.to_string())?
        .get(endpoint)
        .query(&[("appid", appid.as_str())])
        .query(query)
        .send()
        .await
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?;
    if response.status().is_redirection() {
        return Err("WeChat token request refused a redirect".into());
    }
    let raw: Value = response.json().await.map_err(|e| e.to_string())?;
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
    fn configured_client_ids(
        &self,
        ids: &[String],
    ) -> Option<Arc<dyn OAuthAuthorizationCodeHandler>> {
        let mut handler = self.clone();
        handler.client_ids = ids.to_vec();
        Some(Arc::new(handler))
    }
    async fn validate_authorization_code(
        &self,
        context: OAuthAuthorizationCodeContext,
    ) -> Result<OAuthTokenSet, String> {
        token_request(
            &self.token_endpoint,
            &self.client_ids,
            &[
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
    fn configured_client_ids(&self, ids: &[String]) -> Option<Arc<dyn OAuthRefreshTokenHandler>> {
        let mut handler = self.clone();
        handler.client_ids = ids.to_vec();
        Some(Arc::new(handler))
    }
    async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuthTokenSet, String> {
        let mut tokens = token_request(
            &self.refresh_endpoint,
            &self.client_ids,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
            ],
        )
        .await?;
        if let Some(Value::Object(raw)) = &mut tokens.raw {
            _ = raw.remove("openid");
            _ = raw.remove("unionid");
        }
        Ok(tokens)
    }
}
#[derive(Clone)]
struct WeChatProfile {
    application_mapper: Option<Arc<dyn super::OAuthProfileMapper>>,
    endpoint: String,
    mapper: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
}
#[async_trait::async_trait]
impl OAuthUserInfoHandler for WeChatProfile {
    fn errors_are_exceptions(&self) -> bool {
        false
    }

    fn mapped_handler(
        &self,
        mapper: Arc<dyn super::OAuthProfileMapper>,
    ) -> Option<Arc<dyn OAuthUserInfoHandler>> {
        let mut handler = self.clone();
        handler.mapper = None;
        handler.application_mapper = Some(mapper);
        Some(Arc::new(handler))
    }

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
        let openid = super::remaining_profile::js_string(openid)
            .map_err(super::remaining_profile::profile_exception)?;
        let access_token = if super::remaining_profile::has_access_token(&request) {
            super::remaining_profile::bearer_access_token(&request)
                .map_err(super::remaining_profile::profile_exception)?
        } else {
            String::new()
        };
        let profile: Value = reqwest::Client::new()
            .get(&self.endpoint)
            .query(&[
                ("access_token", access_token.as_str()),
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
        let application_output = if let Some(mapper) = &self.application_mapper {
            Some(
                mapper
                    .map_profile(profile.clone())
                    .await
                    .map_err(super::remaining_profile::profile_exception)?,
            )
        } else {
            None
        };
        let mapped = self
            .mapper
            .map(|mapper| mapper(profile.clone()))
            .transpose()
            .map_err(super::remaining_profile::profile_exception)?;
        let raw_id = profile
            .get("unionid")
            .filter(|v| super::remaining_profile::truthy(v))
            .or_else(|| {
                profile
                    .get("openid")
                    .filter(|v| super::remaining_profile::truthy(v))
            });
        let id = raw_id
            .map(super::remaining_profile::js_string)
            .transpose()
            .map_err(super::remaining_profile::profile_exception)?
            .unwrap_or(openid);
        let email = if let Some(value) = profile
            .get("email")
            .filter(|value| super::remaining_profile::truthy(value))
        {
            value.clone()
        } else {
            let email = format!("{id}@wechat.placeholder.invalid");
            if !crate::authentication_helpers::is_valid_email(&email) {
                return Err(super::remaining_profile::profile_exception(
                    "Invalid WeChat placeholder email",
                ));
            }
            Value::String(email)
        };
        let mut output = serde_json::Map::new();
        for (key, field) in [("name", "nickname"), ("image", "headimgurl")] {
            if let Some(value) = profile.get(field) {
                _ = output.insert(key.into(), value.clone());
            }
        }
        _ = output.insert("email".into(), email.clone());
        _ = output.insert("emailVerified".into(), Value::Bool(false));
        if let Some(user) = &mapped {
            output.extend(user.public_profile(true));
        }
        let user = match mapped {
            Some(user) => user,
            None => OAuthUserInfo {
                additional_fields: Map::default(),
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
        let mut response = OAuthUserInfoResponse {
            user_output: Some(output),
            user,
            data: profile,
        };
        if let Some(mapped) = application_output {
            super::apply_application_mapping(&mut response, mapped)?;
        }
        Ok(response)
    }
}
fn subject(profile: &Value) -> Result<String, String> {
    let value = profile
        .get("unionid")
        .filter(|value| super::remaining_profile::truthy(value))
        .or_else(|| profile.get("openid"));
    super::remaining_profile::raw_subject(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn profile_server(profile: Value) -> (String, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let request = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut buffer = [0; 1024];
                let count = stream.read(&mut buffer).await.unwrap();
                assert_ne!(count, 0);
                request.extend_from_slice(&buffer[..count]);
                if request.windows(4).any(|part| part == b"\r\n\r\n") {
                    break;
                }
            }
            let body = profile.to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8(request).unwrap()
        });
        (endpoint, request)
    }

    #[tokio::test]
    async fn wechat_refresh_does_not_publish_code_grant_identity() {
        for refresh in [false, true] {
            let (endpoint, captured) = profile_server(json!({"scope": "snsapi_login", "access_token": "access", "refresh_token": "next", "openid": "openid", "unionid": "unionid", "expires_in": 3600})).await;
            let grants = WeChatGrants {
                client_ids: vec!["client".into()],
                client_secret: "secret".into(),
                token_endpoint: endpoint.clone(),
                refresh_endpoint: endpoint,
            };
            let tokens = if refresh {
                grants.refresh_access_token("refresh").await.unwrap()
            } else {
                grants
                    .validate_authorization_code(OAuthAuthorizationCodeContext {
                        code: "code".into(),
                        redirect_uri: String::new(),
                        code_verifier: None,
                        device_id: None,
                    })
                    .await
                    .unwrap()
            };
            captured.await.unwrap();
            assert_eq!(tokens.access_token.as_deref(), Some("access"));
            assert_eq!(tokens.refresh_token.as_deref(), Some("next"));
            assert_eq!(tokens.scopes, ["snsapi_login"]);
            let raw = tokens.raw.unwrap();
            assert_eq!(raw.get("openid").is_some(), !refresh);
            assert_eq!(raw.get("unionid").is_some(), !refresh);
        }
    }

    #[tokio::test]
    async fn wechat_grants_stringify_client_arrays_as_one_appid() {
        for ids in [vec!["first".into(), "second".into()], Vec::new()] {
            for refresh in [false, true] {
                let (endpoint, captured) = profile_server(
                    json!({"scope": "snsapi_login", "access_token": "access", "expires_in": 3600}),
                )
                .await;
                let grants = WeChatGrants {
                    client_ids: ids.clone(),
                    client_secret: "secret".into(),
                    token_endpoint: endpoint.clone(),
                    refresh_endpoint: endpoint,
                };
                if refresh {
                    grants.refresh_access_token("refresh").await.unwrap();
                } else {
                    grants
                        .validate_authorization_code(OAuthAuthorizationCodeContext {
                            code: "code".into(),
                            redirect_uri: "https://app.example/callback".into(),
                            code_verifier: None,
                            device_id: None,
                        })
                        .await
                        .unwrap();
                }
                let request = captured.await.unwrap();
                let target = request
                    .lines()
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap();
                let url = reqwest::Url::parse(&format!("http://localhost{target}")).unwrap();
                let appids: Vec<_> = url
                    .query_pairs()
                    .filter(|(key, _)| key == "appid")
                    .map(|(_, value)| value.into_owned())
                    .collect();
                assert_eq!(appids, vec![ids.join(",")]);
            }
        }
    }

    #[tokio::test]
    async fn wechat_userinfo_allows_missing_access_token_with_openid() {
        assert!(
            OAuthProvider::wechat("client", "secret")
                .authorization
                .unwrap()
                .allow_missing_access_token
        );
        let (endpoint, captured) =
            profile_server(json!({"openid": "openid", "nickname": "name"})).await;
        let response = WeChatProfile {
            endpoint,
            mapper: None,
            application_mapper: None,
        }
        .get_user_info(OAuthUserInfoRequest {
            raw: Some(json!({"openid": "openid"})),
            ..OAuthUserInfoRequest::default()
        })
        .await
        .unwrap();
        let captured = captured.await.unwrap();
        assert!(
            captured.starts_with("GET /?access_token=&openid=openid&lang=zh_CN HTTP/1.1"),
            "{captured}"
        );
        assert_eq!(response.user.email, "openid@wechat.placeholder.invalid");
    }
}
