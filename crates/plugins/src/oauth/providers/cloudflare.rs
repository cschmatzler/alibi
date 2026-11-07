//! Cloudflare's API profile, scope ordering and OAuth credential transport.
use super::{OAuthAuthorizationPolicy, OAuthProvider, OAuthTokenEndpointAuth};
use crate::oauth::providers::remaining_profile::ProfileResponseExt as _;
use alibi_core::utils::json::JsObject as Map;
use alibi_core::utils::json::{JsString, JsValue as Value};

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
    pub token_endpoint_auth: Option<OAuthTokenEndpointAuth>,
    /// Trusted transport override, retaining Cloudflare's API envelope mapping.
    pub user_info_endpoint: Option<String>,
    /// Receives the original API result. Its ID cannot replace the raw subject.
    pub map_profile_to_user: Option<fn(Value) -> Result<Map, String>>,
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
            token_endpoint_auth: None,
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
        let authentication = options
            .token_endpoint_auth
            .or(options.token_endpoint_auth_method)
            .unwrap_or({
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
                source_profile_exceptions: true,
                configured_scopes: options.scope,
                disable_default_scopes: options.disable_default_scope,
                deduplicate_scopes: true,
                require_client_id: true,
                token_endpoint_auth: Some(authentication),
                redirect_uri: options.redirect_uri,
                login_hint: false,
                ..OAuthAuthorizationPolicy::default()
            }),
            allowed_request_params: Vec::new(),
            authorization_params: Vec::new(),
            account_subject: Some(subject),
            map_user_info: None,
            get_user_info: Some(std::sync::Arc::new(CloudflareUserInfo {
                url: user_info_url,
                mapper: options.map_profile_to_user,
                application_mapper: None,
            })),
            refresh_access_token: None,
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
fn truthy(value: &Value) -> bool {
    value.is_truthy()
}
fn subject(profile: &Value) -> Result<JsString, String> {
    super::remaining_profile::raw_subject(profile.get("id"))
}
#[derive(Clone)]
struct CloudflareUserInfo {
    url: String,
    mapper: Option<fn(Value) -> Result<Map, String>>,
    application_mapper: Option<std::sync::Arc<dyn super::OAuthProfileMapper>>,
}
#[async_trait::async_trait]
impl super::OAuthUserInfoHandler for CloudflareUserInfo {
    fn errors_are_exceptions(&self) -> bool {
        false
    }

    fn mapped_handler(
        &self,
        mapper: std::sync::Arc<dyn super::OAuthProfileMapper>,
    ) -> Option<std::sync::Arc<dyn super::OAuthUserInfoHandler>> {
        let mut handler = self.clone();
        handler.application_mapper = Some(mapper);
        Some(std::sync::Arc::new(handler))
    }

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
        let envelope: Value = response
            .profile_json()
            .await
            .map_err(|error| error.to_string())?;
        if !envelope.get("success").is_some_and(truthy)
            || !envelope.get("result").is_some_and(truthy)
        {
            return Err("Cloudflare API rejected user info".into());
        }
        let profile = envelope
            .get("result")
            .ok_or("Missing Cloudflare API result")?;
        let names = ["first_name", "last_name"]
            .into_iter()
            .filter_map(|key| profile.get(key))
            .filter(|value| truthy(value))
            .map(super::remaining_profile::js_string)
            .collect::<Result<Vec<_>, _>>()
            .map_err(super::remaining_profile::profile_exception)?;
        let name = names
            .into_iter()
            .reduce(|name, next| name.concat(&" ".into()).concat(&next))
            .unwrap_or_default();
        let mut output = Map::new();
        _ = output.insert(
            "name".into(),
            if name.is_empty() {
                profile.get("email").cloned().unwrap_or(Value::Undefined)
            } else {
                Value::String(name)
            },
        );
        _ = output.insert(
            "email".into(),
            profile.get("email").cloned().unwrap_or(Value::Undefined),
        );
        _ = output.insert("emailVerified".into(), Value::Bool(false));
        if let Some(mapper) = self.mapper {
            output.extend(
                mapper(profile.clone()).map_err(super::remaining_profile::profile_exception)?,
            );
        }
        if let Some(mapper) = &self.application_mapper {
            output.extend(
                mapper
                    .map_profile(profile.clone())
                    .await
                    .map_err(super::remaining_profile::profile_exception)?,
            );
        }
        let mut response = super::OAuthUserInfoResponse {
            user: output.clone(),
            data: profile.clone(),
            account_subject: None,
        };
        super::apply_application_mapping(&mut response, output)
            .map_err(super::remaining_profile::profile_exception)?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Mapper;
    #[async_trait::async_trait]
    impl super::super::OAuthProfileMapper for Mapper {
        async fn map_profile(&self, profile: Value) -> Result<Map, String> {
            assert_eq!(profile["id"], "cf-id");
            assert!(profile.get("result").is_none());
            Ok(
                crate::oauth::providers::js!({"name":"Mapped","custom":true})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
        }
    }
    #[tokio::test]
    async fn cloudflare_maps_unwrapped_result_with_partial_defaults() {
        let body =
            crate::oauth::providers::js!({"success":true,"result":{"id":"cf-id","email":null}});

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let body = body.to_string();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 8192];
            let _ = stream.read(&mut request).await.unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        let mut options = CloudflareOptions::new("client", None);
        options.user_info_endpoint = Some(endpoint);
        let provider = OAuthProvider::cloudflare_with_options(options)
            .with_profile_mapper(std::sync::Arc::new(Mapper));
        let response = provider
            .get_user_info
            .unwrap()
            .get_user_info(super::super::OAuthUserInfoRequest {
                access_token: Some("access".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        let output = response.user.clone();
        assert_eq!(output["name"], "Mapped");
        assert_eq!(output["email"], Value::Null);
        assert_eq!(output["emailVerified"], false);
        assert_eq!(output["custom"], true);
        assert!(!output.contains_key("image"));
        assert!(!output.contains_key("id"));
        server.await.unwrap();
    }
    #[tokio::test]
    async fn cloudflare_string_coerces_truthy_name_parts() {
        let body = crate::oauth::providers::js!({"success":true,"result":{"id":"cf-id","first_name":["Cloud","Flare"],"last_name":true,"email":"fallback@example.com"}});

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let body = body.to_string();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 8192];
            let _ = stream.read(&mut request).await.unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        let mut options = CloudflareOptions::new("client", Some("secret".into()));
        options.user_info_endpoint = Some(endpoint);
        let provider = OAuthProvider::cloudflare_with_options(options);
        let response = provider
            .get_user_info
            .unwrap()
            .get_user_info(super::super::OAuthUserInfoRequest {
                access_token: Some("access".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            response.user.get("name").and_then(Value::as_str),
            Some("Cloud,Flare true")
        );
        server.await.unwrap();
    }
}
