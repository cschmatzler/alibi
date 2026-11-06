//! `LinkedIn`'s non-PKCE grants and original subject with nullish email verification.
use super::{
    OAuthAuthorizationPolicy, OAuthProvider, OAuthTokenEndpointAuth, OAuthUserInfo,
    OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use async_trait::async_trait;
use serde_json::Map;
use serde_json::Value;

/// Application-owned `LinkedIn` configuration. Generic signup and asynchronous
/// user-info/refresh callbacks remain configurable on the returned provider.
#[derive(Clone)]
pub struct LinkedInOptions {
    pub client_id: String,
    pub client_secret: Option<String>,
    /// Sent only during authorization-code exchange.
    pub client_key: Option<String>,
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    pub authorization_endpoint: Option<String>,
    pub redirect_uri: Option<String>,
    /// Trusted transport override retaining `LinkedIn`'s actual GET and mapping.
    pub user_info_endpoint: Option<String>,
    /// Receives the original profile before its raw account identity is resolved.
    pub map_profile_to_user: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
}
impl LinkedInOptions {
    #[must_use]
    pub fn new(client_id: impl Into<String>, client_secret: Option<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret,
            client_key: None,
            scope: Vec::new(),
            disable_default_scope: false,
            authorization_endpoint: None,
            redirect_uri: None,
            user_info_endpoint: None,
            map_profile_to_user: None,
        }
    }
}
impl std::fmt::Debug for LinkedInOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LinkedInOptions")
            .field("client_id", &self.client_id)
            .field("scope", &self.scope)
            .field("disable_default_scope", &self.disable_default_scope)
            .field("authorization_endpoint", &self.authorization_endpoint)
            .field("redirect_uri", &self.redirect_uri)
            .finish_non_exhaustive()
    }
}
impl OAuthProvider {
    #[must_use]
    pub fn linkedin(client_id: &str, client_secret: Option<&str>) -> Self {
        Self::linkedin_with_options(LinkedInOptions::new(
            client_id,
            client_secret.map(str::to_owned),
        ))
    }
    #[must_use]
    pub fn linkedin_with_options(options: LinkedInOptions) -> Self {
        let secret = options.client_secret.unwrap_or_default();
        let authentication = if secret.is_empty() {
            OAuthTokenEndpointAuth::None
        } else {
            OAuthTokenEndpointAuth::ClientSecretPost
        };
        let endpoint = options
            .user_info_endpoint
            .unwrap_or_else(|| "https://api.linkedin.com/v2/userinfo".into());
        Self {
            client_id: options.client_id,
            client_secret: secret,
            additional_client_ids: Vec::new(),
            hosted_domain: None,
            require_email_verification: false,
            auth_url: options
                .authorization_endpoint
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "https://www.linkedin.com/oauth/v2/authorization".into()),
            token_url: "https://www.linkedin.com/oauth/v2/accessToken".into(),
            user_info_url: Some(endpoint.clone()),
            scopes: ["profile", "email", "openid"].map(String::from).to_vec(),
            authorization: Some(OAuthAuthorizationPolicy {
                source_profile_exceptions: true,
                configured_scopes: options.scope,
                disable_default_scopes: options.disable_default_scope,
                require_client_id: true,
                token_endpoint_auth: Some(authentication),
                authorization_code_client_key: options.client_key,
                redirect_uri: options.redirect_uri,
                login_hint: true,
                pkce: false,
                ..OAuthAuthorizationPolicy::default()
            }),
            allowed_request_params: Vec::new(),
            authorization_params: Vec::new(),
            account_subject: Some(subject),
            map_user_info: None,
            get_user_info: Some(std::sync::Arc::new(LinkedInUserInfo {
                endpoint,
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
#[derive(Clone)]
struct LinkedInUserInfo {
    endpoint: String,
    mapper: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
    application_mapper: Option<std::sync::Arc<dyn super::OAuthProfileMapper>>,
}
#[async_trait]
impl OAuthUserInfoHandler for LinkedInUserInfo {
    fn errors_are_exceptions(&self) -> bool {
        false
    }

    fn mapped_handler(
        &self,
        mapper: std::sync::Arc<dyn super::OAuthProfileMapper>,
    ) -> Option<std::sync::Arc<dyn OAuthUserInfoHandler>> {
        let mut handler = self.clone();
        handler.application_mapper = Some(mapper);
        Some(std::sync::Arc::new(handler))
    }

    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        let access_token = request
            .access_token
            .ok_or("Missing LinkedIn access token")?;
        let response: Value = reqwest::Client::new()
            .get(&self.endpoint)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|error| error.to_string())?
            .error_for_status()
            .map_err(|error| error.to_string())?
            .json()
            .await
            .map_err(|error| error.to_string())?;
        let profile = response;
        let mut output = Map::new();
        for (value, target) in [
            (profile.get("name"), "name"),
            (profile.get("email"), "email"),
            (profile.get("picture"), "image"),
        ] {
            if let Some(value) = value {
                _ = output.insert(target.into(), value.clone());
            }
        }
        _ = output.insert(
            "emailVerified".into(),
            profile
                .get("email_verified")
                .filter(|value| !value.is_null())
                .cloned()
                .unwrap_or(Value::Bool(false)),
        );
        if let Some(mapper) = self.mapper {
            output.extend(
                mapper(profile.clone())
                    .map_err(super::remaining_profile::profile_exception)?
                    .public_profile(true),
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
        if profile.is_null() {
            return Err(super::remaining_profile::profile_exception(
                "Null linkedin profile",
            ));
        }
        let mut response = OAuthUserInfoResponse {
            user_output: Some(output.clone()),
            user: OAuthUserInfo {
                additional_fields: Map::new(),
                id: super::remaining_profile::scalar(profile.get("sub"))?.unwrap_or_default(),
                name: None,
                email: String::new(),
                image: None,
                email_verified: false,
            },
            data: profile,
        };
        super::apply_application_mapping(&mut response, output)
            .map_err(super::remaining_profile::profile_exception)?;
        Ok(response)
    }
}
fn subject(profile: &Value) -> Result<String, String> {
    super::remaining_profile::raw_subject(profile.get("sub"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct PartialMapper(Value);
    #[async_trait]
    impl super::super::OAuthProfileMapper for PartialMapper {
        async fn map_profile(&self, profile: Value) -> Result<Map<String, Value>, String> {
            assert_eq!(profile, self.0);
            Ok(serde_json::from_value(serde_json::json!({
                "id": "public-id", "name": "Mapped", "custom": true
            }))
            .unwrap())
        }
    }

    #[tokio::test]
    async fn linkedin_http_partial_profile_mapping() {
        for mapped in [false, true] {
            let mut profile = serde_json::json!({"sub":"raw-id","name":"Original","handle":"Original","email":null,"profile_photo_url":null,"img_url":null,"picture":null,"profile_picture":null,"avatarUrl":null,"email_verified":"true"});
            if mapped {
                profile["name"] = serde_json::json!({"requiresMapping": true});
            }
            let body = (profile.clone()).to_string();
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
            let mut options = LinkedInOptions::new("client", Some("secret".into()));
            options.user_info_endpoint = Some(endpoint);
            let mut provider = OAuthProvider::linkedin_with_options(options);
            if mapped {
                provider = provider.with_profile_mapper(Arc::new(PartialMapper(profile.clone())));
            }
            let response = provider
                .get_user_info
                .as_ref()
                .unwrap()
                .get_user_info(OAuthUserInfoRequest {
                    access_token: Some("access".into()),
                    ..Default::default()
                })
                .await
                .unwrap();
            server.await.unwrap();
            assert_eq!(response.data, profile);
            assert_eq!(
                (provider.account_subject.unwrap())(&response.data).unwrap(),
                "raw-id"
            );
            let output = response.user_output.unwrap();
            assert_eq!(output.get("email"), Some(&Value::Null));
            assert_eq!(output.get("image"), Some(&Value::Null));
            assert_eq!(output["name"], if mapped { "Mapped" } else { "Original" });
            assert_eq!(
                response.user.name.as_deref(),
                Some(if mapped { "Mapped" } else { "Original" })
            );
            if mapped {
                assert_eq!(output["id"], "public-id");
                assert_eq!(output["custom"], true);
            } else {
                assert!(!output.contains_key("id"));
            }
        }
    }
}
