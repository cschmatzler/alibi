//! Kick's PKCE grants and first envelope profile bound by original `user_id`.
use super::{
    OAuthAuthorizationPolicy, OAuthProvider, OAuthTokenEndpointAuth, OAuthUserInfoHandler,
    OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use crate::oauth::providers::remaining_profile::ProfileResponseExt as _;
use alibi_core::utils::json::JsObject as Map;
use alibi_core::utils::json::{JsString, JsValue as Value};
use async_trait::async_trait;

/// Application-owned Kick configuration. Generic signup and asynchronous
/// user-info/refresh callbacks remain configurable on the returned provider.
#[derive(Clone)]
pub struct KickOptions {
    pub client_id: String,
    pub client_secret: Option<String>,
    /// Sent only during authorization-code exchange.
    pub client_key: Option<String>,
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    pub authorization_endpoint: Option<String>,
    pub redirect_uri: Option<String>,
    /// Trusted transport override retaining Kick's actual GET and mapping.
    pub user_info_endpoint: Option<String>,
    /// Receives the original profile before its raw account identity is resolved.
    pub map_profile_to_user: Option<fn(Value) -> Result<Map, String>>,
}
impl KickOptions {
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
impl std::fmt::Debug for KickOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KickOptions")
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
    pub fn kick(client_id: &str, client_secret: Option<&str>) -> Self {
        Self::kick_with_options(KickOptions::new(
            client_id,
            client_secret.map(str::to_owned),
        ))
    }
    #[must_use]
    pub fn kick_with_options(options: KickOptions) -> Self {
        let secret = options.client_secret.unwrap_or_default();
        let authentication = if secret.is_empty() {
            OAuthTokenEndpointAuth::None
        } else {
            OAuthTokenEndpointAuth::ClientSecretPost
        };
        let endpoint = options
            .user_info_endpoint
            .unwrap_or_else(|| "https://api.kick.com/public/v1/users".into());
        Self {
            client_id: options.client_id,
            client_secret: secret,
            additional_client_ids: Vec::new(),
            hosted_domain: None,
            require_email_verification: false,
            auth_url: options
                .authorization_endpoint
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "https://id.kick.com/oauth/authorize".into()),
            token_url: "https://id.kick.com/oauth/token".into(),
            user_info_url: Some(endpoint.clone()),
            scopes: vec!["user:read".into()],
            authorization: Some(OAuthAuthorizationPolicy {
                source_profile_exceptions: true,
                configured_scopes: options.scope,
                disable_default_scopes: options.disable_default_scope,
                require_client_id: true,
                token_endpoint_auth: Some(authentication),
                authorization_code_client_key: options.client_key,
                redirect_uri: options.redirect_uri,
                login_hint: false,
                ..OAuthAuthorizationPolicy::default()
            }),
            allowed_request_params: Vec::new(),
            authorization_params: Vec::new(),
            account_subject: Some(subject),
            map_user_info: None,
            get_user_info: Some(std::sync::Arc::new(KickUserInfo {
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
struct KickUserInfo {
    endpoint: String,
    mapper: Option<fn(Value) -> Result<Map, String>>,
    application_mapper: Option<std::sync::Arc<dyn super::OAuthProfileMapper>>,
}
#[async_trait]
impl OAuthUserInfoHandler for KickUserInfo {
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
        let access_token = request.access_token.ok_or("Missing Kick access token")?;
        let response: Value = reqwest::Client::new()
            .get(&self.endpoint)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|error| error.to_string())?
            .error_for_status()
            .map_err(|error| error.to_string())?
            .profile_json()
            .await
            .map_err(|error| error.to_string())?;
        let collection = response
            .property("data")
            .map_err(super::remaining_profile::profile_exception)?;
        let profile = collection
            .property("0")
            .map_err(super::remaining_profile::profile_exception)?;
        let mapped = self
            .mapper
            .map(|mapper| mapper(profile.clone()))
            .transpose()
            .map_err(super::remaining_profile::profile_exception)?;
        let application = if let Some(mapper) = &self.application_mapper {
            Some(
                mapper
                    .map_profile(profile.clone())
                    .await
                    .map_err(super::remaining_profile::profile_exception)?,
            )
        } else {
            None
        };
        let mut output = Map::new();
        for (source, target) in [
            ("name", "name"),
            ("email", "email"),
            ("profile_picture", "image"),
        ] {
            _ = output.insert(
                target.into(),
                profile
                    .property(source)
                    .map_err(super::remaining_profile::profile_exception)?,
            );
        }
        _ = output.insert("emailVerified".into(), Value::Bool(false));
        if let Some(mapped) = mapped {
            output.extend(mapped);
        }
        if let Some(mapped) = application {
            output.extend(mapped);
        }
        let response = OAuthUserInfoResponse {
            user: output,
            data: profile,
            account_subject: None,
        };
        Ok(response)
    }
}
fn subject(profile: &Value) -> Result<JsString, String> {
    super::remaining_profile::raw_subject(profile.get("user_id"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct ObservedMapper {
        expected: Value,
        reject: bool,
        calls: std::sync::atomic::AtomicUsize,
    }
    #[async_trait]
    impl super::super::OAuthProfileMapper for ObservedMapper {
        async fn map_profile(&self, profile: Value) -> Result<Map, String> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            assert_eq!(profile, self.expected);
            if self.reject {
                return Err("mapper rejected before property access".into());
            }
            Ok([("name".into(), Value::String("override".into()))]
                .into_iter()
                .collect())
        }
    }
    async fn fetch_observed(
        body: Value,
        mapper: Arc<ObservedMapper>,
    ) -> Result<OAuthUserInfoResponse, String> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 8192];
            stream.read(&mut request).await.unwrap();
            let body = body.to_string();
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        });
        let handler = KickUserInfo {
            endpoint,
            mapper: None,
            application_mapper: Some(mapper),
        };
        let result = handler
            .get_user_info(OAuthUserInfoRequest {
                access_token: Some("access".into()),
                ..Default::default()
            })
            .await;
        server.await.unwrap();
        result
    }
    #[tokio::test]
    async fn kick_missing_element_calls_mapper_before_property_error() {
        for collection in [
            Value::Array(vec![]),
            Value::Object(Map::new()),
            Value::String("".into()),
            Value::Bool(true),
        ] {
            let mapper = Arc::new(ObservedMapper {
                expected: Value::Undefined,
                reject: false,
                calls: Default::default(),
            });
            let error = fetch_observed(
                Value::Object([("data".into(), collection)].into_iter().collect()),
                mapper.clone(),
            )
            .await
            .unwrap_err();
            assert!(error.contains("Cannot read properties"), "{error}");
            assert_eq!(mapper.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        }
    }
    #[tokio::test]
    async fn kick_mapper_rejection_wins_over_missing_profile_property_error() {
        let mapper = Arc::new(ObservedMapper {
            expected: Value::Undefined,
            reject: true,
            calls: Default::default(),
        });
        let error = fetch_observed(crate::oauth::providers::js!({"data":[]}), mapper.clone())
            .await
            .unwrap_err();
        assert!(
            error.contains("mapper rejected before property access"),
            "{error}"
        );
        assert!(!error.contains("Cannot read properties"));
        assert_eq!(mapper.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn kick_nullish_collection_fails_before_mapper() {
        for body in [
            crate::oauth::providers::js!({}),
            crate::oauth::providers::js!({"data":null}),
            Value::Null,
        ] {
            let mapper = Arc::new(ObservedMapper {
                expected: Value::Undefined,
                reject: true,
                calls: Default::default(),
            });
            let error = fetch_observed(body, mapper.clone()).await.unwrap_err();
            assert!(error.contains("Cannot read properties"), "{error}");
            assert_eq!(mapper.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        }
    }
    #[tokio::test]
    async fn kick_string_collection_passes_own_utf16_index_and_undefined_fields() {
        let unit = JsString::from_code_units(vec![0xd83d]);
        let mapper = Arc::new(ObservedMapper {
            expected: Value::String(unit.clone()),
            reject: false,
            calls: Default::default(),
        });
        let response = fetch_observed(crate::oauth::providers::js!({"data":"😀"}), mapper.clone())
            .await
            .unwrap();
        assert_eq!(response.data, Value::String(unit));
        assert_eq!(response.user.get("email"), Some(&Value::Undefined));
        assert_eq!(response.user.get("image"), Some(&Value::Undefined));
        assert_eq!(response.user["name"], "override");
        assert_eq!(mapper.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    struct PartialMapper(Value);
    #[async_trait]
    impl super::super::OAuthProfileMapper for PartialMapper {
        async fn map_profile(&self, profile: Value) -> Result<Map, String> {
            assert_eq!(profile, self.0);
            Ok(
                alibi_core::utils::json::from_value(crate::oauth::providers::js!({
                    "id": "public-id", "name": "Mapped", "custom": true
                }))
                .unwrap(),
            )
        }
    }

    #[tokio::test]
    async fn kick_http_partial_profile_mapping() {
        for mapped in [false, true] {
            let mut profile = crate::oauth::providers::js!({"user_id":"raw-id","name":"Original","handle":"Original","email":null,"profile_photo_url":null,"img_url":null,"picture":null,"profile_picture":null,"avatarUrl":null,"email_verified":"true"});
            if mapped {
                profile["name"] = crate::oauth::providers::js!({"requiresMapping": true});
            }
            let body = (crate::oauth::providers::js!({"data": [profile.clone()]})).to_string();
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
            let mut options = KickOptions::new("client", Some("secret".into()));
            options.user_info_endpoint = Some(endpoint);
            let mut provider = OAuthProvider::kick_with_options(options);
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
            let output = response.user.clone();
            assert_eq!(output.get("email"), Some(&Value::Null));
            assert_eq!(output.get("image"), Some(&Value::Null));
            assert_eq!(output["name"], if mapped { "Mapped" } else { "Original" });
            assert_eq!(
                response.user.get("name").and_then(Value::as_str),
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
