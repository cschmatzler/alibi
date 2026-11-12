//! Hugging Face's ordered OIDC scopes, profile fallback and raw subject identity.
use super::remaining_profile::truthy;
use super::{
    OAuthAuthorizationPolicy, OAuthProvider, OAuthTokenEndpointAuth, OAuthUserInfoHandler,
    OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use crate::oauth::providers::remaining_profile::ProfileResponseExt as _;
use alibi_core::utils::json::JsObject as Map;
use alibi_core::utils::json::{JsString, JsValue as Value};
use async_trait::async_trait;

/// Application-owned `HuggingFace` configuration. Generic signup and asynchronous
/// user-info/refresh callbacks remain configurable on the returned provider.
#[derive(Clone, Default)]
pub struct HuggingFaceOptions {
    pub client_id: String,
    pub client_secret: Option<String>,
    /// Sent only during authorization-code exchange.
    pub client_key: Option<String>,
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    pub authorization_endpoint: Option<String>,
    pub redirect_uri: Option<String>,
    /// Trusted transport override retaining Hugging Face's actual GET and mapping.
    pub user_info_endpoint: Option<String>,
    /// Receives the original profile before its raw account identity is resolved.
    pub map_profile_to_user: Option<fn(Value) -> Result<Map, String>>,
}
impl HuggingFaceOptions {
    #[must_use]
    pub fn new(client_id: impl Into<String>, client_secret: Option<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret,
            ..Self::default()
        }
    }
}
impl std::fmt::Debug for HuggingFaceOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HuggingFaceOptions")
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
    pub fn huggingface(client_id: &str, client_secret: Option<&str>) -> Self {
        Self::huggingface_with_options(HuggingFaceOptions::new(
            client_id,
            client_secret.map(str::to_owned),
        ))
    }
    #[must_use]
    pub fn huggingface_with_options(options: HuggingFaceOptions) -> Self {
        let secret = options.client_secret.unwrap_or_default();
        let authentication = if secret.is_empty() {
            OAuthTokenEndpointAuth::None
        } else {
            OAuthTokenEndpointAuth::ClientSecretPost
        };
        let endpoint = options
            .user_info_endpoint
            .unwrap_or_else(|| "https://huggingface.co/oauth/userinfo".into());
        Self {
            client_id: options.client_id,
            client_secret: secret,
            auth_url: options
                .authorization_endpoint
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "https://huggingface.co/oauth/authorize".into()),
            token_url: "https://huggingface.co/oauth/token".into(),
            user_info_url: Some(endpoint.clone()),
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
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
            account_subject: Some(subject),
            get_user_info: Some(std::sync::Arc::new(HuggingFaceUserInfo {
                endpoint,
                mapper: options.map_profile_to_user,
                application_mapper: None,
            })),
            ..Self::default()
        }
    }
}
#[derive(Clone)]
struct HuggingFaceUserInfo {
    endpoint: String,
    mapper: Option<fn(Value) -> Result<Map, String>>,
    application_mapper: Option<std::sync::Arc<dyn super::OAuthProfileMapper>>,
}
#[async_trait]
impl OAuthUserInfoHandler for HuggingFaceUserInfo {
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
            .ok_or("Missing Hugging Face access token")?;
        let profile: Value = reqwest::Client::new()
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
        let mut output = Map::new();
        for (value, target) in [
            (
                Some(
                    &profile
                        .get("name")
                        .filter(|value| truthy(value))
                        .or_else(|| {
                            profile
                                .get("preferred_username")
                                .filter(|value| truthy(value))
                        })
                        .cloned()
                        .unwrap_or(Value::String(String::new().into())),
                ),
                "name",
            ),
            (profile.get("email"), "email"),
            (profile.get("picture"), "image"),
        ] {
            _ = output.insert(target.into(), value.cloned().unwrap_or(Value::Undefined));
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
        if profile.is_null() {
            return Err(super::remaining_profile::profile_exception(
                "Null huggingface profile",
            ));
        }
        let mut response = OAuthUserInfoResponse {
            user: output.clone(),
            data: profile,
            account_subject: None,
        };
        super::apply_application_mapping(&mut response, output)
            .map_err(super::remaining_profile::profile_exception)?;
        Ok(response)
    }
}
fn subject(profile: &Value) -> Result<JsString, String> {
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

    struct SparseMapper(Value);
    #[async_trait]
    impl super::super::OAuthProfileMapper for SparseMapper {
        async fn map_profile(&self, profile: Value) -> Result<Map, String> {
            assert_eq!(profile, self.0);
            let mut mapped = crate::oauth::providers::js!({
                "id": "public-id", "name": null, "email": null,
                "emailVerified": 0, "custom": false
            })
            .as_object()
            .unwrap()
            .clone();
            _ = mapped.insert("image".into(), Value::Undefined);
            Ok(mapped)
        }
    }

    #[tokio::test]
    async fn huggingface_http_default_own_undefined_fields() {
        for (profile, expected_wire, undefined_keys) in [
            (
                crate::oauth::providers::js!({"sub":"raw-id"}),
                crate::oauth::providers::js!({"name":"","emailVerified":false}),
                &["email", "image"][..],
            ),
            (
                crate::oauth::providers::js!({"sub":"raw-id","name":null,"email":null,"picture":null,"email_verified":null}),
                crate::oauth::providers::js!({"name":"","email":null,"image":null,"emailVerified":false}),
                &[][..],
            ),
            (
                crate::oauth::providers::js!({"sub":"raw-id","name":0,"preferred_username":false,"email":false,"picture":0,"email_verified":0}),
                crate::oauth::providers::js!({"name":"","email":false,"image":0,"emailVerified":0}),
                &[][..],
            ),
        ] {
            for mapped in [false, true] {
                let wire_profile = profile.clone();
                let body = alibi_core::utils::json::stringify(&wire_profile)
                    .unwrap()
                    .unwrap();
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let endpoint = format!("http://{}", listener.local_addr().unwrap());
                let server = tokio::spawn(async move {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut request = [0; 8192];
                    let _ = stream.read(&mut request).await.unwrap();
                    let headers = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    stream.write_all(headers.as_bytes()).await.unwrap();
                    stream.write_all(&body).await.unwrap();
                });
                let mut options = HuggingFaceOptions::new("client", Some("secret".into()));
                options.user_info_endpoint = Some(endpoint);
                if mapped {
                    options.map_profile_to_user = Some(|_| {
                        Ok(
                            crate::oauth::providers::js!({"name":"Static", "custom":true})
                                .as_object()
                                .unwrap()
                                .clone(),
                        )
                    });
                }
                let mut provider = OAuthProvider::huggingface_with_options(options);
                if mapped {
                    provider =
                        provider.with_profile_mapper(Arc::new(SparseMapper(profile.clone())));
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

                let (expected_wire, undefined_keys) = if mapped {
                    (
                        crate::oauth::providers::js!({
                            "id":"public-id", "name":null, "email":null,
                            "emailVerified":0, "custom":false
                        }),
                        &["image"][..],
                    )
                } else {
                    (expected_wire.clone(), undefined_keys)
                };
                let mut expected_user = expected_wire.as_object().unwrap().clone();
                for key in undefined_keys {
                    _ = expected_user.insert((*key).into(), Value::Undefined);
                    assert_eq!(response.user.get(*key), Some(&Value::Undefined), "{key}");
                }
                assert_eq!(response.user, expected_user);
                assert_eq!(response.user.contains_key("id"), mapped);
                let bytes = alibi_core::utils::json::stringify(&Value::Object(response.user))
                    .unwrap()
                    .unwrap();
                let encoded: Value = alibi_core::utils::json::from_slice(&bytes).unwrap();
                assert_eq!(encoded, expected_wire);
                for key in undefined_keys {
                    assert!(encoded.get(*key).is_none(), "{key}");
                }
            }
        }
    }

    #[tokio::test]
    async fn huggingface_http_partial_profile_mapping() {
        for mapped in [false, true] {
            let mut profile = crate::oauth::providers::js!({"sub":"raw-id","name":"Original","handle":"Original","email":null,"profile_photo_url":null,"img_url":null,"picture":null,"profile_picture":null,"avatarUrl":null,"email_verified":"true"});
            if mapped {
                profile["name"] = crate::oauth::providers::js!({"requiresMapping": true});
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
            let mut options = HuggingFaceOptions::new("client", Some("secret".into()));
            options.user_info_endpoint = Some(endpoint);
            let mut provider = OAuthProvider::huggingface_with_options(options);
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
