//! Figma's ordered scopes, Basic token exchanges and stable raw profile identity.
use super::{
    OAuthAuthorizationPolicy, OAuthProvider, OAuthTokenEndpointAuth, OAuthUserInfoHandler,
    OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use crate::oauth::providers::remaining_profile::ProfileResponseExt as _;
use alibi_core::utils::json::JsObject as Map;
use alibi_core::utils::json::{JsString, JsValue as Value};
use async_trait::async_trait;

/// Application-owned Figma configuration. Generic signup and asynchronous
/// user-info/refresh callbacks remain configurable on the returned provider.
#[derive(Clone)]
pub struct FigmaOptions {
    pub client_id: String,
    pub client_secret: Option<String>,
    /// Sent only during authorization-code exchange.
    pub client_key: Option<String>,
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    pub authorization_endpoint: Option<String>,
    pub redirect_uri: Option<String>,
    /// Trusted transport override retaining Figma's actual GET and mapping.
    pub user_info_endpoint: Option<String>,
    /// Receives the original profile before its raw account identity is resolved.
    pub map_profile_to_user: Option<fn(Value) -> Result<Map, String>>,
}
impl FigmaOptions {
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
impl std::fmt::Debug for FigmaOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FigmaOptions")
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
    pub fn figma(client_id: &str, client_secret: Option<&str>) -> Self {
        Self::figma_with_options(FigmaOptions::new(
            client_id,
            client_secret.map(str::to_owned),
        ))
    }
    #[must_use]
    pub fn figma_with_options(options: FigmaOptions) -> Self {
        let secret = options.client_secret.unwrap_or_default();
        let endpoint = options
            .user_info_endpoint
            .unwrap_or_else(|| "https://api.figma.com/v1/me".into());
        Self {
            client_id: options.client_id,
            client_secret: secret,
            additional_client_ids: Vec::new(),
            hosted_domain: None,
            require_email_verification: false,
            auth_url: options
                .authorization_endpoint
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "https://www.figma.com/oauth".into()),
            token_url: "https://api.figma.com/v1/oauth/token".into(),
            user_info_url: Some(endpoint.clone()),
            scopes: vec!["current_user:read".into()],
            authorization: Some(OAuthAuthorizationPolicy {
                source_profile_exceptions: true,
                configured_scopes: options.scope,
                disable_default_scopes: options.disable_default_scope,
                require_client_id: true,
                require_client_secret: true,
                token_endpoint_auth: Some(OAuthTokenEndpointAuth::ClientSecretBasic),
                authorization_code_client_key: options.client_key,
                redirect_uri: options.redirect_uri,
                login_hint: false,
                ..OAuthAuthorizationPolicy::default()
            }),
            allowed_request_params: Vec::new(),
            authorization_params: Vec::new(),
            account_subject: Some(subject),
            map_user_info: None,
            get_user_info: Some(std::sync::Arc::new(FigmaUserInfo {
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
struct FigmaUserInfo {
    endpoint: String,
    mapper: Option<fn(Value) -> Result<Map, String>>,
    application_mapper: Option<std::sync::Arc<dyn super::OAuthProfileMapper>>,
}
#[async_trait]
impl OAuthUserInfoHandler for FigmaUserInfo {
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
        let access_token = request.access_token.ok_or("Missing Figma access token")?;
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
        if !super::remaining_profile::truthy(&profile) {
            return Err("Missing Figma profile".into());
        }
        let mut output = Map::new();
        for (value, target) in [
            (profile.get("handle"), "name"),
            (profile.get("email"), "email"),
            (profile.get("img_url"), "image"),
        ] {
            _ = output.insert(target.into(), value.cloned().unwrap_or(Value::Undefined));
        }
        _ = output.insert("emailVerified".into(), Value::Bool(false));
        if let Some(mapper) = self.mapper {
            output.extend(mapper(profile.clone())?);
        }
        if let Some(mapper) = &self.application_mapper {
            output.extend(mapper.map_profile(profile.clone()).await?);
        }
        let mut response = OAuthUserInfoResponse {
            user: output.clone(),
            data: profile,
            account_subject: None,
        };
        super::apply_application_mapping(&mut response, output)?;
        Ok(response)
    }
}
fn subject(profile: &Value) -> Result<JsString, String> {
    super::remaining_profile::raw_subject(profile.get("id"))
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
    async fn figma_http_default_own_undefined_fields() {
        for (profile, expected_wire, undefined_keys) in [
            (
                crate::oauth::providers::js!({"id":"raw-id"}),
                crate::oauth::providers::js!({"emailVerified":false}),
                &["name", "email", "image"][..],
            ),
            (
                crate::oauth::providers::js!({"id":"raw-id","handle":null,"email":null,"img_url":null}),
                crate::oauth::providers::js!({"name":null,"email":null,"image":null,"emailVerified":false}),
                &[][..],
            ),
            (
                crate::oauth::providers::js!({"id":"raw-id","handle":0,"email":false,"img_url":0}),
                crate::oauth::providers::js!({"name":0,"email":false,"image":0,"emailVerified":false}),
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
                let mut options = FigmaOptions::new("client", Some("secret".into()));
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
                let mut provider = OAuthProvider::figma_with_options(options);
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
    async fn figma_http_partial_profile_mapping() {
        for mapped in [false, true] {
            let mut profile = crate::oauth::providers::js!({"id":"raw-id","name":"Original","handle":"Original","email":null,"profile_photo_url":null,"img_url":null,"picture":null,"profile_picture":null,"avatarUrl":null,"email_verified":"true"});
            if mapped {
                profile["handle"] = crate::oauth::providers::js!({"requiresMapping": true});
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
            let mut options = FigmaOptions::new("client", Some("secret".into()));
            options.user_info_endpoint = Some(endpoint);
            let mut provider = OAuthProvider::figma_with_options(options);
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
