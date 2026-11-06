//! LINE scopes, delegated direct proof and decoded/fallback profile identity.
use super::{
    OAuthAuthorizationPolicy, OAuthIdTokenVerifier, OAuthProvider, OAuthTokenEndpointAuth,
    OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use crate::oauth::providers::remaining_profile::ProfileResponseExt as _;
use alibi_core::utils::json::JsObject as Map;
use alibi_core::utils::json::{JsString, JsValue as Value};
use async_trait::async_trait;
#[cfg(test)]
use base64::Engine;

/// Application-owned Line configuration. Generic signup and asynchronous
/// user-info/refresh callbacks remain configurable on the returned provider.
#[derive(Clone)]
pub struct LineOptions {
    pub client_id: String,
    pub client_secret: Option<String>,
    /// Sent only during authorization-code exchange.
    pub client_key: Option<String>,
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    pub authorization_endpoint: Option<String>,
    pub redirect_uri: Option<String>,
    /// Trusted transport override retaining LINE's actual GET and mapping.
    pub user_info_endpoint: Option<String>,
    /// Trusted transport override retaining LINE's actual delegated POST proof.
    pub verification_endpoint: Option<String>,
    /// Receives the original profile before its raw account identity is resolved.
    pub map_profile_to_user: Option<fn(Value) -> Result<Map, String>>,
}
impl LineOptions {
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
            verification_endpoint: None,
            map_profile_to_user: None,
        }
    }
}
impl std::fmt::Debug for LineOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LineOptions")
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
    pub fn line(client_id: &str, client_secret: Option<&str>) -> Self {
        Self::line_with_options(LineOptions::new(
            client_id,
            client_secret.map(str::to_owned),
        ))
    }
    #[must_use]
    pub fn line_with_options(options: LineOptions) -> Self {
        let secret = options.client_secret.unwrap_or_default();
        let authentication = if secret.is_empty() {
            OAuthTokenEndpointAuth::None
        } else {
            OAuthTokenEndpointAuth::ClientSecretPost
        };
        let endpoint = options
            .user_info_endpoint
            .unwrap_or_else(|| "https://api.line.me/oauth2/v2.1/userinfo".into());
        let verifier = LineVerifier {
            client_id: options.client_id.clone(),
            endpoint: options
                .verification_endpoint
                .unwrap_or_else(|| "https://api.line.me/oauth2/v2.1/verify".into()),
        };
        Self {
            client_id: options.client_id,
            client_secret: secret,
            additional_client_ids: Vec::new(),
            hosted_domain: None,
            require_email_verification: false,
            auth_url: options
                .authorization_endpoint
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "https://access.line.me/oauth2/v2.1/authorize".into()),
            token_url: "https://api.line.me/oauth2/v2.1/token".into(),
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
                login_hint: true,
                ..OAuthAuthorizationPolicy::default()
            }),
            allowed_request_params: Vec::new(),
            authorization_params: Vec::new(),
            account_subject: Some(subject),
            map_user_info: None,
            get_user_info: Some(std::sync::Arc::new(LineUserInfo {
                endpoint,
                mapper: options.map_profile_to_user,
                application_mapper: None,
            })),
            refresh_access_token: None,
            verify_id_token: Some(std::sync::Arc::new(verifier)),
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
struct LineUserInfo {
    endpoint: String,
    mapper: Option<fn(Value) -> Result<Map, String>>,
    application_mapper: Option<std::sync::Arc<dyn super::OAuthProfileMapper>>,
}
#[async_trait]
impl OAuthUserInfoHandler for LineUserInfo {
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
        let decoded = request.id_token.as_deref().and_then(decode_profile);
        let profile = if let Some(profile) = decoded {
            profile
        } else {
            // The pinned factory tries userinfo even when the caller has no
            // access token. The remote endpoint owns that credential decision.
            reqwest::Client::new()
                .get(&self.endpoint)
                .header(
                    reqwest::header::AUTHORIZATION,
                    format!(
                        "Bearer {}",
                        request.access_token.as_deref().unwrap_or("undefined")
                    ),
                )
                .send()
                .await
                .map_err(|error| error.to_string())?
                .error_for_status()
                .map_err(|error| error.to_string())?
                .profile_json()
                .await
                .map_err(|error| error.to_string())?
        };
        if !super::remaining_profile::truthy(&profile) {
            return Err("Missing line profile".into());
        }
        let mut output = Map::new();
        output.insert(
            "name".into(),
            profile
                .get("name")
                .filter(|value| truthy(value))
                .cloned()
                .unwrap_or_else(|| Value::String(String::new().into())),
        );
        for (source, target) in [("email", "email"), ("picture", "image")] {
            if let Some(value) = profile.get(source) {
                output.insert(target.into(), value.clone());
            }
        }
        output.insert("emailVerified".into(), Value::Bool(false));
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

fn truthy(value: &Value) -> bool {
    value.is_truthy()
}

struct LineVerifier {
    client_id: String,
    endpoint: String,
}
#[async_trait]
impl OAuthIdTokenVerifier for LineVerifier {
    async fn verify_id_token(&self, token: &str, nonce: Option<&str>) -> Result<bool, String> {
        let mut body = vec![("id_token", token), ("client_id", self.client_id.as_str())];
        if let Some(nonce) = nonce.filter(|value| !value.is_empty()) {
            body.push(("nonce", nonce));
        }
        let response = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| error.to_string())?
            .post(&self.endpoint)
            .form(&body)
            .send()
            .await
            .map_err(|error| error.to_string())?
            .error_for_status()
            .map_err(|error| error.to_string())?;
        if response.status().is_redirection() {
            return Ok(false);
        }
        let response: Value = response
            .profile_json()
            .await
            .map_err(|error| error.to_string())?;
        if response.get("aud").and_then(Value::as_str) != Some(self.client_id.as_str()) {
            return Ok(false);
        }
        if response
            .get("nonce")
            .filter(|value| truthy(value))
            .is_some_and(|returned_nonce| {
                returned_nonce
                    .as_str()
                    .is_none_or(|returned_nonce| Some(returned_nonce) != nonce)
            })
        {
            return Ok(false);
        }
        Ok(true)
    }
}
fn decode_profile(token: &str) -> Option<Value> {
    super::remaining_profile::decode_grant_jwt(token).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn grant_payload_decoder_accepts_jose_forgiving_base64() {
        for payload in ["e31=", " e\t3\n0\x0c=\r", "77u_e30="] {
            assert_eq!(
                decode_profile(&format!(".{payload}.")).unwrap(),
                crate::oauth::providers::js!({})
            );
        }
    }

    struct Mapper;
    #[async_trait]
    impl super::super::OAuthProfileMapper for Mapper {
        async fn map_profile(&self, profile: Value) -> Result<Map, String> {
            assert_eq!(profile["sub"], "line-id");
            Ok(
                crate::oauth::providers::js!({"name":"Mapped","custom":true})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
        }
    }
    #[tokio::test]
    async fn line_maps_decoded_and_fallback_profiles() {
        for id_token_valid in [true, false] {
            let body = crate::oauth::providers::js!({"sub":"line-id","name":"Original","email":null,"picture":null});
            let token = format!(
                "e30.{}.sig",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(body.to_string())
            );

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

            let mut options = LineOptions::new("client", None);
            options.user_info_endpoint = Some(endpoint);
            let provider = OAuthProvider::line_with_options(options)
                .with_profile_mapper(std::sync::Arc::new(Mapper));
            let response = provider
                .get_user_info
                .unwrap()
                .get_user_info(OAuthUserInfoRequest {
                    id_token: Some(if id_token_valid {
                        token
                    } else {
                        "malformed".into()
                    }),
                    ..Default::default()
                })
                .await
                .unwrap();
            let output = response.user.clone();
            assert_eq!(output["name"], "Mapped");
            assert_eq!(output["email"], Value::Null);
            assert_eq!(output["image"], Value::Null);
            assert_eq!(output["emailVerified"], false);
            assert!(!output.contains_key("id"));
            assert_eq!(response.data["name"], "Original");
            if id_token_valid {
                server.abort();
            } else {
                server.await.unwrap();
            }
        }
    }
}
