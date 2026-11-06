//! `PayPal`'s sandbox/live endpoints, PKCE grants and original user-info subject.
use super::{
    OAuthAuthorizationPolicy, OAuthProvider, OAuthTokenEndpointAuth, OAuthUserInfo,
    OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use serde_json::Map;
use serde_json::Value;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PayPalEnvironment {
    #[default]
    Sandbox,
    Live,
}

/// Application-owned `PayPal` configuration. The published factory ignores scopes,
/// requestShippingAddress, clientKey and responseMode.
/// Generic signup and asynchronous callbacks remain available on the provider.
#[derive(Clone)]
pub struct PayPalOptions {
    pub client_id: String,
    pub client_secret: String,
    pub environment: PayPalEnvironment,
    pub prompt: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub redirect_uri: Option<String>,
    /// Trusted transport override retaining the `PayPal` query and mapping.
    pub user_info_endpoint: Option<String>,
    /// Receives the original profile; its ID cannot replace the account subject.
    pub map_profile_to_user: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
}
impl PayPalOptions {
    #[must_use]
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            environment: PayPalEnvironment::Sandbox,
            prompt: None,
            authorization_endpoint: None,
            redirect_uri: None,
            user_info_endpoint: None,
            map_profile_to_user: None,
        }
    }
}
impl std::fmt::Debug for PayPalOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PayPalOptions")
            .field("client_id", &self.client_id)
            .field("environment", &self.environment)
            .field("prompt", &self.prompt)
            .field("authorization_endpoint", &self.authorization_endpoint)
            .field("redirect_uri", &self.redirect_uri)
            .finish_non_exhaustive()
    }
}
impl OAuthProvider {
    #[must_use]
    pub fn paypal(client_id: &str, client_secret: &str) -> Self {
        Self::paypal_with_options(PayPalOptions::new(client_id, client_secret))
    }
    #[must_use]
    pub fn paypal_with_options(options: PayPalOptions) -> Self {
        let sandbox = options.environment == PayPalEnvironment::Sandbox;
        let web = if sandbox {
            "www.sandbox.paypal.com"
        } else {
            "www.paypal.com"
        };
        let api = if sandbox {
            "api-m.sandbox.paypal.com"
        } else {
            "api-m.paypal.com"
        };
        let endpoint = options
            .user_info_endpoint
            .unwrap_or_else(|| format!("https://{api}/v1/identity/oauth2/userinfo"));
        Self {
            client_id: options.client_id,
            client_secret: options.client_secret,
            additional_client_ids: Vec::new(),
            hosted_domain: None,
            require_email_verification: false,
            auth_url: options
                .authorization_endpoint
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| format!("https://{web}/signin/authorize")),
            token_url: format!("https://{api}/v1/oauth2/token"),
            user_info_url: Some(endpoint.clone()),
            scopes: Vec::new(),
            authorization: Some(OAuthAuthorizationPolicy {
                preserve_raw_profile_scalars: true,
                source_profile_exceptions: true,
                allow_missing_access_token: true,
                preserve_raw_email_errors: true,
                omit_scopes: true,
                require_client_id: true,
                require_client_secret: true,
                token_endpoint_auth: Some(OAuthTokenEndpointAuth::ClientSecretBasic),
                redirect_uri: options.redirect_uri,
                login_hint: false,
                prompt: options.prompt,
                ..OAuthAuthorizationPolicy::default()
            }),
            allowed_request_params: Vec::new(),
            authorization_params: Vec::new(),
            account_subject: Some(subject),
            map_user_info: None,
            get_user_info: Some(std::sync::Arc::new(PayPalUserInfo {
                application_mapper: None,
                endpoint,
                mapper: options.map_profile_to_user,
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
struct PayPalUserInfo {
    application_mapper: Option<std::sync::Arc<dyn super::OAuthProfileMapper>>,
    endpoint: String,
    mapper: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
}
#[async_trait::async_trait]
impl OAuthUserInfoHandler for PayPalUserInfo {
    fn errors_are_exceptions(&self) -> bool {
        false
    }

    fn mapped_handler(
        &self,
        mapper: std::sync::Arc<dyn super::OAuthProfileMapper>,
    ) -> Option<std::sync::Arc<dyn OAuthUserInfoHandler>> {
        let mut handler = self.clone();
        handler.mapper = None;
        handler.application_mapper = Some(mapper);
        Some(std::sync::Arc::new(handler))
    }

    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        if !super::remaining_profile::has_access_token(&request) {
            return Err("Missing PayPal access token".into());
        }
        let access_token = super::remaining_profile::bearer_access_token(&request)?;
        let profile: Value = reqwest::Client::new()
            .get(&self.endpoint)
            .query(&[("schema", "paypalv1.1")])
            .bearer_auth(access_token)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|error| error.to_string())?
            .error_for_status()
            .map_err(|error| error.to_string())?
            .json()
            .await
            .map_err(|error| error.to_string())?;
        if !truthy(&profile) {
            return Err("Missing PayPal profile".into());
        }
        if let Some(token) = super::remaining_profile::grant_id_token(&request)? {
            // The published factory decodes, it does not verify JWT signatures.
            // This token comes from the trusted code exchange; direct ID-token
            // sign-in remains unsupported because no verifier is configured.
            let claims = super::remaining_profile::decode_grant_jwt(&token)?;
            let token_subject = claims
                .get("sub")
                .filter(|value| truthy(value))
                .ok_or("Missing PayPal ID-token subject")?;
            let profile_subject = profile
                .get("sub")
                .filter(|value| !value.is_null())
                .or_else(|| profile.get("user_id"));
            if !profile_subject.is_some_and(|subject| {
                super::remaining_profile::strict_primitive_equal(subject, token_subject)
            }) {
                return Err("PayPal ID-token subject mismatch".into());
            }
        }
        let application_output = if let Some(mapper) = &self.application_mapper {
            Some(mapper.map_profile(profile.clone()).await?)
        } else {
            None
        };
        let mapped = self
            .mapper
            .map(|mapper| mapper(profile.clone()))
            .transpose()?;
        let mut output = serde_json::Map::new();
        for (source, target) in [
            ("name", "name"),
            ("email", "email"),
            ("picture", "image"),
            ("email_verified", "emailVerified"),
        ] {
            if let Some(value) = profile.get(source) {
                _ = output.insert(target.into(), value.clone());
            }
        }
        if let Some(user) = &mapped {
            output.extend(user.public_profile(true));
        }
        let user = match mapped {
            Some(user) => user,
            None => OAuthUserInfo {
                additional_fields: Map::default(),
                id: profile
                    .get("user_id")
                    .map(super::remaining_profile::js_string)
                    .transpose()?
                    .unwrap_or_default(),
                name: scalar(profile.get("name").filter(|value| truthy(value)))?,
                email: profile
                    .get("email")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .into(),
                image: scalar(profile.get("picture"))?,
                email_verified: profile.get("email_verified").is_some_and(truthy),
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
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(false) => false,
        Value::Number(value) => value.as_f64() != Some(0.0),
        Value::String(value) => !value.is_empty(),
        _ => true,
    }
}
fn scalar(value: Option<&Value>) -> Result<Option<String>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(Value::Number(value)) => alibi_core::utils::json::number_to_string(value)
            .map(Some)
            .map_err(|error| error.to_string()),
        Some(Value::Bool(value)) => Ok(Some(value.to_string())),
        Some(Value::Array(_) | Value::Object(_)) => Ok(None),
    }
}
fn subject(profile: &Value) -> Result<String, String> {
    super::remaining_profile::raw_subject(profile.get("user_id"))
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
    async fn paypal_accepts_raw_id_tokens_without_a_typed_projection() {
        use base64::Engine;

        let payload =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"sub":"paypal-subject"}"#);
        let token = format!("header.{payload}.signature");
        for typed_token in [None, Some("different-typed-token".into())] {
            let (endpoint, captured) = profile_server(json!({
                "sub": "paypal-subject",
                "user_id": "legacy-paypal-id",
                "email": "paypal@example.com"
            }))
            .await;
            let response = PayPalUserInfo {
                endpoint,
                mapper: None,
                application_mapper: None,
            }
            .get_user_info(OAuthUserInfoRequest {
                id_token: typed_token,
                raw: Some(json!({"access_token": "access", "id_token": token})),
                ..OAuthUserInfoRequest::default()
            })
            .await
            .unwrap();
            captured.await.unwrap();
            assert_eq!(response.user.id, "legacy-paypal-id");
            assert_eq!(response.data["sub"], "paypal-subject");
        }
        for raw_token in [json!(42), json!({}), json!("invalid")] {
            let (endpoint, captured) = profile_server(json!({"sub": "paypal-subject"})).await;
            let error = PayPalUserInfo {
                endpoint,
                mapper: None,
                application_mapper: None,
            }
            .get_user_info(OAuthUserInfoRequest {
                raw: Some(json!({"access_token": "access", "id_token": raw_token})),
                ..OAuthUserInfoRequest::default()
            })
            .await
            .unwrap_err();
            captured.await.unwrap();
            assert!(!error.starts_with("oauth-profile-exception:"), "{error}");
        }
    }

    #[tokio::test]
    async fn paypal_retains_truthy_profiles_and_compound_public_fields() {
        for profile in [
            json!({"user_id": "paypal", "name": {}, "email": [], "picture": ["raw"], "email_verified": "raw"}),
            json!(42),
            json!("profile"),
            json!([]),
        ] {
            let (endpoint, captured) = profile_server(profile.clone()).await;
            let response = PayPalUserInfo {
                endpoint,
                mapper: None,
                application_mapper: None,
            }
            .get_user_info(OAuthUserInfoRequest {
                access_token: Some("access".into()),
                ..OAuthUserInfoRequest::default()
            })
            .await
            .unwrap();
            captured.await.unwrap();
            assert_eq!(response.data, profile);
            let output = response.user_output.unwrap();
            if profile.is_object() {
                assert_eq!(output["name"], json!({}));
                assert_eq!(output["image"], json!(["raw"]));
                assert_eq!(output["email"], json!([]));
                assert_eq!(output["emailVerified"], "raw");
            } else {
                assert!(output.is_empty());
            }
        }
        for profile in [Value::Null, json!(false), json!(0), json!("")] {
            let (endpoint, captured) = profile_server(profile).await;
            assert!(
                PayPalUserInfo {
                    endpoint,
                    mapper: None,
                    application_mapper: None
                }
                .get_user_info(OAuthUserInfoRequest {
                    access_token: Some("access".into()),
                    ..OAuthUserInfoRequest::default()
                })
                .await
                .is_err()
            );
            captured.await.unwrap();
        }
    }
}
