//! LINE scopes, delegated direct proof and decoded/fallback profile identity.
use super::{
    OAuthAuthorizationPolicy, OAuthIdTokenVerifier, OAuthProvider, OAuthTokenEndpointAuth,
    OAuthUserInfo, OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use async_trait::async_trait;
use base64::Engine;
use serde_json::Map;
use serde_json::Value;

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
    pub map_profile_to_user: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
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
                configured_scopes: options.scope,
                disable_default_scopes: options.disable_default_scope,
                require_client_id: true,
                token_endpoint_auth: Some(authentication),
                authorization_code_client_key: options.client_key,
                redirect_uri: options.redirect_uri,
                login_hint: true,
                ..OAuthAuthorizationPolicy::default()
            }),
            authorization_params: Vec::new(),
            account_subject: Some(subject),
            map_user_info: None,
            get_user_info: Some(std::sync::Arc::new(LineUserInfo {
                endpoint,
                mapper: options.map_profile_to_user,
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
struct LineUserInfo {
    endpoint: String,
    mapper: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
}
#[async_trait]
impl OAuthUserInfoHandler for LineUserInfo {
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
                .json::<Value>()
                .await
                .map_err(|error| error.to_string())?
        };
        let mapped = self
            .mapper
            .map(|mapper| mapper(profile.clone()))
            .transpose()?;
        // The published profile preserves JSON types and explicit nulls; its
        // typed persistence values remain separate from this public output.
        let user_output = Some(mapped.as_ref().map_or_else(
            || {
                let mut output = serde_json::Map::new();
                _ = output.insert(
                    "name".into(),
                    profile
                        .get("name")
                        .filter(|value| truthy(value))
                        .cloned()
                        .unwrap_or_else(|| Value::String(String::new())),
                );
                for (source, target) in [("email", "email"), ("picture", "image")] {
                    if let Some(value) = profile.get(source) {
                        _ = output.insert(target.into(), value.clone());
                    }
                }
                _ = output.insert("emailVerified".into(), Value::Bool(false));
                output
            },
            |user| user.public_profile(true),
        ));
        let user = match mapped {
            Some(user) => user,
            None => OAuthUserInfo {
                additional_fields: Map::default(),
                id: scalar(profile.get("sub"))?.unwrap_or_default(),
                name: Some(
                    scalar(profile.get("name").filter(|value| truthy(value)))?.unwrap_or_default(),
                ),
                email: profile
                    .get("email")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .into(),
                image: scalar(profile.get("picture"))?,
                email_verified: false,
            },
        };
        Ok(OAuthUserInfoResponse {
            user_output,
            user,
            data: profile,
        })
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
        Some(Value::Array(_) | Value::Object(_)) => Err("Invalid LINE profile field".into()),
    }
}
fn subject(profile: &Value) -> Result<String, String> {
    let id = scalar(profile.get("sub"))?.ok_or("Missing LINE sub")?;
    if id
        .trim_matches(|character: char| {
            (character.is_whitespace() && character != '\u{85}') || character == '\u{feff}'
        })
        .is_empty()
        || id == "null"
        || id == "undefined"
    {
        return Err("Invalid LINE sub".into());
    }
    Ok(id)
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
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
        let response: Value = reqwest::Client::new()
            .post(&self.endpoint)
            .form(&body)
            .send()
            .await
            .map_err(|error| error.to_string())?
            .error_for_status()
            .map_err(|error| error.to_string())?
            .json()
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
    let mut parts = token.split('.');
    _ = parts.next()?;
    let payload = parts.next()?;
    _ = parts.next()?;
    if payload.is_empty() || parts.next().is_some() {
        return None;
    }
    let encoded = payload.replace('-', "+").replace('_', "/");
    let decoder = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );
    let bytes = decoder.decode(encoded).ok()?;
    let profile: Value = alibi_core::utils::json::from_slice(&bytes).ok()?;
    profile.is_object().then_some(profile)
}
