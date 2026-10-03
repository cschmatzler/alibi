//! Paybin PKCE grants and decoded ID-token profile bound by its original subject.
use super::{
    OAuthAuthorizationPolicy, OAuthProvider, OAuthTokenEndpointAuth, OAuthUserInfo,
    OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use async_trait::async_trait;
use base64::Engine;
use serde_json::Value;

/// Application-owned Paybin configuration. Generic signup and asynchronous
/// user-info/refresh callbacks remain configurable on the returned provider.
#[derive(Clone)]
pub struct PaybinOptions {
    pub client_id: String,
    pub client_secret: Option<String>,
    /// Sent only during authorization-code exchange.
    pub client_key: Option<String>,
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    pub authorization_endpoint: Option<String>,
    pub redirect_uri: Option<String>,
    /// Empty issuers use the published default. Trailing slashes are preserved.
    pub issuer: Option<String>,
    pub prompt: Option<String>,
    /// Receives the original profile before its raw account identity is resolved.
    pub map_profile_to_user: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
}
impl PaybinOptions {
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
            issuer: None,
            prompt: None,
            map_profile_to_user: None,
        }
    }
}
impl std::fmt::Debug for PaybinOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PaybinOptions")
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
    pub fn paybin(client_id: &str, client_secret: Option<&str>) -> Self {
        Self::paybin_with_options(PaybinOptions::new(
            client_id,
            client_secret.map(str::to_owned),
        ))
    }
    #[must_use]
    pub fn paybin_with_options(options: PaybinOptions) -> Self {
        let secret = options.client_secret.unwrap_or_default();
        let authentication = if secret.is_empty() {
            OAuthTokenEndpointAuth::None
        } else {
            OAuthTokenEndpointAuth::ClientSecretPost
        };
        let issuer = options
            .issuer
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "https://idp.paybin.io".into());
        Self {
            client_id: options.client_id,
            client_secret: secret,
            additional_client_ids: Vec::new(),
            hosted_domain: None,
            require_email_verification: false,
            auth_url: options
                .authorization_endpoint
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| format!("{issuer}/oauth2/authorize")),
            token_url: format!("{issuer}/oauth2/token"),
            user_info_url: None,
            scopes: vec!["openid".into(), "email".into(), "profile".into()],
            authorization: Some(OAuthAuthorizationPolicy {
                preserve_raw_profile_scalars: true,
                source_profile_exceptions: true,
                allow_missing_access_token: true,
                configured_scopes: options.scope,
                disable_default_scopes: options.disable_default_scope,
                require_client_id: true,
                require_client_secret: true,
                default_prompt: options.prompt,
                token_endpoint_auth: Some(authentication),
                authorization_code_client_key: options.client_key,
                redirect_uri: options.redirect_uri,
                login_hint: true,
                propagate_grant_profile_errors: true,
                preserve_raw_email_errors: true,
                ..OAuthAuthorizationPolicy::default()
            }),
            authorization_params: Vec::new(),
            account_subject: Some(subject),
            map_user_info: None,
            get_user_info: Some(std::sync::Arc::new(PaybinUserInfo {
                application_mapper: None,
                mapper: options.map_profile_to_user,
            })),
            refresh_access_token: None,
            verify_id_token: None,
            id_token: None,
            disable_id_token_sign_in: false,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            override_user_info_on_sign_in: false,
        }
    }
}
#[derive(Clone)]
struct PaybinUserInfo {
    application_mapper: Option<std::sync::Arc<dyn super::OAuthProfileMapper>>,
    mapper: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
}
#[async_trait]
impl OAuthUserInfoHandler for PaybinUserInfo {
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
        // The pinned factory decodes only. Grant transport and state own admission;
        // direct ID-token verification is deliberately unsupported.
        let profile = super::remaining_profile::grant_id_token(&request)?
            .as_deref()
            .and_then(decode_profile)
            .ok_or("Missing or invalid Paybin ID token")?;
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
        // Keep the published raw JSON independently from typed persistence.
        let mut output = serde_json::Map::new();
        for (source, target) in [("email", "email"), ("picture", "image")] {
            if let Some(value) = profile.get(source) {
                drop(output.insert(target.into(), value.clone()));
            }
        }
        let name = profile
            .get("name")
            .filter(|v| truthy(v))
            .or_else(|| profile.get("preferred_username").filter(|v| truthy(v)))
            .cloned()
            .unwrap_or_else(|| Value::String(String::new()));
        drop(output.insert("name".into(), name.clone()));
        drop(
            output.insert(
                "emailVerified".into(),
                profile
                    .get("email_verified")
                    .filter(|v| truthy(v))
                    .cloned()
                    .unwrap_or(Value::Bool(false)),
            ),
        );
        if let Some(user) = &mapped {
            output.extend(user.public_profile(true));
        }
        let user_output = Some(output);
        let user = match mapped {
            Some(user) => user,
            None => OAuthUserInfo {
                additional_fields: Default::default(),
                id: profile
                    .get("sub")
                    .map(super::remaining_profile::js_string)
                    .transpose()?
                    .unwrap_or_default(),
                name: scalar(Some(&name))?,
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
            user_output,
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
        Value::Array(_) | Value::Object(_) | Value::Bool(true) => true,
    }
}
fn scalar(value: Option<&Value>) -> Result<Option<String>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(Value::Number(value)) => better_auth_core::utils::json::number_to_string(value)
            .map(Some)
            .map_err(|error| error.to_string()),
        Some(Value::Bool(value)) => Ok(Some(value.to_string())),
        Some(Value::Array(_) | Value::Object(_)) => Ok(None),
    }
}
fn subject(profile: &Value) -> Result<String, String> {
    super::remaining_profile::raw_subject(profile.get("sub"))
}

fn decode_profile(token: &str) -> Option<Value> {
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let _signature = parts.next()?;
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
    let profile: Value = better_auth_core::utils::json::from_slice(&bytes).ok()?;
    profile.is_object().then_some(profile)
}
