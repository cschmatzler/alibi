//! Railway's PKCE grants, ordered scopes and original user-info account identity.
use super::{
    OAuthAuthorizationPolicy, OAuthProvider, OAuthTokenEndpointAuth, OAuthUserInfo,
    OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use async_trait::async_trait;
use serde_json::Map;
use serde_json::Value;

/// Application-owned Railway configuration. Generic signup and asynchronous
/// user-info/refresh callbacks remain configurable on the returned provider.
#[derive(Clone)]
pub struct RailwayOptions {
    pub client_id: String,
    pub client_secret: Option<String>,
    /// Sent only during authorization-code exchange.
    pub client_key: Option<String>,
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    pub authorization_endpoint: Option<String>,
    pub redirect_uri: Option<String>,
    /// Trusted transport override retaining Railway's bearer GET and mapping.
    pub user_info_endpoint: Option<String>,
    /// Receives the original profile before its raw account identity is resolved.
    pub map_profile_to_user: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
}
impl RailwayOptions {
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
impl std::fmt::Debug for RailwayOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RailwayOptions")
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
    pub fn railway(client_id: &str, client_secret: Option<&str>) -> Self {
        Self::railway_with_options(RailwayOptions::new(
            client_id,
            client_secret.map(str::to_owned),
        ))
    }
    #[must_use]
    pub fn railway_with_options(options: RailwayOptions) -> Self {
        let secret = options.client_secret.unwrap_or_default();
        let refresh_authentication = OAuthTokenEndpointAuth::ClientSecretBasic;
        let endpoint = options
            .user_info_endpoint
            .unwrap_or_else(|| "https://backboard.railway.com/oauth/me".into());
        Self {
            client_id: options.client_id,
            client_secret: secret,
            additional_client_ids: Vec::new(),
            hosted_domain: None,
            require_email_verification: false,
            auth_url: options
                .authorization_endpoint
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "https://backboard.railway.com/oauth/auth".into()),
            token_url: "https://backboard.railway.com/oauth/token".into(),
            user_info_url: Some(endpoint.clone()),
            scopes: vec!["openid".into(), "email".into(), "profile".into()],
            authorization: Some(OAuthAuthorizationPolicy {
                preserve_raw_profile_scalars: true,
                source_profile_exceptions: true,
                allow_missing_access_token: true,
                preserve_raw_email_errors: true,
                configured_scopes: options.scope,
                disable_default_scopes: options.disable_default_scope,
                require_client_id: true,
                token_endpoint_auth: Some(refresh_authentication),
                authorization_code_client_key: options.client_key,
                redirect_uri: options.redirect_uri,
                login_hint: false,
                ..OAuthAuthorizationPolicy::default()
            }),
            authorization_params: Vec::new(),
            account_subject: Some(subject),
            map_user_info: None,
            get_user_info: Some(std::sync::Arc::new(RailwayUserInfo {
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
struct RailwayUserInfo {
    application_mapper: Option<std::sync::Arc<dyn super::OAuthProfileMapper>>,
    endpoint: String,
    mapper: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
}
#[async_trait]
impl OAuthUserInfoHandler for RailwayUserInfo {
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
        let access_token = super::remaining_profile::bearer_access_token(&request)?;
        let profile: Value = reqwest::Client::new()
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
        if profile.is_null()
            || profile == Value::Bool(false)
            || profile.as_f64() == Some(0.0)
            || profile.as_str() == Some("")
        {
            return Err("Missing Railway profile".into());
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
        // Keep the published raw JSON independently from typed persistence.
        let mut output = serde_json::Map::new();
        if let Some(name) = profile.get("name") {
            drop(output.insert("name".into(), name.clone()));
        }
        let email = profile.get("email");
        if let Some(email) = email {
            drop(output.insert("email".into(), email.clone()));
        }
        if let Some(image) = profile.get("picture") {
            drop(output.insert("image".into(), image.clone()));
        }
        drop(output.insert("emailVerified".into(), Value::Bool(false)));
        if let Some(user) = &mapped {
            output.extend(user.public_profile(true));
        }
        let user_output = Some(output);
        let user = match mapped {
            Some(user) => user,
            None => OAuthUserInfo {
                additional_fields: Map::default(),
                id: profile
                    .get("sub")
                    .map(super::remaining_profile::js_string)
                    .transpose()?
                    .unwrap_or_default(),
                // Signup uses Source's `user.name || ""`, while account-info
                // above retains the original raw field.
                name: scalar(profile.get("name").filter(|value| {
                    !matches!(value, Value::Bool(false)) && value.as_f64() != Some(0.0)
                }))?,
                email: email.and_then(Value::as_str).unwrap_or_default().into(),
                image: scalar(profile.get("picture"))?,
                email_verified: false,
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
    super::remaining_profile::raw_subject(profile.get("sub"))
}
