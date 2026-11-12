//! Polar's PKCE grants, ordered scopes and original user-info account identity.
use super::remaining_profile::truthy;
use super::{
    OAuthAuthorizationPolicy, OAuthProvider, OAuthUserInfoHandler, OAuthUserInfoRequest,
    OAuthUserInfoResponse,
};
use alibi_core::utils::json::JsObject as Map;
use alibi_core::utils::json::{JsString, JsValue as Value};
use async_trait::async_trait;

/// Application-owned Polar configuration. Generic signup and asynchronous
/// user-info/refresh callbacks remain configurable on the returned provider.
#[derive(Clone)]
pub struct PolarOptions {
    pub client_id: String,
    pub client_secret: Option<String>,
    /// Sent only during authorization-code exchange.
    pub client_key: Option<String>,
    pub scope: Vec<String>,
    pub prompt: Option<String>,
    pub disable_default_scope: bool,
    pub authorization_endpoint: Option<String>,
    pub redirect_uri: Option<String>,
    /// Trusted transport override retaining Polar's bearer GET and mapping.
    pub user_info_endpoint: Option<String>,
    /// Receives the original profile before its raw account identity is resolved.
    pub map_profile_to_user: Option<fn(Value) -> Result<Map, String>>,
}
impl PolarOptions {
    #[must_use]
    pub fn new(client_id: impl Into<String>, client_secret: Option<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret,
            client_key: None,
            scope: Vec::new(),
            prompt: None,
            disable_default_scope: false,
            authorization_endpoint: None,
            redirect_uri: None,
            user_info_endpoint: None,
            map_profile_to_user: None,
        }
    }
}
impl std::fmt::Debug for PolarOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PolarOptions")
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
    pub fn polar(client_id: &str, client_secret: Option<&str>) -> Self {
        Self::polar_with_options(PolarOptions::new(
            client_id,
            client_secret.map(str::to_owned),
        ))
    }
    #[must_use]
    pub fn polar_with_options(options: PolarOptions) -> Self {
        let secret = options.client_secret.unwrap_or_default();
        let refresh_authentication = super::client_secret_auth(Some(&secret));
        let endpoint = options
            .user_info_endpoint
            .unwrap_or_else(|| "https://api.polar.sh/v1/oauth2/userinfo".into());
        Self {
            client_id: options.client_id,
            client_secret: secret,
            auth_url: options
                .authorization_endpoint
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "https://polar.sh/oauth2/authorize".into()),
            token_url: "https://api.polar.sh/v1/oauth2/token".into(),
            user_info_url: Some(endpoint.clone()),
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
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
                prompt: options.prompt,
                ..OAuthAuthorizationPolicy::default()
            }),
            account_subject: Some(subject),
            get_user_info: Some(std::sync::Arc::new(PolarUserInfo {
                application_mapper: None,
                endpoint,
                mapper: options.map_profile_to_user,
            })),
            ..Self::default()
        }
    }
}
#[derive(Clone)]
struct PolarUserInfo {
    application_mapper: Option<std::sync::Arc<dyn super::OAuthProfileMapper>>,
    endpoint: String,
    mapper: Option<fn(Value) -> Result<Map, String>>,
}
#[async_trait]
impl OAuthUserInfoHandler for PolarUserInfo {
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
        let profile: Value = super::remaining_profile::send_profile_json(
            reqwest::Client::new()
                .get(&self.endpoint)
                .bearer_auth(access_token),
        )
        .await?;
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
        if profile.is_null() {
            return Err(super::remaining_profile::profile_exception(
                "Null Polar profile",
            ));
        }
        // Keep the published raw JSON independently from typed persistence.
        let mut output = Map::new();
        _ = output.insert(
            "name".into(),
            profile
                .get("public_name")
                .filter(|v| truthy(v))
                .or_else(|| profile.get("username").filter(|v| truthy(v)))
                .cloned()
                .unwrap_or_else(|| Value::String(String::new().into())),
        );
        for (source, target) in [("email", "email"), ("avatar_url", "image")] {
            _ = output.insert(
                target.into(),
                profile.get(source).cloned().unwrap_or(Value::Undefined),
            );
        }
        _ = output.insert(
            "emailVerified".into(),
            profile
                .get("email_verified")
                .filter(|value| !value.is_null())
                .cloned()
                .unwrap_or(Value::Bool(false)),
        );
        if let Some(user) = &mapped {
            output.extend(user.clone());
        }
        let mut response = OAuthUserInfoResponse {
            user: output,
            data: profile,
            account_subject: None,
        };
        if let Some(mapped) = application_output {
            super::apply_application_mapping(&mut response, mapped)?;
        }
        Ok(response)
    }
}
fn subject(profile: &Value) -> Result<JsString, String> {
    super::remaining_profile::raw_subject(profile.get("id"))
}
