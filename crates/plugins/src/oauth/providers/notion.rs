//! Notion's bot owner identity, versioned lookup and grant-specific credentials.
use super::{
    OAuthAuthorizationPolicy, OAuthProvider, OAuthTokenEndpointAuth, OAuthUserInfoHandler,
    OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use crate::oauth::providers::remaining_profile::ProfileResponseExt as _;
use alibi_core::utils::json::JsObject as Map;
use alibi_core::utils::json::{JsString, JsValue as Value};
use async_trait::async_trait;

/// Application-owned Notion configuration. Generic signup and asynchronous
/// user-info/refresh callbacks remain configurable on the returned provider.
#[derive(Clone)]
pub struct NotionOptions {
    pub client_id: String,
    pub client_secret: Option<String>,
    /// Sent only during authorization-code exchange.
    pub client_key: Option<String>,
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    pub authorization_endpoint: Option<String>,
    pub redirect_uri: Option<String>,
    /// Trusted transport override retaining Notion's versioned GET and mapping.
    pub user_info_endpoint: Option<String>,
    /// Receives the original profile before its raw account identity is resolved.
    pub map_profile_to_user: Option<fn(Value) -> Result<Map, String>>,
}
impl NotionOptions {
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
impl std::fmt::Debug for NotionOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NotionOptions")
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
    pub fn notion(client_id: &str, client_secret: Option<&str>) -> Self {
        Self::notion_with_options(NotionOptions::new(
            client_id,
            client_secret.map(str::to_owned),
        ))
    }
    #[must_use]
    pub fn notion_with_options(options: NotionOptions) -> Self {
        let secret = options.client_secret.unwrap_or_default();
        let refresh_authentication = if secret.is_empty() {
            OAuthTokenEndpointAuth::None
        } else {
            OAuthTokenEndpointAuth::ClientSecretPost
        };
        let endpoint = options
            .user_info_endpoint
            .unwrap_or_else(|| "https://api.notion.com/v1/users/me".into());
        Self {
            client_id: options.client_id,
            client_secret: secret,
            additional_client_ids: Vec::new(),
            hosted_domain: None,
            require_email_verification: false,
            auth_url: options
                .authorization_endpoint
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "https://api.notion.com/v1/oauth/authorize".into()),
            token_url: "https://api.notion.com/v1/oauth/token".into(),
            user_info_url: Some(endpoint.clone()),
            scopes: Vec::new(),
            authorization: Some(OAuthAuthorizationPolicy {
                preserve_raw_profile_scalars: true,
                source_profile_exceptions: true,
                allow_missing_access_token: true,
                preserve_raw_email_errors: true,
                configured_scopes: options.scope,
                disable_default_scopes: options.disable_default_scope,
                require_client_id: true,
                token_endpoint_auth: Some(OAuthTokenEndpointAuth::ClientSecretBasic),
                refresh_token_endpoint_auth: Some(refresh_authentication),
                fixed_authorization_params: vec![("owner".into(), "user".into())],
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
            get_user_info: Some(std::sync::Arc::new(NotionUserInfo {
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
struct NotionUserInfo {
    application_mapper: Option<std::sync::Arc<dyn super::OAuthProfileMapper>>,
    endpoint: String,
    mapper: Option<fn(Value) -> Result<Map, String>>,
}
#[async_trait]
impl OAuthUserInfoHandler for NotionUserInfo {
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
        let response: Value = reqwest::Client::new()
            .get(&self.endpoint)
            .header("Notion-Version", "2022-06-28")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|error| error.to_string())?
            .error_for_status()
            .map_err(|error| error.to_string())?
            .profile_json()
            .await
            .map_err(|error| error.to_string())?;
        let profile = response
            .get("bot")
            .and_then(|bot| bot.get("owner"))
            .and_then(|owner| owner.get("user"))
            .filter(|user| truthy(user))
            .cloned()
            .ok_or("Missing Notion profile")?;
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
        let mut output = Map::new();
        _ = output.insert(
            "name".into(),
            profile
                .get("name")
                .filter(|v| truthy(v))
                .cloned()
                .unwrap_or_else(|| Value::String(String::new().into())),
        );
        let email = profile
            .get("person")
            .and_then(|person| person.get("email"))
            .filter(|v| truthy(v));
        _ = output.insert("email".into(), email.cloned().unwrap_or(Value::Null));
        if let Some(image) = profile.get("avatar_url") {
            _ = output.insert("image".into(), image.clone());
        }
        _ = output.insert("emailVerified".into(), Value::Bool(false));
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
fn truthy(value: &Value) -> bool {
    value.is_truthy()
}
fn subject(profile: &Value) -> Result<JsString, String> {
    super::remaining_profile::raw_subject(profile.get("id"))
}
