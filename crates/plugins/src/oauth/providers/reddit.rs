//! Reddit's non-PKCE Basic grants and stable placeholder-email profile.
use super::{
    OAuthAuthorizationPolicy, OAuthProvider, OAuthTokenEndpointAuth, OAuthUserInfo,
    OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use async_trait::async_trait;
use serde_json::Value;

/// Application-owned Reddit configuration. Signup policies and asynchronous
/// user-info/refresh overrides remain available on the returned native provider.
#[derive(Clone)]
pub struct RedditOptions {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    /// Forwarded when nonempty; caller additional parameters take precedence.
    pub duration: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub redirect_uri: Option<String>,
    /// Trusted application transport override preserving Reddit's mapping.
    pub user_info_endpoint: Option<String>,
    /// Receives the original profile before account identity resolution.
    pub map_profile_to_user: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
}
impl RedditOptions {
    #[must_use]
    pub fn new(client_id: impl Into<String>, client_secret: Option<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret,
            scope: Vec::new(),
            disable_default_scope: false,
            duration: None,
            authorization_endpoint: None,
            redirect_uri: None,
            user_info_endpoint: None,
            map_profile_to_user: None,
        }
    }
}
impl std::fmt::Debug for RedditOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedditOptions")
            .field("client_id", &self.client_id)
            .field("scope", &self.scope)
            .field("disable_default_scope", &self.disable_default_scope)
            .field("duration", &self.duration)
            .field("authorization_endpoint", &self.authorization_endpoint)
            .field("redirect_uri", &self.redirect_uri)
            .finish_non_exhaustive()
    }
}
impl OAuthProvider {
    #[must_use]
    pub fn reddit(client_id: &str, client_secret: Option<&str>) -> Self {
        Self::reddit_with_options(RedditOptions::new(
            client_id,
            client_secret.map(str::to_owned),
        ))
    }
    #[must_use]
    pub fn reddit_with_options(options: RedditOptions) -> Self {
        let endpoint = options
            .user_info_endpoint
            .unwrap_or_else(|| "https://oauth.reddit.com/api/v1/me".into());
        Self {
            client_id: options.client_id,
            client_secret: options.client_secret.unwrap_or_default(),
            additional_client_ids: Vec::new(),
            hosted_domain: None,
            require_email_verification: false,
            auth_url: options
                .authorization_endpoint
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "https://www.reddit.com/api/v1/authorize".into()),
            token_url: "https://www.reddit.com/api/v1/access_token".into(),
            user_info_url: Some(endpoint.clone()),
            scopes: vec!["identity".into()],
            authorization: Some(OAuthAuthorizationPolicy {
                preserve_raw_profile_scalars: true,
                source_profile_exceptions: true,
                allow_missing_access_token: true,
                preserve_raw_email_errors: true,
                configured_scopes: options.scope,
                disable_default_scopes: options.disable_default_scope,
                require_client_id: true,
                token_endpoint_auth: Some(OAuthTokenEndpointAuth::ClientSecretBasic),
                authorization_code_headers: vec![
                    ("accept".into(), "text/plain".into()),
                    ("user-agent".into(), "better-auth".into()),
                ],
                redirect_uri: options.redirect_uri,
                login_hint: false,
                pkce: false,
                ..OAuthAuthorizationPolicy::default()
            }),
            allowed_request_params: Vec::new(),
            authorization_params: options
                .duration
                .filter(|v| !v.is_empty())
                .map(|v| vec![("duration".into(), v)])
                .unwrap_or_default(),
            account_subject: Some(subject),
            map_user_info: None,
            get_user_info: Some(std::sync::Arc::new(RedditUserInfo {
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
struct RedditUserInfo {
    application_mapper: Option<std::sync::Arc<dyn super::OAuthProfileMapper>>,
    endpoint: String,
    mapper: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
}
#[async_trait]
impl OAuthUserInfoHandler for RedditUserInfo {
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
            .header("User-Agent", "better-auth")
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        let mapped = if let Some(mapper) = &self.application_mapper {
            mapper
                .map_profile(profile.clone())
                .await
                .map_err(super::remaining_profile::profile_exception)?
        } else {
            self.mapper
                .map(|mapper| mapper(profile.clone()))
                .transpose()
                .map_err(super::remaining_profile::profile_exception)?
                .map(|user| user.public_profile(true))
                .unwrap_or_default()
        };
        if profile.is_null() {
            return Err(super::remaining_profile::profile_exception(
                "Null Reddit profile",
            ));
        }
        let email = if let Some(value) = mapped
            .get("email")
            .filter(|value| super::remaining_profile::truthy(value))
        {
            value.clone()
        } else {
            let identifier = profile
                .get("id")
                .map(super::remaining_profile::js_string)
                .transpose()
                .map_err(super::remaining_profile::profile_exception)?
                .unwrap_or_else(|| "undefined".into());
            let email = format!("{identifier}@reddit.placeholder.invalid");
            if !crate::authentication_helpers::is_valid_email(&email) {
                return Err(super::remaining_profile::profile_exception(
                    "Invalid placeholder email",
                ));
            }
            Value::String(email)
        };
        let image = match profile.get("icon_img") {
            None | Some(Value::Null) => None,
            Some(Value::String(image)) => Some(Value::String(
                image.split('?').next().unwrap_or_default().into(),
            )),
            _ => {
                return Err(super::remaining_profile::profile_exception(
                    "Invalid Reddit icon_img",
                ));
            }
        };
        let mut output = serde_json::Map::new();
        if let Some(name) = profile.get("name") {
            _ = output.insert("name".into(), name.clone());
        }
        if let Some(image) = image {
            _ = output.insert("image".into(), image);
        }
        output.extend(mapped.clone());
        _ = output.insert("email".into(), email);
        _ = output.insert(
            "emailVerified".into(),
            mapped
                .get("emailVerified")
                .filter(|value| !value.is_null())
                .cloned()
                .unwrap_or(Value::Bool(false)),
        );
        let user = OAuthUserInfo {
            additional_fields: output
                .iter()
                .filter(|(key, _)| {
                    !matches!(
                        key.as_str(),
                        "id" | "name" | "email" | "image" | "emailVerified"
                    )
                })
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
            id: profile
                .get("id")
                .map(super::remaining_profile::js_string)
                .transpose()
                .map_err(super::remaining_profile::profile_exception)?
                .unwrap_or_default(),
            name: super::remaining_profile::scalar(
                output
                    .get("name")
                    .filter(|value| super::remaining_profile::truthy(value)),
            )?,
            email: output
                .get("email")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .into(),
            image: super::remaining_profile::scalar(output.get("image"))?,
            email_verified: output
                .get("emailVerified")
                .is_some_and(super::remaining_profile::truthy),
        };
        Ok(OAuthUserInfoResponse {
            user_output: Some(output),
            user,
            data: profile,
        })
    }
}
fn subject(profile: &Value) -> Result<String, String> {
    super::remaining_profile::raw_subject(profile.get("id"))
}
