//! The pinned Apple factory: JWT profile data, stable subject and JWKS authority.
use super::{
    OAuthAuthorizationPolicy, OAuthProvider, OAuthUserInfo, OAuthUserInfoHandler,
    OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use crate::plugins::oauth::{OAuthIdTokenConfig, OAuthJwksSource};
use async_trait::async_trait;
use base64::Engine;
use better_auth_core::utils::json::{JsValue, parse_value};
use std::sync::Arc;

/// Apple-specific immutable configuration. Generic provider policy and trusted
/// application callback overrides remain available on the returned provider.
#[derive(Clone)]
pub struct AppleOptions {
    pub client_ids: Vec<String>,
    pub client_secret: String,
    pub audience: Option<Vec<String>>,
    pub app_bundle_identifier: Option<String>,
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    pub disable_id_token_sign_in: bool,
    pub jwks_source: Option<Arc<dyn OAuthJwksSource>>,
    /// Receives the enriched original profile. Its mapped ID cannot replace `sub`.
    pub map_profile_to_user: Option<fn(serde_json::Value) -> Result<OAuthUserInfo, String>>,
}
impl AppleOptions {
    #[must_use]
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            client_ids: vec![client_id.into()],
            client_secret: client_secret.into(),
            audience: None,
            app_bundle_identifier: None,
            scope: Vec::new(),
            disable_default_scope: false,
            disable_id_token_sign_in: false,
            jwks_source: None,
            map_profile_to_user: None,
        }
    }
}
impl std::fmt::Debug for AppleOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppleOptions")
            .field("client_ids", &self.client_ids)
            .field("audience", &self.audience)
            .field("app_bundle_identifier", &self.app_bundle_identifier)
            .field("scope", &self.scope)
            .field("disable_default_scope", &self.disable_default_scope)
            .field("disable_id_token_sign_in", &self.disable_id_token_sign_in)
            .finish_non_exhaustive()
    }
}
impl OAuthProvider {
    #[must_use]
    pub fn apple(client_id: &str, client_secret: &str) -> Self {
        Self::apple_with_options(AppleOptions::new(client_id, client_secret))
    }
    #[must_use]
    pub fn apple_with_options(options: AppleOptions) -> Self {
        let client_ids = options.client_ids.clone();
        let mut clients = options.client_ids.into_iter();
        let mut verification = OAuthIdTokenConfig::apple();
        verification.client_ids = Some(client_ids);
        verification.audience = options
            .audience
            .filter(|values| !values.is_empty())
            .or_else(|| {
                options
                    .app_bundle_identifier
                    .filter(|value| !value.is_empty())
                    .map(|value| vec![value])
            });
        if let Some(source) = options.jwks_source {
            verification.jwks_source = source;
        }
        Self {
            client_id: clients.next().unwrap_or_default(),
            additional_client_ids: clients.collect(),
            hosted_domain: None,
            require_email_verification: false,
            client_secret: options.client_secret,
            auth_url: "https://appleid.apple.com/auth/authorize".into(),
            token_url: "https://appleid.apple.com/auth/token".into(),
            user_info_url: None,
            scopes: vec!["email".into(), "name".into()],
            authorization: Some(OAuthAuthorizationPolicy {
                configured_scopes: options.scope,
                disable_default_scopes: options.disable_default_scope,
                response_type: "code id_token".into(),
                response_mode: Some("form_post".into()),
                require_client_secret: true,
                login_hint: false,
                ..OAuthAuthorizationPolicy::default()
            }),
            authorization_params: Vec::new(),
            map_user_info: None,
            get_user_info: Some(Arc::new(AppleUserInfo {
                map_profile_to_user: options.map_profile_to_user,
            })),
            refresh_access_token: None,
            verify_id_token: None,
            id_token: Some(verification),
            disable_id_token_sign_in: options.disable_id_token_sign_in,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            override_user_info_on_sign_in: false,
        }
    }
}
struct AppleUserInfo {
    map_profile_to_user: Option<fn(serde_json::Value) -> Result<OAuthUserInfo, String>>,
}
#[async_trait]
impl OAuthUserInfoHandler for AppleUserInfo {
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        let token = request.id_token.ok_or("Missing Apple ID token")?;
        let parts: Vec<_> = token.split('.').collect();
        let [_, payload, _] = parts.as_slice() else {
            return Err("Invalid Apple ID token".into());
        };
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|error| error.to_string())?;
        let mut profile =
            parse_value(std::str::from_utf8(&bytes).map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?;
        let _ignored_as_object = profile.as_object().ok_or("Invalid Apple profile")?;
        let name_value = if let Some(name) = request.user.and_then(|user| user.name) {
            JsValue::String(
                format!(
                    "{} {}",
                    name.first_name.unwrap_or_default(),
                    name.last_name.unwrap_or_default()
                )
                .trim_matches(js_whitespace)
                .to_owned(),
            )
        } else {
            match profile.get("name") {
                Some(JsValue::Number(value)) if *value != 0.0 && value.is_finite() => {
                    JsValue::Number(*value)
                }
                Some(JsValue::String(value)) => JsValue::String(value.clone()),
                Some(JsValue::Bool(true)) => JsValue::Bool(true),
                _ => JsValue::String(String::new()),
            }
        };
        let name = match &name_value {
            JsValue::String(value) => value.clone(),
            JsValue::Number(value) => better_auth_core::utils::json::number_to_string(
                &serde_json::Number::from_f64(*value).ok_or("Invalid Apple name")?,
            )
            .map_err(|error| error.to_string())?,
            JsValue::Bool(value) => value.to_string(),
            _ => return Err("Invalid Apple name".into()),
        };
        let id = match profile.get("sub") {
            Some(JsValue::String(value))
                if !value.trim_matches(js_whitespace).is_empty()
                    && value != "null"
                    && value != "undefined" =>
            {
                value.clone()
            }
            Some(JsValue::Number(value)) if value.is_finite() => {
                better_auth_core::utils::json::number_to_string(
                    &serde_json::Number::from_f64(*value).ok_or("Invalid Apple subject")?,
                )
                .map_err(|error| error.to_string())?
            }
            _ => return Err("Invalid Apple subject".into()),
        };
        let email = profile
            .get("email")
            .and_then(JsValue::as_str)
            .unwrap_or_default()
            .to_owned();
        let email_verified = match profile.get("email_verified") {
            Some(JsValue::Bool(value)) => *value,
            Some(JsValue::String(value)) => value == "true",
            _ => false,
        };
        let JsValue::Object(object) = &mut profile else {
            return Err("Invalid Apple profile".into());
        };
        drop(object.insert("name".into(), name_value));
        let data = profile.to_json_value().map_err(|error| error.to_string())?;
        let user = if let Some(mapper) = self.map_profile_to_user {
            let mut mapped = mapper(data.clone())?;
            mapped.id = id;
            mapped
        } else {
            OAuthUserInfo {
                id,
                email,
                name: Some(name),
                image: None,
                email_verified,
            }
        };
        Ok(OAuthUserInfoResponse { user, data })
    }
}

fn js_whitespace(character: char) -> bool {
    (character.is_whitespace() && character != '\u{85}') || character == '\u{feff}'
}
