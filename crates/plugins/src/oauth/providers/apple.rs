//! The pinned Apple factory: JWT profile data, stable subject and JWKS authority.
use super::{
    OAuthAuthorizationPolicy, OAuthProvider, OAuthUserInfo, OAuthUserInfoHandler,
    OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use crate::oauth::{OAuthIdTokenConfig, OAuthJwksSource};
use alibi_core::utils::json::JsValue;
use async_trait::async_trait;
#[cfg(test)]
use base64::Engine;
use serde_json::Map;
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
                source_profile_exceptions: true,
                configured_scopes: options.scope,
                disable_default_scopes: options.disable_default_scope,
                response_type: "code id_token".into(),
                response_mode: Some("form_post".into()),
                require_client_secret: true,
                login_hint: false,
                ..OAuthAuthorizationPolicy::default()
            }),
            allowed_request_params: Vec::new(),
            authorization_params: Vec::new(),
            account_subject: None,
            map_user_info: None,
            get_user_info: Some(Arc::new(AppleUserInfo {
                map_profile_to_user: options.map_profile_to_user,
                application_mapper: None,
            })),
            refresh_access_token: None,
            verify_id_token: None,
            id_token: Some(verification),
            disable_id_token_sign_in: options.disable_id_token_sign_in,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            allow_idp_initiated: false,
            override_user_info_on_sign_in: false,
        }
    }
}
#[derive(Clone)]
struct AppleUserInfo {
    map_profile_to_user: Option<fn(serde_json::Value) -> Result<OAuthUserInfo, String>>,
    application_mapper: Option<Arc<dyn super::OAuthProfileMapper>>,
}
#[async_trait]
impl OAuthUserInfoHandler for AppleUserInfo {
    fn errors_are_exceptions(&self) -> bool {
        false
    }

    fn mapped_handler(
        &self,
        mapper: Arc<dyn super::OAuthProfileMapper>,
    ) -> Option<Arc<dyn OAuthUserInfoHandler>> {
        let mut handler = self.clone();
        handler.application_mapper = Some(mapper);
        Some(Arc::new(handler))
    }

    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        let token = super::remaining_profile::grant_id_token(&request)
            .map_err(super::remaining_profile::profile_exception)?
            .ok_or("Missing Apple ID token")?;
        let mut profile = JsValue::from(
            super::remaining_profile::decode_grant_jwt(&token)
                .map_err(super::remaining_profile::profile_exception)?,
        );
        let name_value = if let Some(name) = request.user.and_then(|user| user.name) {
            JsValue::String(
                format!(
                    "{} {}",
                    name.first_name.unwrap_or_default(),
                    name.last_name.unwrap_or_default()
                )
                .trim_matches(js_whitespace)
                .to_owned()
                .into(),
            )
        } else {
            profile
                .get("name")
                .filter(|value| value.is_truthy())
                .cloned()
                .unwrap_or_else(|| JsValue::String(String::new().into()))
        };
        let id = profile
            .get("sub")
            .and_then(|value| value.coerce_string().ok())
            .unwrap_or_default();
        let email_verified = match profile.get("email_verified") {
            Some(JsValue::Bool(value)) => *value,
            Some(JsValue::String(value)) => value == "true",
            _ => false,
        };
        let JsValue::Object(object) = &mut profile else {
            return Err("Invalid Apple profile".into());
        };
        _ = object.insert("name".into(), name_value);
        let data = profile.to_json_value().map_err(|error| error.to_string())?;
        let mut output = Map::new();
        output.insert("name".into(), data["name"].clone());
        output.insert(
            "emailVerified".into(),
            serde_json::Value::Bool(email_verified),
        );
        if let Some(email) = data.get("email") {
            output.insert("email".into(), email.clone());
        }
        if let Some(mapper) = self.map_profile_to_user {
            output.extend(
                mapper(data.clone())
                    .map_err(super::remaining_profile::profile_exception)?
                    .public_profile(true),
            );
        }
        if let Some(mapper) = &self.application_mapper {
            output.extend(
                mapper
                    .map_profile(data.clone())
                    .await
                    .map_err(super::remaining_profile::profile_exception)?,
            );
        }
        let mut response = OAuthUserInfoResponse {
            user_output: Some(output.clone()),
            user: OAuthUserInfo {
                additional_fields: Map::new(),
                id: id.clone(),
                email: String::new(),
                name: None,
                image: None,
                email_verified: false,
            },
            data,
        };
        super::apply_application_mapping(&mut response, output)
            .map_err(super::remaining_profile::profile_exception)?;
        response.user.id = id;
        Ok(response)
    }
}

fn js_whitespace(character: char) -> bool {
    (character.is_whitespace() && character != '\u{85}') || character == '\u{feff}'
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Mapper;
    #[async_trait]
    impl super::super::OAuthProfileMapper for Mapper {
        async fn map_profile(
            &self,
            profile: serde_json::Value,
        ) -> Result<Map<String, serde_json::Value>, String> {
            assert_eq!(profile["name"], "Ada Lovelace");
            Ok(serde_json::json!({"id":"public-id","custom":true})
                .as_object()
                .unwrap()
                .clone())
        }
    }
    #[tokio::test]
    async fn apple_maps_enriched_callback_name_without_changing_subject() {
        let profile = serde_json::json!({"sub":"subject","name":"Token","email":null,"email_verified":"true"});
        let token = format!(
            "e30.{}.sig",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(profile.to_string())
        );
        let provider =
            OAuthProvider::apple("client", "secret").with_profile_mapper(Arc::new(Mapper));
        let response = provider
            .get_user_info
            .unwrap()
            .get_user_info(OAuthUserInfoRequest {
                id_token: Some(token),
                user: Some(super::super::OAuthCallbackUserPayload {
                    name: Some(super::super::OAuthCallbackUserName {
                        first_name: Some("Ada".into()),
                        last_name: Some("Lovelace".into()),
                    }),
                    email: None,
                }),
                ..Default::default()
            })
            .await
            .unwrap();
        let output = response.user_output.unwrap();
        assert_eq!(output["name"], "Ada Lovelace");
        assert_eq!(output["email"], serde_json::Value::Null);
        assert_eq!(output["emailVerified"], true);
        assert_eq!(output["custom"], true);
        assert_eq!(output["id"], "public-id");
        assert_eq!(response.user.id, "subject");
        assert!(!output.contains_key("image"));
    }
    #[tokio::test]
    async fn apple_accepts_padded_jwt_payload() {
        let profile = serde_json::json!({"sub":"subject","oid":"object-id","name":"A","email":"a@example.com"});
        let mut json = profile.to_string();
        while json.len() % 3 == 0 {
            json.push(' ');
        }
        let payload = base64::engine::general_purpose::URL_SAFE.encode(json);
        assert!(payload.ends_with('='));
        let provider = OAuthProvider::apple("client", "secret");
        let response = provider
            .get_user_info
            .unwrap()
            .get_user_info(OAuthUserInfoRequest {
                id_token: Some(format!("e30.{payload}.signature")),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(response.data["email"], "a@example.com");
    }
}
