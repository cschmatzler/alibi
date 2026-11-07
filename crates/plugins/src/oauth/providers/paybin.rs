//! Paybin PKCE grants and decoded ID-token profile bound by its original subject.
use super::{
    OAuthAuthorizationPolicy, OAuthProvider, OAuthTokenEndpointAuth, OAuthUserInfoHandler,
    OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use alibi_core::utils::json::JsObject as Map;
use alibi_core::utils::json::{JsString, JsValue as Value};
use async_trait::async_trait;
#[cfg(test)]
use base64::Engine;

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
    pub map_profile_to_user: Option<fn(Value) -> Result<Map, String>>,
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
                code_verifier_required_for: Some("Paybin"),
                prompt: options.prompt,
                token_endpoint_auth: Some(authentication),
                authorization_code_client_key: options.client_key,
                redirect_uri: options.redirect_uri,
                login_hint: true,
                propagate_grant_profile_errors: true,
                preserve_raw_email_errors: true,
                ..OAuthAuthorizationPolicy::default()
            }),
            allowed_request_params: Vec::new(),
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
            allow_idp_initiated: false,
            override_user_info_on_sign_in: false,
        }
    }
}
#[derive(Clone)]
struct PaybinUserInfo {
    application_mapper: Option<std::sync::Arc<dyn super::OAuthProfileMapper>>,
    mapper: Option<fn(Value) -> Result<Map, String>>,
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
        let token = super::remaining_profile::grant_id_token(&request)
            .map_err(super::remaining_profile::profile_exception)?
            .ok_or("Missing Paybin ID token")?;
        let profile = decode_profile(&token).ok_or_else(|| {
            super::remaining_profile::profile_exception("Invalid Paybin ID token")
        })?;
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
        let name = profile
            .get("name")
            .filter(|v| truthy(v))
            .or_else(|| profile.get("preferred_username").filter(|v| truthy(v)))
            .cloned()
            .unwrap_or_else(|| Value::String(String::new().into()));
        _ = output.insert("name".into(), name.clone());
        for (source, target) in [("email", "email"), ("picture", "image")] {
            _ = output.insert(
                target.into(),
                profile.get(source).cloned().unwrap_or(Value::Undefined),
            );
        }
        _ = output.insert(
            "emailVerified".into(),
            profile
                .get("email_verified")
                .filter(|v| truthy(v))
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
fn truthy(value: &Value) -> bool {
    value.is_truthy()
}
fn subject(profile: &Value) -> Result<JsString, String> {
    super::remaining_profile::raw_subject(profile.get("sub"))
}

fn decode_profile(token: &str) -> Option<Value> {
    super::remaining_profile::decode_grant_jwt(token).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::providers::js as json;

    #[tokio::test]
    async fn paybin_omits_empty_authorization_prompts() {
        let mut config = crate::test_helpers::create_test_config();
        config.account.store_state_strategy = alibi_core::OAuthStateStrategy::Cookie;
        let ctx = crate::test_helpers::create_test_context_with_config(config).await;
        for (prompt, expected) in [
            (None, None),
            (Some(""), None),
            (Some("login"), Some("login")),
        ] {
            let mut options = PaybinOptions::new("client", Some("secret".into()));
            options.prompt = prompt.map(str::to_owned);
            let mut config = super::super::OAuthConfig::default();
            config
                .providers
                .insert("paybin".into(), OAuthProvider::paybin_with_options(options));
            let flow = crate::oauth::handlers::social_sign_in_core(
                &crate::oauth::OAuthSocialSignInRequest::new("paybin"),
                &config,
                None,
                &ctx,
            )
            .await
            .unwrap();
            let url = url::Url::parse(flow.response.url.as_deref().unwrap()).unwrap();
            let actual = url.query_pairs().find(|(key, _)| key == "prompt");
            assert_eq!(actual.as_ref().map(|(_, value)| value.as_ref()), expected);
        }
    }

    #[tokio::test]
    async fn paybin_invalid_id_tokens_are_profile_exceptions() {
        let handler = PaybinUserInfo {
            mapper: None,
            application_mapper: None,
        };
        assert!(!handler.errors_are_exceptions());
        for token in [json!(null), json!(false), json!(0), json!("")] {
            let error = handler
                .get_user_info(OAuthUserInfoRequest {
                    raw: Some(json!({"id_token": token})),
                    ..OAuthUserInfoRequest::default()
                })
                .await
                .unwrap_err();
            assert_eq!(error, "Missing Paybin ID token");
        }
        for token in [
            json!("broken"),
            json!("a.!.c"),
            json!("a.W10.c"),
            json!(42),
            json!({}),
        ] {
            let error = handler
                .get_user_info(OAuthUserInfoRequest {
                    raw: Some(json!({"id_token": token})),
                    ..OAuthUserInfoRequest::default()
                })
                .await
                .unwrap_err();
            assert!(error.starts_with("oauth-profile-exception:"), "{error}");
        }
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"sub":"paybin","email":"paybin@example.com"}"#);
        let response = handler
            .get_user_info(OAuthUserInfoRequest {
                id_token: Some(format!("header.{payload}.signature")),
                ..OAuthUserInfoRequest::default()
            })
            .await
            .unwrap();
        assert_eq!(response.data["sub"], "paybin");
        assert_eq!(response.user["email"], "paybin@example.com");
    }
}
