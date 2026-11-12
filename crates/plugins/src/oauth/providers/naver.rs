//! Naver's resultcode gate and original envelope account authority.
use super::remaining_profile::truthy;
use super::{
    OAuthAuthorizationPolicy, OAuthProvider, OAuthUserInfoHandler, OAuthUserInfoRequest,
    OAuthUserInfoResponse,
};
use alibi_core::utils::json::JsObject as Map;
use alibi_core::utils::json::{JsString, JsValue as Value};
use async_trait::async_trait;

/// Application-owned Naver configuration. Generic signup and asynchronous
/// user-info/refresh callbacks remain configurable on the returned provider.
#[derive(Clone, Default)]
pub struct NaverOptions {
    pub client_id: String,
    pub client_secret: Option<String>,
    /// Sent only during authorization-code exchange.
    pub client_key: Option<String>,
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    pub authorization_endpoint: Option<String>,
    pub redirect_uri: Option<String>,
    /// Trusted transport override retaining Naver's actual GET and mapping.
    pub user_info_endpoint: Option<String>,
    /// Receives the original profile before its raw account identity is resolved.
    pub map_profile_to_user: Option<fn(Value) -> Result<Map, String>>,
}
impl NaverOptions {
    #[must_use]
    pub fn new(client_id: impl Into<String>, client_secret: Option<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret,
            ..Self::default()
        }
    }
}
impl std::fmt::Debug for NaverOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NaverOptions")
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
    pub fn naver(client_id: &str, client_secret: Option<&str>) -> Self {
        Self::naver_with_options(NaverOptions::new(
            client_id,
            client_secret.map(str::to_owned),
        ))
    }
    #[must_use]
    pub fn naver_with_options(options: NaverOptions) -> Self {
        let secret = options.client_secret.unwrap_or_default();
        let authentication = super::client_secret_auth(Some(&secret));
        let endpoint = options
            .user_info_endpoint
            .unwrap_or_else(|| "https://openapi.naver.com/v1/nid/me".into());
        Self {
            client_id: options.client_id,
            client_secret: secret,
            auth_url: options
                .authorization_endpoint
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "https://nid.naver.com/oauth2.0/authorize".into()),
            token_url: "https://nid.naver.com/oauth2.0/token".into(),
            user_info_url: Some(endpoint.clone()),
            scopes: ["profile", "email"].map(String::from).to_vec(),
            authorization: Some(OAuthAuthorizationPolicy {
                allow_missing_access_token: true,
                source_profile_exceptions: true,
                preserve_raw_profile_scalars: true,
                preserve_raw_email_errors: true,
                configured_scopes: options.scope,
                disable_default_scopes: options.disable_default_scope,
                require_client_id: true,
                token_endpoint_auth: Some(authentication),
                authorization_code_client_key: options.client_key,
                redirect_uri: options.redirect_uri,
                login_hint: false,
                pkce: false,
                ..OAuthAuthorizationPolicy::default()
            }),
            account_subject: Some(subject),
            get_user_info: Some(std::sync::Arc::new(NaverUserInfo {
                endpoint,
                application_mapper: None,
                mapper: options.map_profile_to_user,
            })),
            ..Self::default()
        }
    }
}
#[derive(Clone)]
struct NaverUserInfo {
    endpoint: String,
    application_mapper: Option<std::sync::Arc<dyn super::OAuthProfileMapper>>,
    mapper: Option<fn(Value) -> Result<Map, String>>,
}
#[async_trait]
impl OAuthUserInfoHandler for NaverUserInfo {
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
        let response: Value = super::remaining_profile::send_profile_json(
            reqwest::Client::new()
                .get(&self.endpoint)
                .bearer_auth(access_token),
        )
        .await?;
        let profile = response;
        if profile.get("resultcode").and_then(Value::as_str) != Some("00") {
            return Err("Invalid Naver resultcode".into());
        }
        let account = profile.get("response");
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
        // Keep Source's original JSON publication separate from typed persistence.
        let mut output = Map::new();
        let name = account
            .and_then(|value| value.get("name"))
            .filter(|value| truthy(value))
            .or_else(|| {
                account
                    .and_then(|value| value.get("nickname"))
                    .filter(|value| truthy(value))
            })
            .cloned()
            .unwrap_or_else(|| Value::String(String::new().into()));
        _ = output.insert("name".into(), name);
        for (public, remote) in [("email", "email"), ("image", "profile_image")] {
            _ = output.insert(
                public.into(),
                account
                    .and_then(|value| value.get(remote))
                    .cloned()
                    .unwrap_or(Value::Undefined),
            );
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
fn subject(profile: &Value) -> Result<JsString, String> {
    super::remaining_profile::raw_subject(profile.get("response").and_then(|value| value.get("id")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::providers::js as json;

    #[tokio::test]
    async fn naver_preserves_compound_public_fields() {
        let policy = OAuthProvider::naver("client", None).authorization.unwrap();
        assert!(policy.preserve_raw_profile_scalars);
        assert!(policy.preserve_raw_email_errors);
        let profile = json!({"resultcode": "00", "response": {"id": "naver", "name": {}, "nickname": "ignored", "email": ["raw"], "profile_image": []}});
        let (endpoint, captured) = crate::test_helpers::serve_json_capturing_request(profile).await;
        let response = NaverUserInfo {
            endpoint,
            mapper: None,
            application_mapper: None,
        }
        .get_user_info(OAuthUserInfoRequest::default())
        .await
        .unwrap();
        captured.await.unwrap();
        let output = response.user.clone();
        assert_eq!(output["name"], json!({}));
        assert_eq!(output["email"], json!(["raw"]));
        assert_eq!(output["image"], json!([]));
    }

    #[tokio::test]
    async fn naver_account_subject_uses_javascript_string_coercion() {
        for (id, expected) in [
            (json!({}), "[object Object]"),
            (json!([1, 2]), "1,2"),
            (json!(false), "false"),
        ] {
            let profile = json!({"resultcode": "00", "response": {"id": id}});
            assert_eq!(subject(&profile).unwrap(), expected);
            let (endpoint, captured) =
                crate::test_helpers::serve_json_capturing_request(profile).await;
            let response = NaverUserInfo {
                endpoint,
                mapper: None,
                application_mapper: None,
            }
            .get_user_info(OAuthUserInfoRequest::default())
            .await
            .unwrap();
            captured.await.unwrap();
            assert!(!response.user.contains_key("id"));
            assert_eq!(subject(&response.data).unwrap(), expected);
        }
        for id in [
            json!(null),
            json!([]),
            json!("undefined"),
            json!("\u{feff}"),
        ] {
            assert!(subject(&json!({"response": {"id": id}})).is_err());
        }
    }

    struct Mapper {
        expected: Value,
        fail: bool,
    }

    #[async_trait]
    impl super::super::OAuthProfileMapper for Mapper {
        async fn map_profile(&self, profile: Value) -> Result<Map, String> {
            assert_eq!(profile, self.expected);
            if self.fail {
                return Err("mapping failed".into());
            }
            Ok(json!({"name": "mapped", "custom": 42})
                .as_object()
                .unwrap()
                .clone())
        }
    }

    #[tokio::test]
    async fn naver_async_mapper_receives_envelope_and_merges_partial_fields() {
        let profile = json!({"resultcode": "00", "response": {"id": "original", "email": "original@example.com"}});
        for fail in [false, true] {
            let (endpoint, captured) =
                crate::test_helpers::serve_json_capturing_request(profile.clone()).await;
            let mut options = NaverOptions::new("client", None);
            options.user_info_endpoint = Some(endpoint);
            let provider = OAuthProvider::naver_with_options(options).with_profile_mapper(
                std::sync::Arc::new(Mapper {
                    expected: profile.clone(),
                    fail,
                }),
            );
            assert!(
                provider
                    .authorization
                    .as_ref()
                    .unwrap()
                    .source_profile_exceptions
            );
            let response = provider
                .get_user_info
                .unwrap()
                .get_user_info(OAuthUserInfoRequest::default())
                .await;
            captured.await.unwrap();
            if fail {
                assert_eq!(
                    response.unwrap_err(),
                    "oauth-profile-exception:mapping failed"
                );
            } else {
                let response = response.unwrap();
                assert_eq!(response.data, profile);
                assert_eq!(subject(&response.data).unwrap(), "original");
                let output = response.user.clone();
                assert_eq!(output["name"], "mapped");
                assert_eq!(output["email"], "original@example.com");
                assert_eq!(output["emailVerified"], false);
                assert_eq!(output["custom"], 42);
            }
        }
    }

    #[tokio::test]
    async fn naver_resultcode_failures_are_not_profile_exceptions() {
        for profile in [
            json!(null),
            json!({"resultcode": 0}),
            json!({"resultcode": "01"}),
        ] {
            let (endpoint, captured) =
                crate::test_helpers::serve_json_capturing_request(profile).await;
            let handler = NaverUserInfo {
                endpoint,
                mapper: None,
                application_mapper: None,
            };
            assert!(!handler.errors_are_exceptions());
            assert_eq!(
                handler
                    .get_user_info(OAuthUserInfoRequest::default())
                    .await
                    .unwrap_err(),
                "Invalid Naver resultcode"
            );
            captured.await.unwrap();
        }
        let handler = NaverUserInfo {
            endpoint: "http://127.0.0.1:0".into(),
            mapper: None,
            application_mapper: None,
        };
        assert!(!handler.errors_are_exceptions());
        assert!(
            handler
                .get_user_info(OAuthUserInfoRequest::default())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn naver_bearer_uses_raw_token_without_requiring_access_token() {
        assert!(
            OAuthProvider::naver("client", None)
                .authorization
                .unwrap()
                .allow_missing_access_token
        );
        for (raw, expected) in [
            (None, "undefined"),
            (Some(json!({"access_token": 42})), "42"),
        ] {
            let (endpoint, captured) = crate::test_helpers::serve_json_capturing_request(
                json!({"resultcode": "00", "response": {"id": "naver-id"}}),
            )
            .await;
            let handler = NaverUserInfo {
                endpoint,
                mapper: None,
                application_mapper: None,
            };
            handler
                .get_user_info(OAuthUserInfoRequest {
                    raw,
                    ..OAuthUserInfoRequest::default()
                })
                .await
                .unwrap();
            let request = captured.await.unwrap().to_ascii_lowercase();
            assert!(
                request.contains(&format!("authorization: bearer {expected}\r\n")),
                "{request}"
            );
        }
    }
}
