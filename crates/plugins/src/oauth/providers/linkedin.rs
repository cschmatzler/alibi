//! `LinkedIn`'s non-PKCE grants and original subject with nullish email verification.
use super::{
    OAuthAuthorizationPolicy, OAuthProvider, OAuthUserInfoHandler, OAuthUserInfoRequest,
    OAuthUserInfoResponse,
};
use alibi_core::utils::json::JsObject as Map;
use alibi_core::utils::json::{JsString, JsValue as Value};
use async_trait::async_trait;

/// Application-owned `LinkedIn` configuration. Generic signup and asynchronous
/// user-info/refresh callbacks remain configurable on the returned provider.
#[derive(Clone, Default)]
pub struct LinkedInOptions {
    pub client_id: String,
    pub client_secret: Option<String>,
    /// Sent only during authorization-code exchange.
    pub client_key: Option<String>,
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    pub authorization_endpoint: Option<String>,
    pub redirect_uri: Option<String>,
    /// Trusted transport override retaining `LinkedIn`'s actual GET and mapping.
    pub user_info_endpoint: Option<String>,
    /// Receives the original profile before its raw account identity is resolved.
    pub map_profile_to_user: Option<fn(Value) -> Result<Map, String>>,
}
impl LinkedInOptions {
    #[must_use]
    pub fn new(client_id: impl Into<String>, client_secret: Option<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret,
            ..Self::default()
        }
    }
}
impl std::fmt::Debug for LinkedInOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LinkedInOptions")
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
    pub fn linkedin(client_id: &str, client_secret: Option<&str>) -> Self {
        Self::linkedin_with_options(LinkedInOptions::new(
            client_id,
            client_secret.map(str::to_owned),
        ))
    }
    #[must_use]
    pub fn linkedin_with_options(options: LinkedInOptions) -> Self {
        let secret = options.client_secret.unwrap_or_default();
        let authentication = super::client_secret_auth(Some(&secret));
        let endpoint = options
            .user_info_endpoint
            .unwrap_or_else(|| "https://api.linkedin.com/v2/userinfo".into());
        Self {
            client_id: options.client_id,
            client_secret: secret,
            auth_url: options
                .authorization_endpoint
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "https://www.linkedin.com/oauth/v2/authorization".into()),
            token_url: "https://www.linkedin.com/oauth/v2/accessToken".into(),
            user_info_url: Some(endpoint.clone()),
            scopes: ["profile", "email", "openid"].map(String::from).to_vec(),
            authorization: Some(OAuthAuthorizationPolicy {
                source_profile_exceptions: true,
                configured_scopes: options.scope,
                disable_default_scopes: options.disable_default_scope,
                require_client_id: true,
                token_endpoint_auth: Some(authentication),
                authorization_code_client_key: options.client_key,
                redirect_uri: options.redirect_uri,
                login_hint: true,
                pkce: false,
                ..OAuthAuthorizationPolicy::default()
            }),
            account_subject: Some(subject),
            get_user_info: Some(std::sync::Arc::new(LinkedInUserInfo {
                endpoint,
                mapper: options.map_profile_to_user,
                application_mapper: None,
            })),
            ..Self::default()
        }
    }
}
#[derive(Clone)]
struct LinkedInUserInfo {
    endpoint: String,
    mapper: Option<fn(Value) -> Result<Map, String>>,
    application_mapper: Option<std::sync::Arc<dyn super::OAuthProfileMapper>>,
}
#[async_trait]
impl OAuthUserInfoHandler for LinkedInUserInfo {
    fn errors_are_exceptions(&self) -> bool {
        false
    }

    fn mapped_handler(
        &self,
        mapper: std::sync::Arc<dyn super::OAuthProfileMapper>,
    ) -> Option<std::sync::Arc<dyn OAuthUserInfoHandler>> {
        let mut handler = self.clone();
        handler.application_mapper = Some(mapper);
        Some(std::sync::Arc::new(handler))
    }

    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        let access_token = request
            .access_token
            .ok_or("Missing LinkedIn access token")?;
        let response: Value = super::remaining_profile::send_profile_json(
            reqwest::Client::new()
                .get(&self.endpoint)
                .bearer_auth(access_token),
        )
        .await?;
        let profile = response;
        let mut output = Map::new();
        for (value, target) in [
            (profile.get("name"), "name"),
            (profile.get("email"), "email"),
        ] {
            _ = output.insert(target.into(), value.cloned().unwrap_or(Value::Undefined));
        }
        _ = output.insert(
            "emailVerified".into(),
            profile
                .get("email_verified")
                .filter(|value| !value.is_null())
                .cloned()
                .unwrap_or(Value::Bool(false)),
        );
        _ = output.insert(
            "image".into(),
            profile.get("picture").cloned().unwrap_or(Value::Undefined),
        );
        if let Some(mapper) = self.mapper {
            output.extend(
                mapper(profile.clone()).map_err(super::remaining_profile::profile_exception)?,
            );
        }
        if let Some(mapper) = &self.application_mapper {
            output.extend(
                mapper
                    .map_profile(profile.clone())
                    .await
                    .map_err(super::remaining_profile::profile_exception)?,
            );
        }
        if profile.is_null() {
            return Err(super::remaining_profile::profile_exception(
                "Null linkedin profile",
            ));
        }
        let mut response = OAuthUserInfoResponse {
            user: output.clone(),
            data: profile,
            account_subject: None,
        };
        super::apply_application_mapping(&mut response, output)
            .map_err(super::remaining_profile::profile_exception)?;
        Ok(response)
    }
}
fn subject(profile: &Value) -> Result<JsString, String> {
    super::remaining_profile::raw_subject(profile.get("sub"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn linkedin_http_default_own_undefined_fields() {
        for (profile, expected_wire, undefined_keys) in [
            (
                crate::oauth::providers::js!({"sub":"raw-id"}),
                crate::oauth::providers::js!({"emailVerified":false}),
                &["name", "email", "image"][..],
            ),
            (
                crate::oauth::providers::js!({"sub":"raw-id","name":null,"email":null,"picture":null,"email_verified":null}),
                crate::oauth::providers::js!({"name":null,"email":null,"image":null,"emailVerified":false}),
                &[][..],
            ),
            (
                crate::oauth::providers::js!({"sub":"raw-id","name":0,"email":false,"picture":0,"email_verified":0}),
                crate::oauth::providers::js!({"name":0,"email":false,"image":0,"emailVerified":0}),
                &[][..],
            ),
        ] {
            for mapped in [false, true] {
                let wire_profile = profile.clone();
                let body = alibi_core::utils::json::stringify(&wire_profile)
                    .unwrap()
                    .unwrap();
                let (endpoint, server) = crate::test_helpers::serve_json_once(body).await;
                let mut options = LinkedInOptions::new("client", Some("secret".into()));
                options.user_info_endpoint = Some(endpoint);
                if mapped {
                    options.map_profile_to_user = Some(|_| {
                        Ok(
                            crate::oauth::providers::js!({"name":"Static", "custom":true})
                                .as_object()
                                .unwrap()
                                .clone(),
                        )
                    });
                }
                let mut provider = OAuthProvider::linkedin_with_options(options);
                if mapped {
                    provider = provider.with_profile_mapper(Arc::new(
                        super::super::test_support::SparseProfileMapper(profile.clone()),
                    ));
                }
                let response = super::super::test_support::access_token_profile(&provider)
                    .await
                    .unwrap();
                server.await.unwrap();
                assert_eq!(response.data, profile);
                assert_eq!(
                    (provider.account_subject.unwrap())(&response.data).unwrap(),
                    "raw-id"
                );

                let (expected_wire, undefined_keys) = if mapped {
                    (
                        crate::oauth::providers::js!({
                            "id":"public-id", "name":null, "email":null,
                            "emailVerified":0, "custom":false
                        }),
                        &["image"][..],
                    )
                } else {
                    (expected_wire.clone(), undefined_keys)
                };
                super::super::test_support::assert_undefined_wire_fields(
                    response.user,
                    mapped,
                    expected_wire.clone(),
                    undefined_keys,
                );
            }
        }
    }

    #[tokio::test]
    async fn linkedin_http_partial_profile_mapping() {
        for mapped in [false, true] {
            let mut profile = crate::oauth::providers::js!({"sub":"raw-id","name":"Original","handle":"Original","email":null,"profile_photo_url":null,"img_url":null,"picture":null,"profile_picture":null,"avatarUrl":null,"email_verified":"true"});
            if mapped {
                profile["name"] = crate::oauth::providers::js!({"requiresMapping": true});
            }
            let body = (profile.clone()).to_string();
            let (endpoint, server) = crate::test_helpers::serve_json_once(body).await;
            let mut options = LinkedInOptions::new("client", Some("secret".into()));
            options.user_info_endpoint = Some(endpoint);
            let mut provider = OAuthProvider::linkedin_with_options(options);
            if mapped {
                provider = provider.with_profile_mapper(Arc::new(
                    super::super::test_support::PartialProfileMapper(profile.clone()),
                ));
            }
            let response = super::super::test_support::access_token_profile(&provider)
                .await
                .unwrap();
            server.await.unwrap();
            assert_eq!(response.data, profile);
            assert_eq!(
                (provider.account_subject.unwrap())(&response.data).unwrap(),
                "raw-id"
            );
            super::super::test_support::assert_partial_profile_mapping(&response.user, mapped);
        }
    }
}
