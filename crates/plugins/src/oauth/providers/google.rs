use super::remaining_profile::{decode_grant_jwt, grant_id_token, profile_exception, raw_subject};
use super::{
    OAuthAuthorizationPolicy, OAuthProfileMapper, OAuthProvider, OAuthUserInfo,
    OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use serde_json::Map;
use serde_json::Value;
use std::sync::Arc;
impl OAuthProvider {
    #[must_use]
    pub fn with_hosted_domain(mut self, domain: impl Into<String>) -> Self {
        let domain = domain.into();
        self.authorization_params.retain(|(key, _)| key != "hd");
        self.authorization_params
            .push(("hd".into(), domain.clone()));
        if let Some(handler) = self
            .get_user_info
            .as_ref()
            .and_then(|handler| handler.configured_hosted_domain(&domain))
        {
            self.get_user_info = Some(handler);
        }
        self.hosted_domain = Some(domain);
        self
    }

    #[must_use]
    pub fn google(client_id: &str, client_secret: &str) -> Self {
        Self {
            client_id: client_id.to_owned(),
            additional_client_ids: Vec::new(),
            hosted_domain: None,
            require_email_verification: false,
            client_secret: client_secret.to_owned(),
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth".to_owned(),
            token_url: "https://oauth2.googleapis.com/token".to_owned(),
            user_info_url: None,
            scopes: vec![
                "email".to_owned(),
                "profile".to_owned(),
                "openid".to_owned(),
            ],
            authorization: Some(OAuthAuthorizationPolicy {
                require_client_secret: true,
                source_profile_exceptions: true,
                preserve_raw_email_errors: true,
                preserve_raw_profile_scalars: true,
                ..Default::default()
            }),
            allowed_request_params: Vec::new(),
            authorization_params: vec![("include_granted_scopes".to_owned(), "true".to_owned())],
            account_subject: Some(|profile| raw_subject(profile.get("sub"))),
            map_user_info: Some(|v| {
                Ok(OAuthUserInfo {
                    additional_fields: Map::default(),
                    id: v
                        .get("sub")
                        .and_then(|v| v.as_str())
                        .ok_or("missing sub")?
                        .to_owned(),
                    email: v
                        .get("email")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_owned(),
                    name: v.get("name").and_then(|v| v.as_str()).map(String::from),
                    image: v.get("picture").and_then(|v| v.as_str()).map(String::from),
                    // Google may send the claim as the string "true"; One Tap
                    // reads the mapped value with Better Auth's `toBoolean`.
                    email_verified: v.get("email_verified").is_some_and(|value| {
                        value.as_bool() == Some(true) || value.as_str() == Some("true")
                    }),
                })
            }),
            get_user_info: Some(Arc::new(GoogleUserInfo::default())),
            refresh_access_token: None,
            verify_id_token: None,
            id_token: Some(crate::oauth::id_token::OAuthIdTokenConfig::google()),
            disable_id_token_sign_in: false,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            allow_idp_initiated: false,
            override_user_info_on_sign_in: false,
        }
    }
}

#[derive(Clone, Default)]
struct GoogleUserInfo {
    hosted_domain: Option<String>,
    mapper: Option<Arc<dyn OAuthProfileMapper>>,
}
#[async_trait::async_trait]
impl OAuthUserInfoHandler for GoogleUserInfo {
    fn errors_are_exceptions(&self) -> bool {
        false
    }
    fn configured_hosted_domain(&self, domain: &str) -> Option<Arc<dyn OAuthUserInfoHandler>> {
        Some(Arc::new(Self {
            hosted_domain: Some(domain.into()),
            ..self.clone()
        }))
    }
    fn mapped_handler(
        &self,
        mapper: Arc<dyn OAuthProfileMapper>,
    ) -> Option<Arc<dyn OAuthUserInfoHandler>> {
        Some(Arc::new(Self {
            mapper: Some(mapper),
            ..self.clone()
        }))
    }
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        let token = grant_id_token(&request)
            .map_err(profile_exception)?
            .ok_or("Missing Google ID token")?;
        let profile = decode_grant_jwt(&token).map_err(profile_exception)?;
        if self
            .hosted_domain
            .as_deref()
            .filter(|domain| !domain.is_empty())
            .is_some_and(|domain| {
                profile
                    .get("hd")
                    .and_then(Value::as_str)
                    .is_none_or(|claim| claim.is_empty() || (domain != "*" && domain != claim))
            })
        {
            return Err("Hosted domain mismatch".into());
        }
        let mut output = Map::new();
        for (source, target) in [
            ("name", "name"),
            ("email", "email"),
            ("picture", "image"),
            ("email_verified", "emailVerified"),
        ] {
            if let Some(value) = profile.get(source) {
                output.insert(target.into(), value.clone());
            }
        }
        if let Some(mapper) = &self.mapper {
            output.extend(
                mapper
                    .map_profile(profile.clone())
                    .await
                    .map_err(profile_exception)?,
            );
        }
        let mut response = OAuthUserInfoResponse {
            user_output: Some(output.clone()),
            user: OAuthUserInfo {
                additional_fields: Map::new(),
                id: String::new(),
                email: String::new(),
                name: None,
                image: None,
                email_verified: false,
            },
            data: profile,
        };
        super::apply_application_mapping(&mut response, output).map_err(profile_exception)?;
        response.user.id = raw_subject(response.data.get("sub")).unwrap_or_default();
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use serde_json::json;
    fn request(profile: Value) -> OAuthUserInfoRequest {
        OAuthUserInfoRequest {
            id_token: Some(format!(
                "header.{}.signature",
                base64::engine::general_purpose::STANDARD.encode(profile.to_string())
            )),
            ..Default::default()
        }
    }
    struct Mapper;
    #[async_trait::async_trait]
    impl OAuthProfileMapper for Mapper {
        async fn map_profile(&self, profile: Value) -> Result<Map<String, Value>, String> {
            assert_eq!(profile["hd"], "workspace.test");
            Ok(json!({"name": null, "custom": [1], "id": "public"})
                .as_object()
                .unwrap()
                .clone())
        }
    }
    #[tokio::test]
    async fn google_mapping_preserves_raw_nulls_and_hosted_domain_builder_order() {
        for provider in [
            OAuthProvider::google("client", "secret")
                .with_hosted_domain("workspace.test")
                .with_profile_mapper(Arc::new(Mapper)),
            OAuthProvider::google("client", "secret")
                .with_profile_mapper(Arc::new(Mapper))
                .with_hosted_domain("workspace.test"),
        ] {
            let profile = json!({"sub":"subject", "hd":"workspace.test", "name":"Original", "email":null, "picture":null, "email_verified":"true"});
            let response = crate::oauth::handlers::fetch_user_info_from_provider(
                &provider,
                request(profile.clone()),
            )
            .await
            .unwrap();
            assert_eq!(response.data, profile);
            assert_eq!(response.user_output.unwrap(), json!({"name":null,"email":null,"image":null,"emailVerified":"true","custom":[1],"id":"public"}).as_object().unwrap().clone());
            assert!(response.user.email_verified);
            assert!(
                crate::oauth::handlers::fetch_user_info_from_provider(
                    &provider,
                    request(json!({"hd":"other"}))
                )
                .await
                .unwrap_err()
                .to_string()
                .contains("Hosted domain mismatch")
            );
        }
        let response = crate::oauth::handlers::fetch_user_info_from_provider(
            &OAuthProvider::google("client", "secret"),
            request(json!({})),
        )
        .await
        .unwrap();
        assert!(response.user_output.unwrap().is_empty());
    }
    #[tokio::test]
    async fn google_invalid_tokens_throw_but_absent_tokens_and_domain_rejections_do_not() {
        use alibi_core::AuthError;
        let provider = OAuthProvider::google("client", "secret");
        for token in ["bad", "h.e30=.s.extra", "h.bnVsbA==.s", "h.W10=.s"] {
            let error = crate::oauth::handlers::fetch_user_info_from_provider(
                &provider,
                OAuthUserInfoRequest {
                    id_token: Some(token.into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
            assert!(
                matches!(error, AuthError::Api {code:Some(ref code), ..} if code == "OAUTH_PROFILE_EXCEPTION"),
                "{error}"
            );
        }
        for request in [
            OAuthUserInfoRequest::default(),
            OAuthUserInfoRequest {
                id_token: Some(String::new()),
                ..Default::default()
            },
        ] {
            let error = crate::oauth::handlers::fetch_user_info_from_provider(&provider, request)
                .await
                .unwrap_err();
            assert!(!matches!(error, AuthError::Api { .. }));
        }
    }
    struct Custom;
    #[async_trait::async_trait]
    impl OAuthUserInfoHandler for Custom {
        async fn get_user_info(
            &self,
            _: OAuthUserInfoRequest,
        ) -> Result<OAuthUserInfoResponse, String> {
            Err("custom failure".into())
        }
    }
    #[tokio::test]
    async fn google_custom_handler_keeps_precedence_over_mapping_and_domain() {
        let mut provider = OAuthProvider::google("client", "secret")
            .with_hosted_domain("workspace.test")
            .with_profile_mapper(Arc::new(Mapper));
        provider.get_user_info = Some(Arc::new(Custom));
        provider = provider
            .with_profile_mapper(Arc::new(Mapper))
            .with_hosted_domain("other");
        let error = crate::oauth::handlers::fetch_user_info_from_provider(
            &provider,
            OAuthUserInfoRequest::default(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error, alibi_core::AuthError::Api {code:Some(ref code), ..} if code == "OAUTH_PROFILE_EXCEPTION")
        );
    }
    #[tokio::test]
    async fn google_requires_id_token_for_default_profile_lookup() {
        let provider = OAuthProvider::google("client", "secret");
        let error = crate::oauth::handlers::fetch_user_info_from_provider(
            &provider,
            crate::oauth::OAuthUserInfoRequest {
                access_token: Some("access-token".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("Missing Google ID token"),
            "{error}"
        );
    }
}
