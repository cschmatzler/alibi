use super::remaining_profile::{decode_grant_jwt, grant_id_token, profile_exception, raw_subject};
use super::{
    OAuthAuthorizationPolicy, OAuthProfileMapper, OAuthProvider, OAuthUserInfoHandler,
    OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use alibi_core::utils::json::JsObject as Map;
use alibi_core::utils::json::JsValue as Value;
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
            client_secret: client_secret.to_owned(),
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth".to_owned(),
            token_url: "https://oauth2.googleapis.com/token".to_owned(),
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
            authorization_params: vec![("include_granted_scopes".to_owned(), "true".to_owned())],
            account_subject: Some(|profile| raw_subject(profile.get("sub"))),
            map_user_info: Some(|v| {
                let mut output = Map::new();
                _ = output.insert("id".into(), v.property("sub")?);
                for (source, target) in [("email", "email"), ("name", "name"), ("picture", "image")]
                {
                    _ = output.insert(target.into(), v.property(source)?);
                }
                _ = output.insert(
                    "emailVerified".into(),
                    Value::Bool(super::email_verified_claim(v.get("email_verified"))),
                );
                Ok(output)
            }),
            get_user_info: Some(Arc::new(GoogleUserInfo::default())),
            id_token: Some(crate::oauth::id_token::OAuthIdTokenConfig::google()),
            ..Self::default()
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
            _ = output.insert(
                target.into(),
                profile.get(source).cloned().unwrap_or(Value::Undefined),
            );
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
            user: output.clone(),
            data: profile,
            account_subject: None,
        };
        super::apply_application_mapping(&mut response, output).map_err(profile_exception)?;

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::providers::js as json;
    use base64::Engine;
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
        async fn map_profile(&self, profile: Value) -> Result<Map, String> {
            assert_eq!(profile["hd"], "workspace.test");
            Ok(json!({"name": null, "custom": [1], "id": "public"})
                .as_object()
                .unwrap()
                .clone())
        }
    }
    #[tokio::test]
    async fn google_default_user_retains_own_undefined_fields_before_json_encoding() {
        let provider = OAuthProvider::google("client", "secret");
        let response =
            crate::oauth::handlers::fetch_user_info_from_provider(&provider, request(json!({})))
                .await
                .unwrap();
        assert_eq!(response.data, json!({}));
        assert_eq!(response.user.len(), 4);
        for name in ["name", "email", "image", "emailVerified"] {
            assert_eq!(response.user.get(name), Some(&Value::Undefined), "{name}");
        }
        assert!(!response.user.contains_key("id"));
        assert_eq!(
            alibi_core::utils::json::to_string(&response.user).unwrap(),
            "{}"
        );

        struct Overrides;
        #[async_trait::async_trait]
        impl OAuthProfileMapper for Overrides {
            async fn map_profile(&self, profile: Value) -> Result<Map, String> {
                assert_eq!(profile, json!({"sub": "subject", "name": "Original"}));
                Ok([
                    ("name".into(), Value::Undefined),
                    ("email".into(), Value::Null),
                    ("image".into(), Value::Bool(false)),
                    ("emailVerified".into(), Value::Number(0.0)),
                ]
                .into_iter()
                .collect())
            }
        }
        let response = crate::oauth::handlers::fetch_user_info_from_provider(
            &provider.with_profile_mapper(Arc::new(Overrides)),
            request(json!({"sub": "subject", "name": "Original"})),
        )
        .await
        .unwrap();
        assert_eq!(response.user.get("name"), Some(&Value::Undefined));
        assert_eq!(response.user.get("email"), Some(&Value::Null));
        assert_eq!(response.user.get("image"), Some(&Value::Bool(false)));
        assert_eq!(
            response.user.get("emailVerified"),
            Some(&Value::Number(0.0))
        );
        assert_eq!(
            alibi_core::utils::json::to_string(&response.user).unwrap(),
            r#"{"email":null,"image":false,"emailVerified":0}"#,
        );
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
            assert_eq!(response.user, json!({"name":null,"email":null,"image":null,"emailVerified":"true","custom":[1],"id":"public"}).as_object().unwrap().clone());
            assert!(
                response
                    .user
                    .get("emailVerified")
                    .is_some_and(Value::is_truthy)
            );
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
        assert_eq!(
            alibi_core::utils::json::to_string(&response.user).unwrap(),
            "{}"
        );
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
