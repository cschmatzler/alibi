use super::{
    Arc, OAuthAuthorizationPolicy, OAuthProvider, OAuthUserInfoHandler, OAuthUserInfoRequest,
    OAuthUserInfoResponse, Value, async_trait,
};
use crate::oauth::providers::remaining_profile::ProfileResponseExt as _;
use alibi_core::utils::json::JsObject as Map;
impl OAuthProvider {
    #[must_use]
    pub fn github(client_id: &str, client_secret: &str) -> Self {
        Self::github_with_endpoints(
            client_id,
            client_secret,
            "https://github.com/login/oauth/authorize",
            "https://github.com/login/oauth/access_token",
            "https://api.github.com/user",
            "https://api.github.com/user/emails",
        )
    }

    /// Construct a GitHub provider using custom endpoints.
    ///
    /// This keeps the built-in GitHub semantics while allowing local test
    /// harnesses or GitHub Enterprise-style deployments to override the URLs.
    #[must_use]
    pub fn github_with_endpoints(
        client_id: &str,
        client_secret: &str,
        auth_url: &str,
        token_url: &str,
        user_info_url: &str,
        user_emails_url: &str,
    ) -> Self {
        Self {
            client_id: client_id.to_owned(),
            client_secret: client_secret.to_owned(),
            auth_url: auth_url.to_owned(),
            token_url: token_url.to_owned(),
            user_info_url: Some(user_info_url.to_owned()),
            scopes: vec!["read:user".to_owned(), "user:email".to_owned()],
            authorization: Some(OAuthAuthorizationPolicy {
                source_profile_exceptions: true,
                ..OAuthAuthorizationPolicy::default()
            }),
            account_subject: Some(|profile| {
                super::remaining_profile::raw_subject(profile.get("id"))
            }),
            get_user_info: Some(Arc::new(GitHubUserInfoHandler::new(
                user_info_url.to_owned(),
                user_emails_url.to_owned(),
            ))),
            ..Self::default()
        }
    }
}

#[derive(Clone)]
pub(in crate::oauth::providers) struct GitHubUserInfoHandler {
    pub(in crate::oauth::providers) user_url: String,
    pub(in crate::oauth::providers) emails_url: String,
    mapper: Option<Arc<dyn super::OAuthProfileMapper>>,
}

impl GitHubUserInfoHandler {
    pub(in crate::oauth::providers) const fn new(user_url: String, emails_url: String) -> Self {
        Self {
            user_url,
            emails_url,
            mapper: None,
        }
    }

    pub(in crate::oauth::providers) async fn fetch_json(
        &self,
        client: &reqwest::Client,
        url: &str,
        access_token: &str,
    ) -> Result<Value, String> {
        let response = client
            .get(url)
            .bearer_auth(access_token)
            .header("Accept", "application/json")
            .header("User-Agent", "better-auth")
            .send()
            .await
            .map_err(|error| format!("Failed to fetch GitHub user info: {error}"))?;

        if !response.status().is_success() {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_owned());
            return Err(format!("GitHub user info request failed: {body}"));
        }

        response
            .profile_json()
            .await
            .map_err(|error| format!("Failed to parse GitHub user info: {error}"))
    }
}

#[async_trait]
impl OAuthUserInfoHandler for GitHubUserInfoHandler {
    fn errors_are_exceptions(&self) -> bool {
        false
    }

    fn mapped_handler(
        &self,
        mapper: Arc<dyn super::OAuthProfileMapper>,
    ) -> Option<Arc<dyn OAuthUserInfoHandler>> {
        let mut handler = self.clone();
        handler.mapper = Some(mapper);
        Some(Arc::new(handler))
    }

    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        let access_token = request
            .access_token
            .as_deref()
            .ok_or("Missing access token for user-info lookup")?;

        let client = reqwest::Client::new();
        let mut profile: Value = self
            .fetch_json(&client, &self.user_url, access_token)
            .await?;
        if !super::remaining_profile::truthy(&profile) {
            return Err("Missing github profile".into());
        }
        let emails = self
            .fetch_json(&client, &self.emails_url, access_token)
            .await
            .ok()
            .and_then(|value| value.as_array().map(<[_]>::to_vec));

        let mut selected_email_index = None;
        if !profile
            .get("email")
            .is_some_and(super::remaining_profile::truthy)
            && let Some(emails) = &emails
            && let Some(profile_object) = profile.as_object_mut()
        {
            if let Some((index, record)) = emails
                .iter()
                .enumerate()
                .find(|(_, record)| record.get("primary").is_some_and(Value::is_truthy))
                .or_else(|| emails.iter().enumerate().next())
            {
                selected_email_index = Some(index);
                _ = profile_object.insert(
                    "email".to_owned().into(),
                    record.get("email").cloned().unwrap_or(Value::Undefined),
                );
            } else {
                _ = profile_object.insert("email".into(), Value::Undefined);
            }
        }

        let email = profile.get("email").unwrap_or(&Value::Undefined);
        let email_verified = emails
            .as_ref()
            .and_then(|emails| {
                emails.iter().enumerate().find(|(index, record)| {
                    // Only the fallback assignment can share an object across these responses.
                    if email.is_object() || email.is_array() {
                        selected_email_index == Some(*index)
                    } else {
                        email == record.get("email").unwrap_or(&Value::Undefined)
                    }
                })
            })
            .and_then(|(_, record)| record.get("verified"))
            .filter(|value| !value.is_null() && !value.is_undefined())
            .cloned()
            .unwrap_or(Value::Bool(false));

        let mut output = Map::new();
        _ = output.insert(
            "name".into(),
            ["name", "login"]
                .into_iter()
                .filter_map(|key| profile.get(key))
                .find(|value| super::remaining_profile::truthy(value))
                .cloned()
                .unwrap_or_else(|| Value::String(String::new().into())),
        );
        for (source, target) in [("email", "email"), ("avatar_url", "image")] {
            _ = output.insert(
                target.into(),
                profile.get(source).cloned().unwrap_or(Value::Undefined),
            );
        }
        _ = output.insert("emailVerified".into(), email_verified);
        if let Some(mapper) = &self.mapper {
            output.extend(
                mapper
                    .map_profile(profile.clone())
                    .await
                    .map_err(super::remaining_profile::profile_exception)?,
            );
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

#[cfg(test)]
mod tests {
    use super::*;
    struct Mapper;
    #[async_trait]
    impl super::super::OAuthProfileMapper for Mapper {
        async fn map_profile(&self, profile: Value) -> Result<Map, String> {
            assert_eq!(profile["email"], "primary@example.com");
            Ok(
                crate::oauth::providers::js!({"name":"Mapped","custom":true,"id":"public-id"})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
        }
    }
    #[tokio::test]
    async fn github_empty_email_list_differs_from_failed_lookup() {
        struct EmailMapper(Option<Value>);
        #[async_trait]
        impl super::super::OAuthProfileMapper for EmailMapper {
            async fn map_profile(&self, profile: Value) -> Result<Map, String> {
                assert_eq!(profile.get("email"), self.0.as_ref());
                Ok(Map::new())
            }
        }

        for email in [Value::Null, Value::String(String::new().into())] {
            for (code, failed) in [(200, false), (500, true)] {
                let profile = crate::oauth::providers::js!({"id":42,"login":"login","email":email});
                let (endpoint, server) = crate::test_helpers::serve_json_responses(vec![
                    (200, profile.to_string()),
                    (code, "[]".into()),
                ])
                .await;
                let expected_email = Some(if failed {
                    email.clone()
                } else {
                    Value::Undefined
                });
                let provider = OAuthProvider::github_with_endpoints(
                    "client", "secret", "auth", "token", &endpoint, &endpoint,
                )
                .with_profile_mapper(Arc::new(EmailMapper(expected_email.clone())));
                let response = provider
                    .get_user_info
                    .as_ref()
                    .unwrap()
                    .get_user_info(OAuthUserInfoRequest {
                        access_token: Some("access".into()),
                        ..Default::default()
                    })
                    .await
                    .unwrap();
                assert_eq!(response.data.get("email"), expected_email.as_ref());
                assert_eq!(response.user.get("email"), expected_email.as_ref());
                assert!(
                    !response
                        .user
                        .get("emailVerified")
                        .is_some_and(Value::is_truthy)
                );
                assert_eq!(response.user.get("email"), response.data.get("email"));
                server.await.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn github_maps_after_primary_email_enrichment() {
        let body = crate::oauth::providers::js!({"id":42,"login":"login","name":null,"email":null,"avatar_url":null});

        let body = body.to_string();
        let (endpoint, server) = crate::test_helpers::serve_json_once(body).await;

        let user_endpoint = endpoint;
        let user_server = server;
        let body = crate::oauth::providers::js!([
            {"email":"first@example.com","primary":false,"verified":false},
            {"email":"primary@example.com","primary":true,"verified":true}
        ]);

        let body = body.to_string();
        let (endpoint, server) = crate::test_helpers::serve_json_once(body).await;

        let provider = OAuthProvider::github_with_endpoints(
            "client",
            "secret",
            "auth",
            "token",
            &user_endpoint,
            &endpoint,
        )
        .with_profile_mapper(Arc::new(Mapper));
        let response = provider
            .get_user_info
            .as_ref()
            .unwrap()
            .get_user_info(OAuthUserInfoRequest {
                access_token: Some("access".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            response.user.get("name").and_then(Value::as_str),
            Some("Mapped")
        );
        assert_eq!(response.user["email"], "primary@example.com");
        assert!(
            response
                .user
                .get("emailVerified")
                .is_some_and(Value::is_truthy)
        );
        assert_eq!(response.user["image"], Value::Null);
        assert_eq!(response.user["id"], "public-id");
        assert_eq!(
            provider.account_subject.unwrap()(&response.data).unwrap(),
            "42"
        );
        user_server.await.unwrap();
        server.await.unwrap();
    }
}
