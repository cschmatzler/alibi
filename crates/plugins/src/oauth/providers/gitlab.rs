use super::{OAuthAuthorizationPolicy, OAuthProvider, OAuthUserInfo, Value};
use super::{OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse};
use crate::oauth::providers::remaining_profile::ProfileResponseExt as _;
use alibi_core::utils::json::JsObject as Map;
use async_trait::async_trait;
use std::sync::Arc;
impl OAuthProvider {
    /// GitLab.com social login with the published `read_user` scope and PKCE.
    #[must_use]
    pub fn gitlab(client_id: &str, client_secret: &str) -> Self {
        Self::gitlab_with_issuer(client_id, client_secret, "https://gitlab.com")
    }

    /// GitLab social login hosted at an application-configured issuer.
    ///
    /// The issuer may include a deployment path. Repeated path slashes follow
    /// the pinned provider's endpoint construction rather than URL resolution.
    pub fn gitlab_with_issuer(client_id: &str, client_secret: &str, issuer: &str) -> Self {
        let issuer = if issuer.is_empty() {
            "https://gitlab.com"
        } else {
            issuer
        };
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            auth_url: gitlab_endpoint(issuer, "/oauth/authorize"),
            token_url: gitlab_endpoint(issuer, "/oauth/token"),
            user_info_url: Some(gitlab_endpoint(issuer, "/api/v4/user")),
            scopes: vec!["read_user".into()],
            authorization: Some(OAuthAuthorizationPolicy {
                source_profile_exceptions: true,
                ..OAuthAuthorizationPolicy::default()
            }),
            account_subject: Some(|profile| {
                super::remaining_profile::raw_subject(profile.get("id"))
            }),
            map_user_info: Some(gitlab_user_info),
            get_user_info: Some(Arc::new(GitLabUserInfo {
                endpoint: gitlab_endpoint(issuer, "/api/v4/user"),
                mapper: None,
            })),
            ..Self::default()
        }
    }
}

#[derive(Clone)]
struct GitLabUserInfo {
    endpoint: String,
    mapper: Option<Arc<dyn super::OAuthProfileMapper>>,
}
#[async_trait]
impl OAuthUserInfoHandler for GitLabUserInfo {
    fn errors_are_exceptions(&self) -> bool {
        false
    }

    fn mapped_handler(
        &self,
        mapper: Arc<dyn super::OAuthProfileMapper>,
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
        let profile: Value = reqwest::Client::new()
            .get(&self.endpoint)
            .bearer_auth(request.access_token.as_deref().unwrap_or("undefined"))
            .send()
            .await
            .map_err(|error| error.to_string())?
            .error_for_status()
            .map_err(|error| error.to_string())?
            .profile_json()
            .await
            .map_err(|error| error.to_string())?;
        if profile.is_null() {
            return Err(super::remaining_profile::profile_exception(
                "Null GitLab profile",
            ));
        }
        if profile.get("state").and_then(Value::as_str) != Some("active")
            || profile.get("locked").is_some_and(Value::is_truthy)
        {
            return Err("GitLab account is inactive or locked".into());
        }
        let mut output = Map::new();
        _ = output.insert(
            "name".into(),
            profile
                .get("name")
                .filter(|value| !value.is_null())
                .or_else(|| profile.get("username").filter(|value| !value.is_null()))
                .cloned()
                .unwrap_or(Value::String(String::new().into())),
        );
        for (source, target) in [("email", "email"), ("avatar_url", "image")] {
            _ = output.insert(
                target.into(),
                profile.get(source).cloned().unwrap_or(Value::Undefined),
            );
        }
        _ = output.insert(
            "emailVerified".into(),
            profile
                .get("email_verified")
                .filter(|value| !value.is_null())
                .cloned()
                .unwrap_or(Value::Bool(false)),
        );
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

pub(in crate::oauth::providers) fn gitlab_endpoint(issuer: &str, suffix: &str) -> String {
    format!("{issuer}{suffix}")
        .split("://")
        .map(|part| {
            let mut previous_slash = false;
            part.chars()
                .filter(|character| {
                    let slash = *character == '/';
                    let retain = !slash || !previous_slash;
                    previous_slash = slash;
                    retain
                })
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("://")
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "Match the public provider callback type, which owns its JSON profile"
)]
pub(in crate::oauth::providers) fn gitlab_user_info(profile: Value) -> Result<Map, String> {
    let locked = profile.get("locked").is_some_and(|value| match value {
        Value::Null | Value::Undefined => false,
        Value::Bool(value) => *value,
        Value::Number(value) => *value != 0.0 && !value.is_nan(),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) | Value::Date(_) => true,
    });
    if profile.get("state").and_then(Value::as_str) != Some("active") || locked {
        return Err("GitLab account is inactive or locked".into());
    }
    let id = super::remaining_profile::raw_subject(profile.get("id")).unwrap_or_default();
    Ok(OAuthUserInfo {
        additional_fields: Map::default(),
        id,
        email: profile
            .get("email")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .into(),
        name: Some(
            profile
                .get("name")
                .filter(|value| !value.is_null())
                .or_else(|| profile.get("username").filter(|value| !value.is_null()))
                .and_then(Value::as_str)
                .unwrap_or("")
                .into(),
        ),
        image: profile
            .get("avatar_url")
            .and_then(Value::as_str)
            .map(Into::into),
        email_verified: profile
            .get("email_verified")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    }
    .public_profile(true))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct GuardedMapper;
    #[async_trait]
    impl super::super::OAuthProfileMapper for GuardedMapper {
        async fn map_profile(&self, profile: Value) -> Result<Map, String> {
            assert_eq!(profile["state"], "active");
            assert_eq!(profile["locked"], false);
            Ok(alibi_core::utils::json::from_value(
                crate::oauth::providers::js!({"id":"public-id","custom":true}),
            )
            .unwrap())
        }
    }
    #[tokio::test]
    async fn gitlab_admission_precedes_partial_mapping() {
        for (state, locked) in [("active", false), ("blocked", false), ("active", true)] {
            let body = crate::oauth::providers::js!({"id":42,"state":state,"locked":locked,"name":"","username":"fallback","email":null,"avatar_url":null,"email_verified":"true"});

            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let body = body.to_string();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0; 8192];
                let _ = stream.read(&mut request).await.unwrap();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            });

            let provider = OAuthProvider::gitlab_with_issuer("client", "secret", &endpoint)
                .with_profile_mapper(Arc::new(GuardedMapper));
            let response = provider
                .get_user_info
                .as_ref()
                .unwrap()
                .get_user_info(OAuthUserInfoRequest {
                    access_token: Some("access".into()),
                    ..Default::default()
                })
                .await;
            server.await.unwrap();
            if state != "active" || locked {
                assert!(response.is_err());
                continue;
            }
            let response = response.unwrap();
            assert_eq!(
                (provider.account_subject.unwrap())(&response.data).unwrap(),
                "42"
            );
            let output = response.user.clone();
            assert_eq!(output["name"], "");
            assert_eq!(output["email"], Value::Null);
            assert_eq!(output["image"], Value::Null);
            assert_eq!(output["emailVerified"], "true");
            assert_eq!(output["id"], "public-id");
            assert_eq!(output["custom"], true);
            assert!(
                response
                    .user
                    .get("emailVerified")
                    .is_some_and(Value::is_truthy)
            );
        }
    }

    #[test]
    fn gitlab_optional_email_does_not_reject_active_accounts() {
        let profile = crate::oauth::providers::js!({"id":42,"state":"active","username":"user"});
        assert_eq!(gitlab_user_info(profile.clone()).unwrap()["email"], "");
        let mut profile = profile;
        profile["email"] = Value::Null;
        assert_eq!(gitlab_user_info(profile.clone()).unwrap()["email"], "");
        profile["locked"] = Value::Bool(true);
        assert!(gitlab_user_info(profile).is_err());
    }
}
