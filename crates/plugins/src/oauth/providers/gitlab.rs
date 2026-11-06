use super::{OAuthAuthorizationPolicy, OAuthProvider, OAuthUserInfo, Value};
use super::{OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse};
use async_trait::async_trait;
use serde_json::Map;
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
            additional_client_ids: Vec::new(),
            hosted_domain: None,
            require_email_verification: false,
            client_secret: client_secret.into(),
            auth_url: gitlab_endpoint(issuer, "/oauth/authorize"),
            token_url: gitlab_endpoint(issuer, "/oauth/token"),
            user_info_url: Some(gitlab_endpoint(issuer, "/api/v4/user")),
            scopes: vec!["read_user".into()],
            authorization: Some(OAuthAuthorizationPolicy::default()),
            allowed_request_params: Vec::new(),
            authorization_params: Vec::new(),
            account_subject: Some(|profile| {
                super::remaining_profile::raw_subject(profile.get("id"))
            }),
            map_user_info: Some(gitlab_user_info),
            get_user_info: Some(Arc::new(GitLabUserInfo {
                endpoint: gitlab_endpoint(issuer, "/api/v4/user"),
                mapper: None,
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
struct GitLabUserInfo {
    endpoint: String,
    mapper: Option<Arc<dyn super::OAuthProfileMapper>>,
}
#[async_trait]
impl OAuthUserInfoHandler for GitLabUserInfo {
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
            .json()
            .await
            .map_err(|error| error.to_string())?;
        let user = gitlab_user_info(profile.clone())?;
        let mut output = Map::new();
        _ = output.insert(
            "name".into(),
            profile
                .get("name")
                .filter(|value| !value.is_null())
                .or_else(|| profile.get("username").filter(|value| !value.is_null()))
                .cloned()
                .unwrap_or(Value::String(String::new())),
        );
        for (source, target) in [("email", "email"), ("avatar_url", "image")] {
            if let Some(value) = profile.get(source) {
                _ = output.insert(target.into(), value.clone());
            }
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
            output.extend(mapper.map_profile(profile.clone()).await?);
        }
        let mut response = OAuthUserInfoResponse {
            user_output: Some(output.clone()),
            user,
            data: profile,
        };
        super::apply_application_mapping(&mut response, output)?;
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
pub(in crate::oauth::providers) fn gitlab_user_info(
    profile: Value,
) -> Result<OAuthUserInfo, String> {
    let locked = profile.get("locked").is_some_and(|value| match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value
            .as_f64()
            .is_some_and(|value| value != 0.0 && !value.is_nan()),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    });
    if profile.get("state").and_then(Value::as_str) != Some("active") || locked {
        return Err("GitLab account is inactive or locked".into());
    }
    let id = match profile.get("id") {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Number(value)) => {
            alibi_core::utils::json::number_to_string(value).map_err(|error| error.to_string())?
        }
        _ => return Err("Missing GitLab account ID".into()),
    };
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
            .map(String::from),
        email_verified: profile
            .get("email_verified")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct GuardedMapper;
    #[async_trait]
    impl super::super::OAuthProfileMapper for GuardedMapper {
        async fn map_profile(&self, profile: Value) -> Result<Map<String, Value>, String> {
            assert_eq!(profile["state"], "active");
            assert_eq!(profile["locked"], false);
            Ok(
                serde_json::from_value(serde_json::json!({"id":"public-id","custom":true}))
                    .unwrap(),
            )
        }
    }
    #[tokio::test]
    async fn gitlab_admission_precedes_partial_mapping() {
        for (state, locked) in [("active", false), ("blocked", false), ("active", true)] {
            let body = serde_json::json!({"id":42,"state":state,"locked":locked,"name":"","username":"fallback","email":null,"avatar_url":null,"email_verified":"true"});

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
            let output = response.user_output.unwrap();
            assert_eq!(output["name"], "");
            assert_eq!(output["email"], Value::Null);
            assert_eq!(output["image"], Value::Null);
            assert_eq!(output["emailVerified"], "true");
            assert_eq!(output["id"], "public-id");
            assert_eq!(output["custom"], true);
            assert!(response.user.email_verified);
        }
    }

    #[test]
    fn gitlab_optional_email_does_not_reject_active_accounts() {
        let profile = serde_json::json!({"id":42,"state":"active","username":"user"});
        assert_eq!(gitlab_user_info(profile.clone()).unwrap().email, "");
        let mut profile = profile;
        profile["email"] = Value::Null;
        assert_eq!(gitlab_user_info(profile.clone()).unwrap().email, "");
        profile["locked"] = Value::Bool(true);
        assert!(gitlab_user_info(profile).is_err());
    }
}
