//! Atlassian's published scope, PKCE, fixed audience and stable account subject.
use super::{OAuthAuthorizationPolicy, OAuthProvider, OAuthUserInfo};
use crate::oauth::providers::remaining_profile::ProfileResponseExt as _;
use alibi_core::utils::json::JsObject as Map;
use alibi_core::utils::json::{JsString, JsValue as Value};

/// Atlassian-specific configuration; callback and persistence policies remain
/// configurable on the returned OAuth provider.
#[derive(Clone)]
pub struct AtlassianOptions {
    pub client_id: String,
    pub client_secret: String,
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    pub prompt: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub redirect_uri: Option<String>,
    /// Trusted user-info transport endpoint, retaining the Atlassian mapping.
    pub user_info_endpoint: Option<String>,
    /// Receives the original profile. Its ID cannot replace `account_id`.
    pub map_profile_to_user: Option<fn(Value) -> Result<Map, String>>,
}
impl AtlassianOptions {
    #[must_use]
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            scope: Vec::new(),
            disable_default_scope: false,
            prompt: None,
            authorization_endpoint: None,
            redirect_uri: None,
            user_info_endpoint: None,
            map_profile_to_user: None,
        }
    }
}
impl std::fmt::Debug for AtlassianOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AtlassianOptions")
            .field("client_id", &self.client_id)
            .field("scope", &self.scope)
            .field("disable_default_scope", &self.disable_default_scope)
            .field("prompt", &self.prompt)
            .field("authorization_endpoint", &self.authorization_endpoint)
            .field("redirect_uri", &self.redirect_uri)
            .finish_non_exhaustive()
    }
}
impl OAuthProvider {
    #[must_use]
    pub fn atlassian(client_id: &str, client_secret: &str) -> Self {
        Self::atlassian_with_options(AtlassianOptions::new(client_id, client_secret))
    }
    #[must_use]
    pub fn atlassian_with_options(options: AtlassianOptions) -> Self {
        let mut provider = Self {
            client_id: options.client_id,
            client_secret: options.client_secret,
            account_subject: Some(subject),
            ..Self::default()
        };
        provider.auth_url = options
            .authorization_endpoint
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "https://auth.atlassian.com/authorize".into());
        provider.token_url = "https://auth.atlassian.com/oauth/token".into();
        provider.user_info_url = Some(
            options
                .user_info_endpoint
                .unwrap_or_else(|| "https://api.atlassian.com/me".into()),
        );
        provider.scopes = vec!["read:jira-user".into(), "offline_access".into()];
        provider.authorization = Some(OAuthAuthorizationPolicy {
            source_profile_exceptions: true,
            configured_scopes: options.scope,
            disable_default_scopes: options.disable_default_scope,
            prompt: options.prompt,
            redirect_uri: options.redirect_uri,
            require_client_secret: true,
            login_hint: false,
            ..OAuthAuthorizationPolicy::default()
        });
        provider.authorization_params = vec![("audience".into(), "api.atlassian.com".into())];
        provider.map_user_info = Some(atlassian_user_info);
        provider.account_subject = Some(subject);
        provider.get_user_info = Some(std::sync::Arc::new(AtlassianMappedUserInfo {
            url: provider.user_info_url.clone().unwrap_or_default(),
            mapper: options.map_profile_to_user,
            application_mapper: None,
        }));
        provider
    }
}
fn subject(profile: &Value) -> Result<JsString, String> {
    super::remaining_profile::raw_subject(profile.get("account_id"))
}
#[expect(
    clippy::needless_pass_by_value,
    reason = "signature fixed by the map_user_info callback type"
)]
fn atlassian_user_info(profile: Value) -> Result<Map, String> {
    let name = super::remaining_profile::scalar(profile.get("name"))?.unwrap_or_default();
    Ok(OAuthUserInfo {
        additional_fields: Map::default(),
        id: subject(&profile).unwrap_or_default(),
        name: Some(name),
        email: profile
            .get("email")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .into(),
        image: super::remaining_profile::scalar(profile.get("picture"))?,
        email_verified: false,
    }
    .public_profile(true))
}
#[derive(Clone)]
struct AtlassianMappedUserInfo {
    url: String,
    mapper: Option<fn(Value) -> Result<Map, String>>,
    application_mapper: Option<std::sync::Arc<dyn super::OAuthProfileMapper>>,
}
#[async_trait::async_trait]
impl super::OAuthUserInfoHandler for AtlassianMappedUserInfo {
    fn errors_are_exceptions(&self) -> bool {
        false
    }

    fn mapped_handler(
        &self,
        mapper: std::sync::Arc<dyn super::OAuthProfileMapper>,
    ) -> Option<std::sync::Arc<dyn super::OAuthUserInfoHandler>> {
        let mut handler = self.clone();
        handler.application_mapper = Some(mapper);
        Some(std::sync::Arc::new(handler))
    }

    async fn get_user_info(
        &self,
        request: super::OAuthUserInfoRequest,
    ) -> Result<super::OAuthUserInfoResponse, String> {
        let access_token = request
            .access_token
            .ok_or("Missing Atlassian access token")?;
        let response = reqwest::Client::new()
            .get(&self.url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|error| error.to_string())?
            .error_for_status()
            .map_err(|error| error.to_string())?;
        let profile: Value = response
            .profile_json()
            .await
            .map_err(|error| error.to_string())?;
        if !super::remaining_profile::truthy(&profile) {
            return Err("Missing atlassian profile".into());
        }
        let mut output = Map::new();
        for (source, target) in [("name", "name"), ("email", "email"), ("picture", "image")] {
            _ = output.insert(
                target.into(),
                profile.get(source).cloned().unwrap_or(Value::Undefined),
            );
        }
        _ = output.insert("emailVerified".into(), Value::Bool(false));
        if let Some(mapper) = self.mapper {
            output.extend(mapper(profile.clone())?);
        }
        if let Some(mapper) = &self.application_mapper {
            output.extend(mapper.map_profile(profile.clone()).await?);
        }
        let mut response = super::OAuthUserInfoResponse {
            user: output.clone(),
            data: profile,
            account_subject: None,
        };
        super::apply_application_mapping(&mut response, output)?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Mapper;
    #[async_trait::async_trait]
    impl super::super::OAuthProfileMapper for Mapper {
        async fn map_profile(&self, profile: Value) -> Result<Map, String> {
            assert_eq!(profile["account_id"], "account");
            Ok(crate::oauth::providers::js!({"custom":true})
                .as_object()
                .unwrap()
                .clone())
        }
    }
    #[tokio::test]
    async fn atlassian_maps_partial_fields_without_sync_mapper() {
        let body = crate::oauth::providers::js!({"account_id":"account","name":false,"email":null,"picture":null});

        let body = body.to_string();
        let (endpoint, server) = crate::test_helpers::serve_json_once(body).await;

        let mut options = AtlassianOptions::new("client", "secret");
        options.user_info_endpoint = Some(endpoint);
        let provider = OAuthProvider::atlassian_with_options(options)
            .with_profile_mapper(std::sync::Arc::new(Mapper));
        let response = provider
            .get_user_info
            .unwrap()
            .get_user_info(super::super::OAuthUserInfoRequest {
                access_token: Some("access".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        let output = response.user.clone();
        assert_eq!(output["name"], false);
        assert_eq!(output["email"], Value::Null);
        assert_eq!(output["image"], Value::Null);
        assert_eq!(output["custom"], true);
        assert!(!output.contains_key("id"));
        server.await.unwrap();
    }
    #[test]
    fn atlassian_preserves_falsy_scalar_names() {
        for (name, expected) in [
            (crate::oauth::providers::js!(false), "false"),
            (crate::oauth::providers::js!(0), "0"),
            (crate::oauth::providers::js!(""), ""),
        ] {
            let user = atlassian_user_info(
                crate::oauth::providers::js!({"account_id":"account","name":name}),
            )
            .unwrap();
            assert_eq!(user.get("name").and_then(Value::as_str), Some(expected));
        }
    }
}
