//! Facebook Graph app-bound access tokens and signed Limited Login profiles.
use super::{
    OAuthAuthorizationPolicy, OAuthProvider, OAuthTokenEndpointAuth, OAuthUserInfoHandler,
    OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use crate::oauth::providers::remaining_profile::ProfileResponseExt as _;
use crate::oauth::{
    HttpOAuthJwksSource, OAuthIdTokenConfig, OAuthJwksSelection, OAuthJwksSource,
    id_token::OAuthNonceComparison,
};
use alibi_core::utils::json::JsObject as Map;
use alibi_core::utils::json::{JsString, JsValue as Value};
use async_trait::async_trait;
#[cfg(test)]
use base64::Engine;
use std::sync::Arc;

/// Application-owned Facebook configuration. User-info/refresh callbacks and
/// signup policies remain configurable on the returned provider.
#[derive(Clone)]
pub struct FacebookOptions {
    pub client_ids: Vec<String>,
    pub client_secret: Option<String>,
    /// Sent during authorization-code exchange only.
    pub client_key: Option<String>,
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    pub fields: Vec<String>,
    pub config_id: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub redirect_uri: Option<String>,
    /// Trusted key authority for Limited Login signature verification.
    pub jwks_source: Option<Arc<dyn OAuthJwksSource>>,
    /// Trusted transport overrides retain the actual inspection and mapping.
    pub token_inspection_endpoint: Option<String>,
    pub user_info_endpoint: Option<String>,
    pub map_profile_to_user: Option<fn(Value) -> Result<Map, String>>,
    /// Application user-info resolution. A client-submitted access token, or an
    /// opaque ID token, must first be bound to a configured app.
    pub get_user_info: Option<Arc<dyn OAuthUserInfoHandler>>,
}
impl FacebookOptions {
    #[must_use]
    pub fn new(client_id: impl Into<String>, client_secret: Option<String>) -> Self {
        Self {
            client_ids: vec![client_id.into()],
            client_secret,
            client_key: None,
            scope: Vec::new(),
            disable_default_scope: false,
            fields: Vec::new(),
            config_id: None,
            authorization_endpoint: None,
            redirect_uri: None,
            jwks_source: None,
            token_inspection_endpoint: None,
            user_info_endpoint: None,
            map_profile_to_user: None,
            get_user_info: None,
        }
    }
}
impl std::fmt::Debug for FacebookOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FacebookOptions")
            .field("client_ids", &self.client_ids)
            .field("scope", &self.scope)
            .field("disable_default_scope", &self.disable_default_scope)
            .field("fields", &self.fields)
            .field("config_id", &self.config_id)
            .field("authorization_endpoint", &self.authorization_endpoint)
            .field("redirect_uri", &self.redirect_uri)
            .finish_non_exhaustive()
    }
}
impl OAuthProvider {
    #[must_use]
    pub fn facebook(client_id: &str, client_secret: &str) -> Self {
        Self::facebook_with_options(FacebookOptions::new(client_id, Some(client_secret.into())))
    }
    #[must_use]
    pub fn facebook_with_options(options: FacebookOptions) -> Self {
        let client_id = options.client_ids.first().cloned().unwrap_or_default();
        let secret = options.client_secret.unwrap_or_default();
        let endpoint = options
            .user_info_endpoint
            .unwrap_or_else(|| "https://graph.facebook.com/me".into());
        let verification = OAuthIdTokenConfig {
            issuers: vec!["https://www.facebook.com".into()],
            audience: None,
            client_ids: Some(options.client_ids.clone()),
            jwks_source: options.jwks_source.unwrap_or_else(|| {
                Arc::new(HttpOAuthJwksSource::new(
                    "https://limited.facebook.com/.well-known/oauth/openid/jwks/",
                ))
            }),
            max_age_secs: None,
            allow_opaque_token: true,
            algorithm: Some(jsonwebtoken::Algorithm::RS256),
            algorithms: Some(vec![jsonwebtoken::Algorithm::RS256]),
            default_key_algorithm: None,
            selection: OAuthJwksSelection::RemoteRs256,
            nonce_comparison: OAuthNonceComparison::Exact,
            verify_claims: None,
        };
        Self {
            client_id: client_id.clone(),
            client_secret: secret.clone(),
            additional_client_ids: options.client_ids.iter().skip(1).cloned().collect(),
            hosted_domain: None,
            require_email_verification: false,
            auth_url: options
                .authorization_endpoint
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "https://www.facebook.com/v24.0/dialog/oauth".into()),
            token_url: "https://graph.facebook.com/v24.0/oauth/access_token".into(),
            user_info_url: Some(endpoint.clone()),
            scopes: vec!["email".into(), "public_profile".into()],
            authorization: Some(OAuthAuthorizationPolicy {
                source_profile_exceptions: true,
                configured_scopes: options.scope,
                disable_default_scopes: options.disable_default_scope,
                require_client_id: true,
                require_client_secret: true,
                token_endpoint_auth: Some(OAuthTokenEndpointAuth::ClientSecretPost),
                authorization_code_client_key: options.client_key,
                redirect_uri: options.redirect_uri,
                pkce: false,
                ..OAuthAuthorizationPolicy::default()
            }),
            allowed_request_params: Vec::new(),
            authorization_params: options
                .config_id
                .filter(|value| !value.is_empty())
                .map(|value| vec![("config_id".into(), value)])
                .unwrap_or_default(),
            account_subject: Some(subject),
            map_user_info: None,
            get_user_info: Some(Arc::new(FacebookUserInfo {
                client_id,
                client_ids: options.client_ids,
                client_secret: secret,
                inspection_endpoint: options
                    .token_inspection_endpoint
                    .unwrap_or_else(|| "https://graph.facebook.com/debug_token".into()),
                endpoint,
                fields: options.fields,
                mapper: options.map_profile_to_user,
                application_mapper: None,
                custom: options.get_user_info,
            })),
            refresh_access_token: None,
            verify_id_token: None,
            id_token: Some(verification),
            disable_id_token_sign_in: false,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            allow_idp_initiated: false,
            override_user_info_on_sign_in: false,
        }
    }
}
#[derive(Clone)]
struct FacebookUserInfo {
    client_id: String,
    client_ids: Vec<String>,
    client_secret: String,
    inspection_endpoint: String,
    endpoint: String,
    fields: Vec<String>,
    mapper: Option<fn(Value) -> Result<Map, String>>,
    application_mapper: Option<Arc<dyn super::OAuthProfileMapper>>,
    custom: Option<Arc<dyn OAuthUserInfoHandler>>,
}
#[async_trait]
impl OAuthUserInfoHandler for FacebookUserInfo {
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
        if let Some(custom) = &self.custom {
            // On the client sign-in path the access token, or an opaque ID token,
            // arrives unverified, so bind it to this app before the application
            // resolves identity from it.
            let opaque_id_token = request
                .id_token
                .as_deref()
                .filter(|token| !token.is_empty() && token.split('.').count() != 3);
            if let Some(token) = request
                .access_token
                .as_deref()
                .filter(|token| !token.is_empty())
                .or(opaque_id_token)
            {
                _ = self.inspect(token).await?;
            }
            return custom
                .get_user_info(request)
                .await
                .map_err(super::remaining_profile::profile_exception);
        }
        let limited_login = request
            .id_token
            .as_deref()
            .is_some_and(|token| token.split('.').count() == 3);
        let profile = if limited_login {
            let token = request
                .id_token
                .as_deref()
                .ok_or("Missing Facebook ID token")?;
            super::remaining_profile::decode_grant_jwt(token)
                .map_err(super::remaining_profile::profile_exception)?
        } else {
            self.graph_profile(request.access_token.as_deref()).await?
        };
        let mut mapped = Map::new();
        if let Some(mapper) = self.mapper {
            mapped.extend(
                mapper(profile.clone()).map_err(super::remaining_profile::profile_exception)?,
            );
        }
        if let Some(mapper) = &self.application_mapper {
            mapped.extend(
                mapper
                    .map_profile(profile.clone())
                    .await
                    .map_err(super::remaining_profile::profile_exception)?,
            );
        }
        let mut output = Map::new();
        for key in ["name", "email"] {
            _ = output.insert(
                key.into(),
                profile.get(key).cloned().unwrap_or(Value::Undefined),
            );
        }
        let image = if limited_login {
            profile.get("picture")
        } else {
            let picture = profile
                .get("picture")
                .filter(|value| !value.is_null())
                .ok_or_else(|| {
                    super::remaining_profile::profile_exception("Missing Facebook picture")
                })?;
            let data = picture
                .get("data")
                .filter(|value| !value.is_null())
                .ok_or_else(|| {
                    super::remaining_profile::profile_exception("Missing Facebook picture data")
                })?;
            data.get("url")
        };
        _ = output.insert("image".into(), image.cloned().unwrap_or(Value::Undefined));
        _ = output.insert(
            "emailVerified".into(),
            if limited_login {
                Value::Bool(false)
            } else {
                profile
                    .get("email_verified")
                    .filter(|value| !value.is_null())
                    .cloned()
                    .unwrap_or(Value::Bool(false))
            },
        );
        output.extend(mapped);
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

impl FacebookUserInfo {
    async fn graph_profile(&self, access_token: Option<&str>) -> Result<Value, String> {
        let access_token = access_token
            .filter(|token| !token.is_empty())
            .ok_or("Missing Facebook access token")?;
        let user_id = self.inspect(access_token).await?;
        let mut fields = vec!["id", "name", "email", "picture"];
        fields.extend(self.fields.iter().map(String::as_str));
        let profile: Value = reqwest::Client::new()
            .get(&self.endpoint)
            .query(&[("fields", fields.join(","))])
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(http_error)?
            .error_for_status()
            .map_err(http_error)?
            .profile_json()
            .await?;
        if profile.get("id") != Some(&user_id) {
            return Err("Facebook profile does not match inspected identity".into());
        }
        Ok(profile)
    }
    /// Binds `access_token` to a configured app and returns its user ID.
    async fn inspect(&self, access_token: &str) -> Result<Value, String> {
        if self.client_id.is_empty() || self.client_secret.is_empty() {
            return Err("Facebook client ID and secret are required".into());
        }
        let app_access_token = format!("{}|{}", self.client_id, self.client_secret);
        let response = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(http_error)?
            .get(&self.inspection_endpoint)
            .query(&[
                ("input_token", access_token),
                ("access_token", app_access_token.as_str()),
            ])
            .send()
            .await
            .map_err(http_error)?
            .error_for_status()
            .map_err(|error| http_error(error))?;
        if response.status().is_redirection() {
            return Err("Facebook token inspection refused a redirect".into());
        }
        let inspected: Value = response.profile_json().await?;
        let data = inspected
            .get("data")
            .ok_or("Facebook inspection returned no data")?;
        let app_valid = data
            .get("app_id")
            .and_then(Value::as_str)
            .is_some_and(|id| {
                !id.is_empty() && self.client_ids.iter().any(|configured| configured == id)
            });
        if data.get("is_valid").and_then(Value::as_bool) != Some(true) || !app_valid {
            return Err("Invalid Facebook token or configured app binding".into());
        }
        let user_id = data
            .get("user_id")
            .filter(|value| {
                matches!(value, Value::String(_) | Value::Number(_) | Value::Bool(_))
                    && truthy(value)
            })
            .ok_or("Facebook inspection returned no user")?;
        Ok(user_id.clone())
    }
}
fn http_error(error: reqwest::Error) -> String {
    error.without_url().to_string()
}
fn truthy(value: &Value) -> bool {
    value.is_truthy()
}
fn subject(profile: &Value) -> Result<JsString, String> {
    super::remaining_profile::raw_subject(profile.get("sub").or_else(|| profile.get("id")))
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Mapper;
    #[async_trait]
    impl super::super::OAuthProfileMapper for Mapper {
        async fn map_profile(&self, profile: Value) -> Result<Map, String> {
            assert_eq!(profile["email"], Value::Null);
            Ok(
                crate::oauth::providers::js!({"name":"Mapped","custom":true,"id":"public-id"})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
        }
    }
    #[tokio::test]
    async fn facebook_graph_picture_containers_are_required_after_mapping() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        struct PictureMapper(Arc<AtomicUsize>);
        #[async_trait]
        impl super::super::OAuthProfileMapper for PictureMapper {
            async fn map_profile(&self, profile: Value) -> Result<Map, String> {
                assert_eq!(profile["id"], "subject");
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(crate::oauth::providers::js!({"image":"mapped-image"})
                    .as_object()
                    .unwrap()
                    .clone())
            }
        }

        for (picture, valid) in [
            (None, false),
            (Some(Value::Null), false),
            (Some(Value::Bool(false)), false),
            (Some(crate::oauth::providers::js!({})), false),
            (Some(crate::oauth::providers::js!({"data":null})), false),
            (Some(crate::oauth::providers::js!({"data":{}})), true),
            (Some(crate::oauth::providers::js!({"data":true})), true),
            (
                Some(crate::oauth::providers::js!({"data":{"url":null}})),
                true,
            ),
            (
                Some(crate::oauth::providers::js!({"data":{"url":"photo"}})),
                true,
            ),
        ] {
            let mut profile = crate::oauth::providers::js!({"id":"subject","name":"Original"});
            if let Some(picture) = picture {
                profile["picture"] = picture;
            }
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                for body in [
                    crate::oauth::providers::js!({"data":{"app_id":"client","is_valid":true,"user_id":"subject"}}),
                    profile,
                ] {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut request = [0; 8192];
                    let _ = stream.read(&mut request).await.unwrap();
                    let body = body.to_string();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    stream.write_all(response.as_bytes()).await.unwrap();
                }
            });
            let mut options = FacebookOptions::new("client", Some("secret".into()));
            options.user_info_endpoint = Some(endpoint.clone());
            options.token_inspection_endpoint = Some(endpoint);
            let calls = Arc::new(AtomicUsize::new(0));
            let provider = OAuthProvider::facebook_with_options(options)
                .with_profile_mapper(Arc::new(PictureMapper(calls.clone())));
            let result = provider
                .get_user_info
                .as_ref()
                .unwrap()
                .get_user_info(OAuthUserInfoRequest {
                    access_token: Some("access".into()),
                    ..Default::default()
                })
                .await;
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            if valid {
                let response = result.unwrap();
                assert_eq!(
                    response.user.get("image").and_then(Value::as_str),
                    Some("mapped-image")
                );
                assert_eq!(response.user["image"], "mapped-image");
            } else {
                assert!(
                    result
                        .unwrap_err()
                        .starts_with("oauth-profile-exception:Missing Facebook picture")
                );
            }
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn facebook_partial_mapping_preserves_transport_defaults() {
        for limited in [true, false] {
            let profile = if limited {
                crate::oauth::providers::js!({"sub":"subject","name":"Original","email":null,"picture":null,"email_verified":"true"})
            } else {
                crate::oauth::providers::js!({"id":"subject","name":"Original","email":null,"picture":{"data":{"url":null}},"email_verified":"true"})
            };
            let token = format!(
                "e30.{}.sig",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(profile.to_string())
            );
            let body = profile;

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

            let profile_endpoint = endpoint;
            let profile_server = server;
            let body = crate::oauth::providers::js!({"data":{"app_id":"client","is_valid":true,"user_id":"subject"}});

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

            let mut options = FacebookOptions::new("client", Some("secret".into()));
            options.user_info_endpoint = Some(profile_endpoint);
            options.token_inspection_endpoint = Some(endpoint);
            let provider =
                OAuthProvider::facebook_with_options(options).with_profile_mapper(Arc::new(Mapper));
            let response = provider
                .get_user_info
                .as_ref()
                .unwrap()
                .get_user_info(OAuthUserInfoRequest {
                    id_token: limited.then_some(token),
                    access_token: (!limited).then(|| "access".into()),
                    ..Default::default()
                })
                .await
                .unwrap();
            let output = response.user.clone();
            assert_eq!(output["name"], "Mapped");
            assert_eq!(output["email"], Value::Null);
            assert_eq!(output["image"], Value::Null);
            assert_eq!(
                output["emailVerified"],
                if limited {
                    Value::Bool(false)
                } else {
                    Value::String("true".into())
                }
            );
            assert_eq!(output["id"], "public-id");
            assert_eq!(
                provider.account_subject.unwrap()(&response.data).unwrap(),
                "subject"
            );
            if limited {
                server.abort();
                profile_server.abort();
            } else {
                server.await.unwrap();
                profile_server.await.unwrap();
            }
        }
    }
    #[tokio::test]
    async fn facebook_accepts_padded_jwt_payload() {
        let profile = crate::oauth::providers::js!({"sub":"subject","oid":"object-id","name":"A","email":"a@example.com"});
        let mut json = profile.to_string();
        while json.len() % 3 == 0 {
            json.push(' ');
        }
        let payload = base64::engine::general_purpose::URL_SAFE.encode(json);
        assert!(payload.ends_with('='));
        let provider = OAuthProvider::facebook("client", "secret");
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
