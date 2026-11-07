//! Cognito's configured hosted domain, authenticated subject and profile fallback.
use super::{
    OAuthAuthorizationPolicy, OAuthProvider, OAuthScopeEncoding, OAuthTokenEndpointAuth,
    OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use crate::oauth::providers::remaining_profile::ProfileResponseExt as _;
use crate::oauth::{
    HttpOAuthJwksSource, OAuthIdTokenConfig, OAuthJwksSelection, OAuthJwksSource,
    OAuthNonceComparison,
};
use alibi_core::utils::json::JsObject as Map;
use alibi_core::utils::json::{JsString, JsValue as Value};
use async_trait::async_trait;
#[cfg(test)]
use base64::Engine;
use std::sync::Arc;

/// Immutable Cognito settings. Application callback and signup policies remain
/// configurable on the returned provider.
#[derive(Clone)]
pub struct CognitoOptions {
    pub client_ids: Vec<String>,
    pub client_secret: Option<String>,
    /// Forwarded only during authorization-code exchange, as the pinned helper
    /// ignores this option during refresh.
    pub client_key: Option<String>,
    pub domain: String,
    pub region: String,
    pub user_pool_id: String,
    pub require_client_secret: bool,
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    pub prompt: Option<String>,
    pub identity_provider: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub redirect_uri: Option<String>,
    /// Application-owned transport override; token claims cannot select it.
    pub jwks_source: Option<Arc<dyn OAuthJwksSource>>,
    /// Trusted user-info transport override retaining Cognito's profile mapping.
    pub user_info_endpoint: Option<String>,
    /// Receives the original profile, with the ID-token name fallback applied.
    /// Its mapped ID cannot replace the authenticated raw `sub`.
    pub map_profile_to_user: Option<fn(Value) -> Result<Map, String>>,
}
impl CognitoOptions {
    #[must_use]
    pub fn new(
        client_id: impl Into<String>,
        client_secret: Option<String>,
        domain: impl Into<String>,
        region: impl Into<String>,
        user_pool_id: impl Into<String>,
    ) -> Self {
        Self {
            client_ids: vec![client_id.into()],
            client_secret,
            client_key: None,
            domain: domain.into(),
            region: region.into(),
            user_pool_id: user_pool_id.into(),
            require_client_secret: false,
            scope: Vec::new(),
            disable_default_scope: false,
            prompt: None,
            identity_provider: None,
            authorization_endpoint: None,
            redirect_uri: None,
            jwks_source: None,
            user_info_endpoint: None,
            map_profile_to_user: None,
        }
    }
}
impl std::fmt::Debug for CognitoOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CognitoOptions")
            .field("client_ids", &self.client_ids)
            .field("domain", &self.domain)
            .field("region", &self.region)
            .field("user_pool_id", &self.user_pool_id)
            .field("scope", &self.scope)
            .field("disable_default_scope", &self.disable_default_scope)
            .field("require_client_secret", &self.require_client_secret)
            .finish_non_exhaustive()
    }
}
impl OAuthProvider {
    /// Builds the published Cognito provider from application-owned configuration.
    ///
    /// # Errors
    /// Returns an error if the domain, region or user pool is empty.
    pub fn cognito(options: CognitoOptions) -> Result<Self, String> {
        if options.domain.is_empty() || options.region.is_empty() || options.user_pool_id.is_empty()
        {
            return Err("DOMAIN_AND_REGION_REQUIRED".into());
        }
        let domain = options
            .domain
            .strip_prefix("https://")
            .or_else(|| options.domain.strip_prefix("http://"))
            .unwrap_or(&options.domain);
        let issuer = format!(
            "https://cognito-idp.{}.amazonaws.com/{}",
            options.region, options.user_pool_id
        );
        let endpoint = options
            .user_info_endpoint
            .unwrap_or_else(|| format!("https://{domain}/oauth2/userinfo"));
        let verification = OAuthIdTokenConfig {
            issuers: vec![issuer.clone()],
            audience: None,
            client_ids: Some(options.client_ids.clone()),
            jwks_source: options.jwks_source.unwrap_or_else(|| {
                Arc::new(HttpOAuthJwksSource::new(format!(
                    "{issuer}/.well-known/jwks.json"
                )))
            }),
            max_age_secs: Some(3600),
            allow_opaque_token: false,
            algorithm: None,
            algorithms: Some(vec![jsonwebtoken::Algorithm::RS256]),
            default_key_algorithm: None,
            selection: OAuthJwksSelection::ExactKid,
            nonce_comparison: OAuthNonceComparison::Exact,
            verify_claims: None,
        };
        let mut clients = options.client_ids.into_iter();
        let token_endpoint_auth = if options
            .client_secret
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        {
            OAuthTokenEndpointAuth::ClientSecretPost
        } else {
            OAuthTokenEndpointAuth::None
        };
        Ok(Self {
            client_id: clients.next().unwrap_or_default(),
            additional_client_ids: clients.collect(),
            client_secret: options.client_secret.unwrap_or_default(),
            hosted_domain: None,
            require_email_verification: false,
            auth_url: options
                .authorization_endpoint
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| format!("https://{domain}/oauth2/authorize")),
            token_url: format!("https://{domain}/oauth2/token"),
            user_info_url: Some(endpoint.clone()),
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            authorization: Some(OAuthAuthorizationPolicy {
                source_profile_exceptions: true,
                configured_scopes: options.scope,
                scope_encoding: OAuthScopeEncoding::UriComponent,
                disable_default_scopes: options.disable_default_scope,
                require_client_id: true,
                require_client_secret: options.require_client_secret,
                token_endpoint_auth: Some(token_endpoint_auth),
                authorization_code_client_key: options.client_key,
                prompt: options.prompt,
                redirect_uri: options.redirect_uri,
                login_hint: false,
                ..OAuthAuthorizationPolicy::default()
            }),
            allowed_request_params: Vec::new(),
            authorization_params: options
                .identity_provider
                .map(|value| vec![("identity_provider".into(), value)])
                .unwrap_or_default(),
            map_user_info: None,
            account_subject: Some(subject),
            get_user_info: Some(Arc::new(CognitoUserInfo {
                endpoint,
                mapper: options.map_profile_to_user,
                application_mapper: None,
            })),
            refresh_access_token: None,
            verify_id_token: None,
            id_token: Some(verification),
            disable_id_token_sign_in: false,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            allow_idp_initiated: false,
            override_user_info_on_sign_in: false,
        })
    }
}
#[derive(Clone)]
struct CognitoUserInfo {
    endpoint: String,
    mapper: Option<fn(Value) -> Result<Map, String>>,
    application_mapper: Option<Arc<dyn super::OAuthProfileMapper>>,
}
#[async_trait]
impl OAuthUserInfoHandler for CognitoUserInfo {
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
        if let Some(token) = request.id_token.filter(|value| !value.is_empty())
            && let Ok(mut profile) = decode_profile(&token)
        {
            let name = profile_name(&profile);
            if let Some(object) = profile.as_object_mut() {
                _ = object.insert("name".into(), name);
            }
            // Only decoding or the application's mapper may select the access-token
            // fallback. An invalid raw subject remains an admission failure.
            if let Ok(output) = self.map_profile(&profile, true).await {
                return finish_profile(profile, output);
            }
        }
        let access_token = request
            .access_token
            .filter(|value| !value.is_empty())
            .ok_or("Missing Cognito access token")?;
        let profile: Value = reqwest::Client::new()
            .get(&self.endpoint)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|error| error.to_string())?
            .error_for_status()
            .map_err(|error| error.to_string())?
            .profile_json()
            .await
            .map_err(|error| error.to_string())?;
        if !super::remaining_profile::truthy(&profile) {
            return Err("Missing Cognito profile".into());
        }
        let output = self.map_profile(&profile, false).await?;
        finish_profile(profile, output)
    }
}
impl CognitoUserInfo {
    async fn map_profile(&self, profile: &Value, id_token: bool) -> Result<Map, String> {
        let mut output = Map::new();
        _ = output.insert("name".into(), profile_name(profile));
        for (source, target) in [("email", "email"), ("picture", "image")] {
            _ = output.insert(
                target.into(),
                profile.get(source).cloned().unwrap_or(Value::Undefined),
            );
        }
        if id_token {
            _ = output.insert(
                "emailVerified".into(),
                profile
                    .get("email_verified")
                    .cloned()
                    .unwrap_or(Value::Undefined),
            );
        } else {
            _ = output.insert(
                "emailVerified".into(),
                Value::Bool(super::email_verified_claim(profile.get("email_verified"))),
            );
        }
        if let Some(mapper) = self.mapper {
            output.extend(mapper(profile.clone())?);
        }
        if let Some(mapper) = &self.application_mapper {
            output.extend(mapper.map_profile(profile.clone()).await?);
        }
        Ok(output)
    }
}

fn decode_profile(token: &str) -> Result<Value, String> {
    super::remaining_profile::decode_grant_jwt(token)
}
fn truthy(value: &Value) -> bool {
    value.is_truthy()
}
fn profile_name(profile: &Value) -> Value {
    ["name", "given_name", "username"]
        .into_iter()
        .filter_map(|key| profile.get(key))
        .find(|value| truthy(value))
        .cloned()
        .unwrap_or_else(|| Value::String(String::new().into()))
}
fn finish_profile(profile: Value, output: Map) -> Result<OAuthUserInfoResponse, String> {
    let mut response = OAuthUserInfoResponse {
        user: output.clone(),
        data: profile,
        account_subject: None,
    };
    super::apply_application_mapping(&mut response, output)?;
    Ok(response)
}

fn subject(profile: &Value) -> Result<JsString, String> {
    super::remaining_profile::raw_subject(profile.get("sub"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn grant_payload_decoder_accepts_jose_forgiving_base64() {
        for payload in ["e31=", " e\t3\n0\x0c=\r", "77u_e30="] {
            assert_eq!(
                decode_profile(&format!(".{payload}.")).unwrap(),
                crate::oauth::providers::js!({})
            );
        }
    }

    struct Mapper {
        fallback: bool,
        calls: std::sync::atomic::AtomicUsize,
    }
    #[async_trait]
    impl super::super::OAuthProfileMapper for Mapper {
        async fn map_profile(&self, profile: Value) -> Result<Map, String> {
            let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if call == 0 {
                assert_eq!(profile["name"], "Given");
                if self.fallback {
                    return Err("use HTTP".into());
                }
            } else {
                assert_eq!(profile["sub"], "http-subject");
                assert!(profile.get("name").is_none());
            }
            Ok(crate::oauth::providers::js!({"custom":true})
                .as_object()
                .unwrap()
                .clone())
        }
    }
    #[tokio::test]
    async fn cognito_partial_mapping_can_select_userinfo_fallback() {
        for fallback in [false, true] {
            let body = crate::oauth::providers::js!({"sub":"http-subject","given_name":"HTTP","email":null,"picture":null});

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

            let mut options = CognitoOptions::new("client", None, "domain", "region", "pool");
            options.user_info_endpoint = Some(endpoint);
            let mapper = Arc::new(Mapper {
                fallback,
                calls: std::sync::atomic::AtomicUsize::new(0),
            });
            let provider = OAuthProvider::cognito(options)
                .unwrap()
                .with_profile_mapper(mapper.clone());
            let profile = crate::oauth::providers::js!({"sub":"jwt-subject","given_name":"Given","email":null,"picture":null});
            let token = format!(
                "e30.{}.sig",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(profile.to_string())
            );
            let response = provider
                .get_user_info
                .unwrap()
                .get_user_info(OAuthUserInfoRequest {
                    id_token: Some(token),
                    access_token: Some("access".into()),
                    ..Default::default()
                })
                .await
                .unwrap();
            let output = response.user.clone();
            assert_eq!(output["name"], if fallback { "HTTP" } else { "Given" });
            assert_eq!(output["email"], Value::Null);
            assert_eq!(output["image"], Value::Null);
            assert_eq!(output["custom"], true);
            assert!(!output.contains_key("id"));
            assert_eq!(
                mapper.calls.load(std::sync::atomic::Ordering::SeqCst),
                if fallback { 2 } else { 1 }
            );
            if fallback {
                server.await.unwrap();
            } else {
                server.abort();
            }
        }
    }
    #[tokio::test]
    async fn cognito_verification_output_depends_on_profile_transport() {
        for claim in [
            None,
            Some(Value::Null),
            Some(Value::String("true".into())),
            Some(Value::Bool(true)),
            Some(Value::Bool(false)),
        ] {
            for id_token in [true, false] {
                let mut body = crate::oauth::providers::js!({"sub":"subject","name":"Name"});
                if let Some(value) = &claim {
                    body["email_verified"] = value.clone();
                }
                let token = format!(
                    "e30.{}.sig",
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(body.to_string())
                );

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

                let mut options = CognitoOptions::new("client", None, "domain", "region", "pool");
                options.user_info_endpoint = Some(endpoint);
                let provider = OAuthProvider::cognito(options).unwrap();
                let response = provider
                    .get_user_info
                    .unwrap()
                    .get_user_info(OAuthUserInfoRequest {
                        id_token: id_token.then_some(token),
                        access_token: Some("access".into()),
                        ..Default::default()
                    })
                    .await
                    .unwrap();
                let output = response.user.clone();
                if id_token {
                    assert!(output.contains_key("emailVerified"));
                    assert_eq!(
                        output.get("emailVerified"),
                        Some(claim.as_ref().unwrap_or(&Value::Undefined)),
                    );
                    server.abort();
                } else {
                    assert_eq!(
                        output["emailVerified"],
                        Value::Bool(super::super::email_verified_claim(claim.as_ref()))
                    );
                    server.await.unwrap();
                }
            }
        }
    }
    #[test]
    fn cognito_accepts_padded_jwt_payload() {
        let profile = crate::oauth::providers::js!({"sub":"cognito-id","name":"A"});
        let mut json = profile.to_string();
        while json.len() % 3 == 0 {
            json.push(' ');
        }
        let payload = base64::engine::general_purpose::URL_SAFE.encode(json);
        assert!(payload.ends_with('='));
        assert_eq!(
            decode_profile(&format!("e30.{payload}.signature")).unwrap(),
            profile
        );
    }
}
