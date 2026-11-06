//! Microsoft Entra ID's configured authority, tenant and original object ID.
use super::{
    OAuthAuthorizationPolicy, OAuthClientAssertion, OAuthProvider, OAuthScopeEncoding,
    OAuthTokenEndpointAuth, OAuthUserInfo, OAuthUserInfoHandler, OAuthUserInfoRequest,
    OAuthUserInfoResponse,
};
use crate::oauth::{
    HttpOAuthJwksSource, OAuthIdTokenClaimsVerifier, OAuthIdTokenConfig, OAuthJwksSelection,
    OAuthJwksSource, OAuthNonceComparison,
};
use alibi_core::utils::json::JsValue;
use async_trait::async_trait;
use base64::Engine;
use serde_json::Map;
use serde_json::Value;
use std::sync::Arc;

const CONSUMER_TENANT: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";
const DEFAULT_SCOPES: [&str; 5] = ["openid", "profile", "email", "User.Read", "offline_access"];

/// Supported Graph profile-photo sizes in pixels.
#[derive(Debug, Clone, Copy, Default)]
pub enum MicrosoftProfilePhotoSize {
    #[default]
    Size48,
    Size64,
    Size96,
    Size120,
    Size240,
    Size360,
    Size432,
    Size504,
    Size648,
}
impl MicrosoftProfilePhotoSize {
    const fn pixels(self) -> u16 {
        match self {
            Self::Size48 => 48,
            Self::Size64 => 64,
            Self::Size96 => 96,
            Self::Size120 => 120,
            Self::Size240 => 240,
            Self::Size360 => 360,
            Self::Size432 => 432,
            Self::Size504 => 504,
            Self::Size648 => 648,
        }
    }
}

/// Immutable application configuration for the published Microsoft factory.
#[derive(Clone)]
pub struct MicrosoftOptions {
    pub client_ids: Vec<String>,
    pub client_secret: Option<String>,
    pub client_key: Option<String>,
    pub client_assertion: Option<OAuthClientAssertion>,
    pub tenant_id: Option<String>,
    pub authority: Option<String>,
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    /// Reject new identities, including an explicit signup request.
    pub disable_sign_up: bool,
    pub prompt: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub redirect_uri: Option<String>,
    pub disable_profile_photo: bool,
    pub profile_photo_size: MicrosoftProfilePhotoSize,
    /// Trusted application transport override. Claims never select this source.
    pub jwks_source: Option<Arc<dyn OAuthJwksSource>>,
    /// Trusted application Graph transport override, retaining byte/photo mapping.
    pub profile_photo_endpoint: Option<String>,
    /// Receives the original claims with any successfully fetched photo applied.
    /// Its mapped ID cannot replace the raw oid account identity.
    pub map_profile_to_user: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
}
impl MicrosoftOptions {
    #[must_use]
    pub fn new(client_id: impl Into<String>, client_secret: Option<String>) -> Self {
        Self {
            client_ids: vec![client_id.into()],
            client_secret,
            client_key: None,
            client_assertion: None,
            tenant_id: None,
            authority: None,
            scope: Vec::new(),
            disable_default_scope: false,
            disable_sign_up: false,
            prompt: None,
            authorization_endpoint: None,
            redirect_uri: None,
            disable_profile_photo: false,
            profile_photo_size: MicrosoftProfilePhotoSize::default(),
            jwks_source: None,
            profile_photo_endpoint: None,
            map_profile_to_user: None,
        }
    }
}
impl std::fmt::Debug for MicrosoftOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MicrosoftOptions")
            .field("client_ids", &self.client_ids)
            .field("tenant_id", &self.tenant_id)
            .field("authority", &self.authority)
            .field("scope", &self.scope)
            .field("disable_default_scope", &self.disable_default_scope)
            .field("disable_sign_up", &self.disable_sign_up)
            .field("disable_profile_photo", &self.disable_profile_photo)
            .field("profile_photo_size", &self.profile_photo_size)
            .finish_non_exhaustive()
    }
}
impl OAuthProvider {
    /// Builds Microsoft's actual authorization, grant and tenant-verification policy.
    ///
    /// # Errors
    /// Returns an error when a secret is combined with a client assertion.
    pub fn microsoft(options: MicrosoftOptions) -> Result<Self, String> {
        if options.client_assertion.is_some()
            && options
                .client_secret
                .as_ref()
                .is_some_and(|secret| !secret.is_empty())
        {
            return Err(
                "Microsoft Entra ID clientAssertion cannot be combined with clientSecret".into(),
            );
        }
        let tenant = options
            .tenant_id
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "common".into());
        let authority = options
            .authority
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "https://login.microsoftonline.com".into())
            .trim_end_matches('/')
            .to_owned();
        let multi_tenant = ["common", "organizations", "consumers"].contains(&tenant.as_str());
        let verification = OAuthIdTokenConfig {
            issuers: if multi_tenant {
                Vec::new()
            } else {
                vec![format!("{authority}/{tenant}/v2.0")]
            },
            audience: None,
            client_ids: Some(options.client_ids.clone()),
            jwks_source: options.jwks_source.unwrap_or_else(|| {
                Arc::new(HttpOAuthJwksSource::new(format!(
                    "{authority}/{tenant}/discovery/v2.0/keys"
                )))
            }),
            max_age_secs: Some(3600),
            allow_opaque_token: false,
            algorithm: None,
            algorithms: Some(vec![jsonwebtoken::Algorithm::RS256]),
            // Microsoft's key set omits `alg`; Entra ID signs ID tokens with RS256.
            default_key_algorithm: Some(jsonwebtoken::Algorithm::RS256),
            selection: OAuthJwksSelection::ExactKid,
            nonce_comparison: OAuthNonceComparison::Exact,
            verify_claims: Some(Arc::new(MicrosoftClaims {
                authority: authority.clone(),
                tenant: tenant.clone(),
            })),
        };
        let scopes: Vec<_> = DEFAULT_SCOPES.map(String::from).to_vec();
        let mut refresh_scopes = if options.disable_default_scope {
            Vec::new()
        } else {
            scopes.clone()
        };
        refresh_scopes.extend(options.scope.clone());
        let token_endpoint_auth = if options.client_assertion.is_some() {
            OAuthTokenEndpointAuth::PrivateKeyJwt
        } else if options
            .client_secret
            .as_ref()
            .is_some_and(|secret| !secret.is_empty())
        {
            OAuthTokenEndpointAuth::ClientSecretPost
        } else {
            OAuthTokenEndpointAuth::None
        };
        let size = options.profile_photo_size.pixels();
        let photo_endpoint = options.profile_photo_endpoint.unwrap_or_else(|| {
            format!("https://graph.microsoft.com/v1.0/me/photos/{size}x{size}/$value")
        });
        let mut clients = options.client_ids.into_iter();
        Ok(Self {
            client_id: clients.next().unwrap_or_default(),
            additional_client_ids: clients.collect(),
            client_secret: options.client_secret.unwrap_or_default(),
            hosted_domain: None,
            require_email_verification: false,
            auth_url: options
                .authorization_endpoint
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| format!("{authority}/{tenant}/oauth2/v2.0/authorize")),
            token_url: format!("{authority}/{tenant}/oauth2/v2.0/token"),
            user_info_url: None,
            scopes,
            authorization: Some(OAuthAuthorizationPolicy {
                source_profile_exceptions: true,
                configured_scopes: options.scope,
                scope_encoding: OAuthScopeEncoding::UriComponent,
                disable_default_scopes: options.disable_default_scope,
                disable_sign_up_option: options.disable_sign_up.then_some(true),
                require_client_id: true,
                token_endpoint_auth: Some(token_endpoint_auth),
                authorization_code_client_key: options.client_key,
                client_assertion: options.client_assertion,
                refresh_scope: Some(refresh_scopes.join(" ")),
                prompt: options.prompt,
                redirect_uri: options.redirect_uri,
                ..OAuthAuthorizationPolicy::default()
            }),
            allowed_request_params: Vec::new(),
            authorization_params: Vec::new(),
            account_subject: Some(subject),
            map_user_info: None,
            get_user_info: Some(Arc::new(MicrosoftUserInfo {
                photo_endpoint,
                disable_photo: options.disable_profile_photo,
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
struct MicrosoftClaims {
    authority: String,
    tenant: String,
}
impl OAuthIdTokenClaimsVerifier for MicrosoftClaims {
    fn verify_claims(&self, claims: &JsValue) -> bool {
        let Some(tid) = claims.get("tid").and_then(JsValue::as_str) else {
            return false;
        };
        claims.get("iss").and_then(JsValue::as_str)
            == Some(format!("{}/{tid}/v2.0", self.authority).as_str())
            && !(self.tenant == "organizations" && tid == CONSUMER_TENANT)
            && !(self.tenant == "consumers" && tid != CONSUMER_TENANT)
    }
}
#[derive(Clone)]
struct MicrosoftUserInfo {
    photo_endpoint: String,
    disable_photo: bool,
    mapper: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
    application_mapper: Option<Arc<dyn super::OAuthProfileMapper>>,
}
#[async_trait]
impl OAuthUserInfoHandler for MicrosoftUserInfo {
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
        let token = super::remaining_profile::grant_id_token(&request)
            .map_err(super::remaining_profile::profile_exception)?
            .ok_or("Missing Microsoft ID token")?;
        let mut profile = super::remaining_profile::decode_grant_jwt(&token)
            .map_err(super::remaining_profile::profile_exception)?;
        let id = subject(&profile)?;
        if !self.disable_photo
            && let Some(access) = request.access_token.filter(|value| !value.is_empty())
        {
            // A failed optional photo operation does not deny the authenticated profile.
            if let Ok(response) = reqwest::Client::new()
                .get(&self.photo_endpoint)
                .bearer_auth(access)
                .send()
                .await
                && response.status().is_success()
                && let Ok(bytes) = response.bytes().await
                && let Some(object) = profile.as_object_mut()
            {
                _ = object.insert(
                    "picture".into(),
                    Value::String(format!(
                        "data:image/jpeg;base64, {}",
                        base64::engine::general_purpose::STANDARD.encode(bytes)
                    )),
                );
            }
        }
        let mut mapped = Map::new();
        if let Some(mapper) = self.mapper {
            mapped.extend(
                mapper(profile.clone())
                    .map_err(super::remaining_profile::profile_exception)?
                    .public_profile(true),
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
        let email = profile
            .get("email")
            .filter(|value| super::remaining_profile::truthy(value));
        let verified = match profile.get("email_verified") {
            Some(value) => super::email_verified_claim(Some(value)),
            None => {
                if let Some(email) = email {
                    email_list_includes(profile.get("verified_primary_email"), email)
                        .map_err(super::remaining_profile::profile_exception)?
                        || email_list_includes(profile.get("verified_secondary_email"), email)
                            .map_err(super::remaining_profile::profile_exception)?
                } else {
                    false
                }
            }
        };
        let mut output = Map::new();
        for (source, target) in [("name", "name"), ("email", "email"), ("picture", "image")] {
            if let Some(value) = profile.get(source) {
                output.insert(target.into(), value.clone());
            }
        }
        output.insert("emailVerified".into(), Value::Bool(verified));
        output.extend(mapped);
        let mut response = OAuthUserInfoResponse {
            user_output: Some(output.clone()),
            user: OAuthUserInfo {
                additional_fields: Map::new(),
                id,
                email: String::new(),
                name: None,
                image: None,
                email_verified: false,
            },
            data: profile,
        };
        super::apply_application_mapping(&mut response, output)
            .map_err(super::remaining_profile::profile_exception)?;
        Ok(response)
    }
}

fn subject(profile: &Value) -> Result<String, String> {
    let id = profile
        .get("oid")
        .and_then(Value::as_str)
        .ok_or("Missing Microsoft oid")?;
    if id
        .trim_matches(|character: char| {
            (character.is_whitespace() && character != '\u{85}') || character == '\u{feff}'
        })
        .is_empty()
    {
        return Err("Invalid Microsoft oid".into());
    }
    Ok(id.into())
}
fn email_list_includes(value: Option<&Value>, email: &Value) -> Result<bool, String> {
    match value {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Array(values)) => Ok(values
            .iter()
            .any(|value| super::remaining_profile::strict_primitive_equal(value, email))),
        Some(Value::String(value)) => {
            Ok(value.contains(&super::remaining_profile::js_string(email)?))
        }
        _ => Err("Invalid Microsoft verified email list".into()),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    struct Mapper;
    #[async_trait]
    impl super::super::OAuthProfileMapper for Mapper {
        async fn map_profile(&self, profile: Value) -> Result<Map<String, Value>, String> {
            let expected = base64::engine::general_purpose::STANDARD
                .encode(serde_json::json!("photo").to_string());
            assert_eq!(
                profile["picture"],
                format!("data:image/jpeg;base64, {expected}")
            );
            Ok(
                serde_json::json!({"name":"Mapped","id":"public-id","custom":true})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
        }
    }
    #[tokio::test]
    async fn microsoft_maps_photo_enriched_claims() {
        let body = serde_json::json!("photo");

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

        let mut options = MicrosoftOptions::new("client", None);
        options.profile_photo_endpoint = Some(endpoint);
        let provider = OAuthProvider::microsoft(options)
            .unwrap()
            .with_profile_mapper(Arc::new(Mapper));
        let profile = serde_json::json!({"oid":"object-id","name":"Original","email":"a@example.com","verified_primary_email":["a@example.com"]});
        let token = format!(
            "e30.{}.sig",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(profile.to_string())
        );
        let response = provider
            .get_user_info
            .as_ref()
            .unwrap()
            .get_user_info(OAuthUserInfoRequest {
                id_token: Some(token),
                access_token: Some("access".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        let output = response.user_output.unwrap();
        assert_eq!(output["name"], "Mapped");
        assert_eq!(output["email"], "a@example.com");
        assert_eq!(output["emailVerified"], true);
        assert_eq!(output["custom"], true);
        assert_eq!(output["id"], "public-id");
        assert_eq!(
            provider.account_subject.unwrap()(&response.data).unwrap(),
            "object-id"
        );
        server.await.unwrap();
    }
    #[tokio::test]
    async fn microsoft_accepts_padded_jwt_payload() {
        let profile = serde_json::json!({"sub":"subject","oid":"object-id","name":"A","email":"a@example.com"});
        let mut json = profile.to_string();
        while json.len() % 3 == 0 {
            json.push(' ');
        }
        let payload = base64::engine::general_purpose::URL_SAFE.encode(json);
        assert!(payload.ends_with('='));
        let provider = OAuthProvider::microsoft({
            let mut options = MicrosoftOptions::new("client", Some("secret".into()));
            options.disable_profile_photo = true;
            options
        })
        .unwrap();
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
