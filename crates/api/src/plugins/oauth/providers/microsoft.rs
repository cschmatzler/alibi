//! Microsoft Entra ID's configured authority, tenant and original object ID.
use super::{
    OAuthAuthorizationPolicy, OAuthClientAssertion, OAuthProvider, OAuthScopeEncoding,
    OAuthTokenEndpointAuth, OAuthUserInfo, OAuthUserInfoHandler, OAuthUserInfoRequest,
    OAuthUserInfoResponse,
};
use crate::plugins::oauth::{
    HttpOAuthJwksSource, OAuthIdTokenClaimsVerifier, OAuthIdTokenConfig, OAuthJwksSelection,
    OAuthJwksSource, OAuthNonceComparison,
};
use async_trait::async_trait;
use base64::Engine;
use better_auth_core::utils::json::JsValue;
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
            authorization_params: Vec::new(),
            account_subject: Some(subject),
            map_user_info: None,
            get_user_info: Some(Arc::new(MicrosoftUserInfo {
                photo_endpoint,
                disable_photo: options.disable_profile_photo,
                mapper: options.map_profile_to_user,
            })),
            refresh_access_token: None,
            verify_id_token: None,
            id_token: Some(verification),
            disable_id_token_sign_in: false,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
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
struct MicrosoftUserInfo {
    photo_endpoint: String,
    disable_photo: bool,
    mapper: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
}
#[async_trait]
impl OAuthUserInfoHandler for MicrosoftUserInfo {
    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        let token = request
            .id_token
            .filter(|value| !value.is_empty())
            .ok_or("Missing Microsoft ID token")?;
        let parts: Vec<_> = token.split('.').collect();
        let [_, payload, _] = parts.as_slice() else {
            return Err("Invalid Microsoft ID token".into());
        };
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|error| error.to_string())?;
        let mut profile: Value =
            better_auth_core::utils::json::from_slice(&bytes).map_err(|error| error.to_string())?;
        if !profile.is_object() {
            return Err("Invalid Microsoft ID-token claims set".into());
        }
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
                drop(object.insert(
                    "picture".into(),
                    Value::String(format!(
                        "data:image/jpeg;base64, {}",
                        base64::engine::general_purpose::STANDARD.encode(bytes)
                    )),
                ));
            }
        }
        let mapped = self
            .mapper
            .map(|mapper| mapper(profile.clone()))
            .transpose()?;
        let email = profile
            .get("email")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let verified = match profile.get("email_verified") {
            Some(value) => truthy(value),
            None => {
                !email.is_empty()
                    && (email_list_includes(profile.get("verified_primary_email"), &email)?
                        || email_list_includes(profile.get("verified_secondary_email"), &email)?)
            }
        };
        // Public provider output keeps the original JSON shape independently
        // from the typed values used by account admission and persistence.
        let user_output = Some(mapped.as_ref().map_or_else(
            || {
                let mut output = serde_json::Map::new();
                for (source, target) in [("name", "name"), ("email", "email"), ("picture", "image")]
                {
                    if let Some(value) = profile.get(source) {
                        drop(output.insert(target.into(), value.clone()));
                    }
                }
                drop(
                    output.insert(
                        "emailVerified".into(),
                        profile
                            .get("email_verified")
                            .cloned()
                            .unwrap_or(Value::Bool(verified)),
                    ),
                );
                output
            },
            |user| user.public_profile(true),
        ));
        let user = match mapped {
            Some(user) => user,
            None => OAuthUserInfo {
                additional_fields: Default::default(),
                id,
                email,
                name: scalar(profile.get("name"))?,
                image: scalar(profile.get("picture"))?,
                email_verified: verified,
            },
        };
        Ok(OAuthUserInfoResponse {
            user_output,
            user,
            data: profile,
        })
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
fn email_list_includes(value: Option<&Value>, email: &str) -> Result<bool, String> {
    match value {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Array(values)) => Ok(values.iter().any(|value| value.as_str() == Some(email))),
        Some(Value::String(value)) => Ok(value.contains(email)),
        _ => Err("Invalid Microsoft verified email list".into()),
    }
}
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}
fn scalar(value: Option<&Value>) -> Result<Option<String>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(Value::Number(value)) => better_auth_core::utils::json::number_to_string(value)
            .map(Some)
            .map_err(|error| error.to_string()),
        Some(Value::Bool(value)) => Ok(Some(value.to_string())),
        Some(Value::Array(_) | Value::Object(_)) => Err("Invalid Microsoft profile field".into()),
    }
}
