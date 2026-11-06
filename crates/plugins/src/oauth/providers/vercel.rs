//! Dedicated published Better Auth 1.7.6 Vercel factory.
use super::remaining_profile::{ProfileKind, PublishedProfile};
use super::{OAuthAuthorizationPolicy, OAuthProvider, OAuthTokenEndpointAuth};
use alibi_core::utils::json::JsObject as Map;
use alibi_core::utils::json::{JsString, JsValue as Value};

#[derive(Clone)]
pub struct VercelOptions {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub client_key: Option<String>,
    pub token_endpoint_auth: Option<OAuthTokenEndpointAuth>,
    pub client_assertion: Option<super::OAuthClientAssertion>,
    pub authorization_endpoint: Option<String>,
    pub redirect_uri: Option<String>,
    /// Trusted application transport override; it does not change profile semantics.
    pub user_info_endpoint: Option<String>,
    pub map_profile_to_user: Option<fn(Value) -> Result<Map, String>>,
    pub scope: Vec<String>,
}
impl VercelOptions {
    #[must_use]
    pub fn new(client_id: impl Into<String>, client_secret: Option<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret,
            client_key: None,
            token_endpoint_auth: None,
            client_assertion: None,
            authorization_endpoint: None,
            redirect_uri: None,
            user_info_endpoint: None,
            map_profile_to_user: None,
            scope: Vec::new(),
        }
    }
}
impl std::fmt::Debug for VercelOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VercelOptions")
            .field("client_id", &self.client_id)
            .field("authorization_endpoint", &self.authorization_endpoint)
            .finish_non_exhaustive()
    }
}
impl OAuthProvider {
    #[must_use]
    pub fn vercel(client_id: &str, client_secret: Option<&str>) -> Self {
        Self::vercel_with_options(VercelOptions::new(
            client_id,
            client_secret.map(str::to_owned),
        ))
    }
    /// # Panics
    /// Panics for token authentication/secret combinations rejected by Vercel.
    /// Use `try_vercel_with_options` to handle invalid configuration.
    #[must_use]
    pub fn vercel_with_options(options: VercelOptions) -> Self {
        Self::try_vercel_with_options(options).unwrap_or_else(|error| panic!("{error}"))
    }

    pub fn try_vercel_with_options(options: VercelOptions) -> Result<Self, String> {
        let has_secret = options
            .client_secret
            .as_ref()
            .is_some_and(|s| !s.is_empty());
        let invalid_method = match options.token_endpoint_auth {
            Some(OAuthTokenEndpointAuth::None) if has_secret => Some("none"),
            Some(OAuthTokenEndpointAuth::PrivateKeyJwt) if has_secret => Some("private_key_jwt"),
            Some(OAuthTokenEndpointAuth::ClientSecretBasic) if !has_secret => {
                Some("client_secret_basic")
            }
            Some(OAuthTokenEndpointAuth::ClientSecretPost) if !has_secret => {
                Some("client_secret_post")
            }
            _ => None,
        };
        if let Some(method) = invalid_method {
            let reason = if has_secret {
                "cannot be combined with"
            } else {
                "requires"
            };
            return Err(format!(
                "Vercel {method} token endpoint authentication {reason} clientSecret"
            ));
        }
        let mut policy = OAuthAuthorizationPolicy {
            preserve_raw_profile_scalars: true,
            source_profile_exceptions: true,
            code_verifier_required_for: Some("Vercel"),
            login_hint: false,
            pkce: true,
            configured_scopes: options.scope,
            disable_default_scopes: false,
            authorization_code_client_key: options.client_key,
            redirect_uri: options.redirect_uri,
            client_assertion: options.client_assertion,
            token_endpoint_auth: Some(options.token_endpoint_auth.unwrap_or_else(|| {
                if options
                    .client_secret
                    .as_ref()
                    .is_some_and(|v| !v.is_empty())
                {
                    OAuthTokenEndpointAuth::ClientSecretPost
                } else {
                    OAuthTokenEndpointAuth::None
                }
            })),
            allow_missing_access_token: true,
            preserve_raw_email_errors: true,
            ..OAuthAuthorizationPolicy::default()
        };
        let mut provider = Self {
            client_id: options.client_id,
            client_secret: options.client_secret.unwrap_or_default(),
            additional_client_ids: Vec::new(),
            hosted_domain: None,
            require_email_verification: false,
            auth_url: "https://vercel.com/oauth/authorize".into(),
            token_url: "https://api.vercel.com/login/oauth/token".into(),
            user_info_url: Some("https://api.vercel.com/login/oauth/userinfo".into()),
            scopes: vec![],
            authorization: None,
            allowed_request_params: Vec::new(),
            authorization_params: Vec::new(),
            account_subject: Some(subject),
            map_user_info: None,
            get_user_info: None,
            refresh_access_token: None,
            verify_id_token: None,
            id_token: None,
            disable_id_token_sign_in: false,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            allow_idp_initiated: false,
            override_user_info_on_sign_in: false,
        };
        provider.auth_url = options
            .authorization_endpoint
            .filter(|v| !v.is_empty())
            .unwrap_or(provider.auth_url);
        provider.user_info_url = options.user_info_endpoint.or(provider.user_info_url);
        policy.supports_refresh = false;
        provider.authorization = Some(policy);
        provider.get_user_info = Some(std::sync::Arc::new(PublishedProfile {
            kind: ProfileKind::Vercel,
            endpoint: provider.user_info_url.clone(),
            email_endpoint: None,
            client_id: provider.client_id.clone(),
            mapper: options.map_profile_to_user,
            application_mapper: None,
        }));
        Ok(provider)
    }
}
fn subject(profile: &Value) -> Result<JsString, String> {
    super::remaining_profile::subject(ProfileKind::Vercel, profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vercel_constructor_validates_explicit_authentication_against_secret_truthiness() {
        use OAuthTokenEndpointAuth::{
            ClientKeyPost, ClientSecretBasic, ClientSecretPost, PrivateKeyJwt,
        };
        for secret in [None, Some(""), Some("secret")] {
            for method in [
                None,
                Some(ClientSecretBasic),
                Some(ClientSecretPost),
                Some(PrivateKeyJwt),
                Some(OAuthTokenEndpointAuth::None),
            ] {
                let mut options = VercelOptions::new("client", secret.map(str::to_owned));
                options.token_endpoint_auth = method;
                let has_secret = secret.is_some_and(|s| !s.is_empty());
                let invalid = match method {
                    Some(PrivateKeyJwt | OAuthTokenEndpointAuth::None) => has_secret,
                    Some(ClientSecretBasic | ClientSecretPost) => !has_secret,
                    _ => false,
                };
                let result = OAuthProvider::try_vercel_with_options(options.clone());
                assert_eq!(result.is_err(), invalid, "{secret:?} {method:?}");
                if invalid {
                    let method_name = match method.unwrap() {
                        ClientSecretBasic => "client_secret_basic",
                        ClientSecretPost => "client_secret_post",
                        PrivateKeyJwt => "private_key_jwt",
                        OAuthTokenEndpointAuth::None => "none",
                        ClientKeyPost => unreachable!(),
                    };
                    let reason = if has_secret {
                        "cannot be combined with"
                    } else {
                        "requires"
                    };
                    assert_eq!(
                        result.unwrap_err(),
                        format!(
                            "Vercel {method_name} token endpoint authentication {reason} clientSecret"
                        )
                    );
                    assert!(
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            OAuthProvider::vercel_with_options(options)
                        }))
                        .is_err()
                    );
                } else {
                    let provider = result.unwrap();
                    assert_eq!(
                        provider.authorization.unwrap().token_endpoint_auth,
                        Some(method.unwrap_or(if has_secret {
                            ClientSecretPost
                        } else {
                            OAuthTokenEndpointAuth::None
                        }))
                    );
                }
            }
        }
    }
}
