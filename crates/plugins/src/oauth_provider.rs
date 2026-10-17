//! OAuth authorization-server discovery from installed issuer and provider policy.
pub use authentication::{OAuthAuthenticatedClient, OAuthClientAuthenticationOptions};
mod access_validation;
mod authentication;
pub use client_secret::{OAuthClientSecretCipher, OAuthClientSecretHasher};
mod assertion;
mod authorization;
mod claims_request;
mod client_jwks;
mod client_secret;
mod clients;
mod consent;
mod continuation;
mod credentials;
mod discovery;
mod dpop;
mod extension_authentication;
mod interaction;
pub use extension_authentication::{
    OAuthClientAssertionInput, OAuthClientAuthenticationStrategy,
    OAuthExtensionClientAuthentication, OAuthVerifiedClientAssertion,
};
mod extension_claims;
pub use extension_claims::{
    OAuthExtensionClaims, OAuthTokenClaimsContributor, OAuthTokenClaimsInput,
    OAuthUserInfoClaimsContributor, OAuthUserInfoClaimsInput,
};
mod extensions;
pub use extensions::{
    OAuthExtensionGrantHandler, OAuthExtensionGrantInput, OAuthMetadataContributor,
    OAuthMetadataExtensionInput, OAuthMetadataType, OAuthProviderApi, OAuthProviderExtension,
};
mod id_token;
mod issuance;
pub use issuance::OAuthTokenIssueParams;
mod initial_access_token;
mod introspection;
pub use initial_access_token::{
    OAuthInitialAccessTokenAuthorization, OAuthInitialAccessTokenError,
    OAuthInitialAccessTokenInput, OAuthInitialAccessTokenValidator,
};
mod logout;
mod machine;
mod refresh;
mod resource_policy;
mod resources;
mod revocation;
mod session_retirement;
mod subject;
mod token;
mod token_storage;
pub use token_storage::OAuthTokenHasher;
mod userinfo;
use alibi_core::endpoint::{
    EndpointCall, EndpointDefinition, EndpointInput, EndpointResponse, ServerEndpoint,
};
use alibi_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, HttpMethod,
};
pub use assertion::consume_client_assertion;
use async_trait::async_trait;
pub use client_jwks::{
    OAuthClientMetadataAbortSignal, OAuthClientMetadataFetchOptions,
    OAuthClientMetadataFetchResponse, OAuthClientMetadataResourceFetch,
};
pub use clients::CreateOAuthClientInput;
pub use discovery::OAuthClientDiscovery;
use serde_json::{Value, json};

/// Actual authenticated context passed to an operator client-privilege decision.
#[derive(Debug, Clone)]
pub struct OAuthClientPrivilegeContext {
    pub action: &'static str,
    pub headers: alibi_core::Headers,
    pub user: Value,
    pub session: Value,
}
#[async_trait]
pub trait OAuthClientPrivileges: Send + Sync + std::fmt::Debug {
    async fn allowed(&self, context: &OAuthClientPrivilegeContext) -> AuthResult<bool>;
}
/// Application-owned client identifiers. Empty output is preserved, matching the reference.
pub trait OAuthClientIdGenerator: Send + Sync + std::fmt::Debug {
    fn generate(&self) -> AuthResult<String>;
}
/// Application-owned client credential generation. Empty output uses the default generator.
pub trait OAuthClientSecretGenerator: Send + Sync + std::fmt::Debug {
    fn generate(&self) -> AuthResult<String>;
}
/// Application redirect trust decision. URI safety remains provider-owned.
///
/// The URI is the original request parameter on schema/request errors, and the
/// successfully schema-parsed parameter otherwise. Neither argument uses parsed
/// URL equality. Returning an error denies trust rather than failing the route.
#[async_trait]
pub trait OAuthRedirectUriValidator: Send + Sync + std::fmt::Debug {
    async fn validate(
        &self,
        redirect_uri: &str,
        registered_uris: &[String],
        default_result: bool,
    ) -> AuthResult<bool>;
}
/// Immutable policy shared by authorization-server metadata and grant admission.
#[derive(Clone, Debug)]
pub struct OAuthProviderConfig {
    pub scopes: Vec<String>,
    pub extensions: Vec<std::sync::Arc<OAuthProviderExtension>>,
    /// Operator-owned `UserInfo` claims, applied after additive extension claims.
    /// May override ordinary profile claims, but never the authoritative subject.
    pub custom_user_info_claims: Option<std::sync::Arc<dyn OAuthUserInfoClaimsContributor>>,
    /// Operator-owned ID-token claims. Profile claims may override additive
    /// contributions; provider-owned protocol claims remain authoritative.
    pub custom_id_token_claims: Option<std::sync::Arc<dyn OAuthTokenClaimsContributor>>,
    pub client_discoveries: Vec<std::sync::Arc<dyn OAuthClientDiscovery>>,
    /// Managed identities cached by provider instance and protected from API mutations.
    pub cached_trusted_clients: std::collections::HashSet<String>,
    /// Operator decision for assigning client-credentials scopes.
    pub client_credentials_scope_privileges: Option<std::sync::Arc<dyn OAuthClientPrivileges>>,
    pub client_id_generator: Option<std::sync::Arc<dyn OAuthClientIdGenerator>>,
    pub client_secret_generator: Option<std::sync::Arc<dyn OAuthClientSecretGenerator>>,
    /// Override registered redirect matching after provider-owned URI safety checks.
    pub validate_redirect_uri: Option<std::sync::Arc<dyn OAuthRedirectUriValidator>>,
    pub client_secret_hasher: Option<std::sync::Arc<dyn OAuthClientSecretHasher>>,
    /// Application token hashing for authorization codes, access and refresh tokens.
    pub token_hasher: Option<std::sync::Arc<dyn OAuthTokenHasher>>,
    pub client_secret_cipher: Option<std::sync::Arc<dyn OAuthClientSecretCipher>>,
    /// Wire prefix matching Better Auth's `prefix.clientSecret`; stored credentials exclude it.
    pub client_secret_prefix: Option<String>,
    pub login_page: String,
    pub consent_page: String,
    pub select_account_page: Option<String>,
    pub code_expires_in: f64,
    /// User access-token lifetime in seconds, including refresh grant issuance.
    pub access_token_expires_in: f64,
    /// Access-token lifetime for issuance without a user.
    pub m2m_access_token_expires_in: f64,
    pub id_token_expires_in: f64,
    pub refresh_token_expires_in: f64,
    /// Per-scope access-expiration ceilings. Numeric values are absolute Unix
    /// seconds (and numeric zero is ignored), matching the reference policy.
    pub scope_expirations: std::collections::HashMap<String, crate::jwt::JwtExpiration>,
    /// Maximum assertion future expiration and issued-at age, in seconds (default 300).
    pub assertion_max_lifetime: f64,
    pub refresh_token_reuse_interval: f64,
    pub allow_public_client_prelogin: bool,
    pub enforce_per_client_resources: bool,
    pub advertised_scopes: Option<Vec<String>>,
    pub advertised_claims: Option<Vec<String>>,
    pub grant_types: Vec<String>,
    pub allow_dynamic_client_registration: bool,
    /// Operator authorization for Bearer credentials presented without a genuine user session.
    pub initial_access_token_validator:
        Option<std::sync::Arc<dyn OAuthInitialAccessTokenValidator>>,
    pub allow_unauthenticated_client_registration: bool,
    pub disable_jwt_plugin: bool,
    pub pairwise_secret: Option<String>,
    pub dpop_signing_algorithms: Option<Vec<String>>,
    pub dpop_proof_max_age_seconds: Option<f64>,
}
impl Default for OAuthProviderConfig {
    fn default() -> Self {
        Self {
            extensions: Vec::new(),
            custom_user_info_claims: None,
            custom_id_token_claims: None,
            client_discoveries: Vec::new(),
            cached_trusted_clients: std::collections::HashSet::new(),
            client_credentials_scope_privileges: None,
            client_id_generator: None,
            client_secret_generator: None,
            validate_redirect_uri: None,
            client_secret_hasher: None,
            client_secret_cipher: None,
            token_hasher: None,
            client_secret_prefix: None,
            login_page: "/login".into(),
            consent_page: "/consent".into(),
            select_account_page: None,
            code_expires_in: 600.0,
            access_token_expires_in: 3600.0,
            m2m_access_token_expires_in: 3600.0,
            id_token_expires_in: 36_000.0,
            refresh_token_expires_in: 2_592_000.0,
            scope_expirations: std::collections::HashMap::new(),
            assertion_max_lifetime: 300.0,
            refresh_token_reuse_interval: 0.0,
            allow_public_client_prelogin: false,
            enforce_per_client_resources: true,
            scopes: ["openid", "profile", "email", "offline_access"]
                .map(str::to_owned)
                .into(),
            advertised_scopes: None,
            advertised_claims: None,
            grant_types: ["authorization_code", "client_credentials", "refresh_token"]
                .map(str::to_owned)
                .into(),
            allow_dynamic_client_registration: false,
            initial_access_token_validator: None,
            allow_unauthenticated_client_registration: false,
            disable_jwt_plugin: false,
            pairwise_secret: None,
            dpop_signing_algorithms: None,
            dpop_proof_max_age_seconds: None,
        }
    }
}
#[derive(Clone, Debug, Default)]
pub struct OAuthProviderPlugin {
    config: OAuthProviderConfig,
    client_jwks: std::sync::Arc<client_jwks::Cache>,
    trusted_clients: std::sync::Arc<discovery::TrustedCache>,
}
impl OAuthProviderPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use]
    pub fn with_config(mut config: OAuthProviderConfig) -> Self {
        config.scopes = unique(
            config
                .scopes
                .into_iter()
                .filter(|scope| !scope.is_empty())
                .collect(),
        );
        Self {
            config,
            ..Self::default()
        }
    }
    /// Return the issuer's authorization-server configuration for trusted server callers.
    #[must_use]
    pub fn get_oauth_server_config_endpoint() -> ServerEndpoint<Value> {
        ServerEndpoint::new("oauth-provider", "getOAuthServerConfig")
    }
    /// Return `OpenID` configuration when the provider supports the openid scope.
    #[must_use]
    pub fn get_open_id_config_endpoint() -> ServerEndpoint<Value> {
        ServerEndpoint::new("oauth-provider", "getOpenIdConfig")
    }
    fn metadata<S: AuthSchema>(&self, ctx: &AuthContext<S>) -> AuthResult<Value> {
        let jwt = if self.config.disable_jwt_plugin {
            None
        } else {
            Some(
                ctx.extensions
                    .get::<super::jwt::JwtDiscoveryOptions>()
                    .ok_or_else(|| AuthError::config("jwt_config"))?,
            )
        };
        let base = format!(
            "{}{}",
            ctx.config.base_url.trim_end_matches('/'),
            ctx.config.base_path
        );
        let issuer = jwt
            .as_ref()
            .and_then(|jwt| jwt.issuer.as_deref())
            .unwrap_or(&base);
        let issuer = normalize_issuer(issuer);
        let grants = self.supported_grant_types();
        let endpoint_auth = self.supported_auth_methods(false);
        let mut token_auth = endpoint_auth.clone();
        if self.config.allow_unauthenticated_client_registration
            || !self.config.client_discoveries.is_empty()
        {
            token_auth.insert(0, "none".into());
        }
        let signing = [
            "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512",
            "EdDSA",
        ];
        let mut output: serde_json::Map<String, Value> = serde_json::from_value(json!({
            "scopes_supported":self.config.advertised_scopes.as_ref().unwrap_or(&self.config.scopes),
            "issuer":issuer,"authorization_endpoint":format!("{base}/oauth2/authorize"),"token_endpoint":format!("{base}/oauth2/token"),
            "introspection_endpoint":format!("{base}/oauth2/introspect"),"revocation_endpoint":format!("{base}/oauth2/revoke"),
            "response_types_supported":if grants.iter().any(|grant|grant=="authorization_code"){vec!["code"]}else{vec![]},
            "response_modes_supported":["query"],"grant_types_supported":grants,
            "token_endpoint_auth_methods_supported":token_auth,"token_endpoint_auth_signing_alg_values_supported":signing,
            "introspection_endpoint_auth_methods_supported":endpoint_auth,
            "introspection_endpoint_auth_signing_alg_values_supported":signing,
            "revocation_endpoint_auth_methods_supported":endpoint_auth,
            "revocation_endpoint_auth_signing_alg_values_supported":signing,
            "code_challenge_methods_supported":["S256"],"authorization_response_iss_parameter_supported":true,
            "dpop_signing_alg_values_supported":self.config.dpop_signing_algorithms.clone().unwrap_or_else(||["EdDSA","ES256","ES512","PS256","RS256"].map(str::to_owned).into()),
            "backchannel_logout_supported":!self.config.disable_jwt_plugin,"backchannel_logout_session_supported":!self.config.disable_jwt_plugin,
        }))?;
        if let Some(jwt) = jwt.as_ref() {
            _ = output.insert(
                "jwks_uri".into(),
                json!(
                    jwt.remote_url
                        .clone()
                        .unwrap_or_else(|| format!("{base}{}", jwt.jwks_path))
                ),
            );
        }
        if self.config.allow_dynamic_client_registration {
            _ = output.insert(
                "registration_endpoint".into(),
                json!(format!("{base}/oauth2/register")),
            );
        }
        if self.config.scopes.iter().any(|scope| scope == "openid") {
            _ = output.insert("claims_supported".into(), json!(self.supported_claims()));
            _ = output.insert("claims_parameter_supported".into(), json!(true));
            _ = output.insert(
                "userinfo_endpoint".into(),
                json!(format!("{base}/oauth2/userinfo")),
            );
            _ = output.insert(
                "subject_types_supported".into(),
                json!(if self
                    .config
                    .pairwise_secret
                    .as_ref()
                    .is_some_and(|secret| !secret.is_empty())
                {
                    vec!["public", "pairwise"]
                } else {
                    vec!["public"]
                }),
            );
            _ = output.insert("acr_values_supported".into(), json!(["0"]));
            _ = output.insert(
                "id_token_signing_alg_values_supported".into(),
                json!(jwt.as_ref().map_or_else(
                    || vec!["HS256".to_owned()],
                    |jwt| jwt.signing_algorithms.clone()
                )),
            );
            _ = output.insert(
                "end_session_endpoint".into(),
                json!(format!("{base}/oauth2/end-session")),
            );
            _ = output.insert("request_parameter_supported".into(), json!(false));
            _ = output.insert("request_uri_parameter_supported".into(), json!(false));
            _ = output.insert(
                "prompt_values_supported".into(),
                json!(["login", "consent", "create", "select_account", "none"]),
            );
        }
        let mut contributed = serde_json::Map::new();
        for discovery in &self.config.client_discoveries {
            contributed.extend(discovery.discovery_metadata());
        }
        contributed.extend(output);
        self.apply_metadata_extensions(ctx, Value::Object(contributed))
    }
}
fn unique(values: Vec<String>) -> Vec<String> {
    let mut result = Vec::new();
    for value in values {
        if !result.contains(&value) {
            result.push(value);
        }
    }
    result
}
fn normalize_issuer(value: &str) -> String {
    let Ok(mut url) = url::Url::parse(value) else {
        return value.into();
    };
    let loopback = url.host_str().is_some_and(|host| {
        host == "localhost" || host == "127.0.0.1" || host == "[::1]" || host == "::1"
    });
    if url.scheme() != "https" && !loopback {
        _ = url.set_scheme("https");
    }
    url.set_query(None);
    url.set_fragment(None);
    url.to_string().trim_end_matches('/').to_owned()
}
#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for OAuthProviderPlugin {
    fn name(&self) -> &'static str {
        "oauth-provider"
    }
    fn endpoint_hooks(&self) -> Vec<&dyn alibi_core::endpoint::EndpointHook<S>> {
        vec![self]
    }
    async fn before_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<alibi_core::BeforeRequestAction>> {
        let body = req.body_as_json::<alibi_core::utils::json::JsValue>().ok();
        interaction::admit(
            body.as_ref().and_then(|body| body.get("oauth_query")),
            ctx.config.current_secret(),
            req.extensions(),
        )?
        .map(|response| {
            response
                .to_response()
                .map(alibi_core::BeforeRequestAction::Respond)
        })
        .transpose()
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
        response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        let Some(mut resumed) = interaction::resume(self, req, &response.headers, ctx).await?
        else {
            return Ok(response);
        };
        resumed.merge_headers(response.headers);
        resumed.to_response()
    }
    fn allowed_media_types(&self, route: &AuthRoute) -> Vec<&'static str> {
        match route.path.as_str() {
            "/oauth2/authorize"
            | "/oauth2/end-session/confirm"
            | "/oauth2/token"
            | "/oauth2/introspect"
            | "/oauth2/revoke"
            | "/oauth2/userinfo" => vec!["application/x-www-form-urlencoded"],
            "/oauth2/end-session" => vec!["application/json", "application/x-www-form-urlencoded"],
            _ => vec!["application/json"],
        }
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::post(
                "/oauth2/end-session/confirm",
                "oauth2EndSessionConfirmation",
            ),
            AuthRoute::get("/oauth2/end-session", "oauth2EndSession"),
            AuthRoute::post("/oauth2/end-session", "oauth2EndSession"),
            AuthRoute::get("/oauth2/userinfo", "oauth2UserInfo"),
            AuthRoute::post("/oauth2/userinfo", "oauth2UserInfo"),
            AuthRoute::post("/oauth2/revoke", "oauth2Revoke"),
            AuthRoute::post("/oauth2/introspect", "oauth2Introspect"),
            AuthRoute::post("/oauth2/token", "oauth2Token"),
            AuthRoute::post("/oauth2/create-client", "createOAuthClient"),
            AuthRoute::get("/oauth2/get-client", "getOAuthClient"),
            AuthRoute::get("/oauth2/public-client", "getOAuthClientPublic"),
            AuthRoute::post(
                "/oauth2/public-client-prelogin",
                "getOAuthClientPublicPrelogin",
            ),
            AuthRoute::get("/oauth2/get-clients", "getOAuthClients"),
            AuthRoute::post("/oauth2/delete-client", "deleteOAuthClient"),
            AuthRoute::post("/oauth2/update-client", "updateOAuthClient"),
            AuthRoute::post("/oauth2/register", "registerOAuthClient"),
            AuthRoute::post("/oauth2/consent", "oauth2Consent"),
            AuthRoute::post("/oauth2/continue", "oauth2Continue"),
            AuthRoute::get("/oauth2/get-consents", "getOAuthConsents"),
            AuthRoute::get("/oauth2/get-consent", "getOAuthConsent"),
            AuthRoute::post("/oauth2/update-consent", "updateOAuthConsent"),
            AuthRoute::post("/oauth2/delete-consent", "deleteOAuthConsent"),
            AuthRoute::get("/oauth2/authorize", "oauth2Authorize"),
            AuthRoute::post("/oauth2/authorize", "oauth2Authorize"),
            AuthRoute::post("/oauth2/client/rotate-secret", "rotateClientSecret"),
        ]
    }
    fn server_endpoints(&self) -> Vec<EndpointDefinition> {
        vec![
            crate::endpoint::definition(
                "oauth2EndSessionConfirmation",
                "oauth2EndSessionConfirmation",
                Some("/oauth2/end-session/confirm"),
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "oauth2EndSession",
                "oauth2EndSession",
                Some("/oauth2/end-session"),
                HttpMethod::Get,
            ),
            crate::endpoint::definition(
                "oauth2UserInfo",
                "oauth2UserInfo",
                Some("/oauth2/userinfo"),
                HttpMethod::Get,
            ),
            crate::endpoint::definition(
                "oauth2Revoke",
                "oauth2Revoke",
                Some("/oauth2/revoke"),
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "oauth2Introspect",
                "oauth2Introspect",
                Some("/oauth2/introspect"),
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "oauth2Token",
                "oauth2Token",
                Some("/oauth2/token"),
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "oauth2Continue",
                "oauth2Continue",
                Some("/oauth2/continue"),
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "adminUnlinkClientResource",
                "adminUnlinkClientResource",
                Some("/admin/oauth2/resources/:identifier/clients/:client_id"),
                HttpMethod::Delete,
            ),
            crate::endpoint::definition(
                "adminLinkClientResource",
                "adminLinkClientResource",
                Some("/admin/oauth2/resources/:identifier/clients/:client_id"),
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "adminDeleteOAuthResource",
                "adminDeleteOAuthResource",
                Some("/admin/oauth2/resources/:identifier"),
                HttpMethod::Delete,
            ),
            crate::endpoint::definition(
                "adminUpdateOAuthResource",
                "adminUpdateOAuthResource",
                Some("/admin/oauth2/resources/:identifier"),
                HttpMethod::Patch,
            ),
            crate::endpoint::definition(
                "adminGetOAuthResource",
                "adminGetOAuthResource",
                Some("/admin/oauth2/resources/:identifier"),
                HttpMethod::Get,
            ),
            crate::endpoint::definition(
                "adminListOAuthResources",
                "adminListOAuthResources",
                Some("/admin/oauth2/resources"),
                HttpMethod::Get,
            ),
            crate::endpoint::definition(
                "adminCreateOAuthResource",
                "adminCreateOAuthResource",
                Some("/admin/oauth2/resources"),
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "deleteOAuthConsent",
                "deleteOAuthConsent",
                Some("/oauth2/delete-consent"),
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "updateOAuthConsent",
                "updateOAuthConsent",
                Some("/oauth2/update-consent"),
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "getOAuthConsent",
                "getOAuthConsent",
                Some("/oauth2/get-consent"),
                HttpMethod::Get,
            ),
            crate::endpoint::definition(
                "getOAuthConsents",
                "getOAuthConsents",
                Some("/oauth2/get-consents"),
                HttpMethod::Get,
            ),
            crate::endpoint::definition(
                "oauth2Consent",
                "oauth2Consent",
                Some("/oauth2/consent"),
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "getOAuthClientPublicPrelogin",
                "getOAuthClientPublicPrelogin",
                Some("/oauth2/public-client-prelogin"),
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "oauth2Authorize",
                "oauth2Authorize",
                Some("/oauth2/authorize"),
                HttpMethod::Get,
            ),
            crate::endpoint::definition(
                "adminUpdateOAuthClient",
                "adminUpdateOAuthClient",
                Some("/admin/oauth2/update-client"),
                HttpMethod::Patch,
            ),
            crate::endpoint::definition(
                "adminCreateOAuthClient",
                "adminCreateOAuthClient",
                Some("/admin/oauth2/create-client"),
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "registerOAuthClient",
                "registerOAuthClient",
                Some("/oauth2/register"),
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "updateOAuthClient",
                "updateOAuthClient",
                Some("/oauth2/update-client"),
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "rotateClientSecret",
                "rotateClientSecret",
                Some("/oauth2/client/rotate-secret"),
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "deleteOAuthClient",
                "deleteOAuthClient",
                Some("/oauth2/delete-client"),
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "getOAuthClients",
                "getOAuthClients",
                Some("/oauth2/get-clients"),
                HttpMethod::Get,
            ),
            crate::endpoint::definition(
                "getOAuthClientPublic",
                "getOAuthClientPublic",
                Some("/oauth2/public-client"),
                HttpMethod::Get,
            ),
            crate::endpoint::definition(
                "getOAuthClient",
                "getOAuthClient",
                Some("/oauth2/get-client"),
                HttpMethod::Get,
            ),
            crate::endpoint::definition(
                "createOAuthClient",
                "createOAuthClient",
                Some("/oauth2/create-client"),
                HttpMethod::Post,
            ),
            crate::endpoint::definition(
                "getOAuthServerConfig",
                "getOAuthServerConfig",
                Some("/.well-known/oauth-authorization-server"),
                HttpMethod::Get,
            ),
            crate::endpoint::definition(
                "getOpenIdConfig",
                "getOpenIdConfig",
                Some("/.well-known/openid-configuration"),
                HttpMethod::Get,
            ),
        ]
    }
    fn validate_endpoint(
        &self,
        call: &EndpointCall,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointInput> {
        Ok(EndpointInput {
            body: if call.operation_id() == "oauth2EndSessionConfirmation" {
                Some(crate::endpoint::validate_fields(
                    call.body(),
                    "body",
                    &[crate::authentication_helpers::JsonField {
                        name: "action",
                        kind: crate::authentication_helpers::JsonFieldKind::OneOf(&["confirm"]),
                        required: true,
                    }],
                )?)
            } else if call.operation_id() == "oauth2EndSession" {
                logout::validate(call.body(), "body")?
            } else if call.operation_id() == "oauth2UserInfo" {
                call.body()
                    .map(|body| {
                        crate::endpoint::validate_fields(
                            Some(body),
                            "body",
                            &[crate::authentication_helpers::JsonField::string(
                                "access_token",
                                false,
                            )],
                        )
                    })
                    .transpose()?
            } else if call.operation_id() == "oauth2Continue" {
                Some(continuation::validate(call.body())?)
            } else if call.operation_id() == "adminUpdateOAuthResource" {
                Some(resources::validate_update(call.body())?)
            } else if call.operation_id() == "adminCreateOAuthResource" {
                Some(resources::validate_create(call.body())?)
            } else if call.operation_id() == "deleteOAuthConsent" {
                Some(consent::validate_id(call.body(), "body")?)
            } else if call.operation_id() == "updateOAuthConsent" {
                Some(consent::validate_update(call.body())?)
            } else if call.operation_id() == "oauth2Consent" {
                Some(consent::validate(call.body())?)
            } else if call.operation_id() == "getOAuthClientPublicPrelogin" {
                Some(clients::validate_prelogin(call.body())?)
            } else if call.operation_id() == "adminUpdateOAuthClient" {
                Some(clients::validate_admin_update(call.body())?)
            } else if call.operation_id() == "adminCreateOAuthClient" {
                Some(clients::validate_admin_create(call.body())?)
            } else if call.operation_id() == "updateOAuthClient" {
                Some(clients::validate_update(call.body())?)
            } else if matches!(
                call.operation_id(),
                "deleteOAuthClient" | "rotateClientSecret"
            ) {
                Some(clients::validate_delete(call.body())?)
            } else if call.operation_id() == "createOAuthClient" {
                Some(clients::validate(call.body())?)
            } else {
                call.body().cloned()
            },
            query: if call.operation_id() == "oauth2EndSession" {
                logout::validate(call.query(), "query")?
            } else if call.operation_id() == "getOAuthConsent" {
                Some(consent::validate_id(call.query(), "query")?)
            } else if matches!(
                call.operation_id(),
                "getOAuthClient" | "getOAuthClientPublic"
            ) {
                Some(clients::validate_read(call.query())?)
            } else {
                call.query().cloned()
            },
        })
    }
    async fn on_endpoint(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        if call.operation_id() == "oauth2EndSessionConfirmation" {
            return Box::pin(self.confirm_logout(call, ctx)).await;
        }
        if call.operation_id() == "oauth2EndSession" {
            return Box::pin(self.end_session(call.query(), call.body(), call, ctx)).await;
        }
        if call.operation_id() == "oauth2UserInfo" {
            return Box::pin(self.user_info(call.body(), call, ctx)).await;
        }
        if call.operation_id() == "oauth2Revoke" {
            return Box::pin(self.revoke(call.body(), call, ctx)).await;
        }
        if call.operation_id() == "oauth2Introspect" {
            return Box::pin(self.introspect(call.body(), call, ctx)).await;
        }
        if call.operation_id() == "oauth2Token" {
            return Box::pin(self.token(call.body(), call, ctx)).await;
        }
        if call.operation_id() == "oauth2Continue" {
            return Box::pin(self.continue_authorization(call.body_as()?, call, ctx)).await;
        }
        if call.operation_id() == "adminUnlinkClientResource" {
            return Box::pin(self.unlink_resource(call.params(), call, ctx)).await;
        }
        if call.operation_id() == "adminLinkClientResource" {
            return Box::pin(self.link_resource(call.params(), call, ctx)).await;
        }
        if call.operation_id() == "adminDeleteOAuthResource" {
            return Box::pin(self.delete_resource(call.params(), call, ctx)).await;
        }
        if call.operation_id() == "adminUpdateOAuthResource" {
            return Box::pin(self.update_resource(call.params(), call.body_as()?, call, ctx)).await;
        }
        if call.operation_id() == "adminGetOAuthResource" {
            return Box::pin(self.read_resource(call.params(), call, ctx)).await;
        }
        if call.operation_id() == "adminListOAuthResources" {
            return Box::pin(self.list_resources(call, ctx)).await;
        }
        if call.operation_id() == "adminCreateOAuthResource" {
            return Box::pin(self.create_resource(call.body_as()?, call, ctx)).await;
        }
        if call.operation_id() == "deleteOAuthConsent" {
            return Box::pin(self.delete_consent(call.body_as()?, call, ctx)).await;
        }
        if call.operation_id() == "updateOAuthConsent" {
            return Box::pin(self.update_consent(call.body_as()?, call, ctx)).await;
        }
        if call.operation_id() == "getOAuthConsent" {
            return Box::pin(self.read_consent(call.query_as()?, call, ctx)).await;
        }
        if call.operation_id() == "getOAuthConsents" {
            return Box::pin(self.list_consents(call, ctx)).await;
        }
        if call.operation_id() == "oauth2Consent" {
            return Box::pin(self.consent(call.body_as()?, call, ctx)).await;
        }
        if call.operation_id() == "getOAuthClientPublicPrelogin" {
            return Box::pin(self.read_prelogin_client(call.body_as()?, ctx)).await;
        }
        if call.operation_id() == "oauth2Authorize" {
            let value = if call.method() == Some(&HttpMethod::Post) {
                call.body()
            } else {
                call.query()
            };
            return Box::pin(self.authorize(value.cloned(), call, ctx)).await;
        }
        if call.operation_id() == "adminUpdateOAuthClient" {
            return Box::pin(self.update_client(call.body_as()?, call, ctx, true)).await;
        }
        if call.operation_id() == "adminCreateOAuthClient" {
            return Box::pin(self.admin_create_client(call.body_as()?, call, ctx)).await;
        }
        if call.operation_id() == "registerOAuthClient" {
            return Box::pin(self.register_client(call.body(), call, ctx)).await;
        }
        if call.operation_id() == "updateOAuthClient" {
            return Box::pin(self.update_client(call.body_as()?, call, ctx, false)).await;
        }
        if call.operation_id() == "rotateClientSecret" {
            return Box::pin(self.rotate_client_secret(call.body_as()?, call, ctx)).await;
        }
        if call.operation_id() == "deleteOAuthClient" {
            return Box::pin(self.delete_client(call.body_as()?, call, ctx)).await;
        }
        if call.operation_id() == "getOAuthClients" {
            return Box::pin(self.list_clients(call, ctx)).await;
        }
        if call.operation_id() == "getOAuthClientPublic" {
            return Box::pin(self.read_public_client(call.query_as()?, call, ctx)).await;
        }
        if call.operation_id() == "getOAuthClient" {
            return Box::pin(self.read_client(call.query_as()?, call, ctx)).await;
        }
        if call.operation_id() == "createOAuthClient" {
            return Box::pin(self.create_client(call.body_as()?, call, ctx)).await;
        }
        if call.operation_id() == "getOpenIdConfig"
            && !self.config.scopes.iter().any(|scope| scope == "openid")
        {
            return Ok(EndpointResponse::error(AuthError::Api {
                status: 404,
                code: None,
                message: String::new(),
            })
            .without_error_body()
            .with_header("Content-Type", "application/json"));
        }
        EndpointResponse::json(&self.metadata(ctx)?)
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        if req.path() == "/oauth2/end-session/confirm" && *req.method() == HttpMethod::Post {
            let action = url::form_urlencoded::parse(req.body.as_deref().unwrap_or_default())
                .find(|(key, _)| key == "action")
                .map(|(_, value)| value.into_owned());
            if action.as_deref() != Some("confirm") {
                return Ok(Some(
                    AuthError::bad_request("Invalid logout action").to_auth_response(),
                ));
            }
            return Ok(Some(
                Box::pin(self.confirm_logout(req, ctx))
                    .await?
                    .to_response()?,
            ));
        }
        if req.path() == "/oauth2/end-session"
            && matches!(req.method(), HttpMethod::Get | HttpMethod::Post)
        {
            let query = alibi_core::utils::json::parse_value(&serde_json::to_string(&req.query)?)?;
            let body = if *req.method() == HttpMethod::Post {
                Some(alibi_core::utils::json::parse_value(
                    &serde_json::to_string(
                        &url::form_urlencoded::parse(req.body.as_deref().unwrap_or_default())
                            .into_owned()
                            .collect::<std::collections::HashMap<_, _>>(),
                    )?,
                )?)
            } else {
                None
            };
            return Ok(Some(
                Box::pin(self.end_session(Some(&query), body.as_ref(), req, ctx))
                    .await?
                    .to_response()?,
            ));
        }
        if req.path() == "/oauth2/userinfo"
            && matches!(req.method(), HttpMethod::Get | HttpMethod::Post)
        {
            let body = if *req.method() == HttpMethod::Post {
                let fields = url::form_urlencoded::parse(req.body.as_deref().unwrap_or_default())
                    .map(|(key, value)| {
                        (
                            key.into_owned(),
                            alibi_core::utils::json::JsValue::String(value.into_owned()),
                        )
                    })
                    .collect();
                Some(alibi_core::utils::json::JsValue::Object(fields))
            } else {
                None
            };
            return Ok(Some(
                Box::pin(self.user_info(body.as_ref(), req, ctx))
                    .await?
                    .to_response()?,
            ));
        }
        if matches!(
            req.path(),
            "/oauth2/token" | "/oauth2/introspect" | "/oauth2/revoke"
        ) && *req.method() == HttpMethod::Post
        {
            let mut fields = indexmap::IndexMap::new();
            for (key, value) in url::form_urlencoded::parse(req.body.as_deref().unwrap_or_default())
            {
                _ = fields.insert(
                    key.into_owned(),
                    alibi_core::utils::json::JsValue::String(value.into_owned()),
                );
            }
            if req.path() == "/oauth2/revoke" {
                return Ok(Some(
                    Box::pin(self.revoke(
                        Some(&alibi_core::utils::json::JsValue::Object(fields)),
                        req,
                        ctx,
                    ))
                    .await?
                    .to_response()?,
                ));
            }
            if req.path() == "/oauth2/introspect" {
                return Ok(Some(
                    Box::pin(self.introspect(
                        Some(&alibi_core::utils::json::JsValue::Object(fields)),
                        req,
                        ctx,
                    ))
                    .await?
                    .to_response()?,
                ));
            }
            return Ok(Some(
                Box::pin(self.token(
                    Some(&alibi_core::utils::json::JsValue::Object(fields)),
                    req,
                    ctx,
                ))
                .await?
                .to_response()?,
            ));
        }
        if req.path() == "/oauth2/authorize"
            && matches!(req.method(), HttpMethod::Get | HttpMethod::Post)
        {
            let value = if *req.method() == HttpMethod::Post {
                req.body_as_json::<alibi_core::utils::json::JsValue>()?
            } else {
                req.query_as_js_value()
            };
            return Ok(Some(
                Box::pin(self.authorize(Some(value), req, ctx))
                    .await?
                    .to_response()?,
            ));
        }
        if req.path() == "/oauth2/register" && *req.method() == HttpMethod::Post {
            let body: alibi_core::utils::json::JsValue = req.body_as_json()?;
            return Ok(Some(
                Box::pin(self.register_client(Some(&body), req, ctx))
                    .await?
                    .to_response()?,
            ));
        }
        if req.path() == "/oauth2/update-client" && *req.method() == HttpMethod::Post {
            let body: alibi_core::utils::json::JsValue = req.body_as_json()?;
            let input =
                alibi_core::utils::json::from_value(clients::validate_update(Some(&body))?)?;
            return Ok(Some(
                Box::pin(self.update_client(input, req, ctx, false))
                    .await?
                    .to_response()?,
            ));
        }
        if matches!(
            req.path(),
            "/oauth2/delete-client" | "/oauth2/client/rotate-secret"
        ) && *req.method() == HttpMethod::Post
        {
            let body: alibi_core::utils::json::JsValue = req.body_as_json()?;
            let input =
                alibi_core::utils::json::from_value(clients::validate_delete(Some(&body))?)?;
            if req.path() == "/oauth2/client/rotate-secret" {
                return Ok(Some(
                    Box::pin(self.rotate_client_secret(input, req, ctx))
                        .await?
                        .to_response()?,
                ));
            }
            return Ok(Some(
                Box::pin(self.delete_client(input, req, ctx))
                    .await?
                    .to_response()?,
            ));
        }
        if req.path() == "/oauth2/public-client-prelogin" && *req.method() == HttpMethod::Post {
            let body = req.body_as_json()?;
            let input =
                alibi_core::utils::json::from_value(clients::validate_prelogin(Some(&body))?)?;
            return Ok(Some(
                Box::pin(self.read_prelogin_client(input, ctx))
                    .await?
                    .to_response()?,
            ));
        }
        if req.path() == "/oauth2/continue" && *req.method() == HttpMethod::Post {
            let body = req.body_as_json()?;
            let input = alibi_core::utils::json::from_value(continuation::validate(Some(&body))?)?;
            return Ok(Some(
                Box::pin(self.continue_authorization(input, req, ctx))
                    .await?
                    .to_response()?,
            ));
        }
        if req.path() == "/oauth2/consent" && *req.method() == HttpMethod::Post {
            let body = req.body_as_json()?;
            let input = alibi_core::utils::json::from_value(consent::validate(Some(&body))?)?;
            return Ok(Some(
                Box::pin(self.consent(input, req, ctx))
                    .await?
                    .to_response()?,
            ));
        }
        if req.path() == "/oauth2/delete-consent" && *req.method() == HttpMethod::Post {
            let body = req.body_as_json()?;
            let input =
                alibi_core::utils::json::from_value(consent::validate_id(Some(&body), "body")?)?;
            return Ok(Some(
                Box::pin(self.delete_consent(input, req, ctx))
                    .await?
                    .to_response()?,
            ));
        }
        if req.path() == "/oauth2/update-consent" && *req.method() == HttpMethod::Post {
            let body = req.body_as_json()?;
            let input =
                alibi_core::utils::json::from_value(consent::validate_update(Some(&body))?)?;
            return Ok(Some(
                Box::pin(self.update_consent(input, req, ctx))
                    .await?
                    .to_response()?,
            ));
        }
        if req.path() == "/oauth2/get-consent" && *req.method() == HttpMethod::Get {
            let query = alibi_core::utils::json::parse_value(&serde_json::to_string(&req.query)?)?;
            let input =
                alibi_core::utils::json::from_value(consent::validate_id(Some(&query), "query")?)?;
            return Ok(Some(
                Box::pin(self.read_consent(input, req, ctx))
                    .await?
                    .to_response()?,
            ));
        }
        if req.path() == "/oauth2/get-consents" && *req.method() == HttpMethod::Get {
            return Ok(Some(
                Box::pin(self.list_consents(req, ctx))
                    .await?
                    .to_response()?,
            ));
        }
        if req.path() == "/oauth2/get-clients" && *req.method() == HttpMethod::Get {
            return Ok(Some(
                Box::pin(self.list_clients(req, ctx)).await?.to_response()?,
            ));
        }
        if matches!(req.path(), "/oauth2/get-client" | "/oauth2/public-client")
            && *req.method() == HttpMethod::Get
        {
            let query = alibi_core::utils::json::parse_value(&serde_json::to_string(&req.query)?)?;
            let input = alibi_core::utils::json::from_value(clients::validate_read(Some(&query))?)?;
            if req.path() == "/oauth2/public-client" {
                return Ok(Some(
                    Box::pin(self.read_public_client(input, req, ctx))
                        .await?
                        .to_response()?,
                ));
            }
            return Ok(Some(
                Box::pin(self.read_client(input, req, ctx))
                    .await?
                    .to_response()?,
            ));
        }
        if req.path() == "/oauth2/create-client" && *req.method() == HttpMethod::Post {
            let body: alibi_core::utils::json::JsValue = req.body_as_json()?;
            let input = alibi_core::utils::json::from_value(clients::validate(Some(&body))?)?;
            return Ok(Some(
                Box::pin(self.create_client(input, req, ctx))
                    .await?
                    .to_response()?,
            ));
        }
        Ok(None)
    }
    async fn on_init(&self, ctx: &mut alibi_core::AuthInitContext<S>) -> AuthResult<()> {
        self.validate_extensions()?;
        if self
            .config
            .advertised_scopes
            .as_ref()
            .is_some_and(|scopes| {
                scopes
                    .iter()
                    .any(|scope| !self.config.scopes.contains(scope))
            })
        {
            return Err(AuthError::config(
                "advertisedMetadata.scopes_supported contains an unsupported scope",
            ));
        }
        if self
            .config
            .pairwise_secret
            .as_ref()
            .is_some_and(|secret| !secret.is_empty() && secret.len() < 32)
        {
            return Err(AuthError::config(
                "pairwiseSecret must be at least 32 characters long for adequate HMAC-SHA256 security",
            ));
        }
        if self
            .config
            .grant_types
            .iter()
            .any(|grant| grant == "refresh_token")
            && !self
                .config
                .grant_types
                .iter()
                .any(|grant| grant == "authorization_code")
        {
            return Err(AuthError::config(
                "refresh_token grant requires authorization_code grant",
            ));
        }
        if self.config.disable_jwt_plugin && self.config.client_secret_hasher.is_some() {
            return Err(AuthError::config(
                "unable to store hashed secrets because id tokens will be signed with secret",
            ));
        }
        if !self.config.disable_jwt_plugin && self.config.client_secret_cipher.is_some() {
            return Err(AuthError::config(
                "encryption method not recommended, please use 'hashed' or the 'hash' function",
            ));
        }
        let mut discovery_ids = std::collections::HashSet::new();
        for discovery in &self.config.client_discoveries {
            if alibi_core::utils::javascript::trim(discovery.id()).is_empty() {
                return Err(AuthError::config(
                    "OAuth Provider extension client discovery id cannot be empty",
                ));
            }
            if !discovery_ids.insert(discovery.id()) {
                return Err(AuthError::config(format!(
                    "OAuth Provider extensions register client discovery id \"{}\" more than once. Extension contributions must be disjoint.",
                    discovery.id()
                )));
            }
        }
        ctx.extensions.insert(discovery::TrustedClients {
            ids: self.config.cached_trusted_clients.clone(),
            cache: self.trusted_clients.clone(),
        });
        ctx.extensions.insert(discovery::ClientDiscoveries(
            self.config.client_discoveries.clone(),
        ));
        ctx.register_session_deletion_hook(std::sync::Arc::new(
            session_retirement::TokenRetirementHook(self.clone()),
        ));
        Ok(())
    }
}
