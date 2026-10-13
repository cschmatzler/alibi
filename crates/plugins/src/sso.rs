//! Enterprise single-sign-on provider registration.
mod callback;
mod domain_confirmation;
mod domain_verification;
mod provider_delete;
mod provider_list;
mod provider_read;
mod provider_update;
mod registration_saml;
mod sign_in;
mod sp_metadata;
use alibi_core::endpoint::{
    EndpointCall, EndpointDefinition, EndpointInput, EndpointResponse, ServerEndpoint,
};
use alibi_core::session::SessionRequest;
use alibi_core::store::SsoProvider;
use alibi_core::utils::json::JsValue;
use alibi_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, AuthUser, HttpMethod,
};
use async_trait::async_trait;
use serde_json::{Value, json};
#[derive(Clone, Debug)]
pub struct SsoConfig {
    pub providers_limit: usize,
    pub domain_verification: bool,
    /// Override the system DNS servers, for example for an enterprise DNS zone.
    pub domain_verification_dns_servers: Vec<std::net::SocketAddr>,
    pub domain_verification_token_prefix: String,
    pub default_override_user_info: bool,
    pub redirect_uri: Option<String>,
}
impl Default for SsoConfig {
    fn default() -> Self {
        Self {
            providers_limit: 10,
            domain_verification: false,
            domain_verification_dns_servers: Vec::new(),
            domain_verification_token_prefix: "better-auth-token".into(),
            default_override_user_info: false,
            redirect_uri: None,
        }
    }
}
#[derive(Clone, Debug, Default)]
pub struct SsoPlugin {
    config: SsoConfig,
}
impl SsoPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use]
    pub fn with_config(config: SsoConfig) -> Self {
        Self { config }
    }
    pub fn register_sso_provider_endpoint(input: &Value) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("sso", "registerSSOProvider").with_body(input)
    }
    pub fn callback_sso_shared_endpoint(query: &Value) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("sso", "callbackSSOShared").with_query(query)
    }
    pub(super) fn oidc_redirect_uri(&self, base: &str, provider_id: &str) -> String {
        self.config
            .redirect_uri
            .as_ref()
            .filter(|uri| !uri.trim().is_empty())
            .map_or_else(
                || format!("{base}/sso/callback/{provider_id}"),
                |uri| {
                    if url::Url::parse(uri).is_ok() {
                        uri.clone()
                    } else {
                        format!("{base}/{}", uri.trim_start_matches('/'))
                    }
                },
            )
    }
    async fn register<S: AuthSchema>(
        &self,
        input: &JsValue,
        request: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let (user, _) = super::helpers::ordinary_session(request, ctx).await?;
        if self.config.providers_limit == 0 {
            return Err(api(403, "SSO provider registration is disabled"));
        }
        if ctx
            .database
            .list_sso_providers_by_user(user.id().as_ref())
            .await?
            .len()
            >= self.config.providers_limit
        {
            return Err(api(
                403,
                "You have reached the maximum number of SSO providers",
            ));
        }
        let body = input.to_json_value()?;
        let provider_id = required_string(&body, "providerId")?;
        let issuer = required_string(&body, "issuer")?;
        let domain = required_string(&body, "domain")?;
        if let Some(organization_id) = body.get("organizationId").and_then(Value::as_str) {
            let member = ctx
                .database
                .get_member(organization_id, user.id().as_ref())
                .await?
                .ok_or_else(|| api(400, "You are not a member of the organization"))?;
            if ctx
                .get_metadata(super::organization::METADATA_ENABLED)
                .is_some()
                && !member
                    .role
                    .split(',')
                    .any(|r| matches!(r.trim(), "owner" | "admin"))
            {
                return Err(api(
                    403,
                    "You must be an organization owner or admin to register SSO providers",
                ));
            }
        }
        if [
            "credential",
            "email-otp",
            "magic-link",
            "phone-number",
            "anonymous",
            "siwe",
        ]
        .contains(&provider_id)
            || ctx
                .config
                .account
                .account_linking
                .trusted_providers
                .iter()
                .any(|p| p == provider_id)
        {
            return Err(api(
                422,
                "This providerId is reserved and cannot be used for an SSO provider",
            ));
        }
        if ctx.database.get_sso_provider(provider_id).await?.is_some() {
            return Err(api(422, "SSO provider with this providerId already exists"));
        }
        let oidc=body.get("oidcConfig").map(|config| {
            if config.get("skipDiscovery").and_then(Value::as_bool)!=Some(true) {
                return Err(AuthError::not_implemented("OIDC discovery is not implemented"));
            }
            let method=config.get("tokenEndpointAuthentication").and_then(Value::as_str).unwrap_or("client_secret_basic");
            if method!="private_key_jwt" && config.get("clientSecret").and_then(Value::as_str).is_none_or(str::is_empty) {
                return Err(api(400,"clientSecret is required when using client_secret_basic or client_secret_post authentication"));
            }
            if method=="private_key_jwt" {return Err(api(400,"private_key_jwt authentication requires either a resolvePrivateKey callback or a privateKey in defaultSSO"));}
            let mut output=serde_json::Map::new();
            for field in ["clientId","clientSecret","authorizationEndpoint","tokenEndpoint","privateKeyId","privateKeyAlgorithm","jwksEndpoint","pkce","mapping","scopes","userInfoEndpoint"] {
                if let Some(value)=config.get(field) { _=output.insert(field.into(),value.clone()); }
            }
            _=output.insert("issuer".into(),json!(issuer));
            _=output.insert("tokenEndpointAuthentication".into(),json!(method));
            _=output.insert("discoveryEndpoint".into(),config.get("discoveryEndpoint").cloned().unwrap_or_else(||json!(format!("{issuer}/.well-known/openid-configuration"))));
            _=output.insert("overrideUserInfo".into(),json!(body.get("overrideUserInfo").and_then(Value::as_bool).unwrap_or(false)||self.config.default_override_user_info));
            serde_json::to_string(&output).map_err(Into::into)
        }).transpose()?;
        let saml = body
            .get("samlConfig")
            .map(|config| registration_saml::prepare(config, issuer))
            .transpose()?;
        let provider = ctx
            .database
            .create_sso_provider(SsoProvider {
                id: uuid::Uuid::new_v4().to_string(),
                issuer: issuer.into(),
                domain: domain.into(),
                provider_id: provider_id.into(),
                user_id: Some(user.id().into_owned()),
                organization_id: body
                    .get("organizationId")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                oidc_config: oidc,
                saml_config: saml,
                domain_verified: self.config.domain_verification.then_some(false),
            })
            .await?;
        let mut output = serde_json::to_value(&provider)?;
        let object = output
            .as_object_mut()
            .ok_or_else(|| AuthError::internal("SSO provider serialization failed"))?;
        if self.config.domain_verification {
            let token = self.issue_domain_proof(provider_id, ctx).await?;
            _ = object.insert("domainVerificationToken".into(), json!(token));
        } else {
            _ = object.remove("domainVerified");
        }
        for (key, value) in [
            ("oidcConfig", provider.oidc_config.as_deref()),
            ("samlConfig", provider.saml_config.as_deref()),
        ] {
            _ = object.insert(
                key.into(),
                value
                    .map(serde_json::from_str::<Value>)
                    .transpose()?
                    .unwrap_or(Value::Null),
            );
        }
        let base = format!(
            "{}{}",
            ctx.config.base_url.trim_end_matches('/'),
            ctx.config.base_path.trim_end_matches('/')
        );
        let redirect = self
            .config
            .redirect_uri
            .as_ref()
            .filter(|uri| !uri.trim().is_empty())
            .map_or_else(
                || format!("{base}/sso/callback/{provider_id}"),
                |uri| {
                    if url::Url::parse(uri).is_ok() {
                        uri.clone()
                    } else {
                        format!("{base}/{}", uri.trim_start_matches('/'))
                    }
                },
            );
        _ = object.insert("redirectURI".into(), json!(redirect));
        EndpointResponse::json(&output)
    }
}
fn required_string<'a>(value: &'a Value, name: &str) -> AuthResult<&'a str> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| super::endpoint::validation(format!("Invalid {name}")))
}
fn api(status: u16, message: &str) -> AuthError {
    AuthError::Api {
        status,
        code: None,
        message: message.into(),
    }
}
fn validate(input: Option<&JsValue>) -> AuthResult<JsValue> {
    use super::authentication_helpers::{JsonField, JsonFieldKind};
    let mut output = super::endpoint::validate_fields(
        input,
        "body",
        &[
            JsonField::string("providerId", true),
            JsonField::string("issuer", true),
            JsonField::string("domain", true),
            JsonField {
                name: "oidcConfig",
                kind: JsonFieldKind::Record,
                required: false,
            },
            JsonField {
                name: "samlConfig",
                kind: JsonFieldKind::Record,
                required: false,
            },
            JsonField::string("organizationId", false),
            JsonField {
                name: "overrideUserInfo",
                kind: JsonFieldKind::Boolean,
                required: false,
            },
        ],
    )?;
    if output
        .get("issuer")
        .and_then(JsValue::as_str)
        .is_none_or(|issuer| url::Url::parse(issuer).is_err())
    {
        return Err(super::endpoint::validation("[body.issuer] Invalid URL"));
    }
    if let Some(config) = output.get("oidcConfig") {
        _ = super::endpoint::validate_fields(
            Some(config),
            "body.oidcConfig",
            &[
                JsonField::string("clientId", true),
                JsonField::string("clientSecret", false),
                JsonField::string("authorizationEndpoint", false),
                JsonField::string("tokenEndpoint", false),
                JsonField::string("jwksEndpoint", false),
                JsonField::string("discoveryEndpoint", false),
                JsonField::string("userInfoEndpoint", false),
                JsonField {
                    name: "skipDiscovery",
                    kind: JsonFieldKind::Boolean,
                    required: false,
                },
                JsonField {
                    name: "pkce",
                    kind: JsonFieldKind::Boolean,
                    required: false,
                },
            ],
        )?;
    }
    if let Some(config) = output.get("samlConfig") {
        let parsed = registration_saml::validate(config)?;
        if let JsValue::Object(fields) = &mut output {
            _ = fields.insert("samlConfig".into(), parsed);
        }
    }
    Ok(output)
}
#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for SsoPlugin {
    fn name(&self) -> &'static str {
        "sso"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        let mut routes = vec![
            AuthRoute::get("/sso/callback/:providerId", "handleSSOCallback"),
            AuthRoute::get("/sso/callback", "handleSSOCallbackShared"),
            AuthRoute::get("/sso/saml2/sp/metadata", "getSSOServiceProviderMetadata"),
            AuthRoute::post("/sign-in/sso", "signInSSO"),
            AuthRoute::post("/sso/register", "registerSSOProvider"),
            AuthRoute::get("/sso/get-provider", "getSSOProvider"),
            AuthRoute::get("/sso/providers", "listSSOProviders"),
            AuthRoute::post("/sso/delete-provider", "deleteSSOProvider"),
            AuthRoute::post("/sso/update-provider", "updateSSOProvider"),
        ];
        if self.config.domain_verification {
            routes.push(AuthRoute::post("/sso/verify-domain", "verifyDomain"));
            routes.push(AuthRoute::post(
                "/sso/request-domain-verification",
                "requestDomainVerification",
            ));
        }
        routes
    }
    fn server_endpoints(&self) -> Vec<EndpointDefinition> {
        let mut endpoints = vec![
            super::endpoint::definition(
                "spMetadata",
                "getSSOServiceProviderMetadata",
                Some("/sso/saml2/sp/metadata"),
                HttpMethod::Get,
            ),
            super::endpoint::definition(
                "callbackSSOShared",
                "handleSSOCallbackShared",
                Some("/sso/callback"),
                HttpMethod::Get,
            ),
            super::endpoint::definition(
                "callbackSSO",
                "handleSSOCallback",
                Some("/sso/callback/:providerId"),
                HttpMethod::Get,
            ),
            super::endpoint::definition(
                "signInSSO",
                "signInSSO",
                Some("/sign-in/sso"),
                HttpMethod::Post,
            ),
            super::endpoint::definition(
                "updateSSOProvider",
                "updateSSOProvider",
                Some("/sso/update-provider"),
                HttpMethod::Post,
            ),
            super::endpoint::definition(
                "deleteSSOProvider",
                "deleteSSOProvider",
                Some("/sso/delete-provider"),
                HttpMethod::Post,
            ),
            super::endpoint::definition(
                "listSSOProviders",
                "listSSOProviders",
                Some("/sso/providers"),
                HttpMethod::Get,
            ),
            super::endpoint::definition(
                "getSSOProvider",
                "getSSOProvider",
                Some("/sso/get-provider"),
                HttpMethod::Get,
            ),
            super::endpoint::definition(
                "registerSSOProvider",
                "registerSSOProvider",
                Some("/sso/register"),
                HttpMethod::Post,
            ),
        ];
        if self.config.domain_verification {
            endpoints.push(super::endpoint::definition(
                "verifyDomain",
                "verifyDomain",
                Some("/sso/verify-domain"),
                HttpMethod::Post,
            ));
            endpoints.push(super::endpoint::definition(
                "requestDomainVerification",
                "requestDomainVerification",
                Some("/sso/request-domain-verification"),
                HttpMethod::Post,
            ));
        }
        endpoints
    }
    fn validate_endpoint(
        &self,
        call: &EndpointCall,
        _ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointInput> {
        if matches!(
            call.operation_id(),
            "handleSSOCallback" | "handleSSOCallbackShared"
        ) {
            return Ok(EndpointInput {
                body: None,
                query: Some(super::endpoint::validate_fields(
                    call.query(),
                    "query",
                    &[
                        super::authentication_helpers::JsonField::string("code", false),
                        super::authentication_helpers::JsonField::string("state", false),
                        super::authentication_helpers::JsonField::string("error", false),
                        super::authentication_helpers::JsonField::string(
                            "error_description",
                            false,
                        ),
                    ],
                )?),
            });
        }
        if call.operation_id() == "signInSSO" {
            return Ok(EndpointInput {
                body: Some(sign_in::validate(call.body())?),
                query: call.query().cloned(),
            });
        }
        if call.operation_id() == "updateSSOProvider" {
            return Ok(EndpointInput {
                body: Some(provider_update::validate_update(call.body())?),
                query: call.query().cloned(),
            });
        }
        if matches!(
            call.operation_id(),
            "deleteSSOProvider" | "requestDomainVerification" | "verifyDomain"
        ) {
            return Ok(EndpointInput {
                body: Some(Self::validate_delete(call.body())?),
                query: call.query().cloned(),
            });
        }
        if call.operation_id() == "listSSOProviders" {
            return Ok(EndpointInput {
                body: call.body().cloned(),
                query: call.query().cloned(),
            });
        }
        if matches!(
            call.operation_id(),
            "getSSOProvider" | "getSSOServiceProviderMetadata"
        ) {
            return Ok(EndpointInput {
                body: None,
                query: Some(provider_read::validate_query(call.query())?),
            });
        }
        Ok(EndpointInput {
            body: Some(validate(call.body())?),
            query: call.query().cloned(),
        })
    }
    async fn on_endpoint(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        if matches!(
            call.operation_id(),
            "handleSSOCallback" | "handleSSOCallbackShared"
        ) {
            let provider_id = if call.operation_id() == "handleSSOCallbackShared" {
                None
            } else {
                Some(
                    call.params()
                        .and_then(|params| params.get("providerId"))
                        .and_then(JsValue::as_str)
                        .ok_or_else(|| super::endpoint::validation("Missing providerId"))?,
                )
            };
            let query = call
                .query()
                .map(JsValue::to_json_value)
                .transpose()?
                .unwrap_or_else(|| json!({}));
            let meta = call.request().map_or_else(
                alibi_core::RequestMeta::default,
                alibi_core::RequestMeta::from_request,
            );
            return self.callback(provider_id, &query, call, &meta, ctx).await;
        }
        if call.operation_id() == "getSSOServiceProviderMetadata" {
            return Self::metadata(
                call.query()
                    .ok_or_else(|| crate::endpoint::validation("Missing query"))?,
                ctx,
            )
            .await;
        }
        if call.operation_id() == "signInSSO" {
            return self
                .sign_in(
                    call.body()
                        .ok_or_else(|| super::endpoint::validation("Missing body"))?,
                    ctx,
                )
                .await;
        }
        if call.operation_id() == "verifyDomain" {
            return self
                .verify_domain(
                    call.body()
                        .ok_or_else(|| super::endpoint::validation("Missing body"))?,
                    call,
                    ctx,
                )
                .await;
        }
        if call.operation_id() == "requestDomainVerification" {
            return self
                .request_domain(
                    call.body()
                        .ok_or_else(|| super::endpoint::validation("Missing body"))?,
                    call,
                    ctx,
                )
                .await;
        }
        if call.operation_id() == "updateSSOProvider" {
            return self
                .update(
                    call.body()
                        .ok_or_else(|| super::endpoint::validation("Missing body"))?,
                    call,
                    ctx,
                )
                .await;
        }
        if call.operation_id() == "deleteSSOProvider" {
            return self
                .delete(
                    call.body()
                        .ok_or_else(|| super::endpoint::validation("Missing body"))?,
                    call,
                    ctx,
                )
                .await;
        }
        if call.operation_id() == "listSSOProviders" {
            return self.list(call, ctx).await;
        }
        if call.operation_id() == "getSSOProvider" {
            return self
                .read(
                    call.query()
                        .ok_or_else(|| super::endpoint::validation("Missing query"))?,
                    call,
                    ctx,
                )
                .await;
        }
        self.register(
            call.body()
                .ok_or_else(|| super::endpoint::validation("Missing body"))?,
            call,
            ctx,
        )
        .await
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        if req.path() == "/sso/saml2/sp/metadata" && *req.method() == HttpMethod::Get {
            let query = alibi_core::utils::json::parse_value(&serde_json::to_string(&req.query)?)?;
            return Ok(Some(
                Self::metadata(&provider_read::validate_query(Some(&query))?, ctx)
                    .await?
                    .to_response()?,
            ));
        }
        if req.path() == "/sso/callback" && *req.method() == HttpMethod::Get {
            return Ok(Some(
                self.callback(
                    None,
                    &serde_json::to_value(&req.query)?,
                    req,
                    &alibi_core::RequestMeta::from_request(req),
                    ctx,
                )
                .await?
                .to_response()?,
            ));
        }
        if let Some(provider_id) = req.path().strip_prefix("/sso/callback/")
            && *req.method() == HttpMethod::Get
            && !provider_id.contains('/')
        {
            return Ok(Some(
                self.callback(
                    Some(provider_id),
                    &serde_json::to_value(&req.query)?,
                    req,
                    &alibi_core::RequestMeta::from_request(req),
                    ctx,
                )
                .await?
                .to_response()?,
            ));
        }
        if req.path() == "/sign-in/sso" && *req.method() == HttpMethod::Post {
            let input = alibi_core::utils::json::parse_value(
                std::str::from_utf8(req.body.as_deref().unwrap_or_default())
                    .map_err(|_| super::endpoint::validation("Invalid JSON"))?,
            )?;
            return Ok(Some(
                self.sign_in(&sign_in::validate(Some(&input))?, ctx)
                    .await?
                    .to_response()?,
            ));
        }
        if self.config.domain_verification
            && req.path() == "/sso/verify-domain"
            && *req.method() == HttpMethod::Post
        {
            let input = alibi_core::utils::json::parse_value(
                std::str::from_utf8(req.body.as_deref().unwrap_or_default())
                    .map_err(|_| super::endpoint::validation("Invalid JSON"))?,
            )?;
            return Ok(Some(
                self.verify_domain(&Self::validate_delete(Some(&input))?, req, ctx)
                    .await?
                    .to_response()?,
            ));
        }
        if self.config.domain_verification
            && req.path() == "/sso/request-domain-verification"
            && *req.method() == HttpMethod::Post
        {
            let input = alibi_core::utils::json::parse_value(
                std::str::from_utf8(req.body.as_deref().unwrap_or_default())
                    .map_err(|_| super::endpoint::validation("Invalid JSON"))?,
            )?;
            return Ok(Some(
                self.request_domain(&Self::validate_delete(Some(&input))?, req, ctx)
                    .await?
                    .to_response()?,
            ));
        }
        if req.path() == "/sso/update-provider" && *req.method() == HttpMethod::Post {
            let input = alibi_core::utils::json::parse_value(
                std::str::from_utf8(req.body.as_deref().unwrap_or_default())
                    .map_err(|_| super::endpoint::validation("Invalid JSON"))?,
            )?;
            return Ok(Some(
                self.update(&provider_update::validate_update(Some(&input))?, req, ctx)
                    .await?
                    .to_response()?,
            ));
        }
        if req.path() == "/sso/delete-provider" && *req.method() == HttpMethod::Post {
            let input = alibi_core::utils::json::parse_value(
                std::str::from_utf8(req.body.as_deref().unwrap_or_default())
                    .map_err(|_| super::endpoint::validation("Invalid JSON"))?,
            )?;
            return Ok(Some(
                self.delete(&Self::validate_delete(Some(&input))?, req, ctx)
                    .await?
                    .to_response()?,
            ));
        }
        if req.path() == "/sso/providers" && *req.method() == HttpMethod::Get {
            return Ok(Some(self.list(req, ctx).await?.to_response()?));
        }
        if req.path() == "/sso/get-provider" && *req.method() == HttpMethod::Get {
            let query = alibi_core::utils::json::parse_value(&serde_json::to_string(&req.query)?)?;
            return Ok(Some(
                self.read(&provider_read::validate_query(Some(&query))?, req, ctx)
                    .await?
                    .to_response()?,
            ));
        }
        if req.path() != "/sso/register" || *req.method() != HttpMethod::Post {
            return Ok(None);
        }
        let input = alibi_core::utils::json::parse_value(
            std::str::from_utf8(req.body.as_deref().unwrap_or_default())
                .map_err(|_| super::endpoint::validation("Invalid JSON"))?,
        )?;
        Ok(Some(
            self.register(&validate(Some(&input))?, req, ctx)
                .await?
                .to_response()?,
        ))
    }
}
