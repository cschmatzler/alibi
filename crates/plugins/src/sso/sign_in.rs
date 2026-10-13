//! Registered OIDC provider authorization and state issuance.
use super::{
    AuthContext, AuthError, AuthResult, AuthSchema, EndpointResponse, JsValue, ServerEndpoint,
    SsoPlugin, SsoProvider, Value, api, json,
};
use alibi_core::OAuthStateStrategy;
use base64::Engine as _;
use sha2::Digest as _;
impl SsoPlugin {
    pub fn sign_in_sso_endpoint(input: &Value) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("sso", "signInSSO").with_body(input)
    }
    pub(super) async fn sign_in<S: AuthSchema>(
        &self,
        input: &JsValue,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let body = input.to_json_value()?;
        let string = |name: &str| {
            body.get(name)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
        };
        let email = string("email");
        let domain = string("domain").or_else(|| email.and_then(|email| email.split('@').nth(1)));
        let provider_id = string("providerId");
        let org_slug = string("organizationSlug");
        if email.is_none() && domain.is_none() && provider_id.is_none() && org_slug.is_none() {
            return Err(api(
                400,
                "email, organizationSlug, domain or providerId is required",
            ));
        }
        let org_id = if let Some(slug) = org_slug {
            ctx.database
                .get_organization_by_slug(slug)
                .await?
                .map(|org| org.id)
        } else {
            None
        };
        if provider_id.is_none() && org_id.is_none() && domain.is_none() {
            return Err(api(400, "providerId, orgId or domain is required"));
        }
        let provider = if let Some(id) = provider_id {
            ctx.database.get_sso_provider(id).await?
        } else {
            let providers = ctx.database.list_sso_providers().await?;
            if let Some(id) = org_id.as_deref() {
                providers
                    .into_iter()
                    .find(|provider| provider.organization_id.as_deref() == Some(id))
            } else {
                providers
                    .iter()
                    .find(|provider| Some(provider.domain.as_str()) == domain)
                    .cloned()
                    .or_else(|| {
                        providers.into_iter().find(|provider| {
                            domain.is_some_and(|domain| {
                                provider
                                    .domain
                                    .split(',')
                                    .any(|value| value.trim().eq_ignore_ascii_case(domain))
                            })
                        })
                    })
            }
        }
        .ok_or_else(|| api(404, "No provider found for the issuer"))?;
        let oidc = provider
            .oidc_config
            .as_deref()
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
            .filter(|value| !value.is_null());
        let saml = provider
            .saml_config
            .as_deref()
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
            .filter(|value| !value.is_null());
        if string("providerType") == Some("oidc") && oidc.is_none() {
            return Err(api(400, "OIDC provider is not configured"));
        }
        if string("providerType") == Some("saml") && saml.is_none() {
            return Err(api(400, "SAML provider is not configured"));
        }
        if self.config.domain_verification && provider.domain_verified != Some(true) {
            return Err(api(401, "Provider domain has not been verified"));
        }
        if string("providerType") == Some("saml") || oidc.is_none() {
            return Err(AuthError::not_implemented(
                "SAML SSO authorization is not implemented",
            ));
        }
        let config = oidc
            .as_ref()
            .ok_or_else(|| api(400, "Invalid SSO provider"))?;
        let endpoint = config
            .get("authorizationEndpoint")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                api(
                    400,
                    "Invalid OIDC configuration. Authorization URL not found.",
                )
            })?;
        let state = random(32);
        let verifier = random(128);
        let callback = string("callbackURL")
            .filter(|value| !value.is_empty())
            .unwrap_or(&ctx.config.base_url);
        let mut payload = crate::oauth::state::OAuthStatePayload::new(
            callback.into(),
            verifier.clone(),
            string("errorCallbackURL").map(str::to_owned),
            string("newUserCallbackURL").map(str::to_owned),
            None,
            body.get("requestSignUp").and_then(Value::as_bool),
            serde_json::Map::new(),
        );
        payload.server_context = Some(
            json!({"ssoProviderReference":provider_reference(&provider,self.config.domain_verification)?}),
        );
        _ = payload
            .additional_data
            .insert("oauthState".into(), json!(state));
        let cookie = match ctx.config.account.store_state_strategy {
            OAuthStateStrategy::Database => {
                _ = ctx
                    .verifications()
                    .create(alibi_core::CreateVerification {
                        identifier: crate::oauth::state::state_verification_identifier(&state),
                        value: serde_json::to_string(&payload)?,
                        expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
                    })
                    .await?
                    .ok_or_else(|| api(500, "Unable to create verification"))?;
                alibi_core::utils::cookie_utils::create_cookie(
                    &crate::oauth::state::state_cookie_name(&ctx.config),
                    &alibi_core::utils::cookie_utils::sign_cookie_value(
                        &state,
                        ctx.config.current_secret(),
                    ),
                    300,
                    &ctx.config,
                )?
            }
            OAuthStateStrategy::Cookie => alibi_core::utils::cookie_utils::create_cookie(
                &crate::oauth::state::state_cookie_name(&ctx.config),
                &crate::oauth::state::create_cookie_state_value(&ctx.config, &payload)?,
                600,
                &ctx.config,
            )?,
            OAuthStateStrategy::Automatic => {
                return Err(AuthError::config(
                    "OAuth state strategy has not been initialized",
                ));
            }
        };
        let base = format!(
            "{}{}",
            ctx.config.base_url.trim_end_matches('/'),
            ctx.config.base_path.trim_end_matches('/')
        );
        let redirect = format!("{base}/sso/callback/{}", provider.provider_id);
        let scopes = body
            .get("scopes")
            .or_else(|| config.get("scopes"))
            .cloned()
            .unwrap_or_else(|| json!(["openid", "email", "profile", "offline_access"]));
        let scope = scopes
            .as_array()
            .ok_or_else(|| api(400, "Invalid scopes"))?
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(" ");
        let mut url = url::Url::parse(endpoint).map_err(|_| {
            api(
                400,
                "Invalid OIDC configuration. Authorization URL not found.",
            )
        })?;
        {
            let mut query = url.query_pairs_mut();
            _ = query
                .append_pair("response_type", "code")
                .append_pair(
                    "client_id",
                    config
                        .get("clientId")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                )
                .append_pair("state", &state)
                .append_pair("scope", &scope)
                .append_pair("redirect_uri", &redirect);
            if config.get("pkce") == Some(&json!(true)) {
                _ = query
                    .append_pair("code_challenge_method", "S256")
                    .append_pair(
                        "code_challenge",
                        &base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .encode(sha2::Sha256::digest(verifier.as_bytes())),
                    );
            }
            if let Some(hint) = string("loginHint").or(email) {
                _ = query.append_pair("login_hint", hint);
            }
        }
        Ok(
            EndpointResponse::json(&json!({"url":url.to_string(),"redirect":true}))?
                .with_header("Set-Cookie", cookie),
        )
    }
}
fn random(length: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_";
    use rand::RngExt as _;
    let mut rng = rand::rng();
    (0..length)
        .filter_map(|_| {
            ALPHABET
                .get(rng.random_range(0..ALPHABET.len()))
                .copied()
                .map(char::from)
        })
        .collect()
}
pub(super) fn provider_reference(
    provider: &SsoProvider,
    verified_field: bool,
) -> AuthResult<Value> {
    let mut configuration = serde_json::Map::new();
    _ = configuration.insert("domain".into(), json!(provider.domain));
    _ = configuration.insert("issuer".into(), json!(provider.issuer));
    _ = configuration.insert("organizationId".into(), json!(provider.organization_id));
    if verified_field {
        _ = configuration.insert("domainVerified".into(), json!(provider.domain_verified));
    }
    if let Some(raw) = provider.oidc_config.as_deref() {
        let mut config: Value = serde_json::from_str(raw)?;
        if let Some(object) = config.as_object_mut() {
            _ = object.remove("clientSecret");
        }
        _ = configuration.insert("oidcConfig".into(), config);
    }
    let fingerprint = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        sha2::Sha256::digest(canonical(&Value::Object(configuration))?.into_bytes()),
    );
    Ok(
        json!({"providerId":provider.provider_id,"source":{"type":"persisted","recordId":provider.id},"authenticationConfigurationFingerprint":fingerprint}),
    )
}
pub(super) fn validate(input: Option<&JsValue>) -> AuthResult<JsValue> {
    use super::super::authentication_helpers::{JsonField, JsonFieldKind};
    let output = super::super::endpoint::validate_fields(
        input,
        "body",
        &[
            JsonField::string("email", false),
            JsonField::string("organizationSlug", false),
            JsonField::string("providerId", false),
            JsonField::string("domain", false),
            JsonField::string("callbackURL", true),
            JsonField::string("errorCallbackURL", false),
            JsonField::string("newUserCallbackURL", false),
            JsonField::string("loginHint", false),
            JsonField {
                name: "requestSignUp",
                kind: JsonFieldKind::Boolean,
                required: false,
            },
            JsonField {
                name: "providerType",
                kind: JsonFieldKind::OneOf(&["oidc", "saml"]),
                required: false,
            },
        ],
    )?;
    let mut values = output
        .as_object()
        .cloned()
        .ok_or_else(|| super::super::endpoint::validation("Invalid body"))?;
    for field in ["scopes", "additionalParams"] {
        if let Some(value) = input.and_then(|value| value.get(field)) {
            _ = values.insert(field.into(), value.clone());
        }
    }
    Ok(JsValue::Object(values))
}

fn canonical(value: &Value) -> AuthResult<String> {
    match value {
        Value::Object(object) => {
            let sorted: std::collections::BTreeMap<&String, &Value> = object.iter().collect();
            let pairs = sorted
                .into_iter()
                .map(|(key, value)| {
                    Ok(format!(
                        "{}:{}",
                        serde_json::to_string(key)?,
                        canonical(value)?
                    ))
                })
                .collect::<AuthResult<Vec<_>>>()?;
            Ok(format!("{{{}}}", pairs.join(",")))
        }
        Value::Array(values) => Ok(format!(
            "[{}]",
            values
                .iter()
                .map(canonical)
                .collect::<AuthResult<Vec<_>>>()?
                .join(",")
        )),
        _ => serde_json::to_string(value).map_err(Into::into),
    }
}
