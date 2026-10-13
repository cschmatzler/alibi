//! Merge partial provider configuration against its transaction-locked snapshot.
use super::{
    AuthContext, AuthError, AuthResult, AuthSchema, AuthUser, EndpointResponse, JsValue,
    ServerEndpoint, SessionRequest, SsoPlugin, SsoProvider, Value, api, json,
};
use alibi_core::store::SsoProviderUpdate;
impl SsoPlugin {
    pub fn update_sso_provider_endpoint(input: &Value) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("sso", "updateSSOProvider").with_body(input)
    }
    pub(super) async fn update<S: AuthSchema>(
        &self,
        input: &JsValue,
        request: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let (user, _) = super::super::helpers::ordinary_session(request, ctx).await?;
        if !["issuer", "domain", "samlConfig", "oidcConfig"]
            .iter()
            .any(|field| input.get(field).is_some_and(JsValue::is_truthy))
        {
            return Err(api(400, "No fields provided for update"));
        }
        let provider_id = input
            .get("providerId")
            .and_then(JsValue::as_str)
            .ok_or_else(|| super::super::endpoint::validation("Invalid providerId"))?;
        let authorized = self
            .authorize_provider_id(provider_id, user.id().as_ref(), ctx)
            .await?;
        let body = input.to_json_value()?;
        let prepare = move |existing: &SsoProvider| prepare_update(existing, &body);
        let updated = ctx
            .database
            .update_sso_provider(&authorized.id, provider_id, &prepare)
            .await?
            .ok_or_else(|| api(404, "Provider not found"))?;
        EndpointResponse::json(&super::provider_read::sanitize(&updated, ctx)?)
    }
}
fn prepare_update(existing: &SsoProvider, body: &Value) -> AuthResult<SsoProviderUpdate> {
    let mut provider = existing.clone();
    let mut identity_changed = false;
    if let Some(issuer) = body.get("issuer").and_then(Value::as_str) {
        identity_changed = issuer != existing.issuer;
        provider.issuer = issuer.into();
    }
    if let Some(domain) = body.get("domain").and_then(Value::as_str) {
        if domain != existing.domain {
            provider.domain_verified = Some(false);
        }
        provider.domain = domain.into();
    }
    if body.get("samlConfig").is_some() {
        return Err(AuthError::not_implemented(
            "SAML provider updates are not implemented",
        ));
    }
    if let Some(updates) = body.get("oidcConfig") {
        let current: Value = existing
            .oidc_config
            .as_deref()
            .and_then(|raw| serde_json::from_str(raw).ok())
            .filter(|value: &Value| !value.is_null())
            .ok_or_else(|| {
                api(
                    400,
                    "Cannot update OIDC config for a provider that doesn't have OIDC configured",
                )
            })?;
        let mut merged = current.as_object().cloned().ok_or_else(|| {
            api(
                400,
                "Cannot update OIDC config for a provider that doesn't have OIDC configured",
            )
        })?;
        if let Some(fields) = updates.as_object() {
            for (key, value) in fields {
                _ = merged.insert(key.clone(), value.clone());
            }
        }
        let issuer = body
            .get("issuer")
            .and_then(Value::as_str)
            .or_else(|| current.get("issuer").and_then(Value::as_str))
            .filter(|issuer| !issuer.is_empty())
            .unwrap_or(&existing.issuer);
        _ = merged.insert("issuer".into(), json!(issuer));
        if merged.get("pkce").is_none_or(Value::is_null) {
            _ = merged.insert("pkce".into(), json!(true));
        }
        let method = merged
            .get("tokenEndpointAuthentication")
            .and_then(Value::as_str)
            .unwrap_or("client_secret_basic");
        if method != "private_key_jwt"
            && merged
                .get("clientSecret")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        {
            return Err(api(
                400,
                "clientSecret is required when using client_secret_basic or client_secret_post authentication",
            ));
        }
        if method == "private_key_jwt" {
            return Err(api(
                400,
                "private_key_jwt authentication requires either a resolvePrivateKey callback or a privateKey in defaultSSO",
            ));
        }
        let updated = Value::Object(merged);
        identity_changed |= [
            "authorizationEndpoint",
            "clientId",
            "discoveryEndpoint",
            "jwksEndpoint",
            "tokenEndpoint",
            "userInfoEndpoint",
        ]
        .iter()
        .any(|field| current.get(field) != updated.get(field));
        provider.oidc_config = Some(serde_json::to_string(&updated)?);
    }
    Ok(SsoProviderUpdate {
        provider,
        identity_changed,
    })
}
pub(super) fn validate_update(input: Option<&JsValue>) -> AuthResult<JsValue> {
    use super::super::authentication_helpers::{JsonField, JsonFieldKind};
    let mut output = super::super::endpoint::validate_fields(
        input,
        "body",
        &[
            JsonField::string("issuer", false),
            JsonField::string("domain", false),
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
            JsonField::string("providerId", true),
        ],
    )?;
    if output
        .get("issuer")
        .and_then(JsValue::as_str)
        .is_some_and(|issuer| url::Url::parse(issuer).is_err())
    {
        return Err(super::super::endpoint::validation(
            "[body.issuer] Invalid URL",
        ));
    }
    if let Some(config) = output.get("oidcConfig") {
        let config = super::super::endpoint::validate_fields(
            Some(config),
            "body.oidcConfig",
            &[
                JsonField::string("clientId", false),
                JsonField::string("clientSecret", false),
                JsonField::string("authorizationEndpoint", false),
                JsonField::string("tokenEndpoint", false),
                JsonField::string("userInfoEndpoint", false),
                JsonField {
                    name: "tokenEndpointAuthentication",
                    kind: JsonFieldKind::OneOf(&[
                        "client_secret_post",
                        "client_secret_basic",
                        "private_key_jwt",
                    ]),
                    required: false,
                },
                JsonField::string("privateKeyId", false),
                JsonField::string("privateKeyAlgorithm", false),
                JsonField::string("jwksEndpoint", false),
                JsonField::string("discoveryEndpoint", false),
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
                JsonField {
                    name: "mapping",
                    kind: JsonFieldKind::Record,
                    required: false,
                },
                JsonField {
                    name: "overrideUserInfo",
                    kind: JsonFieldKind::Boolean,
                    required: false,
                },
            ],
        )?;
        let mut normalized = config
            .as_object()
            .cloned()
            .ok_or_else(|| super::super::endpoint::validation("Invalid OIDC config"))?;
        if let Some(scopes) = output
            .get("oidcConfig")
            .and_then(|config| config.get("scopes"))
        {
            _ = normalized.insert("scopes".into(), scopes.clone());
        }
        if let JsValue::Object(object) = &mut output {
            _ = object.insert("oidcConfig".into(), JsValue::Object(normalized));
        }
    }
    Ok(output)
}
