//! Authorized provider configuration without application credentials.
use super::{
    AuthContext, AuthError, AuthResult, AuthSchema, AuthUser, EndpointResponse, JsValue,
    ServerEndpoint, SessionRequest, SsoPlugin, SsoProvider, Value, api, json,
};
impl SsoPlugin {
    pub fn get_sso_provider_endpoint(provider_id: &str) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("sso", "getSSOProvider").with_query(&json!({"providerId":provider_id}))
    }
    pub(super) async fn read<S: AuthSchema>(
        &self,
        input: &JsValue,
        request: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let (user, _) = super::super::helpers::ordinary_session(request, ctx).await?;
        let provider_id = input
            .get("providerId")
            .and_then(JsValue::as_str)
            .ok_or_else(|| super::super::endpoint::validation("Invalid providerId"))?;
        let provider = ctx
            .database
            .get_sso_provider(provider_id)
            .await?
            .ok_or_else(|| api(404, "Provider not found"))?;
        let allowed = if let Some(organization_id) = provider
            .organization_id
            .as_deref()
            .filter(|id| !id.is_empty())
        {
            if ctx
                .get_metadata(super::super::organization::METADATA_ENABLED)
                .is_some()
            {
                ctx.database
                    .get_member(organization_id, user.id().as_ref())
                    .await?
                    .is_some_and(|member| {
                        member
                            .role
                            .split(',')
                            .any(|role| matches!(role.trim(), "owner" | "admin"))
                    })
            } else {
                provider.user_id.as_deref() == Some(user.id().as_ref())
            }
        } else {
            provider.user_id.as_deref() == Some(user.id().as_ref())
        };
        if !allowed {
            return Err(api(403, "You don't have access to this provider"));
        }
        EndpointResponse::json(&sanitize(&provider, ctx)?)
    }
}
fn sanitize<S: AuthSchema>(provider: &SsoProvider, ctx: &AuthContext<S>) -> AuthResult<Value> {
    let saml = provider
        .saml_config
        .as_deref()
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
        .filter(|value| !value.is_null());
    if saml.is_some() {
        return Err(AuthError::not_implemented(
            "SAML provider sanitization is not implemented",
        ));
    }
    let base = format!(
        "{}{}",
        ctx.config.base_url.trim_end_matches('/'),
        ctx.config.base_path.trim_end_matches('/')
    );
    let mut output = json!({"providerId":provider.provider_id,"type":"oidc","issuer":provider.issuer,"domain":provider.domain,"organizationId":provider.organization_id.as_deref().filter(|id|!id.is_empty()),"domainVerified":provider.domain_verified.unwrap_or(false),"spMetadataUrl":format!("{base}/sso/saml2/sp/metadata?providerId={}",component(&provider.provider_id))});
    if let Some(config) = provider
        .oidc_config
        .as_deref()
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
        .filter(|value| !value.is_null())
    {
        let mut safe = serde_json::Map::new();
        for field in [
            "discoveryEndpoint",
            "pkce",
            "authorizationEndpoint",
            "tokenEndpoint",
            "userInfoEndpoint",
            "jwksEndpoint",
            "scopes",
            "tokenEndpointAuthentication",
        ] {
            if let Some(value) = config.get(field) {
                _ = safe.insert(field.into(), value.clone());
            }
        }
        let client_id = config
            .get("clientId")
            .and_then(Value::as_str)
            .ok_or_else(|| AuthError::internal("Stored OIDC configuration has no clientId"))?;
        let units: Vec<u16> = client_id.encode_utf16().collect();
        let last = units
            .get(units.len().saturating_sub(4)..)
            .unwrap_or_default();
        let masked = if units.len() <= 4 {
            "****".into()
        } else {
            format!("****{}", String::from_utf16_lossy(last))
        };
        _ = safe.insert("clientIdLastFour".into(), json!(masked));
        let object = output
            .as_object_mut()
            .ok_or_else(|| AuthError::internal("SSO provider serialization failed"))?;
        _ = object.insert("oidcConfig".into(), Value::Object(safe));
    }
    Ok(output)
}
fn component(value: &str) -> String {
    urlencoding::encode(value)
        .replace("%21", "!")
        .replace("%27", "'")
        .replace("%28", "(")
        .replace("%29", ")")
        .replace("%2A", "*")
}
pub(super) fn validate_query(value: Option<&JsValue>) -> AuthResult<JsValue> {
    super::super::endpoint::validate_fields(
        value,
        "query",
        &[super::super::authentication_helpers::JsonField::string(
            "providerId",
            true,
        )],
    )
}
