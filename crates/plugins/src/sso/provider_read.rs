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
        let provider = self.authorized_provider(input, request, ctx).await?;
        EndpointResponse::json(&sanitize(&provider, ctx)?)
    }
    pub(super) async fn authorized_provider<S: AuthSchema>(
        &self,
        input: &JsValue,
        request: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<SsoProvider> {
        let (user, _) = super::super::helpers::ordinary_session(request, ctx).await?;
        let provider_id = input
            .get("providerId")
            .and_then(JsValue::as_str)
            .ok_or_else(|| super::super::endpoint::validation("Invalid providerId"))?;
        self.authorize_provider_id(provider_id, user.id().as_ref(), ctx)
            .await
    }
    pub(super) async fn authorize_provider_id<S: AuthSchema>(
        &self,
        provider_id: &str,
        user_id: &str,
        ctx: &AuthContext<S>,
    ) -> AuthResult<SsoProvider> {
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
                    .get_member(organization_id, user_id)
                    .await?
                    .is_some_and(|member| {
                        member
                            .role
                            .split(',')
                            .any(|role| matches!(role.trim(), "owner" | "admin"))
                    })
            } else {
                provider.user_id.as_deref() == Some(user_id)
            }
        } else {
            provider.user_id.as_deref() == Some(user_id)
        };
        if !allowed {
            return Err(api(403, "You don't have access to this provider"));
        }
        Ok(provider)
    }
}
pub(super) fn sanitize<S: AuthSchema>(
    provider: &SsoProvider,
    ctx: &AuthContext<S>,
) -> AuthResult<Value> {
    let saml = provider
        .saml_config
        .as_deref()
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
        .filter(|value| !value.is_null());
    let base = format!(
        "{}{}",
        ctx.config.base_url.trim_end_matches('/'),
        ctx.config.base_path.trim_end_matches('/')
    );
    let mut output = json!({"providerId":provider.provider_id,"type":if saml.is_some(){"saml"}else{"oidc"},"issuer":provider.issuer,"domain":provider.domain,"organizationId":provider.organization_id.as_deref().filter(|id|!id.is_empty()),"domainVerified":provider.domain_verified.unwrap_or(false),"spMetadataUrl":format!("{base}/sso/saml2/sp/metadata?providerId={}",component(&provider.provider_id))});
    if let Some(config) = saml {
        let mut safe = serde_json::Map::new();
        for field in [
            "entryPoint",
            "callbackUrl",
            "idpInitiatedCallbackUrl",
            "audience",
            "wantAssertionsSigned",
            "authnRequestsSigned",
            "identifierFormat",
            "signatureAlgorithm",
            "digestAlgorithm",
        ] {
            if let Some(value) = config.get(field) {
                _ = safe.insert(field.into(), value.clone());
            }
        }
        if let Some(certs) = config
            .get("idpMetadata")
            .and_then(|metadata| metadata.get("cert"))
            .filter(|cert| !cert.is_null())
            .or_else(|| config.get("cert"))
        {
            let certs = certs
                .as_array()
                .map_or_else(|| vec![certs], |certs| certs.iter().collect());
            let details = certs
                .into_iter()
                .map(|cert| {
                    cert.as_str().map_or_else(
                        || json!({"error":"Failed to parse certificate"}),
                        certificate_details,
                    )
                })
                .collect::<Vec<_>>();
            _ = safe.insert("certificate".into(), json!(details));
        }
        let object = output
            .as_object_mut()
            .ok_or_else(|| AuthError::internal("SSO provider serialization failed"))?;
        _ = object.insert("samlConfig".into(), Value::Object(safe));
    }
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
    if let Some(object) = output.as_object_mut() {
        for (name, field) in &ctx.config.advanced.database.sso_provider_fields.0 {
            if field.returned
                && let Some(value) = provider.additional_fields.get(name)
            {
                _ = object.insert(name.clone(), value.clone());
            }
        }
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

fn certificate_details(pem: &str) -> Value {
    use base64::Engine as _;
    use sha2::Digest as _;
    let parse = || -> Option<Value> {
        let encoded = if pem.contains("-----BEGIN") {
            pem.split_once("-----BEGIN CERTIFICATE-----")?
                .1
                .split_once("-----END CERTIFICATE-----")?
                .0
        } else {
            pem
        };
        let encoded: String = encoded.chars().filter(|ch| !ch.is_whitespace()).collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .ok()?;
        let (_, certificate) = x509_parser::parse_x509_certificate(&der).ok()?;
        let fingerprint = sha2::Sha256::digest(&der)
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":");
        let date = |timestamp| {
            chrono::DateTime::from_timestamp(timestamp, 0)
                .map(|time| time.format("%b %e %H:%M:%S %Y GMT").to_string())
        };
        let algorithm = match certificate
            .public_key()
            .algorithm
            .algorithm
            .to_id_string()
            .as_str()
        {
            "1.2.840.113549.1.1.1" => "RSA",
            "1.2.840.113549.1.1.10" => "RSA-PSS",
            "1.2.840.10045.2.1" => "EC",
            "1.2.840.10040.4.1" => "DSA",
            "1.3.101.112" => "ED25519",
            "1.3.101.113" => "ED448",
            "1.3.101.110" => "X25519",
            "1.3.101.111" => "X448",
            "1.2.840.113549.1.3.1" | "1.2.840.10046.2.1" => "DH",
            _ => "UNKNOWN",
        };
        Some(json!({"fingerprintSha256":fingerprint,
            "notBefore":date(certificate.validity().not_before.timestamp())?,
            "notAfter":date(certificate.validity().not_after.timestamp())?,
            "publicKeyAlgorithm":algorithm}))
    };
    parse().unwrap_or_else(|| json!({"error":"Failed to parse certificate"}))
}
