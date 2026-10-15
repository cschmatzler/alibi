//! RFC 7523 authentication using registered asymmetric client keys and durable replay claims.
use super::{OAuthProviderPlugin, credentials::Credentials};
use alibi_core::endpoint::{EndpointError, EndpointResponse};
use alibi_core::utils::json::{JsValue, parse_value};
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const SIGNATURE_ERROR: &str = "client assertion signature verification failed";
fn denied(status: u16, description: &str) -> AuthResult<Result<Credentials, EndpointResponse>> {
    Ok(Err(super::clients::status_protocol_error(
        status,
        "invalid_client",
        description,
    )?))
}
fn decode(value: &str) -> Option<JsValue> {
    let bytes = URL_SAFE_NO_PAD.decode(value.trim_end_matches('=')).ok()?;
    let text = String::from_utf8(bytes).ok()?;
    let parsed = parse_value(text.strip_prefix('\u{feff}').unwrap_or(&text)).ok()?;
    parsed.is_object().then_some(parsed)
}
pub(super) async fn verify<S: AuthSchema>(
    body: &Value,
    ctx: &AuthContext<S>,
    provider: &OAuthProviderPlugin,
    endpoint_url: &str,
) -> AuthResult<Result<Credentials, EndpointResponse>> {
    let assertion = body
        .get("client_assertion")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let assertion_type = body
        .get("client_assertion_type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if assertion.is_empty() || assertion_type.is_empty() {
        return denied(
            400,
            "client_assertion and client_assertion_type must both be provided",
        );
    }
    if assertion_type != ASSERTION_TYPE {
        return denied(400, "unsupported client_assertion_type");
    }
    let parts = assertion.split('.').collect::<Vec<_>>();
    let Some(header) = parts
        .first()
        .and_then(|part| decode(part))
        .filter(|_| matches!(parts.len(), 3 | 5))
    else {
        return denied(400, "malformed client assertion: invalid JWT header");
    };
    let alg = header
        .get("alg")
        .and_then(JsValue::as_str)
        .unwrap_or_default();
    if !super::super::oauth::PRIVATE_KEY_JWT_SIGNING_ALGORITHMS.contains(&alg) {
        let value = header
            .get("alg")
            .map(JsValue::coerce_string)
            .transpose()
            .unwrap_or_default()
            .unwrap_or_else(|| "undefined".into());
        return denied(
            400,
            &format!("unsupported assertion signing algorithm: {value}"),
        );
    }
    let Some(payload) = parts
        .get(1)
        .and_then(|part| decode(part))
        .filter(|_| parts.len() == 3)
    else {
        return denied(400, "malformed client assertion: invalid JWT payload");
    };
    let client_id = payload
        .get("sub")
        .filter(|value| !matches!(value, JsValue::Null))
        .or_else(|| payload.get("iss"));
    let Some(client_id) = client_id
        .filter(|value| value.is_truthy())
        .and_then(JsValue::as_str)
    else {
        return denied(
            400,
            "client assertion must contain sub or iss claim identifying the client",
        );
    };
    if body
        .get("client_id")
        .and_then(Value::as_str)
        .is_some_and(|id| !id.is_empty() && id != client_id)
    {
        return denied(400, "client_id in body does not match assertion sub/iss");
    }
    let Some(client) = provider.get_client(ctx, client_id).await? else {
        return denied(400, "unknown client");
    };
    if client.metadata.get("disabled") == Some(&Value::Bool(true)) {
        return denied(400, "client is disabled");
    }
    if client
        .metadata
        .get("token_endpoint_auth_method")
        .and_then(Value::as_str)
        != Some("private_key_jwt")
    {
        return denied(
            400,
            "client is not registered for private_key_jwt authentication",
        );
    }
    let mut jwks = match super::client_jwks::get(ctx, provider, &client).await? {
        Ok(jwks) => jwks,
        Err(description) => return denied(400, description),
    };
    let metadata = provider.metadata(ctx)?;
    let audiences = [
        endpoint_url,
        metadata
            .get("issuer")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    ];
    let mut signature = signature_result(&header, &jwks, alg, assertion);
    if signature == SignatureResult::NoMatchingKey
        && let Some(refreshed) = super::client_jwks::refetch(provider, &client).await?
    {
        jwks = refreshed;
        signature = signature_result(&header, &jwks, alg, assertion);
    }
    if signature != SignatureResult::Valid || !claims_valid(&payload, client_id, &audiences) {
        return denied(401, SIGNATURE_ERROR);
    }
    let expected_audience = audiences
        .iter()
        .copied()
        .find(|aud| audience_contains(&payload, aud))
        .unwrap_or_default();
    if let Err(error) = consume_client_assertion(
        ctx,
        &provider.config,
        &format!("private_key_jwt:{client_id}"),
        &payload,
        expected_audience,
    )
    .await
    {
        if let Some(body) = error.body {
            return Ok(Err(
                EndpointResponse::error(error.error).with_error_body(*body)
            ));
        }
        return Err(error.error);
    }
    Ok(Ok(Credentials {
        client_id: client_id.into(),
        secret: String::new(),
        method: "private_key_jwt",
        pre_verified: true,
    }))
}
/// Check assertion hygiene and atomically consume its durable replay identifier.
///
/// Callers must verify the signature and establish the client identity first.
/// This helper does not authenticate a client or require a registered client row.
/// Namespace the identifier by authentication method and client to isolate proofs.
///
/// # Errors
/// Returns protocol errors for audience, lifetime, missing or reused identifiers;
/// database failures retain their original error.
pub async fn consume_client_assertion<S: AuthSchema>(
    ctx: &AuthContext<S>,
    config: &super::OAuthProviderConfig,
    namespace: &str,
    payload: &JsValue,
    expected_audience: &str,
) -> Result<(), EndpointError> {
    if !audience_contains(payload, expected_audience) {
        return Err(consumption_error(
            "client assertion aud does not match the endpoint",
        ));
    }
    if let Some(description) = lifetime_error(payload, config.assertion_max_lifetime) {
        return Err(consumption_error(&description));
    }
    let exp = payload
        .get("exp")
        .and_then(JsValue::as_f64)
        .unwrap_or_default();
    let jti = payload
        .get("jti")
        .and_then(JsValue::as_str)
        .unwrap_or_default();
    if jti.is_empty() {
        return Err(consumption_error("client assertion must include jti claim"));
    }
    let digest = Sha256::digest(format!("{namespace}:{jti}"));
    let id = URL_SAFE_NO_PAD.encode(digest.iter().take(24).copied().collect::<Vec<_>>());
    #[expect(
        clippy::cast_possible_truncation,
        reason = "ECMAScript Date truncates fractional milliseconds"
    )]
    let expires_at = chrono::DateTime::from_timestamp_millis((exp * 1000.0).trunc() as i64)
        .ok_or_else(|| AuthError::internal("Invalid assertion expiration"))?;
    if !ctx
        .database
        .claim_oauth_client_assertion(&id, expires_at)
        .await?
    {
        return Err(consumption_error(
            "client assertion jti has already been used",
        ));
    }
    Ok(())
}
fn consumption_error(description: &str) -> EndpointError {
    EndpointError {
        error: AuthError::Api {
            status: 400,
            code: None,
            message: String::new(),
        },
        headers: None,
        body: Some(Box::new(JsValue::from(
            serde_json::json!({"error":"invalid_client","error_description":description}),
        ))),
        body_absent: false,
    }
}
fn audience_contains(payload: &JsValue, expected: &str) -> bool {
    let aud = payload.get("aud");
    aud.and_then(JsValue::as_str) == Some(expected)
        || aud
            .and_then(JsValue::as_array)
            .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(expected)))
}
fn claims_valid(payload: &JsValue, client_id: &str, audiences: &[&str]) -> bool {
    if payload.get("iss").and_then(JsValue::as_str) != Some(client_id)
        || payload.get("sub").and_then(JsValue::as_str) != Some(client_id)
    {
        return false;
    }
    if !audiences.iter().any(|aud| audience_contains(payload, aud)) {
        return false;
    }
    let now = current_seconds();
    for name in ["iat", "exp", "nbf"] {
        if let Some(value) = payload.get(name) {
            let Some(number) = value.as_f64() else {
                return false;
            };
            if (name == "exp" && number <= now) || (name == "nbf" && number > now) {
                return false;
            }
        }
    }
    true
}
#[expect(
    clippy::cast_precision_loss,
    reason = "JavaScript timestamp arithmetic uses numbers"
)]
fn current_seconds() -> f64 {
    chrono::Utc::now().timestamp() as f64
}
fn lifetime_error(payload: &JsValue, max: f64) -> Option<String> {
    let Some(exp) = payload.get("exp").and_then(JsValue::as_f64) else {
        return Some("client assertion must include exp claim".into());
    };
    let now = current_seconds();
    if exp <= now {
        return Some("client assertion has expired".into());
    }
    let limit = || JsValue::Number(max).coerce_string().unwrap_or_default();
    if exp - now > max {
        return Some(format!(
            "client assertion exp is too far in the future (max {}s)",
            limit()
        ));
    }
    if payload
        .get("iat")
        .and_then(JsValue::as_f64)
        .is_some_and(|iat| now - iat > max)
    {
        return Some(format!(
            "client assertion iat is too far in the past (max {}s)",
            limit()
        ));
    }
    None
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SignatureResult {
    Valid,
    NoMatchingKey,
    Invalid,
}
fn signature_result(
    header: &JsValue,
    jwks: &Value,
    algorithm: &str,
    assertion: &str,
) -> SignatureResult {
    if let Some(crit) = header.get("crit")
        && (!crit
            .as_array()
            .is_some_and(|values| matches!(values,[JsValue::String(value)] if value=="b64"))
            || header.get("b64") != Some(&JsValue::Bool(true)))
    {
        return SignatureResult::Invalid;
    }
    let Some(keys) = jwks.get("keys").and_then(Value::as_array) else {
        return SignatureResult::Invalid;
    };
    let (kty, curve) = match algorithm {
        "EdDSA" => ("OKP", Some("Ed25519")),
        "ES256" => ("EC", Some("P-256")),
        "ES384" => ("EC", Some("P-384")),
        "ES512" => ("EC", Some("P-521")),
        _ => ("RSA", None),
    };
    let matching = keys
        .iter()
        .filter(|key| {
            key.get("kty").and_then(Value::as_str) == Some(kty)
                && key.get("ext").is_none_or(Value::is_boolean)
                && curve.is_none_or(|curve| key.get("crv").and_then(Value::as_str) == Some(curve))
                && key.get("alg").is_none_or(|alg| alg == algorithm)
                && key.get("use").is_none_or(|usage| usage == "sig")
                && key.get("key_ops").is_none_or(|ops| {
                    ops.as_array().is_some_and(|ops| {
                        ops.iter().any(|op| op == "verify")
                            && ops.iter().enumerate().all(|(index, op)| {
                                op.is_string()
                                    && !ops.iter().take(index).any(|previous| previous == op)
                            })
                    })
                })
                && header.get("kid").is_none_or(|kid| {
                    kid.as_str()
                        .is_some_and(|kid| key.get("kid").and_then(Value::as_str) == Some(kid))
                })
        })
        .collect::<Vec<_>>();
    if matching.is_empty() {
        return SignatureResult::NoMatchingKey;
    }
    let [key] = matching.as_slice() else {
        return SignatureResult::Invalid;
    };
    if verify_signature(key, algorithm, assertion) == Some(true) {
        SignatureResult::Valid
    } else {
        SignatureResult::Invalid
    }
}
fn verify_signature(key: &Value, algorithm: &str, assertion: &str) -> Option<bool> {
    let (message, signature) = assertion.rsplit_once('.')?;
    if algorithm == "ES512" {
        use p521::ecdsa::signature::Verifier as _;
        let mut point = vec![4];
        point.extend(URL_SAFE_NO_PAD.decode(key.get("x")?.as_str()?).ok()?);
        point.extend(URL_SAFE_NO_PAD.decode(key.get("y")?.as_str()?).ok()?);
        let key = p521::ecdsa::VerifyingKey::from_sec1_bytes(&point).ok()?;
        let bytes = URL_SAFE_NO_PAD.decode(signature).ok()?;
        let signature = p521::ecdsa::Signature::from_slice(&bytes).ok()?;
        return Some(key.verify(message.as_bytes(), &signature).is_ok());
    }
    let jwk = serde_json::from_value::<jsonwebtoken::jwk::Jwk>(key.clone()).ok()?;
    let key = jsonwebtoken::DecodingKey::from_jwk(&jwk).ok()?;
    jsonwebtoken::crypto::verify(signature, message.as_bytes(), &key, algorithm.parse().ok()?).ok()
}
