//! RFC 7523 authentication using registered asymmetric client keys and durable replay claims.
use super::{OAuthProviderPlugin, credentials::Credentials};
use alibi_core::endpoint::EndpointResponse;
use alibi_core::utils::json::{JsValue, parse_value};
use alibi_core::{AuthContext, AuthResult, AuthSchema};
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
    endpoint: &str,
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
    let Some(client) = ctx.database.get_oauth_client(client_id).await? else {
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
    let jwks = client.metadata.get("jwks").and_then(|value| {
        if let Some(raw) = value.as_str() {
            serde_json::from_str::<Value>(raw).ok()
        } else {
            Some(value.clone())
        }
    });
    let Some(jwks) = jwks else {
        return denied(
            400,
            if client.metadata.get("jwks_uri").is_some() {
                "failed to fetch client JWKS"
            } else {
                "client has no JWKS configured"
            },
        );
    };
    let metadata = provider.metadata(ctx)?;
    let endpoint_url = format!(
        "{}{}/oauth2/{endpoint}",
        ctx.config.base_url.trim_end_matches('/'),
        ctx.config.base_path
    );
    let audiences = [
        endpoint_url.as_str(),
        metadata
            .get("issuer")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    ];
    if !signature_valid(&header, &jwks, alg, assertion)
        || !claims_valid(&payload, client_id, &audiences)
    {
        return denied(401, SIGNATURE_ERROR);
    }
    if let Some(description) = lifetime_error(&payload) {
        return denied(400, description);
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
        return denied(400, "client assertion must include jti claim");
    }
    let digest = Sha256::digest(format!("private_key_jwt:{client_id}:{jti}"));
    let id = URL_SAFE_NO_PAD.encode(digest.iter().take(24).copied().collect::<Vec<_>>());
    #[expect(
        clippy::cast_possible_truncation,
        reason = "ECMAScript Date truncates fractional milliseconds"
    )]
    let expires_at = chrono::DateTime::from_timestamp_millis((exp * 1000.0).trunc() as i64)
        .ok_or_else(|| alibi_core::AuthError::internal("Invalid assertion expiration"))?;
    if !ctx
        .database
        .claim_oauth_client_assertion(&id, expires_at)
        .await?
    {
        return denied(400, "client assertion jti has already been used");
    }
    Ok(Ok(Credentials {
        client_id: client_id.into(),
        secret: String::new(),
        method: "private_key_jwt",
        pre_verified: true,
    }))
}
fn claims_valid(payload: &JsValue, client_id: &str, audiences: &[&str]) -> bool {
    if payload.get("iss").and_then(JsValue::as_str) != Some(client_id)
        || payload.get("sub").and_then(JsValue::as_str) != Some(client_id)
    {
        return false;
    }
    let aud = payload.get("aud");
    let audience = aud
        .and_then(JsValue::as_str)
        .is_some_and(|aud| audiences.contains(&aud))
        || aud.and_then(JsValue::as_array).is_some_and(|values| {
            values
                .iter()
                .any(|v| v.as_str().is_some_and(|aud| audiences.contains(&aud)))
        });
    if !audience {
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
fn lifetime_error(payload: &JsValue) -> Option<&'static str> {
    let Some(exp) = payload.get("exp").and_then(JsValue::as_f64) else {
        return Some("client assertion must include exp claim");
    };
    let now = current_seconds();
    if exp <= now {
        return Some("client assertion has expired");
    }
    if exp - now > 300.0 {
        return Some("client assertion exp is too far in the future (max 300s)");
    }
    if payload
        .get("iat")
        .and_then(JsValue::as_f64)
        .is_some_and(|iat| now - iat > 300.0)
    {
        return Some("client assertion iat is too far in the past (max 300s)");
    }
    None
}
fn signature_valid(header: &JsValue, jwks: &Value, algorithm: &str, assertion: &str) -> bool {
    if let Some(crit) = header.get("crit")
        && (!crit
            .as_array()
            .is_some_and(|values| matches!(values,[JsValue::String(value)] if value=="b64"))
            || header.get("b64") != Some(&JsValue::Bool(true)))
    {
        return false;
    }
    let Some(keys) = jwks.get("keys").and_then(Value::as_array) else {
        return false;
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
    let [key] = matching.as_slice() else {
        return false;
    };
    verify_signature(key, algorithm, assertion).unwrap_or(false)
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
