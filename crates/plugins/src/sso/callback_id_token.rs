//! Verified OIDC identity claims from the configured JWKS authority.
use super::{AuthContext, AuthResult, AuthSchema, Value, api};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
pub(super) async fn verify<S: AuthSchema>(
    token: &str,
    endpoint: &str,
    client_id: &str,
    issuer: &str,
    ctx: &AuthContext<S>,
) -> AuthResult<Value> {
    let invalid = || api(400, "token_not_verified");
    let header = jsonwebtoken::decode_header(token).map_err(|_| invalid())?;
    let key_type = match header.alg {
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => "RSA",
        Algorithm::ES256 | Algorithm::ES384 => "EC",
        Algorithm::EdDSA => "OKP",
        _ => return Err(invalid()),
    };
    if header
        .crit
        .as_ref()
        .is_some_and(|claims| claims.is_empty() || claims.iter().any(|claim| claim != "b64"))
    {
        return Err(invalid());
    }
    let b64 = header.extras.inner().get("b64");
    if b64.is_some_and(|value| value.as_bool() != Some(true))
        || header
            .crit
            .as_ref()
            .is_some_and(|claims| claims.iter().any(|claim| claim == "b64"))
            && b64.is_none()
    {
        return Err(invalid());
    }
    let (client, endpoint) = super::callback::outbound_client(endpoint, ctx)
        .await
        .map_err(|_| invalid())?;
    let jwks = client
        .get(endpoint)
        .send()
        .await
        .map_err(|_| invalid())?
        .error_for_status()
        .map_err(|_| invalid())?
        .json::<Value>()
        .await
        .map_err(|_| invalid())?;
    let algorithm = serde_json::to_value(header.alg)?;
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    let selected = keys
        .iter()
        .filter(|key| {
            key.get("kty").and_then(Value::as_str) == Some(key_type)
                && header
                    .kid
                    .as_deref()
                    .is_none_or(|kid| key.get("kid").and_then(Value::as_str) == Some(kid))
                && key.get("alg").is_none_or(|alg| alg == &algorithm)
                && key
                    .get("use")
                    .is_none_or(|usage| usage.as_str() == Some("sig"))
                && key.get("key_ops").is_none_or(|ops| {
                    ops.as_array()
                        .is_some_and(|ops| ops.iter().any(|op| op.as_str() == Some("verify")))
                })
                && match header.alg {
                    Algorithm::ES256 => key.get("crv").and_then(Value::as_str) == Some("P-256"),
                    Algorithm::ES384 => key.get("crv").and_then(Value::as_str) == Some("P-384"),
                    Algorithm::EdDSA => key.get("crv").and_then(Value::as_str) == Some("Ed25519"),
                    _ => true,
                }
        })
        .collect::<Vec<_>>();
    let [selected] = selected.as_slice() else {
        return Err(invalid());
    };
    let jwk: jsonwebtoken::jwk::Jwk =
        serde_json::from_value((*selected).clone()).map_err(|_| invalid())?;
    let key = DecodingKey::from_jwk(&jwk).map_err(|_| invalid())?;
    let mut policy = Validation::new(header.alg);
    policy.set_required_spec_claims(&["iss", "aud"]);
    policy.set_issuer(&[issuer]);
    policy.set_audience(&[client_id]);
    policy.validate_exp = false;
    policy.validate_nbf = false;
    policy.leeway = 0;
    let claims = jsonwebtoken::decode::<Value>(token, &key, &policy)
        .map_err(|_| invalid())?
        .claims;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| invalid())?
        .as_secs_f64()
        .floor();
    for field in ["iat", "exp", "nbf"] {
        if let Some(value) = claims.get(field) {
            let value = value.as_f64().ok_or_else(invalid)?;
            if (field == "exp" && value <= now) || (field == "nbf" && value > now) {
                return Err(invalid());
            }
        }
    }
    if claims
        .get("aud")
        .and_then(Value::as_array)
        .is_some_and(|audiences| audiences.len() > 1)
        && claims.get("azp").is_none()
        || claims
            .get("azp")
            .is_some_and(|party| party.as_str() != Some(client_id))
    {
        return Err(invalid());
    }
    if claims
        .get("sub")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(api(400, "id_token_subject_missing"));
    }
    Ok(claims)
}
