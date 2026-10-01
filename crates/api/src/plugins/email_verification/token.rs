use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

use better_auth_core::{AuthError, AuthResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::plugins) struct EmailVerificationClaims {
    pub(in crate::plugins) email: String,
    #[serde(rename = "updateTo", skip_serializing_if = "Option::is_none")]
    pub(in crate::plugins) update_to: Option<String>,
    #[serde(rename = "requestType", skip_serializing_if = "Option::is_none")]
    pub(in crate::plugins) request_type: Option<String>,
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) fn create_email_verification_token(
    secret: &str,
    email: &str,
    update_to: Option<&str>,
    expires_in: Duration,
    request_type: Option<&str>,
) -> AuthResult<String> {
    let now = Utc::now();
    let mut claims = serde_json::to_value(EmailVerificationClaims {
        email: email.to_lowercase(),
        update_to: update_to.map(str::to_lowercase),
        request_type: request_type.map(str::to_owned),
    })?;
    let fields = claims
        .as_object_mut()
        .ok_or_else(|| AuthError::internal("Verification claims must serialize as an object"))?;
    drop(fields.insert("iat".to_owned(), serde_json::json!(now.timestamp())));
    drop(fields.insert(
        "exp".to_owned(),
        serde_json::json!((now + expires_in).timestamp()),
    ));
    let mut header = Header::new(Algorithm::HS256);
    header.typ = None;

    Ok(encode(
        &header,
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?)
}

#[expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) fn decode_email_verification_token(
    secret: &str,
    token: &str,
) -> AuthResult<EmailVerificationClaims> {
    let mut validation = Validation::new(Algorithm::HS256);
    // JOSE imposes no required dates or audience unless configured. Validate
    // NumericDates below to retain its strict exp <= now expiration boundary,
    // fractional numbers and absence of the library's 60-second leeway.
    validation.required_spec_claims.clear();
    validation.leeway = 0;
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;

    let payload = decode::<serde_json::Value>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )?
    .claims;
    let now = Utc::now().timestamp() as f64;
    for field in ["iat", "nbf", "exp"] {
        if let Some(value) = payload.get(field) {
            let value = value.as_f64().ok_or_else(|| {
                AuthError::Jwt(
                    jsonwebtoken::errors::ErrorKind::InvalidClaimFormat(field.to_owned()).into(),
                )
            })?;
            if field == "exp" && value <= now {
                return Err(AuthError::Jwt(
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature.into(),
                ));
            }
            if field == "nbf" && value > now {
                return Err(AuthError::Jwt(
                    jsonwebtoken::errors::ErrorKind::ImmatureSignature.into(),
                ));
            }
        }
    }
    for field in ["updateTo", "requestType"] {
        if payload.get(field).is_some_and(|value| !value.is_string()) {
            return Err(AuthError::internal("Invalid verification claims"));
        }
    }
    if !payload
        .get("email")
        .and_then(serde_json::Value::as_str)
        .is_some_and(crate::plugins::authentication_helpers::is_valid_email)
    {
        return Err(AuthError::internal("Invalid verification claims"));
    }
    serde_json::from_value(payload).map_err(AuthError::from)
}
