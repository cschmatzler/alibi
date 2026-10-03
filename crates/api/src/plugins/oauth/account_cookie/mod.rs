//! Typed account-cookie payload boundary for the shared authenticated JWE codec.

use super::state::AccountCookiePayload;
use better_auth_core::{AuthError, AuthResult, utils::jwe};

pub(super) fn encode(
    secret: &str,
    payload: &AccountCookiePayload,
    max_age: f64,
) -> AuthResult<String> {
    jwe::encode(
        secret,
        "better-auth-account",
        &payload.wire_value()?,
        max_age,
    )
}

pub(super) fn decode(secret: &str, token: &str) -> AuthResult<AccountCookiePayload> {
    let payload = jwe::decode(secret, "better-auth-account", token)
        .map_err(|_error| AuthError::bad_request("Account not found"))?;
    serde_json::from_value(payload).map_err(|_error| AuthError::bad_request("Account not found"))
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as BASE64};

    #[test]
    fn account_cookie_accepts_pinned_encrypted_vectors_and_rejects_unauthenticated_values() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../../tests/fixtures/oauth/account-cookie-vectors.json"
        ))
        .unwrap();
        let secret = (*(vectors)
            .get("secret")
            .expect("fixture contains the requested index"))
        .as_str()
        .unwrap();
        for name in ["valid", "noKid"] {
            let decoded = crate::plugins::oauth::state::decode_account_cookie_value(
                &better_auth_core::AuthConfig::new(secret),
                (*(vectors)
                    .get(name)
                    .expect("fixture contains the requested index"))
                .as_str()
                .unwrap(),
            )
            .unwrap();
            assert_eq!(
                serde_json::to_value(decoded).unwrap(),
                (*(vectors)
                    .get("payload")
                    .expect("fixture contains the requested index"))
            );
        }
        for name in ["wrongSalt", "wrongSecret", "expired", "gcm", "jws"] {
            assert!(
                crate::plugins::oauth::state::decode_account_cookie_value(
                    &better_auth_core::AuthConfig::new(secret),
                    (*(vectors)
                        .get(name)
                        .expect("fixture contains the requested index"))
                    .as_str()
                    .unwrap()
                )
                .is_err(),
                "{name} must not resolve a provider account"
            );
        }
        let original = (*(vectors)
            .get("valid")
            .expect("fixture contains the requested index"))
        .as_str()
        .unwrap();
        for segment in [0, 2, 3, 4] {
            let mut parts: Vec<_> = original.split('.').map(str::to_owned).collect();
            let mut bytes = BASE64
                .decode(
                    (parts)
                        .get(segment)
                        .expect("fixture contains the requested index"),
                )
                .unwrap();
            *bytes.first_mut().expect("decoded fixture is nonempty") ^= 1;
            *parts.get_mut(segment).expect("fixture segment exists") = BASE64.encode(bytes);
            assert!(
                crate::plugins::oauth::state::decode_account_cookie_value(
                    &better_auth_core::AuthConfig::new(secret),
                    &parts.join(".")
                )
                .is_err(),
                "changed segment {segment} must not authenticate"
            );
        }
    }
}
// LCOV_EXCL_STOP
