//! Application policies for configured SAML signing and digest algorithms.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SsoDeprecatedAlgorithmBehavior {
    Reject,
    #[default]
    Warn,
    Allow,
}
/// Admission policy for configured algorithms at provider registration and update.
#[derive(Clone, Debug, Default)]
pub struct SsoSamlSigningPolicy {
    pub on_deprecated: SsoDeprecatedAlgorithmBehavior,
    pub allowed_signature_algorithms: Option<Vec<String>>,
    pub allowed_digest_algorithms: Option<Vec<String>>,
}

use super::{AuthError, AuthResult, Value};
const SIGNATURES: &[(&str, &str)] = &[
    ("sha1", "http://www.w3.org/2000/09/xmldsig#rsa-sha1"),
    (
        "sha256",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    ),
    (
        "sha384",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
    ),
    (
        "sha512",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
    ),
    ("rsa-sha1", "http://www.w3.org/2000/09/xmldsig#rsa-sha1"),
    (
        "rsa-sha256",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    ),
    (
        "rsa-sha384",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
    ),
    (
        "rsa-sha512",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
    ),
    (
        "ecdsa-sha256",
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
    ),
    (
        "ecdsa-sha384",
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
    ),
    (
        "ecdsa-sha512",
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
    ),
];
const DIGESTS: &[(&str, &str)] = &[
    ("sha1", "http://www.w3.org/2000/09/xmldsig#sha1"),
    ("sha256", "http://www.w3.org/2001/04/xmlenc#sha256"),
    ("sha384", "http://www.w3.org/2001/04/xmldsig-more#sha384"),
    ("sha512", "http://www.w3.org/2001/04/xmlenc#sha512"),
];
fn normalize<'a>(algorithm: &'a str, names: &[(&str, &'static str)]) -> &'a str {
    names
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(algorithm))
        .map_or(algorithm, |(_, uri)| *uri)
}
fn failure(code: &str, message: String) -> AuthError {
    AuthError::Api {
        status: 400,
        code: Some(code.into()),
        message,
    }
}
pub(super) fn validate(config: &Value, policy: &SsoSamlSigningPolicy) -> AuthResult<()> {
    for (field, label, names, allowed) in [
        (
            "signatureAlgorithm",
            "signature",
            SIGNATURES,
            &policy.allowed_signature_algorithms,
        ),
        (
            "digestAlgorithm",
            "digest",
            DIGESTS,
            &policy.allowed_digest_algorithms,
        ),
    ] {
        let Some(algorithm) = config
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let normalized = normalize(algorithm, names);
        if let Some(allowed) = allowed {
            if !allowed
                .iter()
                .any(|value| normalize(value, names) == normalized)
            {
                return Err(failure(
                    "SAML_ALGORITHM_NOT_ALLOWED",
                    format!("SAML {label} algorithm not in allow-list: {algorithm}"),
                ));
            }
            continue;
        }
        if names.first().is_some_and(|(_, uri)| normalized == *uri) {
            let message = format!(
                "SAML config uses deprecated {label} algorithm: {algorithm}. Consider using SHA-256 or stronger."
            );
            match policy.on_deprecated {
                SsoDeprecatedAlgorithmBehavior::Reject => {
                    return Err(failure("SAML_DEPRECATED_CONFIG_ALGORITHM", message));
                }
                SsoDeprecatedAlgorithmBehavior::Warn => tracing::warn!("{message}"),
                SsoDeprecatedAlgorithmBehavior::Allow => {}
            }
        } else if !names.iter().any(|(_, uri)| *uri == normalized) {
            return Err(failure(
                "SAML_UNKNOWN_ALGORITHM",
                format!("SAML {label} algorithm not recognized: {algorithm}"),
            ));
        }
    }
    Ok(())
}
