//! Application-owned private key material for SSO client authentication.
use super::Value;
#[derive(Clone, Default)]
pub struct SsoPrivateKey {
    pub private_key_jwk: Option<Value>,
    pub private_key_pem: Option<String>,
    pub kid: Option<String>,
    pub algorithm: Option<String>,
}
impl std::fmt::Debug for SsoPrivateKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SsoPrivateKey")
            .finish_non_exhaustive()
    }
}

impl SsoPrivateKey {
    pub(super) fn has_material(&self) -> bool {
        self.private_key_jwk
            .as_ref()
            .is_some_and(|key| !key.is_null())
            || self
                .private_key_pem
                .as_deref()
                .is_some_and(|pem| !pem.is_empty())
    }
    pub(super) fn assertion(
        &self,
        config: &Value,
    ) -> Result<crate::oauth::OAuthClientAssertion, String> {
        let raw_algorithm = config
            .get("privateKeyAlgorithm")
            .and_then(Value::as_str)
            .or(self.algorithm.as_deref());
        crate::oauth::OAuthPrivateKeyJwtOptions {
            private_key_jwk: self.private_key_jwk.clone(),
            private_key_pem: self.private_key_pem.clone(),
            kid: config
                .get("privateKeyId")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| self.kid.clone()),
            algorithm: raw_algorithm
                .filter(|algorithm| {
                    crate::oauth::PRIVATE_KEY_JWT_SIGNING_ALGORITHMS.contains(algorithm)
                })
                .map(str::to_owned),
            expires_in: None,
        }
        .into_assertion()
    }
}
