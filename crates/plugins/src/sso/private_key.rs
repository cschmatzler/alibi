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

/// Parameters supplied to an application-owned SSO signing-key resolver.
#[derive(Clone, Debug)]
pub struct SsoPrivateKeyContext {
    pub provider_id: String,
    pub key_id: Option<String>,
    pub issuer: String,
}
#[async_trait::async_trait]
pub trait SsoPrivateKeyResolver: Send + Sync {
    async fn resolve(
        &self,
        context: SsoPrivateKeyContext,
    ) -> alibi_core::AuthResult<Option<SsoPrivateKey>>;
}
#[derive(Clone)]
pub struct SsoKeyResolver(pub std::sync::Arc<dyn SsoPrivateKeyResolver>);
impl std::fmt::Debug for SsoKeyResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SsoKeyResolver")
            .finish_non_exhaustive()
    }
}

impl super::SsoPlugin {
    pub(super) fn private_key_source_configured(&self, provider_id: &str) -> bool {
        self.config.resolve_private_key.is_some()
            || self.config.default_providers.iter().any(|provider| {
                provider.provider_id == provider_id && provider.private_key.is_some()
            })
    }
}
