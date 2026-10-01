//! Trusted application policy after successful cryptographic authentication.
use async_trait::async_trait;
use better_auth_core::{
    AuthConfig, AuthRequest, AuthResult, ContextExtensions, utils::json::JsValue,
};
use std::sync::Arc;
pub use webauthn_rs::prelude::AuthenticationResult;

/// Immutable request and application settings. Captures may hold typed services.
pub struct PasskeyAuthenticationContext<'a> {
    pub request: &'a AuthRequest,
    pub auth_config: &'a AuthConfig,
    pub extensions: &'a ContextExtensions,
}

impl std::fmt::Debug for PasskeyAuthenticationContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyAuthenticationContext")
            .finish_non_exhaustive()
    }
}

/// Actual verifier result, supplied only after the signed assertion succeeds.
#[derive(Debug, Clone)]
pub struct VerifiedPasskeyAuthentication {
    pub result: AuthenticationResult,
    pub origin: String,
    pub rp_id: String,
}

/// Awaited before counter persistence and session creation. The client data is
/// untrusted application input; it cannot replace the verified credential owner.
#[async_trait]
pub trait PasskeyAuthenticationAfterVerification: Send + Sync {
    async fn after_verification(
        &self,
        context: &PasskeyAuthenticationContext<'_>,
        verification: &VerifiedPasskeyAuthentication,
        client_data: &JsValue,
    ) -> AuthResult<()>;
}

#[derive(Clone, Default)]
pub struct PasskeyAuthenticationConfig {
    pub after_verification: Option<Arc<dyn PasskeyAuthenticationAfterVerification>>,
}
impl std::fmt::Debug for PasskeyAuthenticationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyAuthenticationConfig")
            .field("after_verification", &self.after_verification.is_some())
            .finish()
    }
}
