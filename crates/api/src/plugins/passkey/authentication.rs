//! Trusted application policy after successful cryptographic authentication.
use async_trait::async_trait;
use better_auth_core::{
    AuthConfig, AuthRequest, AuthResult, ContextExtensions, utils::json::JsValue,
};
use std::sync::Arc;
/// Verification authority: Core verifies supported typed keys; the bounded raw
/// verifier verifies original COSE facts without manufacturing a Core result.
#[derive(Debug, Clone)]
pub enum AuthenticationResult {
    Core(webauthn_rs::prelude::AuthenticationResult),
    Raw(RawAuthenticationResult),
}

#[derive(Debug, Clone)]
pub struct RawAuthenticationResult {
    pub(super) credential_id: webauthn_rs::prelude::CredentialID,
    pub(super) counter: u32,
    pub(super) user_verified: bool,
    pub(super) backup_eligible: bool,
    pub(super) backup_state: bool,
}

impl AuthenticationResult {
    pub fn cred_id(&self) -> &webauthn_rs::prelude::CredentialID {
        match self {
            Self::Core(result) => result.cred_id(),
            Self::Raw(result) => &result.credential_id,
        }
    }
    pub fn counter(&self) -> u32 {
        match self {
            Self::Core(result) => result.counter(),
            Self::Raw(result) => result.counter,
        }
    }
    pub fn user_verified(&self) -> bool {
        match self {
            Self::Core(result) => result.user_verified(),
            Self::Raw(result) => result.user_verified,
        }
    }
    pub fn backup_eligible(&self) -> bool {
        match self {
            Self::Core(result) => result.backup_eligible(),
            Self::Raw(result) => result.backup_eligible,
        }
    }
    pub fn backup_state(&self) -> bool {
        match self {
            Self::Core(result) => result.backup_state(),
            Self::Raw(result) => result.backup_state,
        }
    }
}

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
