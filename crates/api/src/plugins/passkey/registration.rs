//! Trusted application policy for passkey-first registration.
use async_trait::async_trait;
use better_auth_core::{
    AuthConfig, AuthRequest, AuthResult, ContextExtensions, utils::json::JsValue,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyRegistrationUser {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// Immutable request and application settings; captures may hold typed services.
/// A captured store is not automatically rebound to the registration transaction.
pub struct PasskeyRegistrationContext<'a> {
    pub request: &'a AuthRequest,
    pub auth_config: &'a AuthConfig,
    pub extensions: &'a ContextExtensions,
}

/// Resolve an authorized registration identity when no session is available.
#[async_trait]
pub trait PasskeyUserResolver: Send + Sync {
    async fn resolve_user(
        &self,
        context: &PasskeyRegistrationContext<'_>,
        requested_context: Option<&str>,
    ) -> AuthResult<Option<PasskeyRegistrationUser>>;
}

/// Cryptographic facts supplied only after the registration response verifies.
#[derive(Debug, Clone)]
pub struct VerifiedPasskeyRegistration {
    pub credential_id: String,
    pub public_key: Vec<u8>,
    pub counter: u64,
    pub aaguid: Option<String>,
    pub device_type: String,
    pub backed_up: bool,
}

#[derive(Debug, Default)]
pub struct PasskeyRegistrationOverride {
    /// Empty values are absent, as with upstream's truthiness check.
    pub user_id: Option<String>,
    pub name: Option<String>,
}

#[async_trait]
pub trait PasskeyRegistrationAfterVerification: Send + Sync {
    async fn after_verification(
        &self,
        context: &PasskeyRegistrationContext<'_>,
        verification: &VerifiedPasskeyRegistration,
        user: &PasskeyRegistrationUser,
        client_data: &JsValue,
        stored_context: Option<&str>,
    ) -> AuthResult<Option<PasskeyRegistrationOverride>>;
}

#[derive(Clone)]
pub struct PasskeyRegistrationConfig {
    pub require_session: bool,
    pub resolve_user: Option<Arc<dyn PasskeyUserResolver>>,
    pub after_verification: Option<Arc<dyn PasskeyRegistrationAfterVerification>>,
}
impl Default for PasskeyRegistrationConfig {
    fn default() -> Self {
        Self {
            require_session: true,
            resolve_user: None,
            after_verification: None,
        }
    }
}
impl std::fmt::Debug for PasskeyRegistrationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyRegistrationConfig")
            .field("require_session", &self.require_session)
            .field("resolve_user", &self.resolve_user.is_some())
            .field("after_verification", &self.after_verification.is_some())
            .finish()
    }
}

pub(super) fn trim_name(value: &str) -> &str {
    value.trim_matches(|character| {
        matches!(character,
        '\u{0009}'..='\u{000D}' | '\u{0020}' | '\u{00A0}' | '\u{1680}' |
        '\u{2000}'..='\u{200A}' | '\u{2028}' | '\u{2029}' | '\u{202F}' |
        '\u{205F}' | '\u{3000}' | '\u{FEFF}')
    })
}

/// Domain client errors and explicit public API errors preserve their wire contract.
pub(super) fn is_application_error(error: &better_auth_core::AuthError) -> bool {
    matches!(
        error,
        better_auth_core::AuthError::Upstream { .. } | better_auth_core::AuthError::Api { .. }
    ) || error.status_code() < 500
}
