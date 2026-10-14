//! Application-owned inbound bearer verification.
use alibi_core::store::AuthStore;
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthResult, AuthSchema, HttpMethod};
use async_trait::async_trait;
/// Actual logical request data supplied to the bearer verifier.
#[derive(Clone, Debug)]
pub struct ScimBearerTokenVerificationInput {
    pub token: String,
    pub method: HttpMethod,
    pub path: String,
    pub headers: std::collections::BTreeMap<String, String>,
}
/// Verify an external token and return declared or dynamically resolved claims.
/// Claims retain trusted Date values and are validated before authorization.
#[async_trait]
pub trait ScimBearerTokenVerifier<S: AuthSchema>: Send + Sync {
    async fn verify_bearer_token(
        &self,
        input: &ScimBearerTokenVerificationInput,
        database: &dyn AuthStore<S>,
    ) -> AuthResult<Option<JsValue>>;
}
pub(super) struct ScimBearerVerifierHandle<S: AuthSchema>(
    pub std::sync::Arc<dyn ScimBearerTokenVerifier<S>>,
);
