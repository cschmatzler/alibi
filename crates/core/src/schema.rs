//! Schema traits for binding Better Auth to application-owned auth models.

use crate::entity::{AuthAccount, AuthSession, AuthUser, AuthVerification};

/// App-owned auth schema declaration.
pub trait AuthSchema: Send + Sync + 'static {
    /// Wire model projections for this application schema.
    /// Add application fields here with their actual input/output policy; database
    /// column names do not change canonical accessor-backed wire field names.
    #[must_use]
    fn openapi_models() -> Vec<crate::openapi::OpenApiModel> {
        crate::openapi::annotations::core_models()
    }

    type User: AuthUser;
    type Session: AuthSession;
    type Account: AuthAccount;
    type Verification: AuthVerification;
}
