//! Shared HTTP validation and authentication lifecycle behavior.
mod fields;
mod notifications;
mod sessions;
mod validation;

use alibi_core::{
    AuthAccount, AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema,
    AuthSession, AuthUser, CreateUser, CreateVerification, UpdateUser,
};
use chrono::{Duration, Utc};
pub(crate) use fields::apply_creation_input_defaults;
pub(crate) use fields::prepare_additional_user_fields;
pub(crate) use notifications::run_notification;
pub(crate) use notifications::run_owned_notification;
use serde::de::DeserializeOwned;
use serde_json::Value;
pub(crate) use sessions::revoke_unproven_access;
pub(crate) use sessions::session_response;
pub(crate) use sessions::session_response_with_remember;
pub(crate) use validation::JsonField;
pub(crate) use validation::JsonFieldKind;
pub(crate) use validation::RequestBody;
pub(crate) use validation::is_valid_email;
pub(crate) use validation::json_type;
pub(crate) use validation::parse_body;
pub(crate) use validation::parse_body_with_fields;
pub(crate) use validation::parse_body_with_ignored_fields;
pub(crate) use validation::parse_email;
pub(crate) use validation::validation_response;

/// Preserve the newest lookup snapshot before the configured global cleanup.
/// The atomic consume operation has its own expiry and concurrency contract.
pub(crate) async fn find_verification<S: AuthSchema>(
    ctx: &AuthContext<S>,
    identifier: &str,
) -> AuthResult<Option<alibi_core::verification::VerificationSnapshot>> {
    ctx.verifications().find(identifier).await
}

pub(crate) fn redirect(url: &str) -> AuthResponse {
    AuthResponse::text(302, "")
        .with_header("Location", url)
        .with_header("content-type", "application/json")
}
