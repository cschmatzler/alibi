//! Shared HTTP validation and authentication lifecycle behavior.
mod fields;
mod notifications;
mod sessions;
mod validation;

use better_auth_core::{
    AuthAccount, AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema,
    AuthSession, AuthUser, CreateUser, CreateVerification, UpdateUser,
};
use chrono::{Duration, Utc};
pub(in crate::plugins) use fields::apply_creation_input_defaults;
pub(in crate::plugins) use fields::prepare_additional_user_fields;
pub(in crate::plugins) use notifications::run_notification;
pub(in crate::plugins) use notifications::run_owned_notification;
use serde::de::DeserializeOwned;
use serde_json::Value;
pub(in crate::plugins) use sessions::revoke_unproven_access;
pub(in crate::plugins) use sessions::session_response;
pub(in crate::plugins) use sessions::session_response_with_remember;
pub(in crate::plugins) use validation::JsonField;
pub(in crate::plugins) use validation::JsonFieldKind;
pub(in crate::plugins) use validation::RequestBody;
pub(in crate::plugins) use validation::is_valid_email;
pub(in crate::plugins) use validation::json_type;
pub(in crate::plugins) use validation::parse_body;
pub(in crate::plugins) use validation::parse_body_with_fields;
pub(in crate::plugins) use validation::parse_body_with_ignored_fields;
pub(in crate::plugins) use validation::parse_email;
pub(in crate::plugins) use validation::validation_response;

/// Preserve the newest lookup snapshot before the configured global cleanup.
/// The atomic consume operation has its own expiry and concurrency contract.
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn find_verification<S: AuthSchema>(
    ctx: &AuthContext<S>,
    identifier: &str,
) -> AuthResult<Option<better_auth_core::verification::VerificationSnapshot>> {
    ctx.verifications().find(identifier).await
}

pub(in crate::plugins) fn redirect(url: &str) -> AuthResponse {
    AuthResponse::text(302, "")
        .with_header("Location", url)
        .with_header("content-type", "application/json")
}
