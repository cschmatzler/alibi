//! Shared HTTP validation and authentication lifecycle behavior.
mod fields;
mod notifications;
mod sessions;
mod validation;

use alibi_core::{AuthContext, AuthResponse, AuthResult, AuthSchema};
pub(crate) use fields::{
    apply_creation_input_defaults, field_input_error, prepare_additional_user_fields,
};
pub(crate) use notifications::{run_notification, run_owned_notification};
pub(crate) use sessions::{
    dont_remember_preference, revoke_unproven_access, session_response,
    session_response_with_remember, with_session_cookies,
};
pub(crate) use validation::{
    JsonField, JsonFieldKind, RequestBody, field_issue, is_valid_email, json_type, parse_body,
    parse_body_with_fields, parse_body_with_ignored_fields, parse_email, validation_response,
};

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
