use super::*;

// ── status_code ─────────────────────────────────────────────────────

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn bad_request_is_400() {
    assert_eq!(AuthError::bad_request("oops").status_code(), 400);
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn invalid_request_is_400() {
    assert_eq!(AuthError::InvalidRequest("x".into()).status_code(), 400);
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn validation_is_400() {
    assert_eq!(AuthError::validation("x").status_code(), 400);
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn invalid_credentials_is_401() {
    assert_eq!(AuthError::InvalidCredentials.status_code(), 401);
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn unauthenticated_is_401() {
    assert_eq!(AuthError::Unauthenticated.status_code(), 401);
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn session_not_found_is_401() {
    assert_eq!(AuthError::SessionNotFound.status_code(), 401);
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn forbidden_is_403() {
    assert_eq!(AuthError::forbidden("nope").status_code(), 403);
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn unauthorized_is_403() {
    assert_eq!(AuthError::Unauthorized.status_code(), 403);
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn not_found_is_404() {
    assert_eq!(AuthError::not_found("gone").status_code(), 404);
    assert_eq!(AuthError::UserNotFound.status_code(), 404);
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn conflict_is_409() {
    assert_eq!(AuthError::conflict("dup").status_code(), 409);
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn unprocessable_entity_is_422() {
    assert_eq!(
        AuthError::UnprocessableEntity("x".into()).status_code(),
        422
    );
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn rate_limited_is_429() {
    assert_eq!(AuthError::RateLimited.status_code(), 429);
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn not_implemented_is_501() {
    assert_eq!(AuthError::not_implemented("todo").status_code(), 501);
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn internal_errors_are_500() {
    assert_eq!(AuthError::config("bad").status_code(), 500);
    assert_eq!(AuthError::internal("fail").status_code(), 500);
    assert_eq!(AuthError::plugin("p", "m").status_code(), 500);
    assert_eq!(AuthError::PasswordHash("h".into()).status_code(), 500);
    assert_eq!(
        AuthError::Database(DatabaseError::Connection("c".into())).status_code(),
        500
    );
}

// ── code_from_message ───────────────────────────────────────────────

// Upstream reference: BASE_ERROR_CODES in @better-auth/core — a message
// upstream defines a constant for carries that constant.
#[test]
fn code_from_message_returns_the_upstream_constant() {
    assert_eq!(
        AuthError::code_from_message("User not found").as_deref(),
        Some("USER_NOT_FOUND")
    );
}

// Upstream reference: packages/core/src/error/index.ts :: `APIError.from`
// attaches a code, while `new APIError(status, { message })` does not — so
// a message outside every upstream table has no code on the wire.
#[test]
fn code_from_message_is_none_for_unknown_messages() {
    assert_eq!(AuthError::code_from_message("invalid email!"), None);
    assert_eq!(AuthError::code_from_message("Email is the same"), None);
    assert_eq!(AuthError::code_from_message(""), None);
}

// Upstream reference: plugin tables built with `defineErrorCodes` are part
// of the same vocabulary, not just the base set.
#[test]
fn code_from_message_covers_plugin_tables() {
    assert_eq!(
        AuthError::code_from_message("Username is already taken. Please try another.").as_deref(),
        Some("USERNAME_IS_ALREADY_TAKEN")
    );
}

// Upstream reference: BASE_ERROR_CODES in @better-auth/core ::
// packages/core/src/error/codes.ts — codes are explicit constants since
// better-auth 1.5, so these must not be re-derived from the message.
#[test]
fn base_error_codes_are_not_derived_from_the_message() {
    for (message, expected) in [
        ("Invalid callbackURL", "INVALID_CALLBACK_URL"),
        ("Invalid redirectURL", "INVALID_REDIRECT_URL"),
        ("Invalid errorCallbackURL", "INVALID_ERROR_CALLBACK_URL"),
        (
            "Invalid newUserCallbackURL",
            "INVALID_NEW_USER_CALLBACK_URL",
        ),
        ("Email is already verified", "EMAIL_ALREADY_VERIFIED"),
        (
            "Verification email isn't enabled",
            "VERIFICATION_EMAIL_NOT_ENABLED",
        ),
        (
            "Session expired. Re-authenticate to perform this action.",
            "SESSION_EXPIRED",
        ),
        (
            "Cross-site navigation login blocked. This request appears to be a CSRF attack.",
            "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED",
        ),
    ] {
        assert_eq!(
            AuthError::code_from_message(message).as_deref(),
            Some(expected),
            "message {message:?} must carry the upstream constant"
        );
    }
}

// ── error_payload ───────────────────────────────────────────────────

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn error_payload_for_client_error() {
    // Not an upstream message, so it goes out without a code.
    let (status, code, message) = AuthError::bad_request("Missing field").error_payload();
    assert_eq!(status, 400);
    assert_eq!(code, None);
    assert_eq!(message, "Missing field");

    let (status_2, code_2, message_2) = AuthError::bad_request("Field is required").error_payload();
    assert_eq!(status_2, 400);
    assert_eq!(code_2.as_deref(), Some("MISSING_FIELD"));
    assert_eq!(message_2, "Field is required");
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn error_payload_for_internal_error_hides_details() {
    let (status, _code, message) = AuthError::internal("secret detail").error_payload();
    assert_eq!(status, 500);
    assert_eq!(message, "Internal server error");
}

// ── to_auth_response ────────────────────────────────────────────────

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn to_auth_response_returns_correct_status() {
    let resp = AuthError::bad_request("oops").to_auth_response();
    assert_eq!(resp.status, 400);
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn to_auth_response_body_contains_code_and_message() {
    let resp = AuthError::UserNotFound.to_auth_response();
    assert_eq!(resp.status, 404);
    let body: serde_json::Value =
        serde_json::from_slice(&resp.body).expect("response body should be valid JSON");
    assert_eq!(
        (*(body).get("code").unwrap_or(&serde_json::Value::Null)),
        "USER_NOT_FOUND"
    );
    assert_eq!(
        (*(body).get("message").unwrap_or(&serde_json::Value::Null)),
        "User not found"
    );
}

// ── constructor helpers ──────────────────────────────────────────────

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn constructor_helpers_produce_correct_variants() {
    // Each helper should produce the expected Display output
    assert_eq!(AuthError::bad_request("x").to_string(), "x");
    assert_eq!(AuthError::forbidden("x").to_string(), "x");
    assert_eq!(AuthError::not_found("x").to_string(), "x");
    assert_eq!(AuthError::conflict("x").to_string(), "x");
    assert_eq!(AuthError::not_implemented("x").to_string(), "x");
    assert_eq!(AuthError::config("x").to_string(), "Configuration error: x");
    assert_eq!(
        AuthError::internal("x").to_string(),
        "Internal server error: x"
    );
    assert_eq!(
        AuthError::validation("x").to_string(),
        "Validation error: x"
    );
    assert_eq!(
        AuthError::plugin("p", "m").to_string(),
        "Plugin error: p - m"
    );
}

// ── DatabaseError ───────────────────────────────────────────────────

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn database_error_display() {
    let e = DatabaseError::Connection("timeout".into());
    assert_eq!(e.to_string(), "Connection error: timeout");
}

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn database_error_converts_to_auth_error() {
    let db_err = DatabaseError::Query("bad sql".into());
    let auth_err: AuthError = db_err.into();
    assert_eq!(auth_err.status_code(), 500);
}

// ── validation_error_response ───────────────────────────────────────

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn validation_error_response_serializes_field_errors() {
    let mut errors = validator::ValidationErrors::new();
    let mut error = validator::ValidationError::new("email");
    error.message = Some("Email is invalid".into());
    errors.add("email", error);

    let resp = validation_error_response(&errors);
    assert_eq!(resp.status, 400);
    let body: serde_json::Value =
        serde_json::from_slice(&resp.body).expect("response body should be valid JSON");
    assert_eq!(
        (*(body).get("code").unwrap_or(&serde_json::Value::Null)),
        "VALIDATION_ERROR"
    );
    assert_eq!(
        (*(body).get("message").unwrap_or(&serde_json::Value::Null)),
        "[body.email] Email is invalid"
    );
}

// ── Display for fixed-message variants ──────────────────────────────

// Rust-specific surface: `AuthError` and Rust-side response/error conversion behavior are public Rust library APIs with no direct TS analogue.
#[test]
fn fixed_message_variants_display() {
    assert_eq!(
        AuthError::InvalidCredentials.to_string(),
        "Invalid email or password"
    );
    assert_eq!(
        AuthError::Unauthenticated.to_string(),
        "Authentication required"
    );
    assert_eq!(
        AuthError::SessionNotFound.to_string(),
        "Session not found or expired"
    );
    assert_eq!(
        AuthError::Unauthorized.to_string(),
        "Insufficient permissions"
    );
    assert_eq!(AuthError::UserNotFound.to_string(), "User not found");
    assert_eq!(AuthError::RateLimited.to_string(), "Too many requests");
}
