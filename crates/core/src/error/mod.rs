#[cfg(test)]
mod tests;

use thiserror::Error;

/// Authentication framework error types.
///
/// Each variant maps to an HTTP status code via [`AuthError::status_code`].
/// Use [`AuthError::to_auth_response`] to produce a standardized JSON response
/// matching the better-auth `OpenAPI` spec: `{ "message": "..." }`.
#[derive(Error, Debug)]
pub enum AuthError {
    /// An intentional public API error from application policy or input validation.
    ///
    /// The supplied message is returned verbatim, including for a 500 status.
    /// Use internal error variants for database failures or other private details.
    #[error("{message}")]
    Api {
        status: u16,
        code: Option<String>,
        message: String,
    },

    /// A documented upstream API error whose message is safe to return publicly.
    #[error("{message}")]
    Upstream {
        /// HTTP response status defined by the upstream endpoint.
        status: u16,
        /// Stable upstream error code.
        code: &'static str,
        /// Documented public error message. Never include internal failure details.
        message: &'static str,
    },

    #[error("{0}")]
    BadRequest(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Invalid email or password")]
    InvalidCredentials,

    #[error("Authentication required")]
    Unauthenticated,

    #[error("{0}")]
    AuthenticationFailed(String),

    #[error("Session not found or expired")]
    SessionNotFound,

    #[error("{0}")]
    Forbidden(String),

    /// A session-create lifecycle hook explicitly cancelled creation.
    /// Callers may apply endpoint-specific null-session behavior; the default
    /// public response retains the existing cancellation status and message.
    #[error("session creation cancelled by database hook")]
    SessionCreationCancelled,

    /// A user-create database hook explicitly cancelled creation.
    /// Endpoint owners may map the absent user differently from a genuine
    /// application Forbidden error with the same text.
    #[error("user creation cancelled by database hook")]
    UserCreationCancelled,

    #[error("{0}")]
    BannedUser(String),

    #[error("Insufficient permissions")]
    Unauthorized,

    #[error("User not found")]
    UserNotFound,

    #[error("{0}")]
    NotFound(String),

    #[error("{0}")]
    Conflict(String),

    #[error("{0}")]
    MethodNotAllowed(String),

    #[error("{0}")]
    PayloadTooLarge(String),

    #[error("{0}")]
    UnprocessableEntity(String),

    #[error("Too many requests")]
    RateLimited,

    #[error("{0}")]
    NotImplemented(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Database error: {0}")]
    Database(#[from] DatabaseError),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Plugin error: {plugin} - {message}")]
    Plugin { plugin: String, message: String },

    #[error("Internal server error: {0}")]
    Internal(String),

    /// An ordinary application callback failure whose HTTP contract is an empty 500.
    /// The private cause is logged, never sent to the client. Explicit API errors
    /// retain their own response and must not be wrapped in this variant.
    #[error("Application callback failed: {0}")]
    CallbackFailure(Box<Self>),

    #[error("Password hashing error: {0}")]
    PasswordHash(String),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

impl AuthError {
    /// HTTP status code for this error.
    #[must_use]
    pub const fn status_code(&self) -> u16 {
        match self {
            Self::Api { status, .. } | Self::Upstream { status, .. } => *status,
            // 400
            Self::BadRequest(_) | Self::InvalidRequest(_) | Self::Validation(_) => 400,
            // 401
            Self::InvalidCredentials
            | Self::Unauthenticated
            | Self::AuthenticationFailed(_)
            | Self::SessionNotFound => 401,
            // 403
            Self::Forbidden(_)
            | Self::SessionCreationCancelled
            | Self::UserCreationCancelled
            | Self::BannedUser(_)
            | Self::Unauthorized => 403,
            // 404
            Self::UserNotFound | Self::NotFound(_) => 404,
            // 409
            Self::Conflict(_) => 409,
            // 405
            Self::MethodNotAllowed(_) => 405,
            // 413
            Self::PayloadTooLarge(_) => 413,
            // 422
            Self::UnprocessableEntity(_) => 422,
            // 429
            Self::RateLimited => 429,
            // 501
            Self::NotImplemented(_) => 501,
            // 500
            Self::Config(_)
            | Self::Database(_)
            | Self::Serialization(_)
            | Self::Plugin { .. }
            | Self::Internal(_)
            | Self::CallbackFailure(_)
            | Self::PasswordHash(_)
            | Self::Jwt(_) => 500,
        }
    }

    /// Resolve the wire error code for a message, if upstream defines one.
    ///
    /// better-auth 1.5 replaced message-derived codes with explicit constants,
    /// and only errors built from one of those constants carry a `code` at all
    /// (`APIError.from` sets it; a plain `new APIError(status, { message })`
    /// does not). So an unknown message yields `None` and the field is omitted,
    /// rather than being back-derived from the text.
    pub fn code_from_message(message: &str) -> Option<String> {
        upstream_code(message).map(str::to_owned)
    }

    /// Compute the HTTP status, error code, and user-facing message.
    ///
    /// The code is `None` for messages upstream has no constant for; those
    /// responses carry only a `message`.
    ///
    /// Internal errors (500) are logged and replaced with a generic message
    /// to avoid leaking details.
    pub fn error_payload(&self) -> (u16, Option<String>, String) {
        let status = self.status_code();
        let (code, message) = match self {
            Self::Api { code, message, .. } => (code.clone(), message.clone()),
            Self::Upstream { code, message, .. } => {
                (Some((*code).to_owned()), (*message).to_owned())
            }
            Self::BannedUser(message) => (Some("BANNED_USER".to_owned()), message.clone()),
            Self::BadRequest(_)
            | Self::InvalidRequest(_)
            | Self::Validation(_)
            | Self::InvalidCredentials
            | Self::Unauthenticated
            | Self::AuthenticationFailed(_)
            | Self::SessionNotFound
            | Self::Forbidden(_)
            | Self::SessionCreationCancelled
            | Self::UserCreationCancelled
            | Self::Unauthorized
            | Self::UserNotFound
            | Self::NotFound(_)
            | Self::Conflict(_)
            | Self::MethodNotAllowed(_)
            | Self::PayloadTooLarge(_)
            | Self::UnprocessableEntity(_)
            | Self::RateLimited
            | Self::NotImplemented(_)
            | Self::Config(_)
            | Self::Database(_)
            | Self::Serialization(_)
            | Self::Plugin { .. }
            | Self::Internal(_)
            | Self::CallbackFailure(_)
            | Self::PasswordHash(_)
            | Self::Jwt(_) => {
                let message = match status {
                    500 => {
                        tracing::error!(error = %self, "Internal server error");
                        "Internal server error".to_owned()
                    }
                    _ => self.to_string(),
                };
                let code = Self::code_from_message(&message);
                (code, message)
            }
        };
        (status, code, message)
    }

    /// Convert this error into a standardized [`AuthResponse`](crate::types::AuthResponse) matching the
    /// better-auth spec: `{ "code": "...", "message": "..." }`.
    ///
    /// Named `to_auth_response` to avoid collision with Axum's
    /// `IntoResponse::into_response` when the `axum` feature is enabled.
    #[must_use]
    pub fn to_auth_response(self) -> crate::types::AuthResponse {
        if let Self::CallbackFailure(_) = &self {
            tracing::error!(error = %self, "Application callback failed");
            return crate::types::AuthResponse::new(500);
        }
        let (status, code, message) = self.error_payload();
        crate::types::AuthResponse::json(
            status,
            &crate::types::ErrorCodeMessageResponse {
                code,
                message: message.clone(),
            },
        )
        .unwrap_or_else(|_| crate::types::AuthResponse::text(status, &message))
    }

    #[must_use]
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest(message.into())
    }

    #[must_use]
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::Forbidden(message.into())
    }

    #[must_use]
    pub fn banned_user(message: impl Into<String>) -> Self {
        Self::BannedUser(message.into())
    }

    #[must_use]
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::NotFound(message.into())
    }

    #[must_use]
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::Conflict(message.into())
    }

    #[must_use]
    pub fn method_not_allowed(message: impl Into<String>) -> Self {
        Self::MethodNotAllowed(message.into())
    }

    #[must_use]
    pub fn payload_too_large(message: impl Into<String>) -> Self {
        Self::PayloadTooLarge(message.into())
    }

    #[must_use]
    pub fn not_implemented(message: impl Into<String>) -> Self {
        Self::NotImplemented(message.into())
    }

    #[must_use]
    pub fn plugin(plugin: &str, message: impl Into<String>) -> Self {
        Self::Plugin {
            plugin: plugin.to_owned(),
            message: message.into(),
        }
    }

    #[must_use]
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    #[must_use]
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }

    #[must_use]
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation(message.into())
    }

    #[must_use]
    pub fn authentication_failed(message: impl Into<String>) -> Self {
        Self::AuthenticationFailed(message.into())
    }
}

#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Query error: {0}")]
    Query(String),

    #[error("Migration error: {0}")]
    Migration(String),

    #[error("Constraint violation: {0}")]
    Constraint(String),

    #[error("Transaction error: {0}")]
    Transaction(String),
}

pub type AuthResult<T> = Result<T, AuthError>;

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        if let Self::CallbackFailure(_) = &self {
            tracing::error!(error = %self, "Application callback failed");
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        let (status_u16, code, message) = self.error_payload();
        let status = axum::http::StatusCode::from_u16(status_u16)
            .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        (
            status,
            axum::Json(crate::types::ErrorCodeMessageResponse { code, message }),
        )
            .into_response()
    }
}

/// Explicit upstream error codes, ordered by message for binary search.
const UPSTREAM_ERROR_CODES: &[(&str, &str)] = &[
    (
        "API Key getter returned an invalid key type. Expected string.",
        "INVALID_API_KEY_GETTER_RETURN_TYPE",
    ),
    ("API Key has expired", "KEY_EXPIRED"),
    ("API Key has reached its usage limit", "USAGE_EXCEEDED"),
    ("API Key is disabled", "KEY_DISABLED"),
    ("API Key is not recoverable", "KEY_NOT_RECOVERABLE"),
    ("API Key name is required.", "NAME_REQUIRED"),
    ("API Key not found", "KEY_NOT_FOUND"),
    ("Access denied", "ACCESS_DENIED"),
    ("Access token not found", "ACCESS_TOKEN_NOT_FOUND"),
    (
        "Account is not associated with a configured social provider.",
        "PROVIDER_NOT_CONFIGURED",
    ),
    ("Account not found", "ACCOUNT_NOT_FOUND"),
    (
        "Account not linked - different emails not allowed",
        "LINKING_DIFFERENT_EMAILS_NOT_ALLOWED",
    ),
    (
        "Account not linked - linking not allowed",
        "LINKING_NOT_ALLOWED",
    ),
    (
        "Account not linked - unable to create account",
        "LINKING_FAILED",
    ),
    (
        "Anonymous users cannot sign in again anonymously",
        "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY",
    ),
    (
        "Async validation is not supported",
        "ASYNC_VALIDATION_NOT_SUPPORTED",
    ),
    ("Auth cancelled", "AUTH_CANCELLED"),
    ("Authentication failed", "AUTHENTICATION_FAILED"),
    ("Authentication required", "AUTHENTICATION_REQUIRED"),
    ("Authorization pending", "AUTHORIZATION_PENDING"),
    ("Backup codes aren't enabled", "BACKUP_CODES_NOT_ENABLED"),
    ("Body must be an object", "BODY_MUST_BE_AN_OBJECT"),
    ("CAPTCHA service unavailable", "SERVICE_UNAVAILABLE"),
    (
        "Cannot delete a pre-defined role",
        "CANNOT_DELETE_A_PRE_DEFINED_ROLE",
    ),
    (
        "Cannot delete a role that is assigned to members. Please reassign the members to a different role first",
        "ROLE_IS_ASSIGNED_TO_MEMBERS",
    ),
    ("Captcha verification failed", "VERIFICATION_FAILED"),
    ("Challenge not found", "CHALLENGE_NOT_FOUND"),
    ("Change email is disabled", "CHANGE_EMAIL_DISABLED"),
    ("Could not create session", "COULD_NOT_CREATE_SESSION"),
    (
        "Credential account not found",
        "CREDENTIAL_ACCOUNT_NOT_FOUND",
    ),
    (
        "Cross-site navigation login blocked. This request appears to be a CSRF attack.",
        "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED",
    ),
    (
        "Custom key expiration values are disabled.",
        "KEY_DISABLED_EXPIRATION",
    ),
    (
        "Deleting anonymous users is disabled",
        "DELETE_ANONYMOUS_USER_DISABLED",
    ),
    (
        "Device code already processed",
        "DEVICE_CODE_ALREADY_PROCESSED",
    ),
    ("Device code has expired", "EXPIRED_DEVICE_CODE"),
    (
        "Device code has not been claimed by a verifying session; call `GET /device` with the `user_code` while signed in before approving or denying",
        "DEVICE_CODE_NOT_CLAIMED",
    ),
    ("Display username is invalid", "INVALID_DISPLAY_USERNAME"),
    (
        "Dynamic Access Control requires a pre-defined ac instance on the server auth plugin. Read server logs for more information",
        "MISSING_AC_INSTANCE",
    ),
    (
        "Either userId or session is required",
        "USER_ID_OR_SESSION_REQUIRED",
    ),
    (
        "Email and password is not enabled",
        "EMAIL_PASSWORD_DISABLED",
    ),
    (
        "Email and password sign up is not enabled",
        "EMAIL_PASSWORD_SIGN_UP_DISABLED",
    ),
    ("Email can not be updated", "EMAIL_CAN_NOT_BE_UPDATED"),
    ("Email is already verified", "EMAIL_ALREADY_VERIFIED"),
    ("Email mismatch", "EMAIL_MISMATCH"),
    ("Email not verified", "EMAIL_NOT_VERIFIED"),
    (
        "Email verification required before accepting or rejecting invitation",
        "EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION",
    ),
    (
        "Email verification required to view or list invitations for the session email",
        "EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION",
    ),
    (
        "Email was not generated in a valid format",
        "INVALID_EMAIL_FORMAT",
    ),
    ("Failed to create session", "FAILED_TO_CREATE_SESSION"),
    ("Failed to create user", "FAILED_TO_CREATE_USER"),
    (
        "Failed to delete anonymous user",
        "FAILED_TO_DELETE_ANONYMOUS_USER",
    ),
    (
        "Failed to delete anonymous user sessions",
        "FAILED_TO_DELETE_ANONYMOUS_USER_SESSIONS",
    ),
    (
        "Failed to get a valid access token",
        "FAILED_TO_GET_ACCESS_TOKEN",
    ),
    ("Failed to get session", "FAILED_TO_GET_SESSION"),
    ("Failed to get user info", "FAILED_TO_GET_USER_INFO"),
    (
        "Failed to refresh access token",
        "FAILED_TO_REFRESH_ACCESS_TOKEN",
    ),
    (
        "Failed to retrieve invitation",
        "FAILED_TO_RETRIEVE_INVITATION",
    ),
    ("Failed to update API key", "FAILED_TO_UPDATE_API_KEY"),
    ("Failed to update passkey", "FAILED_TO_UPDATE_PASSKEY"),
    ("Failed to update user", "FAILED_TO_UPDATE_USER"),
    (
        "Failed to verify registration",
        "FAILED_TO_VERIFY_REGISTRATION",
    ),
    ("Field is required", "MISSING_FIELD"),
    ("Field not allowed to be set", "FIELD_NOT_ALLOWED"),
    ("Internal Server Error", "INTERNAL_SERVER_ERROR"),
    ("Invalid API key.", "INVALID_API_KEY"),
    ("Invalid OAuth configuration", "INVALID_OAUTH_CONFIGURATION"),
    ("Invalid OAuth configuration.", "INVALID_OAUTH_CONFIG"),
    (
        "Invalid OAuth configuration. Token URL not found.",
        "TOKEN_URL_NOT_FOUND",
    ),
    ("Invalid OTP", "INVALID_OTP"),
    ("Invalid backup code", "INVALID_BACKUP_CODE"),
    ("Invalid callbackURL", "INVALID_CALLBACK_URL"),
    ("Invalid code", "INVALID_CODE"),
    ("Invalid device code", "INVALID_DEVICE_CODE"),
    ("Invalid device code status", "INVALID_DEVICE_CODE_STATUS"),
    ("Invalid email", "INVALID_EMAIL"),
    ("Invalid email or password", "INVALID_EMAIL_OR_PASSWORD"),
    ("Invalid errorCallbackURL", "INVALID_ERROR_CALLBACK_URL"),
    (
        "Invalid newUserCallbackURL",
        "INVALID_NEW_USER_CALLBACK_URL",
    ),
    ("Invalid origin", "INVALID_ORIGIN"),
    ("Invalid password", "INVALID_PASSWORD"),
    ("Invalid phone number", "INVALID_PHONE_NUMBER"),
    (
        "Invalid phone number or password",
        "INVALID_PHONE_NUMBER_OR_PASSWORD",
    ),
    ("Invalid redirectURL", "INVALID_REDIRECT_URL"),
    ("Invalid role type", "INVALID_ROLE_TYPE"),
    ("Invalid token", "INVALID_TOKEN"),
    ("Invalid two factor cookie", "INVALID_TWO_FACTOR_COOKIE"),
    ("Invalid user", "INVALID_USER"),
    ("Invalid user code", "INVALID_USER_CODE"),
    (
        "Invalid username or password",
        "INVALID_USERNAME_OR_PASSWORD",
    ),
    ("Invitation limit reached", "INVITATION_LIMIT_REACHED"),
    ("Invitation not found", "INVITATION_NOT_FOUND"),
    ("Invitation not found!", "INVITATION_NOT_FOUND"),
    (
        "Inviter is no longer a member of the organization",
        "INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION",
    ),
    (
        "Linked account already exists",
        "LINKED_ACCOUNT_ALREADY_EXISTS",
    ),
    ("Member not found", "MEMBER_NOT_FOUND"),
    ("Metadata is disabled.", "METADATA_DISABLED"),
    ("Missing CAPTCHA response", "MISSING_RESPONSE"),
    ("Missing or null Origin", "MISSING_OR_NULL_ORIGIN"),
    ("Missing secret key", "MISSING_SECRET_KEY"),
    (
        "Multiple accounts share this account ID. Pass a providerId to disambiguate.",
        "AMBIGUOUS_ACCOUNT",
    ),
    ("No active organization", "NO_ACTIVE_ORGANIZATION"),
    ("No config found for provider", "PROVIDER_CONFIG_NOT_FOUND"),
    ("No data to update", "NO_DATA_TO_UPDATE"),
    (
        "No default api-key configuration found.",
        "NO_DEFAULT_API_KEY_CONFIGURATION_FOUND",
    ),
    ("No values to update.", "NO_VALUES_TO_UPDATE"),
    ("Not found", "NOT_FOUND"),
    (
        "OAuth issuer mismatch. The authorization server issuer does not match the expected value (RFC 9207).",
        "ISSUER_MISMATCH",
    ),
    (
        "OAuth issuer parameter missing. The authorization server did not include the required iss parameter (RFC 9207).",
        "ISSUER_MISSING",
    ),
    ("OTP expired", "OTP_EXPIRED"),
    ("OTP has expired", "OTP_HAS_EXPIRED"),
    ("OTP not enabled", "OTP_NOT_ENABLED"),
    ("OTP not found", "OTP_NOT_FOUND"),
    (
        "Organization ID is required for organization-owned API keys.",
        "ORGANIZATION_ID_REQUIRED",
    ),
    ("Organization already exists", "ORGANIZATION_ALREADY_EXISTS"),
    (
        "Organization deletion is disabled",
        "ORGANIZATION_DELETION_DISABLED",
    ),
    (
        "Organization membership limit reached",
        "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED",
    ),
    ("Organization not found", "ORGANIZATION_NOT_FOUND"),
    (
        "Organization plugin is required for organization-owned API keys. Please install and configure the organization plugin.",
        "ORGANIZATION_PLUGIN_REQUIRED",
    ),
    (
        "Organization slug already taken",
        "ORGANIZATION_SLUG_ALREADY_TAKEN",
    ),
    (
        "POST method requires deferSessionRefresh to be enabled in session config",
        "METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED",
    ),
    ("Passkey not found", "PASSKEY_NOT_FOUND"),
    (
        "Passkey registration requires an authenticated session",
        "SESSION_REQUIRED",
    ),
    (
        "Passkey registration requires either an authenticated session or a resolveUser callback when requireSession is false",
        "RESOLVE_USER_REQUIRED",
    ),
    (
        "Password cannot be updated through update-user. Use the set-user-password endpoint instead",
        "PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER",
    ),
    ("Password too long", "PASSWORD_TOO_LONG"),
    ("Password too short", "PASSWORD_TOO_SHORT"),
    ("Phone number already exists", "PHONE_NUMBER_EXIST"),
    (
        "Phone number cannot be updated",
        "PHONE_NUMBER_CANNOT_BE_UPDATED",
    ),
    ("Phone number not verified", "PHONE_NUMBER_NOT_VERIFIED"),
    ("Polling too frequently", "POLLING_TOO_FREQUENTLY"),
    ("Popup sign-in failed", "POPUP_SIGN_IN_FAILED"),
    ("Previously registered", "PREVIOUSLY_REGISTERED"),
    ("Provider ID is required", "PROVIDER_ID_REQUIRED"),
    ("Provider not found", "PROVIDER_NOT_FOUND"),
    ("Rate limit exceeded.", "RATE_LIMIT_EXCEEDED"),
    ("Refresh token not found", "REFRESH_TOKEN_NOT_FOUND"),
    ("Registration cancelled", "REGISTRATION_CANCELLED"),
    ("Reset password isn't enabled", "RESET_PASSWORD_DISABLED"),
    ("Resolved user is invalid", "RESOLVED_USER_INVALID"),
    ("Role not found", "ROLE_NOT_FOUND"),
    (
        "Session expired. Re-authenticate to perform this action.",
        "SESSION_EXPIRED",
    ),
    ("Session is not fresh", "SESSION_NOT_FRESH"),
    ("Session is required", "SESSION_REQUIRED"),
    ("Sign-in popup timed out", "POPUP_TIMEOUT"),
    ("Sign-in popup was blocked by the browser", "POPUP_BLOCKED"),
    ("Sign-in popup was closed before completing", "POPUP_CLOSED"),
    (
        "Social account already linked",
        "SOCIAL_ACCOUNT_ALREADY_LINKED",
    ),
    ("Something went wrong", "UNKNOWN_ERROR"),
    ("TOTP not enabled", "TOTP_NOT_ENABLED"),
    ("Team already exists", "TEAM_ALREADY_EXISTS"),
    ("Team id contains a reserved character", "INVALID_TEAM_ID"),
    ("Team member limit reached", "TEAM_MEMBER_LIMIT_REACHED"),
    ("Team not found", "TEAM_NOT_FOUND"),
    (
        "That role name is already taken",
        "ROLE_NAME_IS_ALREADY_TAKEN",
    ),
    (
        "The expiresIn is larger than the predefined maximum value.",
        "EXPIRES_IN_IS_TOO_LARGE",
    ),
    (
        "The expiresIn is smaller than the predefined minimum value.",
        "EXPIRES_IN_IS_TOO_SMALL",
    ),
    (
        "The name length is either too large or too small.",
        "INVALID_NAME_LENGTH",
    ),
    (
        "The prefix length is either too large or too small.",
        "INVALID_PREFIX_LENGTH",
    ),
    (
        "The property you're trying to set can only be set from the server auth instance only.",
        "SERVER_ONLY_PROPERTY",
    ),
    (
        "The provided permission includes an invalid resource",
        "INVALID_RESOURCE",
    ),
    (
        "The reference id from the API key is invalid.",
        "INVALID_REFERENCE_ID_FROM_API_KEY",
    ),
    (
        "The remaining count is either too large or too small.",
        "INVALID_REMAINING",
    ),
    (
        "The user id from the API key is invalid.",
        "INVALID_USER_ID_FROM_API_KEY",
    ),
    ("This organization has too many roles", "TOO_MANY_ROLES"),
    ("Token expired", "TOKEN_EXPIRED"),
    ("Too many attempts", "TOO_MANY_ATTEMPTS"),
    (
        "Too many attempts. Please request a new code.",
        "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE",
    ),
    (
        "Too many failed verification attempts. Your account is temporarily locked. Please try again later.",
        "ACCOUNT_TEMPORARILY_LOCKED",
    ),
    ("Two factor isn't enabled", "TWO_FACTOR_NOT_ENABLED"),
    ("Unable to create session", "UNABLE_TO_CREATE_SESSION"),
    (
        "Unable to create verification",
        "FAILED_TO_CREATE_VERIFICATION",
    ),
    ("Unable to remove last team", "UNABLE_TO_REMOVE_LAST_TEAM"),
    ("Unauthorized", "UNAUTHORIZED"),
    ("Unauthorized or invalid session", "UNAUTHORIZED_SESSION"),
    ("Unexpected error", "UNEXPECTED_ERROR"),
    ("Unknown error", "UNKNOWN_ERROR"),
    ("User already exists.", "USER_ALREADY_EXISTS"),
    (
        "User already exists. Use another email.",
        "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
    ),
    ("User already has a password set", "PASSWORD_ALREADY_SET"),
    (
        "User already has a password. Provide that to delete the account.",
        "USER_ALREADY_HAS_PASSWORD",
    ),
    ("User code has expired", "EXPIRED_USER_CODE"),
    ("User email not found", "USER_EMAIL_NOT_FOUND"),
    (
        "User is already a member of this organization",
        "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION",
    ),
    (
        "User is already invited to this organization",
        "USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION",
    ),
    ("User is banned", "USER_BANNED"),
    (
        "User is not a member of the organization",
        "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
    ),
    (
        "User is not a member of the team",
        "USER_IS_NOT_A_MEMBER_OF_THE_TEAM",
    ),
    ("User is not anonymous", "USER_IS_NOT_ANONYMOUS"),
    ("User not found", "USER_NOT_FOUND"),
    (
        "Username is already taken. Please try another.",
        "USERNAME_IS_ALREADY_TAKEN",
    ),
    ("Username is invalid", "INVALID_USERNAME"),
    ("Username is too long", "USERNAME_TOO_LONG"),
    ("Username is too short", "USERNAME_TOO_SHORT"),
    ("Validation Error", "VALIDATION_ERROR"),
    (
        "Verification email isn't enabled",
        "VERIFICATION_EMAIL_NOT_ENABLED",
    ),
    (
        "You are not a member of the organization that owns this API key.",
        "USER_NOT_MEMBER_OF_ORGANIZATION",
    ),
    (
        "You are not a member of this organization",
        "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
    ),
    (
        "You are not allowed to access this organization as an owner",
        "YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION",
    ),
    (
        "You are not allowed to ban users",
        "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS",
    ),
    (
        "You are not allowed to cancel this invitation",
        "YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION",
    ),
    (
        "You are not allowed to change users role",
        "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE",
    ),
    (
        "You are not allowed to create a new member",
        "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM_MEMBER",
    ),
    (
        "You are not allowed to create a new organization",
        "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION",
    ),
    (
        "You are not allowed to create a new team",
        "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM",
    ),
    (
        "You are not allowed to create a role",
        "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE",
    ),
    (
        "You are not allowed to create teams in this organization",
        "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION",
    ),
    (
        "You are not allowed to create users",
        "YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS",
    ),
    (
        "You are not allowed to delete a role",
        "YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE",
    ),
    (
        "You are not allowed to delete teams in this organization",
        "YOU_ARE_NOT_ALLOWED_TO_DELETE_TEAMS_IN_THIS_ORGANIZATION",
    ),
    (
        "You are not allowed to delete this member",
        "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER",
    ),
    (
        "You are not allowed to delete this organization",
        "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION",
    ),
    (
        "You are not allowed to delete this team",
        "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM",
    ),
    (
        "You are not allowed to delete users",
        "YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS",
    ),
    (
        "You are not allowed to get a role",
        "YOU_ARE_NOT_ALLOWED_TO_GET_A_ROLE",
    ),
    (
        "You are not allowed to get user",
        "YOU_ARE_NOT_ALLOWED_TO_GET_USER",
    ),
    (
        "You are not allowed to impersonate users",
        "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS",
    ),
    (
        "You are not allowed to invite a user with this role",
        "YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE",
    ),
    (
        "You are not allowed to invite users to this organization",
        "YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION",
    ),
    (
        "You are not allowed to list a role",
        "YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE",
    ),
    (
        "You are not allowed to list the members of this team",
        "YOU_CAN_NOT_ACCESS_THE_MEMBERS_OF_THIS_TEAM",
    ),
    (
        "You are not allowed to list users",
        "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS",
    ),
    (
        "You are not allowed to list users sessions",
        "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS",
    ),
    (
        "You are not allowed to read a role",
        "YOU_ARE_NOT_ALLOWED_TO_READ_A_ROLE",
    ),
    (
        "You are not allowed to register this passkey",
        "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY",
    ),
    (
        "You are not allowed to remove a team member",
        "YOU_ARE_NOT_ALLOWED_TO_REMOVE_A_TEAM_MEMBER",
    ),
    (
        "You are not allowed to revoke users sessions",
        "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS",
    ),
    (
        "You are not allowed to set a non-existent role value",
        "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE",
    ),
    (
        "You are not allowed to set users password",
        "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD",
    ),
    (
        "You are not allowed to update a role",
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE",
    ),
    (
        "You are not allowed to update this member",
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER",
    ),
    (
        "You are not allowed to update this organization",
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION",
    ),
    (
        "You are not allowed to update this team",
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM",
    ),
    (
        "You are not allowed to update users",
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS",
    ),
    (
        "You are not allowed to update users email",
        "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_EMAIL",
    ),
    (
        "You are not the recipient of the invitation",
        "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION",
    ),
    (
        "You can't unlink your last account",
        "FAILED_TO_UNLINK_LAST_ACCOUNT",
    ),
    ("You cannot ban yourself", "YOU_CANNOT_BAN_YOURSELF"),
    (
        "You cannot impersonate admins",
        "YOU_CANNOT_IMPERSONATE_ADMINS",
    ),
    (
        "You cannot leave the organization as the only owner",
        "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER",
    ),
    (
        "You cannot leave the organization without an owner",
        "YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER",
    ),
    ("You cannot remove yourself", "YOU_CANNOT_REMOVE_YOURSELF"),
    (
        "You do not have an active team",
        "YOU_DO_NOT_HAVE_AN_ACTIVE_TEAM",
    ),
    (
        "You do not have permission to perform this action on organization API keys.",
        "INSUFFICIENT_API_KEY_PERMISSIONS",
    ),
    ("You have been banned from this application", "BANNED_USER"),
    (
        "You have reached the maximum number of organizations",
        "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS",
    ),
    (
        "You have reached the maximum number of teams",
        "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS",
    ),
    (
        "You must be in an organization to create a role",
        "YOU_MUST_BE_IN_AN_ORGANIZATION_TO_CREATE_A_ROLE",
    ),
    ("callbackURL is required", "CALLBACK_URL_REQUIRED"),
    ("failed to create session", "FAILED_TO_CREATE_SESSION"),
    ("id_token not supported", "ID_TOKEN_NOT_SUPPORTED"),
    (
        "metadata must be an object or undefined",
        "INVALID_METADATA_TYPE",
    ),
    ("otp isn't configured", "OTP_NOT_CONFIGURED"),
    ("phone number isn't registered", "PHONE_NUMBER_NOT_EXIST"),
    (
        "refillAmount is required when refillInterval is provided",
        "REFILL_AMOUNT_AND_INTERVAL_REQUIRED",
    ),
    (
        "refillInterval is required when refillAmount is provided",
        "REFILL_INTERVAL_AND_AMOUNT_REQUIRED",
    ),
    ("sendOTP not implemented", "SEND_OTP_NOT_IMPLEMENTED"),
    ("totp isn't configured", "TOTP_NOT_CONFIGURED"),
];

/// Convert `validator::ValidationErrors` into a standardized error response body.
///
/// Returns a 400 response with `{ "code": "VALIDATION_ERROR", "message": "[body.field] ..." }`
/// matching the TS better-auth error shape.
#[must_use]
pub fn validation_error_response(
    errors: &validator::ValidationErrors,
) -> crate::types::AuthResponse {
    // Build a TS-compatible message: "[body.field] message; [body.field2] message2"
    let messages: Vec<String> = errors
        .field_errors()
        .into_iter()
        .flat_map(|(field, errs)| {
            errs.iter().map(move |e| {
                let msg = e
                    .message
                    .as_ref()
                    .map_or_else(|| format!("Invalid value for {field}"), ToString::to_string);
                format!("[body.{field}] {msg}")
            })
        })
        .collect();
    let message = messages.join("; ");

    let body = crate::types::ErrorCodeMessageResponse {
        code: Some("VALIDATION_ERROR".to_owned()),
        message,
    };

    // Validation errors return 400 (not 422) per the TS spec
    crate::types::AuthResponse::json(400, &body)
        .unwrap_or_else(|_| crate::types::AuthResponse::text(400, "Validation failed"))
}

/// Validate a request body, returning a parsed + validated value or an error response.
///
/// # Errors
///
/// Returns an error response if the request body is missing, malformed, or fails validation.
pub fn validate_request_body<T>(
    req: &crate::types::AuthRequest,
) -> Result<T, crate::types::AuthResponse>
where
    T: serde::de::DeserializeOwned + validator::Validate + 'static,
{
    let value: T = req.body_as_json().map_err(|e| {
        let message = format!("Invalid JSON: {e}");
        let code = AuthError::code_from_message(&message);
        crate::types::AuthResponse::json(
            400,
            &crate::types::ErrorCodeMessageResponse { code, message },
        )
        .unwrap_or_else(|_| crate::types::AuthResponse::text(400, "Invalid JSON"))
    })?;

    value
        .validate()
        .map_err(|e| validation_error_response(&e))?;

    Ok(value)
}

fn upstream_code(message: &str) -> Option<&'static str> {
    UPSTREAM_ERROR_CODES
        .binary_search_by_key(&message, |(candidate, _)| candidate)
        .ok()
        .and_then(|index| UPSTREAM_ERROR_CODES.get(index))
        .map(|(_, code)| *code)
}
