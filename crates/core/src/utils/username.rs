//! Shared username normalization and validation helpers.

mod policy;
pub use policy::{
    UsernameConfig, UsernameNormalization, UsernameNormalizer, UsernameValidationOrder,
    UsernameValidator,
};

pub const USERNAME_MIN_LENGTH: usize = 3;
pub const USERNAME_MAX_LENGTH: usize = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsernameValidationError {
    TooShort,
    TooLong,
    Invalid,
}

#[must_use]
pub fn normalize_username(username: &str) -> String {
    username.to_lowercase()
}

/// # Errors
///
/// Returns an error if the username fails the configured length or character validation.
pub fn validate_username(username: &str) -> Result<(), UsernameValidationError> {
    let length = username.encode_utf16().count();
    if length < USERNAME_MIN_LENGTH {
        Err(UsernameValidationError::TooShort)
    } else if length > USERNAME_MAX_LENGTH {
        Err(UsernameValidationError::TooLong)
    } else if valid_default_characters(username) {
        Ok(())
    } else {
        Err(UsernameValidationError::Invalid)
    }
}

#[must_use]
pub fn normalize_username_fields(
    username: Option<String>,
    display_username: Option<String>,
) -> (Option<String>, Option<String>) {
    let display_username = display_username.or_else(|| username.clone());
    let username = username
        .or_else(|| display_username.clone())
        .map(|username| normalize_username(&username));
    (username, display_username)
}

fn valid_default_characters(username: &str) -> bool {
    username
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '.')
}
impl UsernameValidationError {
    #[must_use]
    pub const fn auth_error(self, status: u16) -> crate::AuthError {
        let (code, message) = match self {
            Self::TooShort => ("USERNAME_TOO_SHORT", "Username is too short"),
            Self::TooLong => ("USERNAME_TOO_LONG", "Username is too long"),
            Self::Invalid => ("INVALID_USERNAME", "Username is invalid"),
        };
        crate::AuthError::Upstream {
            status,
            code,
            message,
        }
    }
}
