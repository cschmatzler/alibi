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

///
/// # Errors
///
/// Returns an error if the username fails the configured length or character validation.
pub fn validate_username(username: &str) -> Result<(), UsernameValidationError> {
    if username.encode_utf16().count() < USERNAME_MIN_LENGTH {
        return Err(UsernameValidationError::TooShort);
    }

    if username.encode_utf16().count() > USERNAME_MAX_LENGTH {
        return Err(UsernameValidationError::TooLong);
    }

    if valid_default_characters(username) {
        Ok(())
    } else {
        Err(UsernameValidationError::Invalid)
    }
}

#[must_use]
pub fn normalize_username_fields(
    mut username: Option<String>,
    mut display_username: Option<String>,
) -> (Option<String>, Option<String>) {
    if username.is_some() && display_username.is_none() {
        display_username.clone_from(&username);
    }

    if display_username.is_some() && username.is_none() {
        username.clone_from(&display_username);
    }

    if let Some(username_value) = username.as_mut() {
        *username_value = normalize_username(username_value);
    }

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
