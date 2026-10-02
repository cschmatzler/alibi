//! Shared utility modules for `better-auth-core`.

pub mod cookie_utils;
pub mod password;
pub mod sessions;
pub mod username;

pub mod datetime;

pub mod id;
pub mod javascript;
pub mod json;
/// Normalize a user identity email to the canonical persisted form.
pub(crate) fn normalize_user_email(email: &str) -> String {
    email.to_lowercase()
}
