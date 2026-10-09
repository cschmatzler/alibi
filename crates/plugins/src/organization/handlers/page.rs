//! Only these adapter-page handlers map actual SQL/join failures to Source's empty500.
use alibi_core::{AuthError, AuthResponse, AuthResult};
#[derive(Debug)]
pub(crate) enum OrganizationPageError {
    Auth(AuthError),
    MissingUser,
}
impl From<AuthError> for OrganizationPageError {
    fn from(value: AuthError) -> Self {
        Self::Auth(value)
    }
}
impl OrganizationPageError {
    pub(super) fn response(self) -> AuthResult<AuthResponse> {
        match self {
            Self::MissingUser | Self::Auth(AuthError::Database(_)) => Ok(AuthResponse::new(500)),
            Self::Auth(error) => Err(error),
        }
    }
}

impl From<OrganizationPageError> for AuthError {
    fn from(error: OrganizationPageError) -> Self {
        match error {
            OrganizationPageError::Auth(error) => error,
            OrganizationPageError::MissingUser => {
                Self::internal("Organization member user not found")
            }
        }
    }
}
