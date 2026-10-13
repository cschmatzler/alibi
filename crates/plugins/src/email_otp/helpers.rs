use alibi_core::AuthError;
use alibi_core::error::codes;

pub(super) const fn invalid_otp() -> AuthError {
    AuthError::Upstream {
        status: 400,
        code: codes::INVALID_OTP,
        message: "Invalid OTP",
    }
}

pub(super) const fn expired_otp() -> AuthError {
    AuthError::Upstream {
        status: 400,
        code: codes::OTP_EXPIRED,
        message: "OTP expired",
    }
}

pub(super) const fn too_many_attempts() -> AuthError {
    AuthError::Upstream {
        status: 403,
        code: codes::TOO_MANY_ATTEMPTS,
        message: "Too many attempts",
    }
}

pub(super) const fn user_not_found() -> AuthError {
    AuthError::Upstream {
        status: 400,
        code: codes::USER_NOT_FOUND,
        message: "User not found",
    }
}
