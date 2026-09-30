use better_auth_core::AuthError;

pub(super) fn invalid_otp() -> AuthError {
    AuthError::Upstream {
        status: 400,
        code: "INVALID_OTP",
        message: "Invalid OTP",
    }
}

pub(super) fn expired_otp() -> AuthError {
    AuthError::Upstream {
        status: 400,
        code: "OTP_EXPIRED",
        message: "OTP expired",
    }
}

pub(super) fn too_many_attempts() -> AuthError {
    AuthError::Upstream {
        status: 403,
        code: "TOO_MANY_ATTEMPTS",
        message: "Too many attempts",
    }
}

pub(super) fn user_not_found() -> AuthError {
    AuthError::Upstream {
        status: 400,
        code: "USER_NOT_FOUND",
        message: "User not found",
    }
}
