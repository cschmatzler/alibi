//! Shared helpers for plugin implementations.
mod api_key_authorization;
mod credentials;
mod sessions;

use alibi_core::{AuthContext, AuthError, CreateUser};
pub use api_key_authorization::{get_owned_api_key, require_org_api_key_permission};
pub use credentials::{get_credential_account, get_credential_password_hash, user_has_password};
pub use sessions::{
    admin_banned_user_message, admin_plugin_enabled, delete_session_cookie_headers,
    expires_in_to_at, get_cookie, issue_user_session, issue_user_session_record,
    issue_user_session_with_fields, issue_user_session_with_fields_record,
    issue_user_session_with_overrides, issue_user_session_with_overrides_record, response_session,
};
pub(crate) use sessions::{
    completed_response_session, create_user_session_record, issue_selected_user_session_record,
    ordinary_session, record_completed_session, record_completed_session_record,
    record_completed_session_user_view, response_has_session_cookie,
};

/// Join the configured auth origin and mount path for links sent to users.
pub(crate) fn auth_base_url(config: &alibi_core::AuthConfig) -> String {
    let origin = config.base_url.trim_end_matches('/');
    let path = config.base_path.trim_matches('/');
    if path.is_empty() {
        origin.to_owned()
    } else {
        format!("{origin}/{path}")
    }
}

/// Wrap an ordinary application callback failure as an empty HTTP 500; explicit
/// API errors keep their public status and body.
pub(crate) fn callback_failure(error: AuthError) -> AuthError {
    if matches!(
        error,
        AuthError::Api { .. } | AuthError::Upstream { .. } | AuthError::CallbackFailure(_)
    ) {
        error
    } else {
        AuthError::CallbackFailure(Box::new(error))
    }
}

/// The documented 401 for a request without an authenticated session.
pub(crate) const fn unauthorized() -> AuthError {
    AuthError::Upstream {
        status: 401,
        code: "UNAUTHORIZED",
        message: "Unauthorized",
    }
}

/// Map a missing session to the documented 401, passing other errors through.
pub(crate) fn unauthorized_if_unauthenticated(error: AuthError) -> AuthError {
    if matches!(error, AuthError::Unauthenticated) {
        unauthorized()
    } else {
        error
    }
}

/// Like [`unauthorized_if_unauthenticated`], also for a session or user that
/// no longer exists.
pub(crate) fn unauthorized_if_session_missing(error: AuthError) -> AuthError {
    if matches!(
        error,
        AuthError::Unauthenticated | AuthError::SessionNotFound | AuthError::UserNotFound
    ) {
        unauthorized()
    } else {
        error
    }
}

/// Result of issuing a real session for a user.
pub struct IssuedSession<S: alibi_core::AuthSchema> {
    pub user: S::User,
    pub session: S::Session,
}

/// Actual session issuance with retained adapter output for framework callbacks
/// and separately filtered public responses.
pub struct IssuedSessionRecord<S: alibi_core::AuthSchema> {
    pub user: alibi_core::AdapterRecord<S::User>,
    pub session: alibi_core::AdapterRecord<S::Session>,
}
impl<S: alibi_core::AuthSchema> IssuedSessionRecord<S> {
    fn into_stored(self) -> IssuedSession<S> {
        IssuedSession {
            user: self.user.into_stored(),
            session: self.session.into_stored(),
        }
    }
}

/// Original rows used by the handler that issued the completed session.
/// This is a callback observation; authorization still uses a current session read.
pub(crate) struct CompletedSession<S: alibi_core::AuthSchema> {
    pub(crate) user: S::User,
    pub(crate) session: S::Session,
    pub(crate) user_view: Option<alibi_core::wire::UserView>,
    user_record: Option<alibi_core::AdapterRecord<S::User>>,
    session_record: Option<alibi_core::AdapterRecord<S::Session>>,
}
impl<S: alibi_core::AuthSchema> CompletedSession<S> {
    pub(crate) fn callback_user(&self, ctx: &AuthContext<S>) -> alibi_core::UserView {
        self.user_view.clone().unwrap_or_else(|| {
            self.user_record.as_ref().map_or_else(
                || ctx.trusted_user_view(&self.user),
                |record| ctx.trusted_user_view(record),
            )
        })
    }
    pub(crate) fn callback_session(&self, ctx: &AuthContext<S>) -> alibi_core::SessionView {
        self.session_record.as_ref().map_or_else(
            || ctx.trusted_session_view(&self.session),
            |record| ctx.trusted_session_view(record),
        )
    }
}

/// Session issuance failures that callers may need to surface differently from
/// a generic auth error (for example OAuth callback redirects).
#[derive(Debug)]
pub enum SessionIssueError {
    Auth(AuthError),
    Banned { message: String },
}

impl SessionIssueError {
    #[must_use]
    pub fn into_auth_error(self) -> AuthError {
        match self {
            Self::Auth(error) => error,
            Self::Banned { message } => AuthError::banned_user(message),
        }
    }

    #[must_use]
    pub const fn banned_message(&self) -> Option<&str> {
        match self {
            Self::Banned { message } => Some(message.as_str()),
            Self::Auth(_) => None,
        }
    }
}

impl From<AuthError> for SessionIssueError {
    fn from(value: AuthError) -> Self {
        Self::Auth(value)
    }
}

/// Trusted fields for the initial session insert in a custom sign-in flow.
///
/// These values pass through configured field policies and session creation
/// hooks. Use only after authenticating the user and authorizing the requested
/// organization, team, or impersonation; issuance does not check membership.
/// The issuer owns the session token, user ID, and expiry.
#[derive(Clone, Debug, Default)]
pub struct SessionOverrides {
    /// Application-defined session fields declared by the schema and configuration.
    pub additional_fields: alibi_core::field_policy::FieldValues,
    /// The trusted administrator responsible for impersonation, if any.
    pub impersonated_by: Option<String>,
    /// The organization selected by the application for this session.
    pub active_organization_id: Option<String>,
    /// The team selected by the application for this session.
    pub active_team_id: Option<String>,
}

impl<S: alibi_core::AuthSchema> std::fmt::Debug for IssuedSession<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedSession").finish_non_exhaustive()
    }
}

/// Apply the configured default admin role to a new user when the caller
/// didn't set an explicit role.
pub fn apply_default_role(
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
    create_user: &mut CreateUser,
) {
    // The registered admin create transform runs after identity validation.
    // Preserve that ordering for policy-enabled instances.
    if ctx.config.user_validation.is_some() || create_user.role.is_some() {
        return;
    }

    if let Some(default_role) = ctx
        .get_metadata("admin.default_role")
        .and_then(|value| value.as_str())
    {
        create_user.role = Some(default_role.to_owned());
    }
}
