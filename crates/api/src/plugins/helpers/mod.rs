//! Shared helpers for plugin implementations.
//!
//! Extracted to avoid duplicating common patterns across plugins (DRY).
mod api_key_authorization;
mod credentials;
mod sessions;

use alibi_core::entity::{AuthAccount, AuthUser};
use alibi_core::{AuthContext, AuthError, AuthRequest, AuthResult, CreateUser, UpdateUser};
pub use api_key_authorization::get_owned_api_key;
pub use api_key_authorization::require_org_api_key_permission;
pub use credentials::get_credential_account;
pub use credentials::get_credential_password_hash;
pub use credentials::user_has_password;
pub use sessions::admin_banned_user_message;
pub use sessions::admin_plugin_enabled;
pub(in crate::plugins) use sessions::completed_response_session;
pub(in crate::plugins) use sessions::create_user_session_record;
pub use sessions::delete_session_cookie_headers;
pub use sessions::expires_in_to_at;
pub use sessions::get_cookie;
pub(in crate::plugins) use sessions::issue_selected_user_session_record;
pub use sessions::issue_user_session;
pub use sessions::issue_user_session_record;
pub use sessions::issue_user_session_with_fields;
pub use sessions::issue_user_session_with_fields_record;
pub use sessions::issue_user_session_with_overrides;
pub use sessions::issue_user_session_with_overrides_record;
pub(in crate::plugins) use sessions::ordinary_session;
pub(in crate::plugins) use sessions::record_completed_session;
pub(in crate::plugins) use sessions::record_completed_session_record;
pub(in crate::plugins) use sessions::record_completed_session_user_view;
pub(in crate::plugins) use sessions::response_has_session_cookie;
pub use sessions::response_session;

/// Join the configured auth origin and mount path for links sent to users.
pub(in crate::plugins) fn auth_base_url(config: &alibi_core::AuthConfig) -> String {
    let origin = config.base_url.trim_end_matches('/');
    let path = config.base_path.trim_matches('/');
    if path.is_empty() {
        origin.to_owned()
    } else {
        format!("{origin}/{path}")
    }
}
use chrono::Utc;

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
pub(in crate::plugins) struct CompletedSession<S: alibi_core::AuthSchema> {
    pub(in crate::plugins) user: S::User,
    pub(in crate::plugins) session: S::Session,
    pub(in crate::plugins) user_view: Option<alibi_core::wire::UserView>,
    user_record: Option<alibi_core::AdapterRecord<S::User>>,
    session_record: Option<alibi_core::AdapterRecord<S::Session>>,
}
impl<S: alibi_core::AuthSchema> CompletedSession<S> {
    pub(in crate::plugins) fn callback_user(&self, ctx: &AuthContext<S>) -> alibi_core::UserView {
        self.user_view.clone().unwrap_or_else(|| {
            self.user_record.as_ref().map_or_else(
                || ctx.trusted_user_view(&self.user),
                |record| ctx.trusted_user_view(record),
            )
        })
    }
    pub(in crate::plugins) fn callback_session(
        &self,
        ctx: &AuthContext<S>,
    ) -> alibi_core::SessionView {
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
