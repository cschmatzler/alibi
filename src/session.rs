//! Session issuance and signed cookies for custom sign-in flows.
//!
//! After your application verifies its sign-in proof and resolves the user ID,
//! issue the session through the initialized auth instance. Issuance applies
//! configured session hooks and the admin plugin's ban policy.
//!
//! ```
//! use alibi::prelude::AuthSession;
//! use alibi::session::{
//!     IssuedSession, SessionIssueError, create_session_cookie, issue_user_session,
//! };
//! use alibi::{AuthError, AuthResult, AuthSchema, BetterAuth};
//!
//! async fn sign_in_verified_user<S: AuthSchema>(
//!     auth: &BetterAuth<S>,
//!     user_id: &str,
//! ) -> AuthResult<(IssuedSession<S>, String)> {
//!     let issued = match issue_user_session(auth.context(), user_id, None, None).await {
//!         Ok(issued) => issued,
//!         Err(SessionIssueError::Banned { message }) => {
//!             return Err(AuthError::banned_user(message));
//!         }
//!         Err(SessionIssueError::Auth(error)) => return Err(error),
//!     };
//!     let cookie = create_session_cookie(issued.session.token(), auth.config())?;
//!     Ok((issued, cookie))
//! }
//! ```
//!
//! Deliver the returned cookie as a `Set-Cookie` response header. The optional
//! IP address and user agent arguments to [`issue_user_session`] populate session
//! metadata. [`create_session_cookie`] uses the configured name, signing secret,
//! lifetime and cookie attributes.
//!
//! To select an organization during the initial insert, use
//! [`issue_user_session_with_fields`] after verifying access to that organization:
//!
//! ```
//! use alibi::session::{SessionIssueError, SessionOverrides, issue_user_session_with_fields};
//! use alibi::{AuthSchema, BetterAuth};
//!
//! async fn sign_in_to_organization<S: AuthSchema>(
//!     auth: &BetterAuth<S>, user_id: &str, organization_id: &str,
//! ) -> Result<(), SessionIssueError> {
//!     let issued = issue_user_session_with_fields(
//!         auth.context(), user_id, None, None,
//!         SessionOverrides {
//!             active_organization_id: Some(organization_id.to_owned()),
//!             ..Default::default()
//!         },
//!     ).await?;
//!     // Deliver a signed cookie using `issued.session`, as above.
//!     Ok(())
//! }
//! ```
//!
//! Overrides also support active teams, impersonation, and configured additional
//! fields. Creation hooks see these fields and can transform or reject them;
//! the returned session contains the final stored values. For callbacks that
//! need retained adapter output, use [`issue_user_session_with_fields_record`].

pub use alibi_core::session::*;
pub use alibi_core::utils::cookie_utils::create_session_cookie;
pub use alibi_plugins::helpers::{
    IssuedSession, IssuedSessionRecord, SessionIssueError, SessionOverrides, issue_user_session,
    issue_user_session_record, issue_user_session_with_fields,
    issue_user_session_with_fields_record, issue_user_session_with_overrides,
    issue_user_session_with_overrides_record,
};
