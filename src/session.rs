//! Session issuance and signed cookies for custom sign-in flows.
//!
//! After your application verifies its sign-in proof and resolves the user ID,
//! issue the session through the initialized auth instance. Issuance applies
//! configured session hooks and the admin plugin's ban policy.
//!
//! ```
//! use better_auth::prelude::AuthSession;
//! use better_auth::session::{
//!     IssuedSession, SessionIssueError, create_session_cookie, issue_user_session,
//! };
//! use better_auth::{AuthError, AuthResult, AuthSchema, BetterAuth};
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

pub use better_auth_api::plugins::helpers::{IssuedSession, SessionIssueError, issue_user_session};
pub use better_auth_core::utils::cookie_utils::create_session_cookie;
