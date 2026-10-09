//! Backend-neutral pieces shared by the bundled persistence adapters.
//!
//! Everything here is independent of the driver: hook sequencing after a
//! committed transaction, the error a vetoing hook produces, raw configured
//! field values, and timestamp parsing for string-dated plugin rows.

use crate::error::{AuthError, AuthResult};
use crate::schema::AuthSchema;
use crate::store::{DatabaseHookContext, DatabaseHooks, HookBackend};
use crate::utils::json::JsValue;
use crate::verification::VerificationSnapshot;
use chrono::{DateTime, Utc};
use std::sync::Arc;

/// The error returned when a `before_*` hook cancels an operation.
#[must_use]
pub fn cancelled_by_hook(operation: &str) -> AuthError {
    AuthError::forbidden(format!("{operation} cancelled by database hook"))
}

/// Preserve an ordinary application callback exception as an empty HTTP 500.
/// Explicit API errors retain their public status and body.
#[must_use]
pub fn callback_error(error: AuthError) -> AuthError {
    match error {
        AuthError::Internal(_) => AuthError::CallbackFailure(Box::new(error)),
        other => other,
    }
}

/// Parse an RFC 3339 timestamp of a string-dated plugin field.
///
/// # Errors
///
/// Returns a bad-request error naming `field` when the text is not RFC 3339.
pub fn parse_rfc3339(value: &str, field: &str) -> AuthResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| AuthError::bad_request(format!("Invalid RFC 3339 timestamp for {field}")))
}

/// [`parse_rfc3339`] over an optional value.
///
/// # Errors
///
/// Returns a bad-request error naming `field` when the text is not RFC 3339.
pub fn parse_optional_rfc3339(
    value: Option<&str>,
    field: &str,
) -> AuthResult<Option<DateTime<Utc>>> {
    value.map(|inner| parse_rfc3339(inner, field)).transpose()
}

/// An after-hook deferred until the enclosing auth transaction commits.
pub enum AfterHook<S: AuthSchema> {
    UserCreated(S::User),
    AccountCreated(S::Account),
    SessionCreated(S::Session),
    SessionUpdated(S::Session),
    SessionUpdateMissing(String),
    VerificationCreated(S::Verification),
    VerificationRecordCreated(VerificationSnapshot),
}

impl<S: AuthSchema> AfterHook<S> {
    /// Invoke the matching callback on one hook.
    ///
    /// # Errors
    ///
    /// Returns the hook's error.
    pub async fn dispatch<B: HookBackend>(
        &self,
        hook: &dyn DatabaseHooks<S, B>,
        ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        match self {
            Self::UserCreated(user) => hook.after_create_user(user, ctx).await,
            Self::AccountCreated(account) => hook.after_create_account(account, ctx).await,
            Self::SessionCreated(session) => hook
                .after_create_session(session, ctx)
                .await
                .map_err(callback_error),
            Self::SessionUpdated(session) => hook.after_update_session(session, ctx).await,
            Self::SessionUpdateMissing(token) => {
                hook.after_update_session_missing(token, ctx).await
            }
            Self::VerificationCreated(verification) => {
                hook.after_create_verification(verification, ctx).await
            }
            Self::VerificationRecordCreated(snapshot) => {
                hook.after_create_verification_record(snapshot, ctx).await
            }
        }
    }
}

/// After-hooks recorded by writes inside an auth transaction.
///
/// Rollback drops the queue. After commit, [`run`](Self::run) replays every
/// event in operation order, invoking each registered hook per event; a hook
/// error is returned to the caller after the auth writes have committed.
pub struct AfterHookQueue<S: AuthSchema>(tokio::sync::Mutex<Vec<AfterHook<S>>>);

impl<S: AuthSchema> Default for AfterHookQueue<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: AuthSchema> AfterHookQueue<S> {
    #[must_use]
    pub const fn new() -> Self {
        Self(tokio::sync::Mutex::const_new(Vec::new()))
    }

    pub async fn push(&self, event: AfterHook<S>) {
        self.0.lock().await.push(event);
    }

    /// Run every queued event against `hooks`, in order.
    ///
    /// # Errors
    ///
    /// Returns the first hook error.
    pub async fn run<B: HookBackend>(
        self,
        hooks: &[Arc<dyn DatabaseHooks<S, B>>],
        ctx: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<()> {
        for event in self.0.into_inner() {
            for hook in hooks {
                event.dispatch(hook.as_ref(), ctx).await?;
            }
        }
        Ok(())
    }
}

/// A configured additional-field value before backend coercion.
///
/// JavaScript numbers that are finite integers within `i64` range bind as
/// integers so SQLite keeps INTEGER affinity; `-0` and fractions stay doubles.
#[derive(Clone, Debug, PartialEq)]
pub enum RawFieldValue {
    Null,
    Bool(bool),
    Integer(i64),
    Number(f64),
    Text(String),
    Json(serde_json::Value),
}

impl RawFieldValue {
    /// # Errors
    ///
    /// Returns an error if an object or array cannot be serialized as JSON.
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        reason = "the range guard above makes the integer coercion exact"
    )]
    pub fn from_js(value: &JsValue) -> Result<Self, serde_json::Error> {
        Ok(match value {
            JsValue::Null => Self::Null,
            JsValue::Bool(value) => Self::Bool(*value),
            JsValue::Number(value)
                if value.is_finite()
                    && value.fract() == 0.0
                    && !(*value == 0.0 && value.is_sign_negative())
                    && (-9_223_372_036_854_776_000.0..9_223_372_036_854_776_000.0)
                        .contains(value) =>
            {
                Self::Integer(*value as i64)
            }
            JsValue::Number(value) => Self::Number(*value),
            JsValue::String(value) => Self::Text(value.clone()),
            JsValue::Array(_) | JsValue::Object(_) => Self::Json(value.to_json_value()?),
        })
    }
}
