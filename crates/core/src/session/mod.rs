#[cfg(test)]
mod tests;

use chrono::Utc;

use std::sync::Arc;

use crate::config::AuthConfig;

use crate::entity::{AuthSession, AuthUser};

use crate::error::AuthResult;

use crate::schema::AuthSchema;

use crate::store::AuthStore;

use crate::types::CreateSession;

/// Controls whether a persistent session read may write to its store.
#[derive(Debug, Clone, Copy)]
pub struct SessionReadOptions {
    pub allow_refresh: bool,
    pub cleanup_expired: bool,
}

impl Default for SessionReadOptions {
    fn default() -> Self {
        Self {
            allow_refresh: true,
            cleanup_expired: true,
        }
    }
}

/// The persisted result and refresh state of a session read.
pub struct SessionRead<T> {
    pub session: Option<T>,
    pub needs_refresh: bool,
    pub refreshed: bool,
}

/// Session manager handles session creation, validation, and cleanup
pub struct SessionManager<S: AuthSchema> {
    config: Arc<AuthConfig>,
    database: Arc<dyn AuthStore<S>>,
}

impl<S: AuthSchema> Clone for SessionManager<S> {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            database: Arc::clone(&self.database),
        }
    }
}

impl<S: AuthSchema> SessionManager<S> {
    #[must_use]
    pub fn new(config: Arc<AuthConfig>, database: Arc<dyn AuthStore<S>>) -> Self {
        Self { config, database }
    }

    /// Create a new session for a user
    ///
    /// # Errors
    ///
    /// Propagates errors from session hooks or persistence.
    pub async fn create_session(
        &self,
        user: &impl AuthUser,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> AuthResult<S::Session> {
        let expires_at = Utc::now() + self.config.session.expires_in;

        let create_session = CreateSession {
            additional_fields: crate::field_policy::FieldValues::default(),
            token: None,
            active_team_id: None,
            user_id: user.id().to_string(),
            expires_at,
            ip_address,
            user_agent,
            impersonated_by: None,
            active_organization_id: None,
        };

        let session = self.database.create_session(create_session).await?;
        Ok(session)
    }

    /// Read and refresh a session according to the configured expiry window.
    ///
    /// # Errors
    ///
    /// Propagates errors from the session store.
    pub async fn get_session(&self, token: &str) -> AuthResult<Option<S::Session>> {
        Ok(self
            .read_session(token, SessionReadOptions::default())
            .await?
            .session)
    }

    /// Read persisted session state with explicit control over side effects.
    /// Deferred browser reads leave expired rows in place until a later write.
    ///
    /// # Errors
    ///
    /// Propagates errors from the session store.
    pub async fn read_session(
        &self,
        token: &str,
        options: SessionReadOptions,
    ) -> AuthResult<SessionRead<S::Session>> {
        let Some(session) = self.database.get_session(token).await? else {
            return Ok(SessionRead {
                session: None,
                needs_refresh: false,
                refreshed: false,
            });
        };
        self.read_loaded_session(session, options).await
    }

    /// Apply the session lifecycle to a snapshot already read from this store.
    /// Session handlers use this to retain their original hook context without
    /// looking up the session a second time. Validation and refresh still run.
    /// The supplied snapshot must come from this manager's store, never client input.
    ///
    /// # Errors
    ///
    /// Propagates errors from the session store.
    pub async fn read_loaded_session(
        &self,
        session: S::Session,
        options: SessionReadOptions,
    ) -> AuthResult<SessionRead<S::Session>> {
        let token = session.token();
        let now = Utc::now();
        if session.expires_at() < now || !session.active() {
            if options.cleanup_expired {
                self.database.delete_session(token).await?;
            }
            return Ok(SessionRead {
                session: None,
                needs_refresh: false,
                refreshed: false,
            });
        }
        let needs_refresh = !self.config.session.disable_session_refresh
            && self.config.session.update_age.is_none_or(|age| {
                session.expires_at() - self.config.session.expires_in + age <= now
            });
        if needs_refresh && options.allow_refresh {
            let refreshed_session = self
                .database
                .refresh_session(token, now + self.config.session.expires_in)
                .await?;
            let refreshed = refreshed_session.is_some();
            return Ok(SessionRead {
                session: refreshed_session,
                needs_refresh,
                refreshed,
            });
        }
        Ok(SessionRead {
            session: Some(session),
            needs_refresh,
            refreshed: false,
        })
    }

    /// Whether signed browser preferences or the query suppress refresh.
    /// Query values use the upstream Boolean coercion: any nonempty string,
    /// including `false`, disables refreshing.
    #[must_use]
    pub fn request_disables_refresh(&self, request: &crate::types::AuthRequest) -> bool {
        if request
            .query
            .get("disableRefresh")
            .is_some_and(|value| !value.is_empty())
        {
            return true;
        }
        let name = crate::utils::cookie_utils::related_cookie_name(&self.config, "dont_remember");
        request.headers.get("cookie").is_some_and(|header| {
            cookie::Cookie::split_parse(header)
                .flatten()
                .find(|cookie| cookie.name() == name)
                .and_then(|cookie| {
                    crate::utils::cookie_utils::verify_cookie_value(
                        cookie.value(),
                        &self.config.secret,
                    )
                })
                .is_some_and(|value| !value.is_empty())
        })
    }

    /// Delete a session
    ///
    /// # Errors
    ///
    /// Propagates errors from the session store.
    pub async fn delete_session(&self, token: &str) -> AuthResult<()> {
        self.database.delete_session(token).await?;
        Ok(())
    }

    /// Delete all sessions for a user
    ///
    /// # Errors
    ///
    /// Propagates errors from the session store.
    pub async fn delete_user_sessions(&self, user_id: impl AsRef<str>) -> AuthResult<()> {
        self.database.delete_user_sessions(user_id.as_ref()).await?;
        Ok(())
    }

    /// Get all active sessions for a user
    ///
    /// # Errors
    ///
    /// Propagates errors from the session store.
    pub async fn list_user_sessions(
        &self,
        user_id: impl AsRef<str>,
    ) -> AuthResult<Vec<S::Session>> {
        let sessions = self.database.get_user_sessions(user_id.as_ref()).await?;
        let now = Utc::now();

        // Filter out expired sessions
        let active_sessions = sessions
            .into_iter()
            .filter(|session| session.expires_at() > now && session.active())
            .collect();

        Ok(active_sessions)
    }

    /// Revoke a specific session by token
    ///
    /// # Errors
    ///
    /// Propagates errors from the session store.
    pub async fn revoke_session(&self, token: &str) -> AuthResult<bool> {
        // Check if session exists before trying to delete
        let session_exists = self.get_session(token).await?.is_some();

        if session_exists {
            self.delete_session(token).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Revoke all sessions for a user
    ///
    /// # Errors
    ///
    /// Propagates errors from the session store.
    pub async fn revoke_all_user_sessions(&self, user_id: impl AsRef<str>) -> AuthResult<usize> {
        // Get count of sessions before deletion for return value
        let user_id = user_id.as_ref();
        let sessions = self.list_user_sessions(user_id).await?;
        let count = sessions.len();

        self.delete_user_sessions(user_id).await?;
        Ok(count)
    }

    /// Revoke all sessions for a user except the current one
    ///
    /// # Errors
    ///
    /// Propagates errors from the session store.
    pub async fn revoke_other_user_sessions(
        &self,
        user_id: impl AsRef<str>,
        current_token: &str,
    ) -> AuthResult<usize> {
        let sessions = self.list_user_sessions(user_id).await?;
        let mut count = 0;

        for session in sessions {
            if session.token() != current_token {
                self.delete_session(session.token()).await?;
                count += 1;
            }
        }

        Ok(count)
    }

    /// Cleanup expired sessions
    ///
    /// # Errors
    ///
    /// Propagates errors from the session store.
    pub async fn cleanup_expired_sessions(&self) -> AuthResult<usize> {
        let count = self.database.delete_expired_sessions().await?;
        Ok(count)
    }

    /// Check whether a session is "fresh" (created recently enough for
    /// sensitive operations like password change or account deletion).
    ///
    /// A positive freshness window requires creation time within that window.
    /// `None` and zero disable the restriction, matching upstream `freshAge: 0`.
    pub fn is_session_fresh(&self, session: &impl AuthSession) -> bool {
        match self.config.session.fresh_age {
            Some(fresh_age) if fresh_age != chrono::Duration::zero() => {
                session.created_at() + fresh_age > Utc::now()
            }
            _ => true,
        }
    }

    /// Validate session token format
    #[must_use]
    pub fn validate_token_format(&self, token: &str) -> bool {
        token.len() == 32 && token.bytes().all(|byte| byte.is_ascii_alphanumeric())
    }

    /// Extract a verified session token from the configured cookie.
    ///
    /// The core runtime does not authenticate bearer headers. The separate
    /// bearer plugin may establish a signed cookie before this parser runs.
    #[must_use]
    pub fn extract_session_token(&self, req: &crate::types::AuthRequest) -> Option<String> {
        let header = req.headers.get("cookie")?;
        cookie::Cookie::split_parse(header)
            .flatten()
            .find(|cookie| cookie.name() == self.config.session.cookie_name)
            .and_then(|cookie| {
                crate::utils::cookie_utils::verify_cookie_value(cookie.value(), &self.config.secret)
            })
            .filter(|token| !token.is_empty())
    }
}

impl<T> std::fmt::Debug for SessionRead<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionRead").finish_non_exhaustive()
    }
}

impl<S: AuthSchema> std::fmt::Debug for SessionManager<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionManager").finish_non_exhaustive()
    }
}
