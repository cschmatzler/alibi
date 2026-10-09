use crate::AdapterRecord;
pub mod cookie_cache;
mod request;
use crate::config::AuthConfig;
use crate::entity::{AuthSession, AuthUser};
use crate::error::AuthResult;
use crate::schema::AuthSchema;
use crate::store::AuthStore;
use crate::types::CreateSession;
use chrono::Utc;
pub use request::SessionRequest;
use std::sync::Arc;

/// Insert into request extensions to suppress automatic renewal for a server
/// render or an application-controlled request, like Source request-local
/// `setShouldSkipSessionRefresh`. It is never accepted from client input.
#[derive(Clone, Copy, Debug)]
pub struct SessionRefreshSuppressed;

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

impl<T> SessionRead<T> {
    const fn absent() -> Self {
        Self {
            session: None,
            needs_refresh: false,
            refreshed: false,
        }
    }
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
        self.database
            .create_session(self.new_session(user, ip_address, user_agent))
            .await
    }

    /// Create a real session and retain its declared adapter output.
    ///
    /// # Errors
    /// Propagates errors from persistence or configured callbacks.
    pub async fn create_session_record(
        &self,
        user: &impl AuthUser,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> AuthResult<AdapterRecord<S::Session>> {
        self.database
            .create_session_record(self.new_session(user, ip_address, user_agent))
            .await
    }

    fn new_session(
        &self,
        user: &impl AuthUser,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> CreateSession {
        CreateSession {
            additional_fields: crate::field_policy::FieldValues::default(),
            token: None,
            active_team_id: None,
            user_id: user.id().to_string(),
            expires_at: Utc::now() + self.config.session.expires_in,
            ip_address,
            user_agent,
            impersonated_by: None,
            active_organization_id: None,
        }
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
            return Ok(SessionRead::absent());
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
        self.read_loaded(session, options, |token, expires_at| async move {
            self.database.refresh_session(&token, expires_at).await
        })
        .await
    }

    /// Apply the same physical expiry/refresh lifecycle to retained adapter output.
    /// The record must originate from this manager's actual initialized store.
    pub async fn read_loaded_session_record(
        &self,
        session: AdapterRecord<S::Session>,
        options: SessionReadOptions,
    ) -> AuthResult<SessionRead<AdapterRecord<S::Session>>> {
        self.read_loaded(session, options, |token, expires_at| async move {
            self.database
                .refresh_session_record(&token, expires_at)
                .await
        })
        .await
    }

    async fn read_loaded<T, F, Fut>(
        &self,
        session: T,
        options: SessionReadOptions,
        refresh: F,
    ) -> AuthResult<SessionRead<T>>
    where
        T: AuthSession,
        F: FnOnce(String, chrono::DateTime<chrono::Utc>) -> Fut,
        Fut: std::future::Future<Output = AuthResult<Option<T>>>,
    {
        let token = session.token();
        let now = Utc::now();
        if session.expires_at() < now || !session.active() {
            if options.cleanup_expired {
                self.database.delete_session(token).await?;
            }
            return Ok(SessionRead::absent());
        }
        let needs_refresh = !self.config.session.disable_session_refresh
            && self.config.session.update_age.is_none_or(|age| {
                session.expires_at() - self.config.session.expires_in + age <= now
            });
        if needs_refresh && options.allow_refresh {
            let refreshed_session =
                refresh(token.to_owned(), now + self.config.session.expires_in).await?;
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
    pub fn request_disables_refresh(&self, request: &impl SessionRequest) -> bool {
        request.session_query_truthy("disableRefresh") || self.has_dont_remember_cookie(request)
    }

    /// The independently signed browser session preference.
    #[must_use]
    pub fn has_dont_remember_cookie(&self, request: &impl SessionRequest) -> bool {
        let name = crate::utils::cookie_utils::related_cookie_name(&self.config, "dont_remember");
        request
            .session_headers()
            .get("cookie")
            .is_some_and(|header| {
                cookie::Cookie::split_parse(header)
                    .flatten()
                    .find(|cookie| cookie.name() == name)
                    .and_then(|cookie| {
                        crate::utils::cookie_utils::verify_cookie_value(
                            cookie.value(),
                            self.config.current_secret(),
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
        self.database.delete_session(token).await
    }

    /// Delete all sessions for a user
    ///
    /// # Errors
    ///
    /// Propagates errors from the session store.
    pub async fn delete_user_sessions(&self, user_id: impl AsRef<str>) -> AuthResult<()> {
        self.database.delete_user_sessions(user_id.as_ref()).await
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
        Ok(sessions
            .into_iter()
            .filter(|session| session.expires_at() > now && session.active())
            .collect())
    }

    /// Revoke a specific session by token
    ///
    /// # Errors
    ///
    /// Propagates errors from the session store.
    pub async fn revoke_session(&self, token: &str) -> AuthResult<bool> {
        if self.get_session(token).await?.is_none() {
            return Ok(false);
        }
        self.delete_session(token).await?;
        Ok(true)
    }

    /// Revoke all sessions for a user
    ///
    /// # Errors
    ///
    /// Propagates errors from the session store.
    pub async fn revoke_all_user_sessions(&self, user_id: impl AsRef<str>) -> AuthResult<usize> {
        let user_id = user_id.as_ref();
        let count = self.list_user_sessions(user_id).await?.len();
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
    pub fn extract_session_token(&self, req: &impl SessionRequest) -> Option<String> {
        let header = req.session_headers().get("cookie")?;
        header
            .split(';')
            .find_map(|pair| {
                let (name, value) = pair.split_once('=')?;
                (crate::utils::javascript::trim(name) == self.config.session.cookie_name)
                    .then(|| crate::utils::javascript::trim(value))
            })
            .map(|value| {
                // Better Call unwraps the first quoted value before verifying;
                // later duplicates cannot recover an invalid first credential.
                if value.starts_with('"') {
                    value.get(1..value.len().saturating_sub(1)).unwrap_or("")
                } else {
                    value
                }
            })
            .and_then(|value| {
                crate::utils::cookie_utils::verify_cookie_value(value, self.config.current_secret())
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

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::AuthSession;
    use crate::test_store::{BundledSchema, test_config, test_database};
    use crate::types::AuthRequest;
    use crate::types::HttpMethod;
    use crate::wire::SessionView;
    use chrono::Duration;

    fn test_manager() -> SessionManager<BundledSchema> {
        let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
        SessionManager::new(test_config(), runtime.block_on(test_database()))
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[test]
    fn valid_token_format() {
        let mgr = test_manager();
        let token = "abcdefghijklmnopqrstuvwxyz123456";
        assert!(mgr.validate_token_format(token));
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[test]
    fn invalid_token_non_alphanumeric() {
        let mgr = test_manager();
        assert!(!mgr.validate_token_format("abcdefghijklmnopqrstuvwxy_123456"));
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[test]
    fn invalid_token_too_short() {
        let mgr = test_manager();
        assert!(!mgr.validate_token_format("session_short"));
    }

    // Pinned Better Call sessions require a signed cookie; bearer authentication
    // is supplied by the separate bearer plugin, not core session parsing.
    #[test]
    fn extract_rejects_bare_bearer() {
        let mgr = test_manager();
        let mut req = AuthRequest::new(HttpMethod::Get, "/test");
        _ = req
            .headers
            .insert("authorization".into(), "Bearer my-token".into());
        assert_eq!(mgr.extract_session_token(&req), None);
    }

    #[test]
    fn extract_cookie_checks_signature_and_first_duplicate() {
        let mgr = test_manager();
        let signed = crate::utils::cookie_utils::sign_cookie_value("tok123", &mgr.config.secret);
        let foreign =
            crate::utils::cookie_utils::sign_cookie_value("tok123", "another-server-secret");
        for (cookie, expected) in [
            (
                format!("better-auth.session_token={signed}; other=val"),
                Some("tok123"),
            ),
            ("better-auth.session_token=tok123".to_owned(), None),
            (format!("better-auth.session_token={foreign}"), None),
            (
                format!("better-auth.session_token={signed}; better-auth.session_token=invalid"),
                Some("tok123"),
            ),
            (
                format!("better-auth.session_token=invalid; better-auth.session_token={signed}"),
                None,
            ),
        ] {
            let mut req = AuthRequest::new(HttpMethod::Get, "/test");
            _ = req.headers.insert("cookie".into(), cookie);
            assert_eq!(mgr.extract_session_token(&req).as_deref(), expected);
        }
    }

    #[test]
    fn extract_ignores_bearer_when_signed_cookie_exists() {
        let mgr = test_manager();
        let mut req = AuthRequest::new(HttpMethod::Get, "/test");
        _ = req
            .headers
            .insert("authorization".into(), "Bearer bearer-tok".into());
        let signed =
            crate::utils::cookie_utils::sign_cookie_value("cookie-tok", &mgr.config.secret);
        _ = req.headers.insert(
            "cookie".into(),
            format!("better-auth.session_token={signed}"),
        );
        assert_eq!(mgr.extract_session_token(&req), Some("cookie-tok".into()));
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[test]
    fn extract_returns_none_without_auth() {
        let mgr = test_manager();
        let req = AuthRequest::new(HttpMethod::Get, "/test");
        assert_eq!(mgr.extract_session_token(&req), None);
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[test]
    fn extract_skips_empty_cookie_value() {
        let mgr = test_manager();
        let mut req = AuthRequest::new(HttpMethod::Get, "/test");
        _ = req
            .headers
            .insert("cookie".into(), "better-auth.session_token=".into());
        assert_eq!(mgr.extract_session_token(&req), None);
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[test]
    fn session_fresh_when_within_window() {
        let mut config = AuthConfig::new("test-secret-min-32-chars-1234567");
        config.session.fresh_age = Some(Duration::minutes(10));
        let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
        let mgr = SessionManager::new(Arc::new(config), runtime.block_on(test_database()));

        // A session created "now" is fresh within a 10-minute window.
        let session = SessionView {
            omitted_fields: std::collections::BTreeSet::default(),
            active_team_id: None,
            extension_fields: std::collections::BTreeMap::default(),
            id: "s1".into(),
            expires_at: Utc::now() + Duration::hours(1),
            token: "tok".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            ip_address: None,
            user_agent: None,
            user_id: "u1".into(),
            impersonated_by: None,
            active_organization_id: None,
            active: true,
        };
        assert!(mgr.is_session_fresh(&session));
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[test]
    fn session_not_fresh_when_old() {
        let mut config = AuthConfig::new("test-secret-min-32-chars-1234567");
        config.session.fresh_age = Some(Duration::minutes(10));
        let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
        let mgr = SessionManager::new(Arc::new(config), runtime.block_on(test_database()));

        let session = SessionView {
            omitted_fields: std::collections::BTreeSet::default(),
            active_team_id: None,
            extension_fields: std::collections::BTreeMap::default(),
            id: "s1".into(),
            expires_at: Utc::now() + Duration::hours(1),
            token: "tok".into(),
            created_at: Utc::now() - Duration::minutes(20),
            updated_at: Utc::now(),
            ip_address: None,
            user_agent: None,
            user_id: "u1".into(),
            impersonated_by: None,
            active_organization_id: None,
            active: true,
        };
        assert!(!mgr.is_session_fresh(&session));
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[test]
    fn disabled_freshness_allows_an_old_session() {
        let mut config = (*test_config()).clone();
        config.session.fresh_age = None;
        let mgr = SessionManager::new(Arc::new(config), test_manager().database);
        let session = SessionView {
            omitted_fields: std::collections::BTreeSet::default(),
            active_team_id: None,
            extension_fields: std::collections::BTreeMap::default(),
            id: "s1".into(),
            expires_at: Utc::now() + Duration::hours(1),
            token: "tok".into(),
            created_at: Utc::now() - Duration::days(30),
            updated_at: Utc::now(),
            ip_address: None,
            user_agent: None,
            user_id: "u1".into(),
            impersonated_by: None,
            active_organization_id: None,
            active: true,
        };
        assert!(mgr.is_session_fresh(&session));
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[tokio::test]
    async fn create_and_get_session() {
        let db = test_database().await;
        let mgr = SessionManager::new(test_config(), Arc::clone(&db));

        // Create a user first
        let user = db
            .create_user(crate::types::CreateUser::new().with_email("test@test.com"))
            .await
            .unwrap();

        let session = mgr.create_session(&user, None, None).await.unwrap();
        let token = session.token().to_owned();

        let retrieved = mgr.get_session(&token).await.unwrap();
        assert!(retrieved.is_some());
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[tokio::test]
    async fn refresh_returns_the_persisted_expiry() {
        let db = test_database().await;
        let mut config = AuthConfig::new("test-secret-min-32-chars-1234567");
        // Refresh on every access so a single `get_session` exercises the path.
        config.session.update_age = None;
        let mgr = SessionManager::new(Arc::new(config), Arc::clone(&db));

        let user = db
            .create_user(crate::types::CreateUser::new().with_email("refresh@test.com"))
            .await
            .unwrap();
        let session = mgr.create_session(&user, None, None).await.unwrap();
        let token = session.token().to_owned();

        // Move the stored expiry back so the refresh is observable.
        let stale = session.expires_at() - Duration::minutes(30);
        db.update_session_expiry(&token, stale).await.unwrap();

        let returned = mgr
            .get_session(&token)
            .await
            .unwrap()
            .expect("session should still be live");
        let stored = db
            .get_session(&token)
            .await
            .unwrap()
            .expect("session should still be stored");

        assert!(
            returned.expires_at() > stale,
            "refresh should have extended the expiry"
        );
        assert_eq!(
            returned.expires_at(),
            stored.expires_at(),
            "returned session must reflect the persisted expiry, not the pre-refresh value"
        );
    }

    #[test]
    fn refresh_preferences_verify_the_first_cookie_and_use_javascript_truthiness() {
        let manager = test_manager();
        let name =
            crate::utils::cookie_utils::related_cookie_name(&manager.config, "dont_remember");
        let valid = crate::utils::cookie_utils::sign_cookie_value("true", &manager.config.secret);
        let empty = crate::utils::cookie_utils::sign_cookie_value("", &manager.config.secret);
        let wrong = crate::utils::cookie_utils::sign_cookie_value("true", "foreign-secret");
        for (header, expected) in [
            (format!("{name}={valid}"), true),
            (format!("{name}={empty}"), false),
            (format!("{name}={wrong}"), false),
            (format!("{name}=invalid; {name}={valid}"), false),
            (format!("{name}={valid}; {name}=invalid"), true),
        ] {
            let mut request = AuthRequest::new(HttpMethod::Get, "/get-session");
            _ = request.headers.insert("cookie".into(), header);
            assert_eq!(manager.request_disables_refresh(&request), expected);
        }
        for (value, expected) in [("", false), ("false", true), ("0", true), ("true", true)] {
            let mut request = AuthRequest::new(HttpMethod::Get, "/get-session");
            _ = request.query.insert("disableRefresh".into(), value.into());
            assert_eq!(manager.request_disables_refresh(&request), expected);
        }
    }

    #[tokio::test]
    async fn recent_sessions_refresh_at_the_expiry_based_half_second_boundary() {
        let db = test_database().await;
        let config = test_config();
        let manager = SessionManager::new(Arc::clone(&config), Arc::clone(&db));
        let user = db
            .create_user(crate::types::CreateUser::new().with_email("half-second@test.com"))
            .await
            .unwrap();
        for difference in [Duration::milliseconds(500), Duration::milliseconds(-500)] {
            let session = manager.create_session(&user, None, None).await.unwrap();
            let expiry = Utc::now() + config.session.expires_in
                - config.session.update_age.unwrap()
                + difference;
            db.update_session_expiry(session.token(), expiry)
                .await
                .unwrap();
            let returned = manager.get_session(session.token()).await.unwrap().unwrap();
            let stored = db.get_session(session.token()).await.unwrap().unwrap();
            assert_eq!(returned.expires_at(), stored.expires_at());
            assert_eq!(returned.token(), session.token());
            if difference > Duration::zero() {
                assert_eq!(stored.expires_at(), expiry);
            } else {
                assert!(stored.expires_at() > expiry + Duration::hours(23));
            }
        }
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[tokio::test]
    async fn create_session_without_metadata_uses_empty_strings() {
        let db = test_database().await;
        let mgr = SessionManager::new(test_config(), Arc::clone(&db));

        let user = db
            .create_user(crate::types::CreateUser::new().with_email("test@test.com"))
            .await
            .unwrap();

        let session = mgr.create_session(&user, None, None).await.unwrap();
        assert_eq!(session.ip_address.as_deref(), Some(""));
        assert_eq!(session.user_agent.as_deref(), Some(""));
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[tokio::test]
    async fn delete_session_removes_it() {
        let db = test_database().await;
        let mgr = SessionManager::new(test_config(), Arc::clone(&db));

        let user = db
            .create_user(crate::types::CreateUser::new().with_email("test@test.com"))
            .await
            .unwrap();

        let session = mgr.create_session(&user, None, None).await.unwrap();
        let token = session.token().to_owned();

        mgr.delete_session(&token).await.unwrap();
        let retrieved = mgr.get_session(&token).await.unwrap();
        assert!(retrieved.is_none());
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[tokio::test]
    async fn revoke_session_returns_true_when_found() {
        let db = test_database().await;
        let mgr = SessionManager::new(test_config(), Arc::clone(&db));

        let user = db
            .create_user(crate::types::CreateUser::new().with_email("test@test.com"))
            .await
            .unwrap();

        let session = mgr.create_session(&user, None, None).await.unwrap();
        let result = mgr.revoke_session(session.token()).await.unwrap();
        assert!(result);
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[tokio::test]
    async fn revoke_session_returns_false_when_not_found() {
        let mgr = SessionManager::new(test_config(), test_database().await);
        let result = mgr.revoke_session("nonexistent-token").await.unwrap();
        assert!(!result);
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[tokio::test]
    async fn list_user_sessions_excludes_expired() {
        let db = test_database().await;
        let mgr = SessionManager::new(test_config(), Arc::clone(&db));

        let user = db
            .create_user(crate::types::CreateUser::new().with_email("test@test.com"))
            .await
            .unwrap();

        // Create two sessions
        _ = mgr.create_session(&user, None, None).await.unwrap();
        _ = mgr.create_session(&user, None, None).await.unwrap();

        let sessions = mgr.list_user_sessions(user.id()).await.unwrap();
        assert_eq!(sessions.len(), 2);
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[tokio::test]
    async fn revoke_all_user_sessions() {
        let db = test_database().await;
        let mgr = SessionManager::new(test_config(), Arc::clone(&db));

        let user = db
            .create_user(crate::types::CreateUser::new().with_email("test@test.com"))
            .await
            .unwrap();

        _ = mgr.create_session(&user, None, None).await.unwrap();
        _ = mgr.create_session(&user, None, None).await.unwrap();

        let count = mgr.revoke_all_user_sessions(user.id()).await.unwrap();
        assert_eq!(count, 2);

        let sessions = mgr.list_user_sessions(user.id()).await.unwrap();
        assert_eq!(sessions, Vec::<SessionView>::new());
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[tokio::test]
    async fn revoke_other_sessions_keeps_current() {
        let db = test_database().await;
        let mgr = SessionManager::new(test_config(), Arc::clone(&db));

        let user = db
            .create_user(crate::types::CreateUser::new().with_email("test@test.com"))
            .await
            .unwrap();

        let current = mgr.create_session(&user, None, None).await.unwrap();
        _ = mgr.create_session(&user, None, None).await.unwrap();
        _ = mgr.create_session(&user, None, None).await.unwrap();

        let count = mgr
            .revoke_other_user_sessions(user.id(), current.token())
            .await
            .unwrap();
        assert_eq!(count, 2);

        let remaining = mgr.list_user_sessions(user.id()).await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(
            (*(remaining)
                .first()
                .expect("fixture contains the requested index"))
            .token(),
            current.token()
        );
    }
}
// LCOV_EXCL_STOP
