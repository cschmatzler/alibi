//! Request-local cache cookies and genuine stored/cached snapshot transitions.
use crate::utils::LockUnpoisoned;
mod cookies;
mod issuance;
mod read;

use crate::session::SessionRequest;
use crate::{AuthContext, AuthRequest, AuthSchema};
pub(super) use cookies::browser_preference;
use cookies::cache_value;
pub(super) use cookies::chunk_index;
pub use cookies::chunked_cookie_headers;
pub use cookies::chunked_cookie_value;
pub use cookies::session_cleanup_headers;
use cookies::{cookie_values, cookies, existing_names};
use issuance::build_headers;
pub use issuance::emit_issuance;
pub use issuance::emit_issuance_in_transaction;
pub use issuance::emit_issuance_snapshot;
pub use issuance::stored_headers;
use issuance::stored_read_headers;
pub use issuance::take_issuance;
pub use read::authenticated;
pub use read::read;
pub(crate) use read::renew_cache;
pub(crate) use read::{CacheDecoding, authenticated_with};
use std::sync::{Arc, Mutex};

#[derive(Debug)]
struct IssuancePreference(bool);

/// Metadata from the authenticated cache snapshot retained by get-session
/// response hooks. Nested middleware publishes its completed session instead.
#[derive(Clone, Debug)]
pub struct SessionHookCacheMetadata {
    pub updated_at: f64,
    pub version: Option<String>,
}

#[derive(Debug)]
struct SessionHookCache(Option<SessionHookCacheMetadata>);

#[derive(Debug)]
struct PublishedSession(Option<PublishedSessionSnapshot>);

/// One completed issuance with actual retained callback-stage output.
/// Trusted hooks may observe it; it never establishes authentication.
#[derive(Clone, Debug)]
pub struct PublishedSessionSnapshot {
    user: crate::UserView,
    session: crate::SessionView,
    user_output: Option<crate::AdapterOutput>,
    session_output: Option<crate::AdapterOutput>,
}
impl PublishedSessionSnapshot {
    #[must_use]
    pub const fn user(&self) -> &crate::UserView {
        &self.user
    }
    #[must_use]
    pub const fn session(&self) -> &crate::SessionView {
        &self.session
    }
    #[must_use]
    pub const fn user_output(&self) -> Option<&crate::AdapterOutput> {
        self.user_output.as_ref()
    }
    #[must_use]
    pub const fn session_output(&self) -> Option<&crate::AdapterOutput> {
        self.session_output.as_ref()
    }
}

/// The snapshot whose session cookies completed successfully in this dispatch.
/// Response hooks may observe it; it never establishes authentication.
#[must_use]
pub fn published_session(
    request: &impl SessionRequest,
) -> Option<(crate::UserView, crate::SessionView)> {
    published_session_snapshot(request).map(|snapshot| (snapshot.user, snapshot.session))
}

/// Observe immutable retained output without reconstructing a storage model.
#[must_use]
pub fn published_session_snapshot(
    request: &impl SessionRequest,
) -> Option<PublishedSessionSnapshot> {
    request
        .extensions()
        .get::<PublishedSession>()
        .and_then(|session| session.0.clone())
}

/// Retire cookie publication when a real login becomes a pending factor challenge.
pub fn discard_issuance(request: &impl SessionRequest) {
    request.extensions().insert(PublishedSession(None));
    if let Some(pending) = request.extensions().get::<PendingIssuance>() {
        *pending.0.lock_unpoisoned() = PendingData::default();
    }
}

fn record_publication(snapshot: PublishedSessionSnapshot) {
    if let Some(endpoint) = crate::endpoint::current_endpoint_call_context() {
        endpoint
            .extensions()
            .insert(PublishedSession(Some(snapshot)));
    } else if let Some(request) = crate::hooks::current_request_hook_context() {
        request.extensions.insert(PublishedSession(Some(snapshot)));
    }
}

/// Read the metadata attached to the actual authenticated hook snapshot.
#[must_use]
pub fn session_hook_cache_metadata(
    request: &impl SessionRequest,
) -> Option<SessionHookCacheMetadata> {
    request
        .extensions()
        .get::<SessionHookCache>()
        .and_then(|context| context.0.clone())
}

#[derive(Debug, Default)]
struct PendingIssuance(Mutex<PendingData>);

#[derive(Debug, Default)]
struct PendingData {
    prior_headers: Vec<String>,
    cache_headers: Vec<String>,
    ordinary_error: bool,
}

/// Result of a cache-aware HTTP session read. A cached user is an output
/// snapshot, while Stored retains the actual application model.
pub struct AuthenticatedRead<S: AuthSchema> {
    pub user: crate::AuthenticatedUser<S>,
    pub session: crate::SessionView,
    pub needs_refresh: Option<bool>,
}

struct EstablishedSession<S: AuthSchema>(Option<EstablishedRead<S>>);

struct EstablishedRead<S: AuthSchema> {
    read: AuthenticatedRead<S>,
    headers: std::collections::HashMap<String, String>,
    virtual_session: Option<crate::SessionView>,
    config: Arc<crate::AuthConfig>,
    database: Arc<dyn crate::AuthStore<S>>,
}

/// Retire the ordinary middleware result before a sensitive physical read.
pub fn clear_established_session<S: AuthSchema>(request: &impl SessionRequest) {
    request.extensions().insert(EstablishedSession::<S>(None));
}

fn establish<S: AuthSchema>(
    ctx: &AuthContext<S>,
    request: &impl SessionRequest,
    read: AuthenticatedRead<S>,
) -> AuthenticatedRead<S> {
    request
        .extensions()
        .insert(EstablishedSession::<S>(Some(EstablishedRead {
            read: AuthenticatedRead {
                user: read.user.clone(),
                session: read.session.clone(),
                needs_refresh: read.needs_refresh,
            },
            headers: request.session_headers().clone(),
            virtual_session: request.virtual_session(ctx),
            config: Arc::clone(&ctx.config),
            database: Arc::clone(&ctx.database),
        })));
    read
}

impl<S: AuthSchema> std::fmt::Debug for AuthenticatedRead<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedRead").finish_non_exhaustive()
    }
}

/// Preserve a validated endpoint preference without trusting embedding state.
/// Public dispatch resets request extensions before any endpoint executes.
#[doc(hidden)]
pub fn set_issuance_preference(request: &AuthRequest, dont_remember: bool) {
    request
        .extensions()
        .insert(IssuancePreference(dont_remember));
}
