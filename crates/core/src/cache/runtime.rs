//! Request-local cache cookies and genuine stored/cached snapshot transitions.
use super::{CacheValidation, CacheVersionContext};
use crate::session::SessionRequest;
use crate::types::RequestExtensions;
use crate::utils::cookie_utils::{related_cookie_name, sign_cookie_value, verify_cookie_value};
use crate::{AuthContext, AuthError, AuthRequest, AuthResult, AuthSchema, AuthSession, AuthUser};
use indexmap::IndexMap;
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
        *pending
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = PendingData::default();
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

// Better Call reads the first base cookie. Better Auth's session-store reader
// uses the last valid duplicate for chunks, with its stricter octet grammar.
fn cookies<H: std::hash::BuildHasher + Sync>(
    headers: &std::collections::HashMap<String, String, H>,
) -> IndexMap<String, String> {
    cookie_values(headers, false)
}

fn cookie_values<H: std::hash::BuildHasher + Sync>(
    headers: &std::collections::HashMap<String, String, H>,
    chunks: bool,
) -> IndexMap<String, String> {
    let mut values = IndexMap::new();
    if let Some(header) = headers.get("cookie") {
        for pair in header.split(';') {
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            let (name, mut value) = if chunks {
                (
                    name.trim_matches([' ', '\t']),
                    value.trim_matches([' ', '\t']),
                )
            } else {
                (
                    crate::utils::javascript::trim(name),
                    crate::utils::javascript::trim(value),
                )
            };
            if value.starts_with('"') && (!chunks || (value.len() >= 2 && value.ends_with('"'))) {
                value = if value.len() == 1 {
                    ""
                } else {
                    value.get(1..value.len() - 1).unwrap_or(value)
                };
            }
            if chunks && (name.is_empty() || !name.bytes().all(|byte|
                matches!(byte, b'!' | b'#'..=b'\'' | b'*' | b'+' | b'-' | b'.' | b'0'..=b'9' | b'A'..=b'Z' | b'^' | b'_' | b'`' | b'a'..=b'z' | b'|' | b'~'))
                || !value.bytes().all(|byte| matches!(byte, 0x20..=0x21 | 0x23..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e))) {
                continue;
            }
            let decoded = percent_encoding::percent_decode_str(value)
                .decode_utf8()
                .map_or_else(|_| value.to_owned(), |decoded| decoded.into_owned());
            if chunks {
                drop(values.insert(name.to_owned(), decoded));
            } else {
                _ = values.entry(name.to_owned()).or_insert(decoded);
            }
        }
    }
    values
}

fn chunk_index(name: &str, base: &str) -> Option<u64> {
    let suffix = name.strip_prefix(base)?.strip_prefix('.')?;
    let index: u64 = suffix.parse().ok()?;
    (index <= 9_007_199_254_740_991 && index.to_string() == suffix).then_some(index)
}

fn cache_value(
    values: &IndexMap<String, String>,
    chunks: &IndexMap<String, String>,
    name: &str,
) -> Option<String> {
    if let Some(value) = values.get(name).filter(|value| !value.is_empty()) {
        return Some(value.clone());
    }
    let mut chunks: Vec<_> = chunks
        .iter()
        .filter_map(|(key, value)| Some((chunk_index(key, name)?, value)))
        .collect();
    chunks.sort_by_key(|(index, _)| *index);
    (!chunks.is_empty()).then(|| {
        chunks
            .into_iter()
            .map(|(_, value)| value.as_str())
            .collect()
    })
}

fn existing_names(values: &IndexMap<String, String>, name: &str) -> Vec<String> {
    values
        .keys()
        .filter(|key| key.as_str() == name || chunk_index(key, name).is_some())
        .cloned()
        .collect()
}

pub(super) fn browser_preference(
    headers: &std::collections::HashMap<String, String>,
    config: &crate::AuthConfig,
) -> bool {
    cookies(headers)
        .get(&related_cookie_name(config, "dont_remember"))
        .and_then(|value| verify_cookie_value(value, config.current_secret()))
        .is_some_and(|value| !value.is_empty())
}

/// Build cache cookies from the actual stored models and their public output.
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub async fn stored_headers<S: AuthSchema, H: std::hash::BuildHasher + Sync>(
    ctx: &AuthContext<S>,
    user: &impl AuthUser,
    session: &impl AuthSession,
    headers: &std::collections::HashMap<String, String, H>,
    dont_remember: bool,
) -> AuthResult<Vec<String>> {
    let context = CacheVersionContext::created(
        user.clone(),
        session.clone(),
        ctx.trusted_user_view(user),
        ctx.trusted_session_view(session),
    )
    .with_public_projection(ctx.user_view(user), ctx.session_view(session));
    build_headers(ctx, context, headers, dont_remember, None).await
}

async fn stored_read_headers<S: AuthSchema>(
    ctx: &AuthContext<S>,
    user: &impl AuthUser,
    session: &impl AuthSession,
    headers: &std::collections::HashMap<String, String>,
) -> AuthResult<Vec<String>> {
    let user_fields = ctx.extensions.get::<crate::field_policy::UserFields>();
    let user_fields = user_fields
        .as_ref()
        .map_or(&ctx.config.user.additional_fields, |fields| &fields.0.0);
    let session_fields = ctx.extensions.get::<crate::field_policy::SessionFields>();
    let session_fields = session_fields
        .as_ref()
        .map_or(&ctx.config.session.additional_fields, |fields| &fields.0);
    let context = CacheVersionContext::stored(
        ctx.user_view(user),
        ctx.session_view(session),
        user.adapter_snapshot()
            .map(|output| output.filter_returned(user_fields)),
        session
            .adapter_snapshot()
            .map(|output| output.filter_returned(session_fields)),
    )
    .with_public_projection(ctx.user_view(user), ctx.session_view(session));
    build_headers(ctx, context, headers, false, None).await
}

async fn build_headers<S: AuthSchema, H: std::hash::BuildHasher + Sync>(
    ctx: &AuthContext<S>,
    context: CacheVersionContext,
    headers: &std::collections::HashMap<String, String, H>,
    dont_remember: bool,
    transaction: Option<&dyn crate::store::AuthTransaction<S>>,
) -> AuthResult<Vec<String>> {
    let Some(config) = ctx
        .config
        .session
        .cookie_cache
        .as_ref()
        .filter(|config| config.enabled)
    else {
        return Ok(Vec::new());
    };
    let version = match &config.version {
        Some(policy) => policy.resolve(&context).await?,
        None => "1".into(),
    };
    let now = chrono::Utc::now().timestamp_millis();
    let value = match config.strategy {
        crate::CookieCacheStrategy::Compact => super::encode_compact(
            context.public_user(),
            context.public_session(),
            &version,
            now,
            config.max_age,
            dont_remember,
            ctx.config.current_secret(),
        )?,
        crate::CookieCacheStrategy::Jwt | crate::CookieCacheStrategy::Jwe => {
            let payload = super::jwt::payload(
                context.public_user(),
                context.public_session(),
                &version,
                now,
            )?;
            let max_age = if dont_remember {
                300.0
            } else {
                super::effective_max_age(config.max_age)
            };
            if config.strategy == crate::CookieCacheStrategy::Jwe {
                crate::utils::jwe::encode(
                    ctx.config.current_secret(),
                    "better-auth-session",
                    &payload,
                    max_age,
                )?
            } else if let Some(signer) = ctx
                .extensions
                .get::<super::jwt::CookieCacheSignerHandle<S>>()
            {
                signer.0.sign(payload, max_age, ctx, transaction).await?
            } else {
                super::jwt::encode(payload, ctx.config.current_secret(), max_age)?
            }
        }
    };
    let name = related_cookie_name(&ctx.config, "session_data");
    let max_age = (!dont_remember).then(|| super::effective_max_age(config.max_age));
    chunked_cookie_headers(&name, &value, max_age, &ctx.config, headers, false)
}

/// Read a base cookie or numerically ordered canonical chunks.
#[must_use]
pub fn chunked_cookie_value(
    headers: &std::collections::HashMap<String, String>,
    name: &str,
) -> Option<String> {
    cache_value(&cookies(headers), &cookie_values(headers, true), name)
}

/// Emit bounded chunks, replacing incoming names and expiring stale chunks.
/// Account chunks resolve attributes against their base cookie.
///
/// # Errors
/// Propagates invalid attributes or encoding.
pub fn chunked_cookie_headers<H: std::hash::BuildHasher + Sync>(
    name: &str,
    value: &str,
    max_age: Option<f64>,
    config: &crate::AuthConfig,
    headers: &std::collections::HashMap<String, String, H>,
    account: bool,
) -> AuthResult<Vec<String>> {
    let render = |part: &str, value: &str, age: Option<f64>| {
        if account {
            crate::utils::cookie_utils::create_account_cookie_header(
                part,
                name,
                value,
                age.unwrap_or(300.0),
                config,
            )
        } else {
            super::cookie_header(part, value, age, config)
        }
    };
    let empty_header = render(&format!("{name}.99"), "", max_age)?;
    let capacity = 4050_usize.saturating_sub(empty_header.len());
    let count = if capacity == 0 {
        usize::MAX
    } else {
        value.len().div_ceil(capacity)
    };
    let mut output = IndexMap::new();
    for old in existing_names(&cookie_values(headers, true), name) {
        drop(output.insert(old.clone(), render(&old, "", Some(0.0))?));
    }
    if count <= 1 {
        drop(output.insert(name.to_owned(), render(name, value, max_age)?));
    } else if count <= 100 {
        // Encoded compact values are ASCII, so byte chunking matches JS strings.
        for (index, chunk) in value.as_bytes().chunks(capacity).enumerate() {
            let chunk = std::str::from_utf8(chunk)
                .map_err(|_error| AuthError::internal("Invalid compact cache encoding"))?;
            let part = format!("{name}.{index}");
            drop(output.insert(part.clone(), render(&part, chunk, max_age)?));
        }
    }
    Ok(output.into_values().collect())
}

/// Await cache emission before publishing a completed-session snapshot.
/// Error headers are request local and only explicit public API errors retain
/// the queued token; ordinary callback errors follow the source empty500 path.
#[doc(hidden)]
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub async fn emit_issuance<S: AuthSchema>(
    ctx: &AuthContext<S>,
    user: &impl AuthUser,
    session: &impl AuthSession,
) -> AuthResult<()> {
    emit_issuance_snapshot(
        ctx,
        CacheVersionContext::created(
            user.clone(),
            session.clone(),
            ctx.trusted_user_view(user),
            ctx.trusted_session_view(session),
        )
        .with_public_projection(ctx.user_view(user), ctx.session_view(session)),
    )
    .await
}

/// Publish the user snapshot chosen by a completed authentication stage.
/// The caller must establish the session and retain its owner and token.
///
/// # Errors
/// Propagates cookie encoding and configured cache-version callback errors.
#[doc(hidden)]
pub async fn emit_issuance_snapshot<S: AuthSchema>(
    ctx: &AuthContext<S>,
    context: CacheVersionContext,
) -> AuthResult<()> {
    emit_snapshot_inner(ctx, context, None).await
}

/// Publish a newly created session before committing its actual transaction.
///
/// # Errors
/// Propagates transactional signing-key access and cookie encoding failures.
pub async fn emit_issuance_in_transaction<S: AuthSchema>(
    ctx: &AuthContext<S>,
    user: &impl AuthUser,
    session: &impl AuthSession,
    transaction: &dyn crate::store::AuthTransaction<S>,
) -> AuthResult<()> {
    let context = CacheVersionContext::created(
        user.clone(),
        session.clone(),
        ctx.trusted_user_view(user),
        ctx.trusted_session_view(session),
    );
    emit_snapshot_inner(ctx, context, Some(transaction)).await
}

async fn emit_snapshot_inner<S: AuthSchema>(
    ctx: &AuthContext<S>,
    context: CacheVersionContext,
    transaction: Option<&dyn crate::store::AuthTransaction<S>>,
) -> AuthResult<()> {
    let public_user = ctx.user_view(context.user());
    let public_session = ctx.session_view(context.session());
    let context = context.with_public_projection(public_user, public_session);
    let published = PublishedSessionSnapshot {
        user: context.user().clone(),
        session: context.session().clone(),
        user_output: context.user_output().cloned(),
        session_output: context.session_output().cloned(),
    };
    if !ctx
        .config
        .session
        .cookie_cache
        .as_ref()
        .is_some_and(|config| config.enabled)
    {
        record_publication(published);
        return Ok(());
    }
    let endpoint = crate::endpoint::current_endpoint_call_context();
    let request = crate::hooks::current_request_hook_context();
    let extensions = endpoint
        .as_ref()
        .map(crate::endpoint::EndpointCall::extensions)
        .or_else(|| request.as_ref().map(|request| &request.extensions));
    let headers = if let Some(endpoint) = &endpoint {
        endpoint.headers().cloned().unwrap_or_default()
    } else {
        request
            .as_ref()
            .map(|request| request.headers.clone())
            .unwrap_or_default()
    };
    let dont_remember = extensions
        .and_then(|extensions| extensions.get::<IssuancePreference>())
        .map_or_else(
            || browser_preference(&headers, &ctx.config),
            |value| value.0,
        );
    let pending = extensions.and_then(|extensions| {
        if extensions.get::<PendingIssuance>().is_none() {
            extensions.insert(PendingIssuance::default());
        }
        extensions.get::<PendingIssuance>()
    });
    if let Some(pending) = &pending {
        let token_header = super::cookie_header(
            &ctx.config.session.cookie_name,
            &percent_encoding::percent_decode_str(&sign_cookie_value(
                &context.session().token,
                ctx.config.current_secret(),
            ))
            .decode_utf8_lossy(),
            (!dont_remember)
                .then(|| {
                    serde_json::Number::from(ctx.config.session.expires_in.num_seconds()).as_f64()
                })
                .flatten(),
            &ctx.config,
        )?;
        let mut data = pending
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        data.prior_headers.push(token_header);
        if dont_remember {
            data.prior_headers.push(super::cookie_header(
                &related_cookie_name(&ctx.config, "dont_remember"),
                &percent_encoding::percent_decode_str(&sign_cookie_value(
                    "true",
                    ctx.config.current_secret(),
                ))
                .decode_utf8_lossy(),
                None,
                &ctx.config,
            )?);
        }
    }
    match build_headers(ctx, context, &headers, dont_remember, transaction).await {
        Ok(cache_headers) => {
            if let Some(pending) = pending {
                let mut data = pending
                    .0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                data.prior_headers.clear();
                data.cache_headers.extend(cache_headers);
            }
            record_publication(published);
            Ok(())
        }
        Err(error) => {
            if let Some(pending) = pending {
                pending
                    .0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .ordinary_error =
                    !matches!(error, AuthError::Api { .. } | AuthError::Upstream { .. });
            }
            Err(error)
        }
    }
}

/// Consume only this dispatch's cache issuer state before completed hooks.
#[doc(hidden)]
pub fn take_issuance(extensions: &RequestExtensions) -> (Vec<String>, bool) {
    let Some(pending) = extensions.get::<PendingIssuance>() else {
        return (Vec::new(), false);
    };
    let mut data = std::mem::take(
        &mut *pending
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    );
    if data.ordinary_error {
        return (Vec::new(), true);
    }
    data.prior_headers.extend(data.cache_headers);
    (data.prior_headers, false)
}

/// Try the authenticated compact cache before any physical session lookup.
/// Missing or invalid cache data can only produce a storage fallback.
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub async fn read<S: AuthSchema>(
    ctx: &AuthContext<S>,
    request: &impl SessionRequest,
) -> AuthResult<Option<super::CompactCache>> {
    let manager = ctx.session_manager();
    let enabled = ctx
        .config
        .session
        .cookie_cache
        .as_ref()
        .filter(|config| config.enabled);
    let token = manager.extract_session_token(request);
    if token.is_none() && enabled.is_some() {
        return Ok(None);
    }
    let name = related_cookie_name(&ctx.config, "session_data");
    let values = cookies(request.session_headers());
    let chunks = cookie_values(request.session_headers(), true);
    if enabled.is_none() {
        for old in existing_names(&chunks, &name) {
            request.queue_response_header(
                "Set-Cookie",
                super::cookie_header(&old, "", Some(0.0), &ctx.config)?,
            );
        }
        return Ok(None);
    }
    if request.session_query_truthy("disableCookieCache") {
        return Ok(None);
    }
    let Some(token) = token else {
        return Ok(None);
    };
    let Some(value) = cache_value(&values, &chunks, &name) else {
        return Ok(None);
    };
    let config =
        enabled.ok_or_else(|| AuthError::internal("Missing enabled cache configuration"))?;
    let decoded = match config.strategy {
        crate::CookieCacheStrategy::Compact => {
            super::decode_compact_http(&value, ctx.config.current_secret())?
        }
        crate::CookieCacheStrategy::Jwt => {
            if let Some(signer) = ctx
                .extensions
                .get::<super::jwt::CookieCacheSignerHandle<S>>()
            {
                signer
                    .0
                    .verify(&value, ctx)
                    .await?
                    .and_then(|claims| super::jwt::decode_payload(&claims.into(), 15.0))
            } else {
                super::jwt::decode(&value, ctx.config.current_secret())
            }
        }
        crate::CookieCacheStrategy::Jwe => ctx
            .config
            .verification_secrets()
            .find_map(|secret| {
                crate::utils::jwe::decode(secret, "better-auth-session", &value).ok()
            })
            .and_then(|claims| super::jwt::decode_payload(&claims.into(), 15.0)),
    };
    if let Some(cache) = decoded
        && let CacheValidation::Hit(cache) = super::validate_compact(
            cache,
            &token,
            config.version.as_ref(),
            chrono::Utc::now().timestamp_millis(),
        )
        .await?
    {
        return Ok(Some(*cache));
    }
    request.queue_response_header(
        "Set-Cookie",
        super::cookie_header(&name, "", Some(0.0), &ctx.config)?,
    );
    Ok(None)
}

/// Renew an authenticated envelope without changing embedded session state.
pub(crate) async fn renew_cache<S: AuthSchema>(
    ctx: &AuthContext<S>,
    request: &impl SessionRequest,
    cache: &super::CompactCache,
) -> AuthResult<()> {
    if ctx.config.session.stateless
        && request
            .extensions()
            .get::<crate::session::SessionRefreshSuppressed>()
            .is_none()
    {
        let config = ctx
            .config
            .session
            .cookie_cache
            .as_ref()
            .ok_or_else(|| AuthError::internal("Missing stateless cache configuration"))?;
        let update_age = match ctx.config.session.cookie_refresh_cache {
            crate::CookieRefreshCache::Disabled => None,
            crate::CookieRefreshCache::Automatic => {
                Some((super::effective_max_age(config.max_age) * 0.2).floor())
            }
            crate::CookieRefreshCache::UpdateAge(age) => Some(age),
        };
        // Source's cache-hit branch precedes disableRefresh, dontRemember,
        // disableSessionRefresh, and deferSessionRefresh. None of these
        // suppress envelope renewal or extend the embedded session expiry.
        if update_age.is_some_and(|age| {
            cache.expires_at - (chrono::Utc::now().timestamp_millis() as f64) < age * 1000.0
        }) {
            let context = CacheVersionContext::cached(cache.user.clone(), cache.session.clone());
            for header in
                build_headers(ctx, context, request.session_headers(), false, None).await?
            {
                request.queue_response_header("Set-Cookie", header);
            }
            let remember = ctx.session_manager().has_dont_remember_cookie(request);
            request.queue_response_header(
                "Set-Cookie",
                super::cookie_header(
                    &ctx.config.session.cookie_name,
                    &percent_encoding::percent_decode_str(&sign_cookie_value(
                        &cache.session.token,
                        ctx.config.current_secret(),
                    ))
                    .decode_utf8_lossy(),
                    (!remember).then_some(ctx.config.session.expires_in.num_seconds() as f64),
                    &ctx.config,
                )?,
            );
        }
    }
    Ok(())
}

/// Shared direct/nested get-session lifecycle for the explicitly migrated
/// guards. Nested reads behave as GET even when their parent endpoint is POST.
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub async fn authenticated<S: AuthSchema>(
    ctx: &AuthContext<S>,
    request: &impl SessionRequest,
    direct: bool,
) -> AuthResult<Option<AuthenticatedRead<S>>> {
    if !direct && let Some(call) = request.endpoint_call() {
        let nested = call.session_read_context();
        crate::endpoint::with_endpoint_call_context(
            nested.clone(),
            Box::pin(authenticated_inner(ctx, &nested, false)),
        )
        .await
    } else {
        Box::pin(authenticated_inner(ctx, request, direct)).await
    }
}

#[expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    reason = "Preserve JavaScript Number rounding at the compatibility boundary"
)]
async fn authenticated_inner<S: AuthSchema>(
    ctx: &AuthContext<S>,
    request: &impl SessionRequest,
    direct: bool,
) -> AuthResult<Option<AuthenticatedRead<S>>> {
    if let Some(established) = request.extensions().get::<EstablishedSession<S>>()
        && let Some(established) = &established.0
        && Arc::ptr_eq(&established.config, &ctx.config)
        && Arc::ptr_eq(&established.database, &ctx.database)
        && &established.headers == request.session_headers()
        && established.virtual_session == request.virtual_session(ctx)
    {
        let read = &established.read;
        return Ok(Some(AuthenticatedRead {
            user: read.user.clone(),
            session: read.session.clone(),
            needs_refresh: read.needs_refresh,
        }));
    }
    request.extensions().insert(SessionHookCache(None));
    if let Some(session) = request.virtual_session(ctx) {
        let user = if let Some(user) = request.authenticated_user::<S>(ctx) {
            ctx.user_adapter_record(user).await?
        } else {
            let Some(user) = ctx.database.get_user_by_id_record(&session.user_id).await? else {
                return Ok(None);
            };
            user
        };
        request.set_session_hook_snapshot(ctx.user_view(&user), session.clone());
        return Ok(Some(establish(
            ctx,
            request,
            AuthenticatedRead {
                user: crate::AuthenticatedUser::Stored(user),
                session,
                needs_refresh: None,
            },
        )));
    }
    if let Some(cache) = read(ctx, request).await? {
        renew_cache(ctx, request, &cache).await?;
        request
            .extensions()
            .insert(SessionHookCache(Some(SessionHookCacheMetadata {
                updated_at: cache.updated_at,
                version: cache.version.clone(),
            })));
        request.set_session_hook_snapshot(cache.user.clone(), cache.session.clone());
        return Ok(Some(establish(
            ctx,
            request,
            AuthenticatedRead {
                user: crate::AuthenticatedUser::Cached(Box::new(cache.user)),
                session: cache.session,
                needs_refresh: None,
            },
        )));
    }
    let manager = ctx.session_manager();
    let Some(token) = manager.extract_session_token(request) else {
        return Ok(None);
    };
    let Some(original) = ctx.database.get_session_record(&token).await? else {
        cleanup(ctx, request)?;
        return Ok(None);
    };
    let user = match ctx.database.get_session_user_record(&token).await? {
        Some(user) => Some(user),
        None if ctx.config.session.secondary_storage.is_some()
            && (!ctx.config.session.store_in_database
                || ctx.config.session.preserve_in_database) =>
        {
            None
        }
        None => {
            ctx.database
                .get_user_by_id_record(original.user_id().as_ref())
                .await?
        }
    };
    let Some(user) = user else {
        cleanup(ctx, request)?;
        return Ok(None);
    };
    request.set_session_hook_snapshot(ctx.user_view(&user), ctx.session_view(&original));
    let suppressed = manager.request_disables_refresh(request);
    let skip = request
        .extensions()
        .get::<crate::session::SessionRefreshSuppressed>()
        .is_some();
    let deferred = ctx.config.session.defer_session_refresh
        && !(direct && request.session_method() == &crate::HttpMethod::Post);
    let read = manager
        .read_loaded_session_record(
            original,
            crate::session::SessionReadOptions {
                allow_refresh: !suppressed && !deferred && !skip,
                cleanup_expired: !deferred,
            },
        )
        .await?;
    let Some(session) = read.session else {
        cleanup(ctx, request)?;
        if read.needs_refresh {
            return Err(AuthError::Upstream {
                status: 401,
                code: "FAILED_TO_GET_SESSION",
                message: "Failed to get session",
            });
        }
        return Ok(None);
    };
    if read.refreshed {
        request.queue_response_header(
            "Set-Cookie",
            super::cookie_header(
                &ctx.config.session.cookie_name,
                &percent_encoding::percent_decode_str(&sign_cookie_value(
                    session.token(),
                    ctx.config.current_secret(),
                ))
                .decode_utf8_lossy(),
                Some(ctx.config.session.expires_in.num_seconds() as f64),
                &ctx.config,
            )?,
        );
    }
    if read.refreshed {
        let user = ctx.filter_user_record(user.clone());
        emit_issuance(ctx, &user, &session).await?;
    } else if !suppressed {
        for header in stored_read_headers(ctx, &user, &session, request.session_headers()).await? {
            request.queue_response_header("Set-Cookie", header);
        }
    }
    Ok(Some(establish(
        ctx,
        request,
        AuthenticatedRead {
            user: crate::AuthenticatedUser::Stored(user),
            session: ctx.session_view(&session),
            needs_refresh: (deferred && !suppressed).then_some(read.needs_refresh && !skip),
        },
    )))
}

fn cleanup<S: AuthSchema>(ctx: &AuthContext<S>, request: &impl SessionRequest) -> AuthResult<()> {
    let cache_name = related_cookie_name(&ctx.config, "session_data");
    let mut names = vec![ctx.config.session.cookie_name.clone(), cache_name.clone()];
    if ctx.config.account.store_account_cookie {
        names.push(related_cookie_name(&ctx.config, "account_data"));
    }
    if matches!(
        ctx.config.account.store_state_strategy,
        crate::config::OAuthStateStrategy::Cookie
    ) {
        names.push(related_cookie_name(&ctx.config, "oauth_state"));
    }
    // Source expiration replaces earlier response entries for each cleared
    // cookie. The subsequent chunk-store cleanup retains incoming cache names.
    let prior = request.take_response_headers();
    let remember_name = related_cookie_name(&ctx.config, "dont_remember");
    for (name, value) in prior {
        let replaced = name.eq_ignore_ascii_case("set-cookie")
            && names
                .iter()
                .chain(std::iter::once(&remember_name))
                .any(|cookie_name| {
                    value.starts_with(&format!("{cookie_name}="))
                        || value.starts_with(&format!("{cookie_name}."))
                });
        if !replaced {
            request.queue_response_header(name, value);
        }
    }
    for header in session_cleanup_headers(&ctx.config, request.session_headers(), false)? {
        request.queue_response_header("Set-Cookie", header);
    }
    Ok(())
}

/// Clear session cookies and the actual incoming compact-cache chunks.
/// Pending two-factor stages can preserve the signed browser preference.
///
/// # Errors
/// Propagates invalid configured cookie attributes.
pub fn session_cleanup_headers(
    config: &crate::AuthConfig,
    headers: &std::collections::HashMap<String, String>,
    skip_remember: bool,
) -> AuthResult<Vec<String>> {
    let cache_name = related_cookie_name(config, "session_data");
    let mut names = vec![config.session.cookie_name.clone(), cache_name.clone()];
    if config.account.store_account_cookie {
        let account_name = related_cookie_name(config, "account_data");
        names.push(account_name.clone());
        names.extend(existing_names(&cookie_values(headers, true), &account_name));
    }
    if matches!(
        config.account.store_state_strategy,
        crate::config::OAuthStateStrategy::Cookie
    ) {
        names.push(related_cookie_name(config, "oauth_state"));
    }
    names.extend(existing_names(&cookie_values(headers, true), &cache_name));
    if !skip_remember {
        names.push(related_cookie_name(config, "dont_remember"));
    }
    names
        .into_iter()
        .map(|name| super::cookie_header(&name, "", Some(0.0), config))
        .collect()
}
