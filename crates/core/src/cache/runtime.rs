//! Request-local cache cookies and genuine stored/cached snapshot transitions.
use super::{CacheValidation, CacheVersionContext};
use crate::types::RequestExtensions;
use crate::utils::cookie_utils::{related_cookie_name, sign_cookie_value, verify_cookie_value};
use crate::{AuthContext, AuthError, AuthRequest, AuthResult, AuthSchema, AuthSession};
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
struct PublishedSession(Option<(crate::UserView, crate::SessionView)>);

/// The snapshot whose session cookies completed successfully in this dispatch.
/// Response hooks may observe it; it never establishes authentication.
#[must_use]
pub fn published_session(request: &AuthRequest) -> Option<(crate::UserView, crate::SessionView)> {
    request
        .extensions()
        .get::<PublishedSession>()
        .and_then(|session| session.0.clone())
}

/// Retire cookie publication when a real login becomes a pending factor challenge.
pub fn discard_issuance(request: &AuthRequest) {
    request.extensions().insert(PublishedSession(None));
    if let Some(pending) = request.extensions().get::<PendingIssuance>() {
        *pending
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = PendingData::default();
    }
}

fn record_publication(user: crate::UserView, session: crate::SessionView) {
    if let Some(request) = crate::hooks::current_request_hook_context() {
        request
            .extensions
            .insert(PublishedSession(Some((user, session))));
    }
}

/// Read the metadata attached to the actual authenticated hook snapshot.
#[must_use]
pub fn session_hook_cache_metadata(request: &AuthRequest) -> Option<SessionHookCacheMetadata> {
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
pub fn clear_established_session<S: AuthSchema>(request: &AuthRequest) {
    request.extensions().insert(EstablishedSession::<S>(None));
}

fn establish<S: AuthSchema>(
    ctx: &AuthContext<S>,
    request: &AuthRequest,
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
            headers: request.headers.clone(),
            virtual_session: request.virtual_session().cloned(),
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

fn cookies<H: std::hash::BuildHasher + Sync>(
    headers: &std::collections::HashMap<String, String, H>,
) -> IndexMap<String, String> {
    let mut values = IndexMap::new();
    if let Some(header) = headers.get("cookie") {
        for cookie in cookie::Cookie::split_parse(header).flatten() {
            _ = values.entry(cookie.name().into()).or_insert_with(|| {
                percent_encoding::percent_decode_str(cookie.value())
                    .decode_utf8_lossy()
                    .into_owned()
            });
        }
    }
    values
}

fn chunk_index(name: &str, base: &str) -> Option<u64> {
    let suffix = name.strip_prefix(base)?.strip_prefix('.')?;
    let index: u64 = suffix.parse().ok()?;
    (index <= 9_007_199_254_740_991 && index.to_string() == suffix).then_some(index)
}

fn cache_value(values: &IndexMap<String, String>, name: &str) -> Option<String> {
    if let Some(value) = values.get(name).filter(|value| !value.is_empty()) {
        return Some(value.clone());
    }
    let mut chunks: Vec<_> = values
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
        .and_then(|value| verify_cookie_value(value, &config.secret))
        .is_some_and(|value| !value.is_empty())
}

/// Build cache cookies from the actual stored models and their public output.
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub async fn stored_headers<S: AuthSchema, H: std::hash::BuildHasher + Sync>(
    ctx: &AuthContext<S>,
    user: &S::User,
    session: &S::Session,
    headers: &std::collections::HashMap<String, String, H>,
    dont_remember: bool,
) -> AuthResult<Vec<String>> {
    let context = CacheVersionContext::created(
        user.clone(),
        session.clone(),
        ctx.user_view(user),
        ctx.session_view(session),
    );
    build_headers(ctx, context, headers, dont_remember).await
}

async fn stored_read_headers<S: AuthSchema>(
    ctx: &AuthContext<S>,
    user: &S::User,
    session: &S::Session,
    headers: &std::collections::HashMap<String, String>,
) -> AuthResult<Vec<String>> {
    let context = CacheVersionContext::stored(ctx.user_view(user), ctx.session_view(session));
    build_headers(ctx, context, headers, false).await
}

async fn build_headers<S: AuthSchema, H: std::hash::BuildHasher + Sync>(
    ctx: &AuthContext<S>,
    context: CacheVersionContext,
    headers: &std::collections::HashMap<String, String, H>,
    dont_remember: bool,
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
    super::validate_config(config)?;
    let version = match &config.version {
        Some(policy) => policy.resolve(&context).await?,
        None => "1".into(),
    };
    let value = super::encode_compact(
        context.user(),
        context.session(),
        &version,
        chrono::Utc::now().timestamp_millis(),
        config.max_age,
        dont_remember,
        &ctx.config.secret,
    )?;
    let name = related_cookie_name(&ctx.config, "session_data");
    let max_age = (!dont_remember).then(|| super::effective_max_age(config.max_age));
    let empty_header = super::cookie_header(&format!("{name}.99"), "", max_age, &ctx.config)?;
    let capacity = 4050_usize.saturating_sub(empty_header.len());
    let count = if capacity == 0 {
        usize::MAX
    } else {
        value.len().div_ceil(capacity)
    };
    let mut output = IndexMap::new();
    for old in existing_names(&cookies(headers), &name) {
        drop(output.insert(
            old.clone(),
            super::cookie_header(&old, "", Some(0.0), &ctx.config)?,
        ));
    }
    if count <= 1 {
        drop(output.insert(
            name.clone(),
            super::cookie_header(&name, &value, max_age, &ctx.config)?,
        ));
    } else if count <= 100 {
        // Encoded compact values are ASCII, so byte chunking matches JS strings.
        for (index, chunk) in value.as_bytes().chunks(capacity).enumerate() {
            let chunk = std::str::from_utf8(chunk)
                .map_err(|_error| AuthError::internal("Invalid compact cache encoding"))?;
            let part = format!("{name}.{index}");
            drop(output.insert(
                part.clone(),
                super::cookie_header(&part, chunk, max_age, &ctx.config)?,
            ));
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
    user: &S::User,
    session: &S::Session,
) -> AuthResult<()> {
    emit_issuance_snapshot(
        ctx,
        CacheVersionContext::created(
            user.clone(),
            session.clone(),
            ctx.user_view(user),
            ctx.session_view(session),
        ),
    )
    .await
}

/// Publish the user snapshot chosen by a completed authentication stage.
/// The caller must establish the session and retain its owner and token.
///
/// # Errors
/// Propagates cookie encoding and configured cache-version callback errors.
#[doc(hidden)]
#[expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    reason = "Preserve JavaScript Number rounding at the compatibility boundary"
)]
pub async fn emit_issuance_snapshot<S: AuthSchema>(
    ctx: &AuthContext<S>,
    context: CacheVersionContext,
) -> AuthResult<()> {
    let published = (context.user().clone(), context.session().clone());
    if !ctx
        .config
        .session
        .cookie_cache
        .as_ref()
        .is_some_and(|config| config.enabled)
    {
        record_publication(published.0, published.1);
        return Ok(());
    }
    let request = crate::hooks::current_request_hook_context();
    let headers = request
        .as_ref()
        .map(|request| request.headers.clone())
        .unwrap_or_default();
    let dont_remember = request
        .as_ref()
        .and_then(|request| request.extensions.get::<IssuancePreference>())
        .map_or_else(
            || browser_preference(&headers, &ctx.config),
            |value| value.0,
        );
    let pending = request.as_ref().and_then(|request| {
        if request.extensions.get::<PendingIssuance>().is_none() {
            request.extensions.insert(PendingIssuance::default());
        }
        request.extensions.get::<PendingIssuance>()
    });
    if let Some(pending) = &pending {
        let token_header = super::cookie_header(
            &ctx.config.session.cookie_name,
            &percent_encoding::percent_decode_str(&sign_cookie_value(
                &context.session().token,
                &ctx.config.secret,
            ))
            .decode_utf8_lossy(),
            (!dont_remember).then(|| ctx.config.session.expires_in.num_seconds() as f64),
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
                    &ctx.config.secret,
                ))
                .decode_utf8_lossy(),
                None,
                &ctx.config,
            )?);
        }
    }
    match build_headers(ctx, context, &headers, dont_remember).await {
        Ok(cache_headers) => {
            if let Some(pending) = pending {
                let mut data = pending
                    .0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                data.prior_headers.clear();
                data.cache_headers.extend(cache_headers);
            }
            record_publication(published.0, published.1);
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
    request: &AuthRequest,
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
    let values = cookies(&request.headers);
    if enabled.is_none() {
        for old in existing_names(&values, &name) {
            request.queue_response_header(
                "Set-Cookie",
                super::cookie_header(&old, "", Some(0.0), &ctx.config)?,
            );
        }
        return Ok(None);
    }
    if request
        .query
        .get("disableCookieCache")
        .is_some_and(|value| !value.is_empty())
    {
        return Ok(None);
    }
    let Some(token) = token else {
        return Ok(None);
    };
    let Some(value) = cache_value(&values, &name) else {
        return Ok(None);
    };
    let config =
        enabled.ok_or_else(|| AuthError::internal("Missing enabled cache configuration"))?;
    super::validate_config(config)?;
    if let Some(cache) = super::decode_compact(&value, &ctx.config.secret)
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

/// Shared direct/nested get-session lifecycle for the explicitly migrated
/// guards. Nested reads behave as GET even when their parent endpoint is POST.
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
#[expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    reason = "Preserve JavaScript Number rounding at the compatibility boundary"
)]
pub async fn authenticated<S: AuthSchema>(
    ctx: &AuthContext<S>,
    request: &AuthRequest,
    direct: bool,
) -> AuthResult<Option<AuthenticatedRead<S>>> {
    if let Some(established) = request.extensions().get::<EstablishedSession<S>>()
        && let Some(established) = &established.0
        && Arc::ptr_eq(&established.config, &ctx.config)
        && Arc::ptr_eq(&established.database, &ctx.database)
        && established.headers == request.headers
        && established.virtual_session.as_ref() == request.virtual_session()
    {
        let read = &established.read;
        return Ok(Some(AuthenticatedRead {
            user: read.user.clone(),
            session: read.session.clone(),
            needs_refresh: read.needs_refresh,
        }));
    }
    request.extensions().insert(SessionHookCache(None));
    if let Some(session) = request.virtual_session() {
        let Some(user) = ctx.database.get_user_by_id(&session.user_id).await? else {
            return Ok(None);
        };
        request.set_session_hook_snapshot(ctx.user_view(&user), ctx.session_view(session));
        return Ok(Some(establish(
            ctx,
            request,
            AuthenticatedRead {
                user: crate::AuthenticatedUser::Stored(user),
                session: ctx.session_view(session),
                needs_refresh: None,
            },
        )));
    }
    if let Some(cache) = read(ctx, request).await? {
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
    let Some(original) = ctx.database.get_session(&token).await? else {
        cleanup(ctx, request)?;
        return Ok(None);
    };
    let Some(user) = ctx
        .database
        .get_user_by_id(original.user_id().as_ref())
        .await?
    else {
        cleanup(ctx, request)?;
        return Ok(None);
    };
    request.set_session_hook_snapshot(ctx.user_view(&user), ctx.session_view(&original));
    let suppressed = manager.request_disables_refresh(request);
    let deferred = ctx.config.session.defer_session_refresh
        && !(direct && request.method() == &crate::HttpMethod::Post);
    let read = manager
        .read_loaded_session(
            original,
            crate::session::SessionReadOptions {
                allow_refresh: !suppressed && !deferred,
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
                    &ctx.config.secret,
                ))
                .decode_utf8_lossy(),
                Some(ctx.config.session.expires_in.num_seconds() as f64),
                &ctx.config,
            )?,
        );
    }
    if !suppressed {
        for header in stored_read_headers(ctx, &user, &session, &request.headers).await? {
            request.queue_response_header("Set-Cookie", header);
        }
    }
    Ok(Some(establish(
        ctx,
        request,
        AuthenticatedRead {
            user: crate::AuthenticatedUser::Stored(user),
            session: ctx.session_view(&session),
            needs_refresh: (deferred && !suppressed).then_some(read.needs_refresh),
        },
    )))
}

fn cleanup<S: AuthSchema>(ctx: &AuthContext<S>, request: &AuthRequest) -> AuthResult<()> {
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
    for header in session_cleanup_headers(&ctx.config, &request.headers, false)? {
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
        names.push(related_cookie_name(config, "account_data"));
    }
    if matches!(
        config.account.store_state_strategy,
        crate::config::OAuthStateStrategy::Cookie
    ) {
        names.push(related_cookie_name(config, "oauth_state"));
    }
    names.extend(existing_names(&cookies(headers), &cache_name));
    if !skip_remember {
        names.push(related_cookie_name(config, "dont_remember"));
    }
    names
        .into_iter()
        .map(|name| super::cookie_header(&name, "", Some(0.0), config))
        .collect()
}
