use crate::session::cookie_cache as cache;
use crate::session::cookie_cache::runtime::{
    IssuancePreference, PendingIssuance, PublishedSessionSnapshot, browser_preference,
    chunked_cookie_headers, record_publication,
};
use crate::types::RequestExtensions;
use crate::utils::LockUnpoisoned;
use crate::utils::cookie_utils::{related_cookie_name, sign_cookie_value};
use crate::{
    AuthContext, AuthError, AuthResult, AuthSchema, AuthSession, AuthUser, CacheVersionContext,
};
/// Build cache cookies from the actual stored models and their public output.
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

pub(in crate::session::cookie_cache::runtime) async fn stored_read_headers<S: AuthSchema>(
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

pub(in crate::session::cookie_cache::runtime) async fn build_headers<
    S: AuthSchema,
    H: std::hash::BuildHasher + Sync,
>(
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
    let configured_age = crate::utils::cookie_utils::session_cache_max_age(
        &ctx.config,
        cache::effective_max_age(config.max_age),
    );
    let value = match config.strategy {
        crate::CookieCacheStrategy::Compact => cache::encode_compact(
            context.public_user(),
            context.public_session(),
            &version,
            now,
            if configured_age == 0.0 || configured_age.is_nan() {
                60.0
            } else {
                configured_age
            },
            dont_remember,
            ctx.config.current_secret(),
        )?,
        crate::CookieCacheStrategy::Jwt | crate::CookieCacheStrategy::Jwe => {
            let payload = cache::jwt::payload(
                context.public_user(),
                context.public_session(),
                &version,
                now,
            )?;
            let max_age = if dont_remember {
                300.0
            } else {
                cache::effective_max_age(configured_age)
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
                .get::<cache::jwt::CookieCacheSignerHandle<S>>()
            {
                signer.0.sign(payload, max_age, ctx, transaction).await?
            } else {
                cache::jwt::encode(payload, ctx.config.current_secret(), max_age)?
            }
        }
    };
    let name = related_cookie_name(&ctx.config, "session_data");
    let max_age = (!dont_remember).then_some(configured_age);
    chunked_cookie_headers(&name, &value, max_age, &ctx.config, headers, false)
}

/// Await cache emission before publishing a completed-session snapshot.
/// Error headers are request local and only explicit public API errors retain
/// the queued token; ordinary callback errors follow the source empty500 path.
#[doc(hidden)]
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

pub(in crate::session::cookie_cache::runtime) async fn emit_snapshot_inner<S: AuthSchema>(
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
        .and_then(crate::types::RequestExtensions::get::<IssuancePreference>)
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
        let token_header = cache::cookie_header(
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
        let mut data = pending.0.lock_unpoisoned();
        data.prior_headers.push(token_header);
        if dont_remember {
            data.prior_headers.push(cache::cookie_header(
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
                let mut data = pending.0.lock_unpoisoned();
                data.prior_headers.clear();
                data.cache_headers.extend(cache_headers);
            }
            record_publication(published);
            Ok(())
        }
        Err(error) => {
            if let Some(pending) = pending {
                pending.0.lock_unpoisoned().ordinary_error =
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
    let mut data = std::mem::take(&mut *pending.0.lock_unpoisoned());
    if data.ordinary_error {
        return (Vec::new(), true);
    }
    data.prior_headers.extend(data.cache_headers);
    (data.prior_headers, false)
}
