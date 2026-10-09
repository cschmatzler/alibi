use super::*;
/// Try the authenticated compact cache before any physical session lookup.
/// Missing or invalid cache data can only produce a storage fallback.
pub async fn read<S: AuthSchema>(
    ctx: &AuthContext<S>,
    request: &impl SessionRequest,
) -> AuthResult<Option<super::super::CompactCache>> {
    read_cache(ctx, request, CacheDecoding::Http).await
}

/// How a compact envelope that is not valid base64 is treated.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CacheDecoding {
    /// Raise the decoding error, which get-session answers with its 500.
    Http,
    /// Treat it as a cache miss; storage remains the authority.
    MalformedIsMiss,
}

async fn read_cache<S: AuthSchema>(
    ctx: &AuthContext<S>,
    request: &impl SessionRequest,
    decoding: CacheDecoding,
) -> AuthResult<Option<super::super::CompactCache>> {
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
                super::super::cookie_header(&old, "", Some(0.0), &ctx.config)?,
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
        crate::CookieCacheStrategy::Compact => match decoding {
            CacheDecoding::Http => {
                super::super::decode_compact_http(&value, ctx.config.current_secret())?
            }
            CacheDecoding::MalformedIsMiss => {
                super::super::decode_compact(&value, ctx.config.current_secret())
            }
        },
        crate::CookieCacheStrategy::Jwt => {
            if let Some(signer) = ctx
                .extensions
                .get::<super::super::jwt::CookieCacheSignerHandle<S>>()
            {
                signer
                    .0
                    .verify(&value, ctx)
                    .await?
                    .and_then(|claims| super::super::jwt::decode_payload(&claims.into(), 15.0))
            } else {
                super::super::jwt::decode(&value, ctx.config.current_secret())
            }
        }
        crate::CookieCacheStrategy::Jwe => ctx
            .config
            .verification_secrets()
            .find_map(|secret| {
                crate::utils::jwe::decode(secret, "better-auth-session", &value).ok()
            })
            .and_then(|claims| super::super::jwt::decode_payload(&claims.into(), 15.0)),
    };
    if let Some(cache) = decoded
        && let CacheValidation::Hit(cache) = super::super::validate_compact(
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
        super::super::cookie_header(&name, "", Some(0.0), &ctx.config)?,
    );
    Ok(None)
}

/// Renew an authenticated envelope without changing embedded session state.
pub(crate) async fn renew_cache<S: AuthSchema>(
    ctx: &AuthContext<S>,
    request: &impl SessionRequest,
    cache: &super::super::CompactCache,
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
                Some((super::super::effective_max_age(config.max_age) * 0.2).floor())
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
                super::super::cookie_header(
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
pub async fn authenticated<S: AuthSchema>(
    ctx: &AuthContext<S>,
    request: &impl SessionRequest,
    direct: bool,
) -> AuthResult<Option<AuthenticatedRead<S>>> {
    authenticated_with(ctx, request, direct, CacheDecoding::Http).await
}

pub(crate) async fn authenticated_with<S: AuthSchema>(
    ctx: &AuthContext<S>,
    request: &impl SessionRequest,
    direct: bool,
    decoding: CacheDecoding,
) -> AuthResult<Option<AuthenticatedRead<S>>> {
    if !direct && let Some(call) = request.endpoint_call() {
        let nested = call.session_read_context();
        crate::endpoint::with_endpoint_call_context(
            nested.clone(),
            Box::pin(authenticated_inner(ctx, &nested, false, decoding)),
        )
        .await
    } else {
        Box::pin(authenticated_inner(ctx, request, direct, decoding)).await
    }
}

#[expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    reason = "Preserve JavaScript Number rounding at the compatibility boundary"
)]
pub(in crate::session::cookie_cache::runtime) async fn authenticated_inner<S: AuthSchema>(
    ctx: &AuthContext<S>,
    request: &impl SessionRequest,
    direct: bool,
    decoding: CacheDecoding,
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
    if let Some(cache) = read_cache(ctx, request, decoding).await? {
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
            super::super::cookie_header(
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

pub(in crate::session::cookie_cache::runtime) fn cleanup<S: AuthSchema>(
    ctx: &AuthContext<S>,
    request: &impl SessionRequest,
) -> AuthResult<()> {
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
