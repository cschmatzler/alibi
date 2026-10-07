//! Session creation hooks, tokens and batch lookup.

use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use alibi::{AuthConfig, AuthSchema};
use alibi_core::store::{
    DatabaseHookContext, DatabaseHooks, HookBackend, HookControl, SessionStore, UserStore,
    transaction,
};
use alibi_core::{AuthError, AuthResult, AuthSession, AuthUser, CreateSession, CreateUser};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use std::sync::{Arc, Mutex};

backend_tests!(
    javascript_only_cache_values_fall_back_without_reconstructing_or_mutating_owners,
    strict_cached_session_separates_invalid_sessions_from_storage_failures,
    session_cancel_preserves_default_wire_error_and_transaction_rollback,
    generates_default_tokens_before_hooks_and_persists_trusted_overrides,
    batch_session_lookup_returns_token_index_order_and_includes_expired_rows_once,
);
postgres_tests!(
    strict_cached_session_separates_invalid_sessions_from_storage_failures,
    session_cancel_preserves_default_wire_error_and_transaction_rollback,
    generates_default_tokens_before_hooks_and_persists_trusted_overrides,
    // Token-index order is SQLite's plan for the unique token index. Both
    // stores return PostgreSQL's physical row order instead.
);

fn input(user_id: &str, token: Option<&str>, expiry: DateTime<Utc>) -> CreateSession {
    CreateSession {
        additional_fields: alibi_core::field_policy::FieldValues::default(),
        token: token.map(str::to_owned),
        user_id: user_id.to_owned(),
        expires_at: expiry,
        ip_address: None,
        user_agent: None,
        impersonated_by: None,
        active_organization_id: None,
        active_team_id: None,
    }
}

struct RejectSession {
    cancel: bool,
    observed_transaction: Arc<Mutex<Option<bool>>>,
}

#[async_trait]
impl<S: AuthSchema, B: HookBackend> DatabaseHooks<S, B> for RejectSession {
    async fn before_create_session(
        &self,
        _session: &mut CreateSession,
        context: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        *self.observed_transaction.lock().unwrap() = Some(context.tx.is_some());
        if self.cancel {
            Ok(HookControl::Cancel)
        } else {
            Err(AuthError::forbidden(
                "session creation cancelled by database hook",
            ))
        }
    }
}

struct TokenHook {
    observed: Arc<Mutex<Option<String>>>,
}

#[async_trait]
impl<S: AuthSchema, B: HookBackend> DatabaseHooks<S, B> for TokenHook {
    async fn before_create_session(
        &self,
        session: &mut CreateSession,
        _context: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        *self.observed.lock().unwrap() = session.token.clone();
        session.token = Some("hook-assigned-token".to_owned());
        Ok(HookControl::Continue)
    }
}

async fn session_cancel_preserves_default_wire_error_and_transaction_rollback<B: Backend>(
    db: Db,
) -> TestResult {
    for cancel in [false, true] {
        for in_transaction in [false, true] {
            let db = db.fresh().await?;
            let (connection, store) = db
                .migrated::<B>("cancel-session-hook-secret-at-least-32")
                .await?;
            let observed = Arc::new(Mutex::new(None));
            let store = B::hook(
                store,
                RejectSession {
                    cancel,
                    observed_transaction: Arc::clone(&observed),
                },
            );
            let email = "cancel-owner@fixture.test";
            let expiry = Utc::now() + Duration::hours(1);
            let error = if in_transaction {
                transaction(&store, move |tx| {
                    Box::pin(async move {
                        let user = tx.create_user(CreateUser::new().with_email(email)).await?;
                        drop(
                            tx.create_session(input(
                                user.id().as_ref(),
                                Some("cancel-token"),
                                expiry,
                            ))
                            .await?,
                        );
                        Ok(())
                    })
                })
                .await
                .unwrap_err()
            } else {
                let user = store
                    .create_user(CreateUser::new().with_email(email))
                    .await?;
                store
                    .create_session(input(user.id().as_ref(), Some("cancel-token"), expiry))
                    .await
                    .unwrap_err()
            };
            assert_eq!(*observed.lock().unwrap(), Some(in_transaction));
            assert_eq!(matches!(error, AuthError::SessionCreationCancelled), cancel);
            assert_eq!(matches!(error, AuthError::Forbidden(_)), !cancel);
            let response = error.to_auth_response();
            assert_eq!(response.status, 403);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&response.body)?,
                serde_json::json!({"message":"session creation cancelled by database hook"})
            );
            assert!(store.get_session("cancel-token").await?.is_none());
            assert_eq!(
                store.get_user_by_email(email).await?.is_none(),
                in_transaction
            );
            B::close(connection).await?;
        }
    }
    Ok(())
}

async fn generates_default_tokens_before_hooks_and_persists_trusted_overrides<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("session-token-hook-local-secret-at-least-32")
        .await?;
    let user = store
        .create_user(CreateUser::new().with_email("session-hook@example.com"))
        .await?;
    let user = user.id().into_owned();
    let expiry = Utc::now() + Duration::hours(1);
    let first = store.create_session(input(&user, None, expiry)).await?;
    let second = store.create_session(input(&user, None, expiry)).await?;
    assert_eq!(first.token().len(), 32);
    assert!(
        first
            .token()
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric())
    );
    assert_ne!(first.token(), second.token());
    let explicit = store
        .create_session(input(&user, Some("trusted-server-override"), expiry))
        .await?;
    assert_eq!(explicit.token(), "trusted-server-override");
    assert!(
        store
            .create_session(input(&user, Some(explicit.token()), expiry))
            .await
            .is_err()
    );
    let observed = Arc::new(Mutex::new(None));
    let hooked = B::hook(
        store,
        TokenHook {
            observed: Arc::clone(&observed),
        },
    );
    let overridden = hooked.create_session(input(&user, None, expiry)).await?;
    let generated = observed
        .lock()
        .unwrap()
        .clone()
        .ok_or("Hook saw no token")?;
    assert_eq!(generated.len(), 32);
    assert!(generated.bytes().all(|byte| byte.is_ascii_alphanumeric()));
    assert_eq!(overridden.token(), "hook-assigned-token");
    assert!(hooked.get_session(&generated).await?.is_none());
    assert_eq!(
        hooked
            .get_session(overridden.token())
            .await?
            .map(|row| row.id().into_owned()),
        Some(overridden.id().into_owned())
    );
    B::close(connection).await
}

async fn batch_session_lookup_returns_token_index_order_and_includes_expired_rows_once<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("session-batch-local-secret-at-least-32")
        .await?;
    let user = store
        .create_user(CreateUser::new().with_email("session-batch@example.com"))
        .await?;
    let user = user.id().into_owned();
    let now = Utc::now();
    for (token, expiry) in [
        ("z-token", now + Duration::hours(1)),
        ("a-token", now - Duration::minutes(1)),
        ("m-token", now + Duration::hours(1)),
    ] {
        drop(
            store
                .create_session(input(&user, Some(token), expiry))
                .await?,
        );
    }
    let result = store
        .get_sessions_by_tokens(&[
            "z-token".to_owned(),
            "unknown".to_owned(),
            "a-token".to_owned(),
            "z-token".to_owned(),
            "m-token".to_owned(),
        ])
        .await?;
    assert_eq!(
        result.iter().map(AuthSession::token).collect::<Vec<_>>(),
        vec!["a-token", "m-token", "z-token"]
    );
    assert!(result.first().is_some_and(|row| row.expires_at() < now));
    assert_eq!(store.get_sessions_by_tokens(&[]).await?.len(), 0);
    let mut config = AuthConfig::new("session-batch-local-secret-at-least-32");
    config.advanced.database.default_find_many_limit = 2;
    let limited = B::store(Arc::new(config), &connection);
    assert_eq!(
        limited
            .get_sessions_by_tokens(&[
                "z-token".to_owned(),
                "a-token".to_owned(),
                "m-token".to_owned()
            ])
            .await?
            .iter()
            .map(AuthSession::token)
            .collect::<Vec<_>>(),
        vec!["a-token", "m-token"]
    );
    store.delete_session("m-token").await?;
    assert_eq!(
        store
            .get_sessions_by_tokens(&["m-token".to_owned(), "z-token".to_owned()])
            .await?
            .iter()
            .map(AuthSession::token)
            .collect::<Vec<_>>(),
        vec!["z-token"]
    );
    B::close(connection).await
}

// Source can return ill-formed UTF-16 and prototype-bearing JavaScript objects.
// Rust's public String/JSON views cannot represent these runtime values. This
// owner checks the deliberate native type boundary through a genuine builder,
// signed token, actual physical fallback and independent complete SQL rows.
async fn javascript_only_cache_values_fall_back_without_reconstructing_or_mutating_owners<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    use alibi::AuthBuilder;
    use alibi::plugins::SessionManagementPlugin;
    use alibi_core::{AuthRequest, HttpMethod};
    use alibi_core::{AuthenticatedUser, CookieCacheConfig};
    use serde_json::Value;
    const SECRET: &str = "compat-test-only-key-not-real-minimum-32chars";
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET)
        .base_url("http://localhost:42594")
        .session_cookie_cache(CookieCacheConfig {
            enabled: true,
            ..Default::default()
        });
    let store = B::store(Arc::new(config.clone()), &connection);
    let auth = AuthBuilder::<B::Schema>::new(config)
        .store(store)
        .plugin(SessionManagementPlugin::new())
        .build()
        .await?;
    let owner = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_email("native-exotic@example.test")
                .with_name("Physical Native Owner"),
        )
        .await?;
    let foreign = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_email("native-exotic-foreign@example.test")
                .with_name("Physical Native Foreign"),
        )
        .await?;
    let session = auth
        .store()
        .create_session(input(
            owner.id().as_ref(),
            Some("00010000000000000000000000000001"),
            Utc::now() + auth.config().session.expires_in,
        ))
        .await?;
    drop(
        auth.store()
            .create_session(input(
                foreign.id().as_ref(),
                Some("foreign-native-token"),
                Utc::now() + auth.config().session.expires_in,
            ))
            .await?,
    );
    let signed = alibi_core::utils::cookie_utils::sign_cookie_value(session.token(), SECRET);
    let token_cookie = format!("{}={signed}", auth.config().session.cookie_name);
    let vectors: Value = serde_json::from_str(include_str!(
        "../../fixtures/session/compact-exotic-inputs.json"
    ))?;
    let snapshot = db
        .raw
        .tables(&["users", "sessions", "accounts", "verifications"])
        .await?;
    let request = |header: &str| {
        let mut request = AuthRequest::new(HttpMethod::Get, "/api/auth/get-session");
        drop(
            request
                .headers
                .insert("cookie".into(), format!("{token_cookie}; {header}")),
        );
        request
    };
    let canonical = vectors["observations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "canonical")
        .unwrap();
    let cached = auth
        .context()
        .require_cached_session(&request(canonical["header"].as_str().unwrap()))
        .await?;
    assert!(matches!(cached.0, AuthenticatedUser::Cached(_)));
    assert_eq!(cached.0.name(), Some("Signed Exotic Owner"));
    for case in vectors["javascriptOnlyObservations"].as_array().unwrap() {
        let read = auth
            .context()
            .require_cached_session(&request(case["header"].as_str().unwrap()))
            .await?;
        assert!(
            matches!(read.0, AuthenticatedUser::Stored(_)),
            "{}",
            case["name"]
        );
        assert_eq!(read.0.id(), owner.id());
        assert_eq!(read.0.name(), Some("Physical Native Owner"));
        assert_eq!(read.1.token, session.token());
        assert_eq!(
            db.raw
                .tables(&["users", "sessions", "accounts", "verifications"])
                .await?,
            snapshot
        );
    }
    drop(auth);
    B::close(connection).await
}

// Application routes must not report a storage outage as a signed-out user.
async fn strict_cached_session_separates_invalid_sessions_from_storage_failures<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::plugins::SessionManagementPlugin;
    use alibi::{AuthBuilder, AuthenticatedUser};
    use alibi_core::{AuthRequest, CookieCacheConfig, HttpMethod};
    const SECRET: &str = "strict-session-test-key-minimum-32-characters";
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET)
        .base_url("http://localhost:42594")
        .session_cookie_cache(CookieCacheConfig {
            enabled: true,
            ..Default::default()
        });
    let auth = AuthBuilder::<B::Schema>::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .plugin(SessionManagementPlugin::new())
        .build()
        .await?;
    let owner = auth
        .store()
        .create_user(CreateUser::new().with_email("strict@example.test"))
        .await?;
    let session = auth
        .store()
        .create_session(input(
            owner.id().as_ref(),
            None,
            Utc::now() + auth.config().session.expires_in,
        ))
        .await?;
    let request = |token: &str, cache: &str| {
        let signed = alibi_core::utils::cookie_utils::sign_cookie_value(token, SECRET);
        let mut request = AuthRequest::new(HttpMethod::Get, "/api/auth/get-session");
        drop(request.headers.insert(
            "cookie".into(),
            format!("better-auth.session_token={signed}; {cache}"),
        ));
        request
    };
    let context = auth.context();

    // A malformed cache cookie is a cache miss; storage remains the authority.
    let (user, read) = context
        .require_cached_session_strict(&request(
            session.token(),
            "better-auth.session_data=not!base64",
        ))
        .await?;
    assert!(matches!(user, AuthenticatedUser::Stored(_)));
    assert_eq!(read.token, session.token());
    assert!(matches!(
        context
            .require_cached_session_strict(&request("unknown-token", ""))
            .await,
        Err(AuthError::Unauthenticated)
    ));

    let _ = db.raw.execute("DROP TABLE sessions", &[]).await?;
    let outage = context
        .require_cached_session_strict(&request(session.token(), ""))
        .await
        .unwrap_err();
    assert_eq!(outage.status_code(), 500, "{outage:?}");
    // The upstream-compatible plugin guard still answers every failure with 401.
    assert!(matches!(
        context
            .require_cached_session(&request(session.token(), ""))
            .await,
        Err(AuthError::Unauthenticated)
    ));
    drop(auth);
    B::close(connection).await
}
