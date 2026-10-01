use super::*;

use crate::hooks::{HookControl, SeaOrmHookContext, SeaOrmHooks};

use crate::store::{bundled_schema::BundledSchema, migrator::run_migrations};

use better_auth_core::store::UserStore;

use better_auth_core::{AuthConfig, AuthSession, CreateUser};

use chrono::Duration;

use sea_orm::Database;

use std::sync::{Arc, Mutex};

struct TokenHook {
    observed: Arc<Mutex<Option<String>>>,
}

#[async_trait]
impl SeaOrmHooks<BundledSchema> for TokenHook {
    async fn before_create_session(
        &self,
        session: &mut CreateSession,
        _context: &SeaOrmHookContext<'_>,
    ) -> AuthResult<HookControl> {
        *self
            .observed
            .lock()
            .map_err(|_error| AuthError::internal("Hook token observation lock poisoned"))? =
            session.token.clone();
        session.token = Some("hook-assigned-token".to_owned());
        Ok(HookControl::Continue)
    }
}

fn input(user_id: &str, token: Option<&str>, expiry: DateTime<Utc>) -> CreateSession {
    CreateSession {
        additional_fields: better_auth_core::field_policy::FieldValues::default(),
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

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn session_cancel_preserves_default_wire_error_and_transaction_rollback()
-> Result<(), Box<dyn std::error::Error>> {
    struct RejectSession {
        cancel: bool,
        observed_transaction: Arc<Mutex<Option<bool>>>,
    }
    #[async_trait]
    impl SeaOrmHooks<BundledSchema> for RejectSession {
        async fn before_create_session(
            &self,
            _session: &mut CreateSession,
            context: &SeaOrmHookContext<'_>,
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
    for cancel in [false, true] {
        for in_transaction in [false, true] {
            let db = Database::connect("sqlite::memory:").await?;
            run_migrations(&db).await?;
            let observed = Arc::new(Mutex::new(None));
            let store = SeaOrmStore::<BundledSchema>::new(
                AuthConfig::new("cancel-session-hook-secret-at-least-32"),
                db.clone(),
            )
            .hook(RejectSession {
                cancel,
                observed_transaction: Arc::clone(&observed),
            });
            let email = "cancel-owner@fixture.test";
            let expiry = Utc::now() + Duration::hours(1);
            let error = if in_transaction {
                better_auth_core::store::transaction(&store, move |tx| {
                    Box::pin(async move {
                        let user = tx.create_user(CreateUser::new().with_email(email)).await?;
                        drop(
                            tx.create_session(input(&user.id, Some("cancel-token"), expiry))
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
                    .create_session(input(&user.id, Some("cancel-token"), expiry))
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
            db.close().await?;
        }
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
async fn generates_default_tokens_before_hooks_and_persists_trusted_overrides()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    run_migrations(&database).await?;
    let store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("session-token-hook-local-secret-at-least-32"),
        database,
    );
    let user = store
        .create_user(CreateUser::new().with_email("session-hook@example.com"))
        .await?;
    let expiry = Utc::now() + Duration::hours(1);
    let first = store.create_session(input(&user.id, None, expiry)).await?;
    let second = store.create_session(input(&user.id, None, expiry)).await?;
    assert_eq!(first.token().len(), 32);
    assert!(
        first
            .token()
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric())
    );
    assert_ne!(first.token(), second.token());
    let explicit = store
        .create_session(input(&user.id, Some("trusted-server-override"), expiry))
        .await?;
    assert_eq!(explicit.token(), "trusted-server-override");
    assert!(
        store
            .create_session(input(&user.id, Some(explicit.token()), expiry))
            .await
            .is_err()
    );
    let observed = Arc::new(Mutex::new(None));
    let hooked = store.hook(TokenHook {
        observed: Arc::clone(&observed),
    });
    let overridden = hooked.create_session(input(&user.id, None, expiry)).await?;
    let generated = observed
        .lock()
        .map_err(|_error| std::io::Error::other("Observation lock poisoned"))?
        .clone()
        .ok_or_else(|| std::io::Error::other("Hook saw no token"))?;
    assert_eq!(generated.len(), 32);
    assert!(generated.bytes().all(|byte| byte.is_ascii_alphanumeric()));
    assert_eq!(overridden.token(), "hook-assigned-token");
    assert!(hooked.get_session(&generated).await?.is_none());
    assert_eq!(
        hooked
            .get_session(overridden.token())
            .await?
            .map(|row| row.id),
        Some(overridden.id)
    );
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
async fn batch_session_lookup_returns_token_index_order_and_includes_expired_rows_once()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    run_migrations(&database).await?;
    let store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("session-batch-local-secret-at-least-32"),
        database,
    );
    let user = store
        .create_user(CreateUser::new().with_email("session-batch@example.com"))
        .await?;
    let now = Utc::now();
    for (token, expiry) in [
        ("z-token", now + Duration::hours(1)),
        ("a-token", now - Duration::minutes(1)),
        ("m-token", now + Duration::hours(1)),
    ] {
        drop(
            store
                .create_session(input(&user.id, Some(token), expiry))
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
    assert!(store.get_sessions_by_tokens(&[]).await?.is_empty());
    let mut config = store.config().as_ref().clone();
    config.advanced.database.default_find_many_limit = 2;
    let limited = SeaOrmStore::<BundledSchema>::new(config, store.connection().clone());
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
    Ok(())
}
