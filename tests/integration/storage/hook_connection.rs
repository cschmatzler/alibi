//! Application SQL sees transaction-local auth writes and shares their rollback.
use super::{Backend, Db, Sqlx, TestResult};
use alibi::sqlx::{SqlxBackend, SqlxHookContext, SqlxHookContextExt, SqlxPool};
use alibi::store::{AccountStore, DatabaseHooks, HookControl, UserStore, transaction};
use alibi::{AuthAccount, AuthError, AuthResult, AuthSchema, AuthUser, CreateAccount, CreateUser};
use async_trait::async_trait;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct ObserveAccount(Arc<Mutex<Vec<(bool, String)>>>);

impl ObserveAccount {
    async fn observe(&self, user_id: &str, ctx: &SqlxHookContext<'_>) -> AuthResult<()> {
        let mut guard = ctx.connection().await?;
        // The engine is an application choice; transaction selection is the API's job.
        macro_rules! observe {
            ($connection:expr) => {{
                let connection = $connection.ok_or_else(|| AuthError::internal("wrong engine"))?;
                let email: String = sqlx::query_scalar("SELECT email FROM \"user\" WHERE id = $1")
                    .bind(user_id)
                    .fetch_one(&mut *connection)
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                _ = sqlx::query("INSERT INTO hook_audit (email) VALUES ($1)")
                    .bind(&email)
                    .execute(connection)
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                email
            }};
        }
        let email = match ctx.db {
            SqlxPool::Sqlite(_) => observe!(guard.sqlite()),
            SqlxPool::Postgres(_) => observe!(guard.postgres()),
        };
        self.0.lock().unwrap().push((ctx.tx.is_some(), email));
        Ok(())
    }
}

#[async_trait]
impl<S: AuthSchema> DatabaseHooks<S, SqlxBackend> for ObserveAccount {
    async fn before_create_account(
        &self,
        input: &mut CreateAccount,
        ctx: &SqlxHookContext<'_>,
    ) -> AuthResult<HookControl> {
        self.observe(&input.user_id, ctx).await?;
        Ok(HookControl::Continue)
    }

    async fn after_create_account(
        &self,
        account: &S::Account,
        ctx: &SqlxHookContext<'_>,
    ) -> AuthResult<()> {
        self.observe(&account.user_id(), ctx).await
    }
}

fn account(user_id: &str) -> CreateAccount {
    CreateAccount {
        user_id: user_id.into(),
        provider_id: "application".into(),
        account_id: "hook-query".into(),
        additional_fields: Default::default(),
        access_token: None,
        refresh_token: None,
        id_token: None,
        access_token_expires_at: None,
        refresh_token_expires_at: None,
        scope: None,
        password: None,
    }
}

async fn hook_connection(db: Db) -> TestResult {
    let (connection, store) = db.migrated::<Sqlx>("hook-connection-secret").await?;
    _ = db
        .raw
        .execute("CREATE TABLE hook_audit (email TEXT NOT NULL)", &[])
        .await?;
    let hook = ObserveAccount::default();
    let store = store.hook(hook.clone());

    // Both branches create the account while its user is still uncommitted.
    // A pool-only implementation cannot read that user, even if the hook runs.
    for rollback in [true, false] {
        let email = if rollback {
            "rollback@example.test"
        } else {
            "commit@example.test"
        };
        let result = transaction(&store, move |tx| {
            Box::pin(async move {
                let user = tx.create_user(CreateUser::new().with_email(email)).await?;
                _ = tx.create_account(account(&user.id())).await?;
                if rollback {
                    return Err(AuthError::forbidden(
                        "roll back application and auth writes",
                    ));
                }
                Ok(())
            })
        })
        .await;
        if rollback {
            assert!(
                matches!(result, Err(AuthError::Forbidden(ref message)) if message == "roll back application and auth writes")
            );
            assert_eq!(db.count("user").await?, 0);
            assert_eq!(db.count("account").await?, 0);
            assert_eq!(db.count("hook_audit").await?, 0);
            assert_eq!(*hook.0.lock().unwrap(), vec![(true, email.to_owned())]);
        } else {
            result?;
            assert_eq!(db.count("user").await?, 1);
            assert_eq!(db.count("account").await?, 1);
            assert_eq!(db.count("hook_audit").await?, 2);
            assert_eq!(
                *hook.0.lock().unwrap(),
                vec![(true, email.to_owned()), (false, email.to_owned())]
            );
        }
        hook.0.lock().unwrap().clear();
    }

    let user = store
        .create_user(CreateUser::new().with_email("pool@example.test"))
        .await?;
    _ = store.create_account(account(&user.id())).await?;
    assert_eq!(
        *hook.0.lock().unwrap(),
        vec![
            (false, "pool@example.test".into()),
            (false, "pool@example.test".into())
        ]
    );
    assert_eq!(db.count("account").await?, 2);
    assert_eq!(db.count("hook_audit").await?, 4);
    Sqlx::close(connection).await
}

#[tokio::test]
async fn sqlite_hook_connection_uses_active_transaction_or_pool() -> TestResult {
    hook_connection(Db::sqlite().await?).await
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
async fn postgres_hook_connection_uses_active_transaction_or_pool() -> TestResult {
    hook_connection(Db::postgres().await?).await
}
