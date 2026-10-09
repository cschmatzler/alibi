//! OAuth account rows keep row identities without choosing ambiguous owners.

use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use alibi::AuthConfig;
use alibi::store::{AccountStore, UserStore};
use alibi::{AuthError, AuthUser, CreateAccount, CreateUser, DatabaseError};
use std::sync::Arc;

backend_tests!(independent_connections_admit_duplicate_account_rows_without_selecting_an_owner);
postgres_tests!(independent_connections_admit_duplicate_account_rows_without_selecting_an_owner,);

fn account(user_id: &str) -> CreateAccount {
    CreateAccount {
        additional_fields: Default::default(),
        user_id: user_id.to_owned(),
        provider_id: "gitlab".into(),
        account_id: "shared-provider-identity".into(),
        access_token: Some("retained-access".into()),
        refresh_token: Some("retained-refresh".into()),
        id_token: None,
        access_token_expires_at: None,
        refresh_token_expires_at: None,
        scope: Some("read_user".into()),
        password: None,
    }
}

async fn independent_connections_admit_duplicate_account_rows_without_selecting_an_owner<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (first_db, first) = db
        .migrated::<B>("independent-account-admission-secret")
        .await?;
    let second_db = B::connect(&db.url, None).await?;
    let second = B::store(
        Arc::new(AuthConfig::new("independent-account-admission-secret")),
        &second_db,
    );
    let owner = first
        .create_user(CreateUser::new().with_email("concurrent@account-pair.test"))
        .await?;
    let foreign = first
        .create_user(CreateUser::new().with_email("foreign@account-pair.test"))
        .await?;
    let mut peer_input = account(foreign.id().as_ref());
    peer_input.account_id = "independent-foreign-identity".into();
    let peer = first.create_account(peer_input).await?;
    let (left, right) = tokio::join!(
        first.create_account(account(owner.id().as_ref())),
        second.create_account(account(owner.id().as_ref()))
    );
    let left = left?;
    let right = right?;
    assert_ne!(
        serde_json::to_value(&left)?["id"],
        serde_json::to_value(&right)?["id"]
    );
    let rows = first.get_user_accounts(owner.id().as_ref()).await?;
    assert_eq!(rows.len(), 2);
    let second_rows = serde_json::to_value(second.get_user_accounts(owner.id().as_ref()).await?)?;
    for expected in [left, right] {
        let expected = serde_json::to_value(expected)?;
        assert!(second_rows.as_array().unwrap().contains(&expected));
    }
    assert!(matches!(
        second
            .get_account("gitlab", "shared-provider-identity")
            .await,
        Err(AuthError::Database(DatabaseError::AmbiguousAccount { .. }))
    ));
    assert_eq!(
        serde_json::to_value(first.get_user_accounts(foreign.id().as_ref()).await?)?,
        serde_json::to_value(vec![peer])?
    );
    B::close(first_db).await?;
    B::close(second_db).await?;
    Ok(())
}
