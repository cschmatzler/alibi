//! Wallet owner lookup and atomic user deletion.

use super::{Backend, Db, TestResult, backend_tests};
use better_auth_core::store::{UserStore, WalletAddressStore};
use better_auth_core::{AuthError, AuthUser, CreateUser, CreateWalletAddress};

backend_tests!(wallet_owner_lookup_and_user_deletion_keep_state_atomic);

async fn wallet_owner_lookup_and_user_deletion_keep_state_atomic<B: Backend>(db: Db) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("wallet-owner-native-at-least-32-characters")
        .await?;
    let owner = store
        .create_user(CreateUser::new().with_email("wallet-owner@fixture.test"))
        .await?
        .id()
        .into_owned();
    let other = store
        .create_user(CreateUser::new().with_email("wallet-other@fixture.test"))
        .await?
        .id()
        .into_owned();
    let address = "0x52908400098527886E0F7030069857D2E4169EE7";
    let first = store
        .create_wallet_address(CreateWalletAddress {
            user_id: owner.clone(),
            address: address.to_owned(),
            chain_id: 100.0,
            is_primary: true,
        })
        .await?;
    let second = store
        .create_wallet_address(CreateWalletAddress::new(&other, address, 1.0))
        .await?;
    let third = store
        .create_wallet_address(CreateWalletAddress::new(
            &owner,
            "0xde709f2102306220921060314715629080e2fb77",
            1e21,
        ))
        .await?;
    assert_eq!(
        store.get_wallet_address(address, None).await?,
        Some(first.clone())
    );
    assert_eq!(
        store.get_wallet_address(address, Some(1.0)).await?,
        Some(second.clone())
    );
    assert_eq!(
        store.get_wallet_address(&third.address, Some(1e21)).await?,
        Some(third.clone())
    );
    assert!(matches!(
        store
            .create_wallet_address(CreateWalletAddress::new("missing-owner", address, 2.0))
            .await,
        Err(AuthError::UserNotFound)
    ));
    assert_eq!(db.count("wallet_address").await?, 3);
    _ = db.execute("CREATE TRIGGER wallet_user_delete_abort BEFORE DELETE ON users BEGIN SELECT RAISE(ABORT,'wallet deletion veto'); END", &[]).await?;
    assert!(store.delete_user(&owner).await.is_err());
    assert!(store.get_user_by_id(&owner).await?.is_some());
    assert_eq!(
        store.get_wallet_address(address, Some(100.0)).await?,
        Some(first)
    );
    assert_eq!(
        store.get_wallet_address(&third.address, Some(1e21)).await?,
        Some(third)
    );
    assert_eq!(
        store.get_wallet_address(address, Some(1.0)).await?,
        Some(second.clone())
    );
    _ = db
        .execute("DROP TRIGGER wallet_user_delete_abort", &[])
        .await?;
    store.delete_user(&owner).await?;
    assert!(store.get_user_by_id(&owner).await?.is_none());
    assert!(
        store
            .get_wallet_address(address, Some(100.0))
            .await?
            .is_none()
    );
    assert!(
        store
            .get_wallet_address("0xde709f2102306220921060314715629080e2fb77", None)
            .await?
            .is_none()
    );
    assert_eq!(store.get_wallet_address(address, None).await?, Some(second));
    assert!(store.get_user_by_id(&other).await?.is_some());
    assert_eq!(db.count("wallet_address").await?, 1);
    B::close(connection).await
}
