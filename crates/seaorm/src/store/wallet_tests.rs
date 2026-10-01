use super::SeaOrmStore;
use super::bundled_schema::BundledSchema;
use super::entities::wallet_address;
use super::migrator::run_migrations;
use better_auth_core::store::{UserStore, WalletAddressStore};
use better_auth_core::{AuthConfig, AuthError, CreateUser, CreateWalletAddress};
use sea_orm::{ConnectionTrait, Database, EntityTrait, PaginatorTrait, Statement};

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
async fn wallet_owner_lookup_and_user_deletion_keep_state_atomic()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    run_migrations(&database).await?;
    let store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("wallet-owner-native-at-least-32-characters"),
        database.clone(),
    );
    let owner = store
        .create_user(CreateUser::new().with_email("wallet-owner@fixture.test"))
        .await?;
    let other = store
        .create_user(CreateUser::new().with_email("wallet-other@fixture.test"))
        .await?;
    let address = "0x52908400098527886E0F7030069857D2E4169EE7";
    let first = store
        .create_wallet_address(CreateWalletAddress {
            user_id: owner.id.clone(),
            address: address.to_owned(),
            chain_id: 100.0,
            is_primary: true,
        })
        .await?;
    let second = store
        .create_wallet_address(CreateWalletAddress::new(&other.id, address, 1.0))
        .await?;
    let third = store
        .create_wallet_address(CreateWalletAddress::new(
            &owner.id,
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
    assert_eq!(wallet_address::Entity::find().count(&database).await?, 3);
    let _ignored_to_owned = database.execute_raw(Statement::from_string(database.get_database_backend(),
        "CREATE TRIGGER wallet_user_delete_abort BEFORE DELETE ON users BEGIN SELECT RAISE(ABORT,'wallet deletion veto'); END".to_owned())).await?;
    assert!(store.delete_user(&owner.id).await.is_err());
    assert!(store.get_user_by_id(&owner.id).await?.is_some());
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
    let _ignored_to_owned_2 = database
        .execute_raw(Statement::from_string(
            database.get_database_backend(),
            "DROP TRIGGER wallet_user_delete_abort".to_owned(),
        ))
        .await?;
    store.delete_user(&owner.id).await?;
    assert!(store.get_user_by_id(&owner.id).await?.is_none());
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
    assert!(store.get_user_by_id(&other.id).await?.is_some());
    assert_eq!(wallet_address::Entity::find().count(&database).await?, 1);
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
async fn wallet_upgrade_preserves_installed_identity_and_defaults_primary_to_false()
-> Result<(), Box<dyn std::error::Error>> {
    use sea_orm_migration::{MigrationTrait, MigratorTrait};
    struct InstalledSchema;
    #[async_trait::async_trait]
    impl MigratorTrait for InstalledSchema {
        fn migrations() -> Vec<Box<dyn MigrationTrait>> {
            let mut migrations = super::migrator::AuthMigrator::migrations();
            drop(migrations.pop());
            migrations
        }
        fn migration_table_name() -> sea_orm::DynIden {
            use sea_orm::sea_query::IntoIden;
            "better_auth_migrations".into_iden()
        }
    }
    let database = Database::connect("sqlite::memory:").await?;
    InstalledSchema::up(&database, None).await?;
    let store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("wallet-upgrade-native-at-least-32-characters"),
        database.clone(),
    );
    let owner = store
        .create_user(CreateUser::new().with_email("wallet-upgrade@fixture.test"))
        .await?;
    run_migrations(&database).await?;
    let _ignored_execute_unprepared = database.execute_unprepared(&format!("INSERT INTO wallet_address (id,user_id,address,chain_id,created_at) VALUES ('upgraded-wallet','{}','0x52908400098527886E0F7030069857D2E4169EE7',1,'2026-09-30 00:00:00+00:00')",owner.id)).await?;
    let wallet = store
        .get_wallet_address("0x52908400098527886E0F7030069857D2E4169EE7", Some(1.0))
        .await?
        .ok_or("wallet missing after upgrade")?;
    assert_eq!(wallet.user_id, owner.id);
    assert!(!wallet.is_primary);
    assert_eq!(store.get_user_by_id(&owner.id).await?, Some(owner));
    run_migrations(&database).await?;
    assert_eq!(wallet_address::Entity::find().count(&database).await?, 1);
    Ok(())
}
