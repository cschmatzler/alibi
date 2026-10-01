//! Installed OAuth account rows keep row identities without choosing ambiguous owners.
#![expect(clippy::panic_in_result_fn, reason = "Persistence assertions propagate setup failures")]
use super::{SeaOrmStore, bundled_schema::BundledSchema, migrator::AuthMigrator};
use better_auth_core::store::{AccountStore, UserStore};
use better_auth_core::{AuthConfig, CreateAccount, CreateUser};
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement};
use sea_orm_migration::MigratorTrait;
type TestResult = Result<(), Box<dyn std::error::Error>>;
const UPGRADE: &str = "m20261001_000016_account_key_multiplicity";
fn account(user_id:&str)->CreateAccount {CreateAccount {user_id:user_id.to_owned(),provider_id:"gitlab".into(),account_id:"shared-provider-identity".into(),access_token:Some("retained-access".into()),refresh_token:Some("retained-refresh".into()),id_token:None,access_token_expires_at:None,refresh_token_expires_at:None,scope:Some("read_user".into()),password:None}}
async fn scalar(db:&DatabaseConnection,sql:&str)->Result<String,sea_orm::DbErr>{db.query_one_raw(Statement::from_string(DbBackend::Sqlite,sql)).await?.ok_or_else(||sea_orm::DbErr::Custom("missing snapshot".into()))?.try_get("","value")}
#[tokio::test]
async fn installed_account_upgrade_preserves_rows_and_app_schema_then_rejects_ambiguous_identity()->TestResult {
 let db=Database::connect("sqlite::memory:").await?;
 let prior=AuthMigrator::migrations().iter().take_while(|migration|migration.name()!=UPGRADE).count();
 AuthMigrator::up(&db,Some(u32::try_from(prior)?)).await?;
 let store=SeaOrmStore::<BundledSchema>::new(AuthConfig::new("installed-account-multiplicity-secret"),db.clone());
 let owner=store.create_user(CreateUser::new().with_email("owner@account-multiplicity.test")).await?;
 let foreign=store.create_user(CreateUser::new().with_email("foreign@account-multiplicity.test")).await?;
 let original=store.create_account(account(&owner.id)).await?;
 assert!(store.create_account(account(&owner.id)).await.is_err());
 for sql in ["ALTER TABLE accounts ADD COLUMN app_note TEXT NOT NULL DEFAULT 'kept,bytes' CHECK(app_note <> 'blocked')","CREATE INDEX app_account_note ON accounts(app_note)","CREATE TABLE app_account_audit(id TEXT)","CREATE TRIGGER app_account_changes AFTER UPDATE ON accounts BEGIN INSERT INTO app_account_audit VALUES(NEW.id); END","CREATE VIEW app_accounts AS SELECT id,app_note FROM accounts"]{let _result=db.execute_unprepared(sql).await?;}
 let rows="SELECT json_group_array(json_object('rowid',rowid,'id',id,'owner',user_id,'provider',provider_id,'account',account_id,'access',access_token,'created',created_at,'note',app_note)) AS value FROM (SELECT rowid,* FROM accounts ORDER BY rowid)";
 let schema="SELECT json_group_array(json_object('type',type,'name',name,'sql',sql)) AS value FROM (SELECT type,name,sql FROM sqlite_schema WHERE (tbl_name='accounts' OR name='app_accounts') AND name NOT IN ('idx_accounts_provider_account','idx_accounts_provider_account_lookup') ORDER BY type,name)";
 let before=(scalar(&db,rows).await?,scalar(&db,schema).await?);
 AuthMigrator::up(&db,None).await?;
 assert_eq!((scalar(&db,rows).await?,scalar(&db,schema).await?),before);
 let same_owner=store.create_account(account(&owner.id)).await?;
 assert_ne!(same_owner.id,original.id);
 assert!(store.get_account("gitlab","shared-provider-identity").await.is_err(),"same-owner multiplicity must not silently choose a row");
 store.delete_account(&same_owner.id).await?;
 assert_eq!(serde_json::to_value(store.get_account("gitlab","shared-provider-identity").await?)?,serde_json::to_value(Some(original.clone()))?);
 let other_owner=store.create_account(account(&foreign.id)).await?;
 assert!(store.get_account("gitlab","shared-provider-identity").await.is_err(),"foreign-owner multiplicity must fail closed");
 assert_eq!(store.get_user_accounts(&owner.id).await?.len(),1);
 assert_eq!(store.get_user_accounts(&foreign.id).await?.len(),1);
 store.delete_account(&other_owner.id).await?;
 assert_eq!(serde_json::to_value(store.get_user_accounts(&owner.id).await?)?,serde_json::to_value(vec![original])?);
 assert!(db.execute_unprepared("UPDATE accounts SET app_note='blocked'").await.is_err());
 Ok(())
}
