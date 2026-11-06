use super::super::bundled_schema::BundledSchema;
use super::*;
use crate::hooks::{DatabaseHooks, HookControl};
use alibi_core::store::{AccountStore, SchemaMigrator, UserStore};
use alibi_core::utils::json::JsString;
use alibi_core::{AuthAccount, AuthConfig, AuthUser, CreateAccount, CreateUser};
use std::sync::{Arc, Mutex};
type Account = <BundledSchema as alibi_core::AuthSchema>::Account;

#[derive(Clone)]
struct RawHooks(Arc<Mutex<Vec<(&'static str, JsString)>>>);
#[async_trait]
impl DatabaseHooks<BundledSchema, crate::hooks::SqlxBackend> for RawHooks {
    async fn before_create_account(
        &self,
        input: &mut CreateAccount,
        _: &crate::hooks::SqlxHookContext<'_>,
    ) -> alibi_core::AuthResult<HookControl> {
        self.0
            .lock()
            .unwrap()
            .push(("before", input.account_id.clone()));
        Ok(HookControl::Continue)
    }
    async fn after_create_account(
        &self,
        account: &Account,
        _: &crate::hooks::SqlxHookContext<'_>,
    ) -> alibi_core::AuthResult<()> {
        self.0.lock().unwrap().push(("after", account.account_id()));
        Ok(())
    }
}
fn input(user: &str, key: JsString) -> CreateAccount {
    CreateAccount {
        additional_fields: Default::default(),
        user_id: user.into(),
        account_id: key,
        provider_id: "fixture".into(),
        access_token: None,
        refresh_token: None,
        id_token: None,
        access_token_expires_at: None,
        refresh_token_expires_at: None,
        scope: None,
        password: None,
    }
}
#[tokio::test]
async fn account_utf16_hooks_precede_real_sqlite_usv_binding_and_query_collisions() {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let trace = Arc::new(Mutex::new(Vec::new()));
    let store = SqlxStore::<BundledSchema>::new(AuthConfig::default(), pool.clone())
        .hook(RawHooks(trace.clone()));
    store.migrate().await.unwrap();
    let owner = store
        .create_user(
            CreateUser::new()
                .with_email("account@fixture.test")
                .with_name("Owner"),
        )
        .await
        .unwrap();
    let high = JsString::from_code_units(vec![0x61, 0xd800, 0x62]);
    let low = JsString::from_code_units(vec![0x61, 0xdc00, 0x62]);
    let replacement = JsString::from("a\u{fffd}b");
    let first = store
        .create_account(input(&owner.id(), high.clone()))
        .await
        .unwrap();
    assert_eq!(first.account_id(), replacement);
    let raw_hex: String = sqlx::query_scalar("SELECT hex(accountId) FROM account WHERE id = ?")
        .bind(first.id().as_ref())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(raw_hex, "61EFBFBD62");
    for query in [&high, &replacement] {
        let found = store.get_account("fixture", query).await.unwrap().unwrap();
        assert_eq!(found.id(), first.id());
    }
    let second = store
        .create_account(input(&owner.id(), low.clone()))
        .await
        .unwrap();
    assert_ne!(first.id(), second.id());
    assert_eq!(second.account_id(), replacement);
    assert!(matches!(
        store.get_account("fixture", &high).await,
        Err(alibi_core::AuthError::Database(
            alibi_core::DatabaseError::AmbiguousAccount { .. }
        ))
    ));
    assert_eq!(
        trace.lock().unwrap().as_slice(),
        [
            ("before", high),
            ("after", replacement.clone()),
            ("before", low),
            ("after", replacement),
        ]
    );
}
