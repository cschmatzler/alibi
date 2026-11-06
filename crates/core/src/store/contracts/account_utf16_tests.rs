use super::*;
use crate::AccountView;
use crate::utils::json::{JsString, to_js_value};
use std::marker::PhantomData;
use std::sync::Mutex;

struct Observed<S, T> {
    inner: T,
    calls: Mutex<Vec<(&'static str, JsString)>>,
    schema: PhantomData<fn() -> S>,
}
#[async_trait]
impl<S, T> AccountStore<S> for Observed<S, T>
where
    S: AuthSchema<Account = AccountView>,
    T: AccountStore<S>,
{
    async fn create_account(&self, input: CreateAccount) -> AuthResult<AccountView> {
        self.calls
            .lock()
            .unwrap()
            .push(("create", input.account_id.clone()));
        self.inner.create_account(input).await
    }
    async fn get_account(&self, provider: &str, key: &JsString) -> AuthResult<Option<AccountView>> {
        self.calls.lock().unwrap().push(("query", key.clone()));
        self.inner.get_account(provider, key).await
    }
    async fn get_user_accounts(&self, user: &str) -> AuthResult<Vec<AccountView>> {
        self.inner.get_user_accounts(user).await
    }
    async fn update_account(&self, id: &str, update: UpdateAccount) -> AuthResult<AccountView> {
        self.inner.update_account(id, update).await
    }
    async fn delete_account(&self, id: &str) -> AuthResult<()> {
        self.inner.delete_account(id).await
    }
}
fn input(id: JsString) -> CreateAccount {
    CreateAccount {
        additional_fields: Default::default(),
        user_id: "owner".into(),
        account_id: id,
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
async fn exercise<S, T>(inner: T)
where
    S: AuthSchema<Account = AccountView>,
    T: AccountStore<S>,
{
    let store = Observed::<S, T> {
        inner,
        calls: Default::default(),
        schema: PhantomData,
    };
    let keys = [
        JsString::from_code_units(vec![0x61, 0xd800, 0x62]),
        JsString::from_code_units(vec![0x61, 0xdc00, 0x62]),
        JsString::from("a\u{fffd}b"),
    ];
    let mut rows = Vec::new();
    for key in &keys {
        let row = store.create_account(input(key.clone())).await.unwrap();
        assert_eq!(row.account_id(), *key);
        assert_eq!(
            to_js_value(&row).unwrap()["accountId"].as_js_string(),
            Some(key)
        );
        rows.push(row);
    }
    for (key, expected) in keys.iter().zip(&rows) {
        let selected = store.get_account("fixture", key).await.unwrap().unwrap();
        assert_eq!(selected.id, expected.id);
        assert_eq!(selected.account_id(), *key);
    }
    let trace = store.calls.lock().unwrap();
    assert_eq!(trace.len(), 6);
    for (index, key) in keys.iter().enumerate() {
        assert_eq!(trace[index], ("create", key.clone()));
        assert_eq!(trace[index + 3], ("query", key.clone()));
    }
    assert_ne!(rows[0].id, rows[1].id);
    assert_ne!(rows[1].id, rows[2].id);
}
#[tokio::test]
async fn memory_account_queries_and_writes_preserve_distinct_utf16_keys() {
    let store =
        crate::test_store::MemoryStore::new(std::sync::Arc::new(crate::AuthConfig::default()));
    exercise::<crate::test_store::BundledSchema, _>(store).await;
}
#[tokio::test]
async fn stateless_account_queries_and_writes_preserve_distinct_utf16_keys() {
    exercise::<crate::store::stateless::StatelessSchema, _>(
        crate::store::stateless::StatelessStore::default(),
    )
    .await;
}
