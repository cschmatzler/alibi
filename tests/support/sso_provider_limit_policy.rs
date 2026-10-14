//! A mutable application policy observes the actual authenticated user.
use alibi::plugins::SsoProviderLimitResolver;
use alibi::wire::UserView;
use std::sync::{Arc, Mutex};
#[derive(Clone, Default)]
pub(crate) struct Policy {
    pub(crate) limit: Arc<Mutex<f64>>,
    pub(crate) events: Arc<Mutex<Vec<serde_json::Value>>>,
}
#[async_trait::async_trait]
impl SsoProviderLimitResolver for Policy {
    async fn limit(&self, user: UserView) -> alibi::AuthResult<f64> {
        self.events.lock().unwrap().push(serde_json::json!({"userId":user.id,"email":user.email,"name":user.name,"emailVerified":user.email_verified}));
        Ok(*self.limit.lock().unwrap())
    }
}
