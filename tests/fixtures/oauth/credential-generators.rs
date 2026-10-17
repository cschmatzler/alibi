use alibi::plugins::OAuthTokenIssueParams;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
pub(crate) struct Generators {
    pub access_mode: Mutex<String>,
    pub refresh_mode: Mutex<String>,
    pub calls: Mutex<Vec<String>>,
    pub contexts: Mutex<Vec<Value>>,
    pub access_count: Mutex<usize>,
    pub refresh_count: Mutex<usize>,
}
#[derive(Debug)]
struct Generator {
    state: Arc<Generators>,
    kind: &'static str,
}
#[async_trait::async_trait]
impl alibi::plugins::OAuthTokenGenerator for Generator {
    async fn generate(&self, params: &OAuthTokenIssueParams) -> alibi::AuthResult<String> {
        self.state.calls.lock().unwrap().push(self.kind.into());
        self.state.contexts.lock().unwrap().push(json!({
            "kind":self.kind,"userId":params.user.as_ref().map(|user| &user.id),
            "clientId":params.client.client_id,"scopes":params.scopes,"sessionId":params.session_id,
        }));
        let (count, mode) = if self.kind == "access" {
            (&self.state.access_count, &self.state.access_mode)
        } else {
            (&self.state.refresh_count, &self.state.refresh_mode)
        };
        let number = {
            let mut count = count.lock().unwrap();
            *count += 1;
            *count
        };
        match mode.lock().unwrap().as_str() {
            "error" => Err(alibi::AuthError::internal(format!(
                "{} generator failed",
                self.kind
            ))),
            "empty" => Ok(String::new()),
            "fixed" => Ok(format!("application-{}-fixed", self.kind)),
            _ => Ok(format!("application-{}-{number}", self.kind)),
        }
    }
}
pub(crate) fn access(state: Arc<Generators>) -> Arc<dyn alibi::plugins::OAuthTokenGenerator> {
    Arc::new(Generator {
        state,
        kind: "access",
    })
}
pub(crate) fn refresh(state: Arc<Generators>) -> Arc<dyn alibi::plugins::OAuthTokenGenerator> {
    Arc::new(Generator {
        state,
        kind: "refresh",
    })
}
