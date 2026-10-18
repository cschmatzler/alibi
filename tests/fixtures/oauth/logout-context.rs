//! Application-owned keyring and background completion observations for real logout.
use alibi::plugins::jwt::{JwtKeyring, JwtKeyringContext};
use alibi::{AuthResult, CreateJwk, Jwk};
use serde_json::{Value, json};
use std::sync::Mutex;

#[derive(Default)]
pub(super) struct LogoutContext {
    pub rows: Mutex<Vec<Jwk>>,
    pub calls: Mutex<Vec<Value>>,
    pub completions: Mutex<Vec<alibi::BackgroundTaskCompletion>>,
}

impl LogoutContext {
    async fn observe(&self, operation: &str, context: &JwtKeyringContext<'_>) {
        // Resume after the initiating endpoint can have returned. The callback
        // must still see that endpoint, not another concurrent host's request.
        if context.path == "/sign-out" {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        self.calls.lock().unwrap().push(json!({
            "operation": operation,
            "path": context.path,
            "physicalHost": context.request.and_then(|request| request.headers.get("host")),
            "physicalProof": context.request.and_then(|request| request.headers.get("x-logout-proof")),
            "logicalHost": context.endpoint.and_then(|call| call.headers()).and_then(|headers| headers.get("host")),
            "logicalProof": context.endpoint.and_then(|call| call.headers()).and_then(|headers| headers.get("x-logout-proof")),
        }));
    }

    pub(super) async fn drain(&self) -> AuthResult<()> {
        let completions = std::mem::take(&mut *self.completions.lock().unwrap());
        for completion in completions {
            completion.await?;
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl JwtKeyring for LogoutContext {
    async fn keys(&self, context: &JwtKeyringContext<'_>) -> AuthResult<Vec<Jwk>> {
        self.observe("read", context).await;
        Ok(self.rows.lock().unwrap().clone())
    }

    async fn create_key(
        &self,
        data: CreateJwk,
        context: &JwtKeyringContext<'_>,
    ) -> AuthResult<Jwk> {
        self.observe("create", context).await;
        let mut rows = self.rows.lock().unwrap();
        let key = Jwk {
            id: format!("logout-key-{}", rows.len() + 1),
            public_key: data.public_key,
            private_key: data.private_key,
            created_at: data.created_at,
            expires_at: data.expires_at,
            alg: data.alg,
            crv: data.crv,
        };
        rows.push(key.clone());
        Ok(key)
    }
}

impl alibi::BackgroundTaskHandler for LogoutContext {
    fn handle(&self, completion: alibi::BackgroundTaskCompletion) -> AuthResult<()> {
        self.completions.lock().unwrap().push(completion);
        Ok(())
    }
}
