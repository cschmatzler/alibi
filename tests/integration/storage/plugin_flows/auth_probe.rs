//! Shared request probe and cheap password hasher for the authentication matrix suites.
use super::*;
use crate::snapshot::Trace;
use alibi::{AuthResult, PasswordHasher};

/// Records every response in a snapshot trace while keeping async frames small.
pub(super) struct Probe<'a, S: AuthSchema> {
    pub(super) auth: &'a BetterAuth<S>,
    pub(super) trace: Trace,
    pub(super) prefix: String,
}

impl<'a, S: AuthSchema> Probe<'a, S> {
    pub(super) fn new(auth: &'a BetterAuth<S>) -> Self {
        Self {
            auth,
            trace: Trace::default(),
            prefix: String::new(),
        }
    }

    pub(super) async fn send(&mut self, label: &str, input: AuthRequest) -> AuthResponse {
        let response = Box::pin(self.auth.handle_request(input)).await.unwrap();
        self.trace
            .response(&format!("{}{label}", self.prefix), &response);
        response
    }

    pub(super) async fn post(
        &mut self,
        label: &str,
        path: &str,
        text: &str,
        cookie: &str,
    ) -> AuthResponse {
        self.send(label, raw(path, text, cookie)).await
    }
}

pub(super) fn raw(path: &str, text: &str, cookie: &str) -> AuthRequest {
    let mut request = request(path, None, cookie);
    request.method = HttpMethod::Post;
    request.body = Some(text.as_bytes().to_vec());
    request
}

/// Deterministic stand-in for scrypt so matrices with many accounts stay fast.
pub(super) struct FastHasher;

#[async_trait::async_trait]
impl PasswordHasher for FastHasher {
    async fn hash(&self, password: &str) -> AuthResult<String> {
        Ok(format!("fast${password}"))
    }

    async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
        Ok(hash == format!("fast${password}"))
    }
}

pub(super) fn fast_password() -> EmailPasswordPlugin {
    EmailPasswordPlugin::new().password_hasher(Arc::new(FastHasher))
}

pub(super) fn fast_builder<B: Backend>(connection: &B::Connection) -> AuthBuilder<B::Schema> {
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(fast_password())
        .plugin(SessionManagementPlugin::new())
}
