//! Shared observation of the genuine server-call protocol for session revocation.
use super::*;
use alibi::endpoint::{EndpointCall, EndpointHook, EndpointOptions, EndpointResponse};
use alibi::{AuthContext, AuthResult};

#[derive(Clone)]
pub(super) struct Observer(
    pub(super) Arc<Mutex<Vec<Option<String>>>>,
    &'static str,
    &'static str,
);
impl Observer {
    pub(super) fn new(operation: &'static str, path: &'static str) -> Self {
        Self(Arc::default(), operation, path)
    }
}
#[async_trait::async_trait]
impl<S: AuthSchema> EndpointHook<S> for Observer {
    fn matches_after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        _: &EndpointResponse,
    ) -> AuthResult<bool> {
        Ok(call.operation_id() == self.1)
    }
    async fn after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        response: EndpointResponse,
    ) -> AuthResult<EndpointResponse> {
        assert!(call.request().is_none());
        assert_eq!(call.path(), Some(self.2));
        self.0
            .lock()
            .unwrap()
            .push(call.session().map(|(user, _)| user.id));
        Ok(response.with_header("x-revocation-result", "logical"))
    }
}
pub(super) fn options(response: &AuthResponse) -> EndpointOptions {
    EndpointOptions {
        headers: Some([("cookie".into(), cookies(response))].into_iter().collect()),
        ..Default::default()
    }
}
