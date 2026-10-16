//! Trusted endpoint dispatch falls back to pass-through validation for plugins without a schema.
#![allow(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "tests assert independently specified wire fields and fixtures"
)]
use alibi::endpoint::{
    BeforeEndpointAction, EndpointCall, EndpointDefinition, EndpointHook, EndpointOptions,
    EndpointResponse, ServerEndpoint,
};
use alibi::{AuthBuilder, AuthConfig};
use alibi::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute, AuthSchema,
    HttpMethod,
};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

struct Echo;

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Echo {
    fn name(&self) -> &'static str {
        "trusted-echo"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    fn server_endpoints(&self) -> Vec<EndpointDefinition> {
        vec![EndpointDefinition {
            name: "echo",
            operation_id: "echo",
            path: Some("/echo".into()),
            method: HttpMethod::Post,
        }]
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
    async fn on_endpoint(
        &self,
        call: &EndpointCall,
        context: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        EndpointResponse::json(&json!({
            "body": call.body().map(|body| body.to_json_value().unwrap()),
            "query": call.query().map(|query| query.to_json_value().unwrap()),
            "has": [call.has_body(), call.has_query(), call.has_method()],
            "session": call.session().is_some(),
            "baseURL": context.config.base_url,
        }))
    }
}

#[tokio::test]
async fn default_validation_passes_body_and_query_through_to_the_handler() {
    let auth =
        AuthBuilder::without_database(AuthConfig::new("trusted-endpoint-secret-at-least-32-chars"))
            .plugin(Echo)
            .build()
            .await
            .unwrap();
    let endpoint = ServerEndpoint::<Value>::new("trusted-echo", "echo")
        .with_body(&json!({"name":"Ada"}))
        .unwrap()
        .with_query(&json!({"page":"2"}))
        .unwrap();
    let output = auth
        .dispatch_endpoint(endpoint, EndpointOptions::default())
        .await
        .unwrap();
    assert_eq!(
        output.decode().unwrap(),
        json!({
            "body": {"name":"Ada"},
            "query": {"page":"2"},
            "has": [true, true, true],
            "session": false,
            "baseURL": auth.config().base_url,
        })
    );
}

struct AuthorityObserver(Arc<Mutex<Vec<String>>>);

#[async_trait]
impl<S: AuthSchema> EndpointHook<S> for AuthorityObserver {
    async fn before(
        &self,
        _: &EndpointCall,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeEndpointAction>> {
        self.0.lock().unwrap().push(context.config.base_url.clone());
        Ok(None)
    }
}

#[tokio::test]
async fn trusted_dynamic_authority_is_resolved_before_hooks_without_mutating_shared_config() {
    let observed = Arc::new(Mutex::new(Vec::new()));
    let auth = AuthBuilder::without_database(
        AuthConfig::new("trusted-endpoint-secret-at-least-32-chars").dynamic_base_url(
            alibi::config::DynamicBaseUrl {
                allowed_hosts: vec!["tenant.example.test".into(), "physical.example.test".into()],
                protocol: Some(alibi::config::BaseUrlProtocol::Auto),
                fallback: None,
            },
        ),
    )
    .endpoint_hook(AuthorityObserver(observed.clone()))
    .plugin(Echo)
    .build()
    .await
    .unwrap();
    let shared = auth.config().base_url.clone();
    for headers in [None, Some(std::collections::HashMap::new())] {
        let error = auth
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("trusted-echo", "echo"),
                EndpointOptions {
                    headers,
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), 500);
        assert!(
            error
                .to_string()
                .contains("Dynamic baseURL could not be resolved")
        );
        assert!(error.headers.is_none());
    }
    assert!(observed.lock().unwrap().is_empty());
    for physical in [false, true] {
        let output = auth
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("trusted-echo", "echo"),
                EndpointOptions {
                    headers: Some([("host".into(), "tenant.example.test".into())].into()),
                    request: physical.then(|| {
                        AuthRequest::new(HttpMethod::Post, "/unrelated").with_url(
                            url::Url::parse("http://physical.example.test/unrelated").unwrap(),
                        )
                    }),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .decode()
            .unwrap();
        assert_eq!(
            output["baseURL"],
            if physical {
                "http://physical.example.test"
            } else {
                "https://tenant.example.test"
            }
        );
        assert_eq!(auth.config().base_url, shared);
    }
    assert_eq!(
        *observed.lock().unwrap(),
        [
            "https://tenant.example.test",
            "http://physical.example.test"
        ],
    );
}
