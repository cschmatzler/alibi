//! Trusted endpoint dispatch falls back to pass-through validation for plugins without a schema.
#![allow(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "tests assert independently specified wire fields and fixtures"
)]
use alibi::{AuthBuilder, AuthConfig};
use alibi_core::endpoint::{
    EndpointCall, EndpointDefinition, EndpointOptions, EndpointResponse, ServerEndpoint,
};
use alibi_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute, AuthSchema,
    HttpMethod,
};
use async_trait::async_trait;
use serde_json::{Value, json};

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
        _: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        EndpointResponse::json(&json!({
            "body": call.body().map(|body| body.to_json_value().unwrap()),
            "query": call.query().map(|query| query.to_json_value().unwrap()),
            "has": [call.has_body(), call.has_query(), call.has_method()],
            "session": call.session().is_some(),
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
        })
    );
}
