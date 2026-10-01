#![cfg(test)]
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
#![expect(
    clippy::indexing_slicing,
    reason = "Assert successful public metadata extension setup and independently specified document schemas"
)]
//! Public metadata extension contracts; HTTP differential evidence owns built-in schemas.
#[cfg(test)]
#[path = "open_api_tests/tests.rs"]
mod tests;

use async_trait::async_trait;
use better_auth::plugin::{
    AuthContext, AuthInitContext, AuthPlugin, AuthRoute, OpenApiEndpoint, OpenApiField,
    OpenApiModel, PluginOpenApiMetadata,
};
use better_auth::plugins::{OpenApiConfig, OpenApiPlugin};
use better_auth::{AuthBuilder, AuthConfig, AuthResult, AuthSchema};
use better_auth_core::{AuthRequest, AuthResponse, HttpMethod};
use better_auth_seaorm::store::entities::{account, session, user, verification};
use better_auth_seaorm::{Database, SeaOrmStore};
use serde_json::{Value, json};
use std::sync::Arc;

struct AppSchema;

impl AuthSchema for AppSchema {
    type User = user::Model;
    type Session = session::Model;
    type Account = account::Model;
    type Verification = verification::Model;
    fn openapi_models() -> Vec<OpenApiModel> {
        let mut models = better_auth_core::openapi::annotations::core_models();
        // This schema's concrete User has a metadata JSON field. Declaring its
        // documentation does not install a request parser or alter its persistence.
        models[0].fields.push(
            OpenApiField::new("metadata", json!({"type":"json","default":null}), true)
                .read_only()
                .hidden(),
        );
        models
    }
}

struct AppPlugin;

#[async_trait]
impl AuthPlugin<AppSchema> for AppPlugin {
    fn name(&self) -> &'static str {
        "application"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/items/:id", "ignored_dispatch_id"),
            AuthRoute::post("/items/:id", "ignored_post_id"),
            AuthRoute::get("/internal", "internal"),
        ]
    }
    fn openapi_metadata(&self, _ctx: &AuthInitContext<AppSchema>) -> PluginOpenApiMetadata {
        let get = OpenApiEndpoint {
            document_path: Some("/items/:itemId".into()),
            operation_id: Some("items".into()),
            description: Some("Read an application item".into()),
            parameters: vec![json!({"name":"id","in":"query","schema":{"type":"string"}})],
            ..Default::default()
        };
        let post = OpenApiEndpoint {
            document_path: Some("/items/:itemId".into()),
            operation_id: Some("items".into()),
            tags: Some(vec!["Custom".into()]),
            request_body: Some(
                json!({"required":false,"content":{"application/json":{"schema":{"type":["array","null"],"items":{"anyOf":[{"type":"number"},{"type":"string","enum":["approved"]}]}}}}}),
            ),
            ..Default::default()
        };
        PluginOpenApiMetadata::default()
            .endpoint(HttpMethod::Get, "/items/:id", get)
            .endpoint(HttpMethod::Post, "/items/:id", post)
            .endpoint(
                HttpMethod::Get,
                "/internal",
                OpenApiEndpoint {
                    server_only: true,
                    ..Default::default()
                },
            )
            .model(OpenApiModel::new(
                "Item",
                vec![
                    OpenApiField::new(
                        "labels",
                        json!({"type":"array","items":{"type":"string"}}),
                        true,
                    ),
                    OpenApiField::new("secret", json!({"type":"string"}), true).hidden(),
                ],
            ))
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        _ctx: &AuthContext<AppSchema>,
    ) -> AuthResult<Option<AuthResponse>> {
        if req.method() == &HttpMethod::Get && req.path().starts_with("/items/") {
            return Ok(Some(AuthResponse::json(
                200,
                &json!({"id":req.path().trim_start_matches("/items/")}),
            )?));
        }
        if req.method() == &HttpMethod::Post && req.path().starts_with("/items/") {
            let labels: Value = req.body_as_json()?;
            return Ok(Some(AuthResponse::json(
                200,
                &json!({"id":req.path().trim_start_matches("/items/"),"labels":labels}),
            )?));
        }
        Ok(None)
    }
}
