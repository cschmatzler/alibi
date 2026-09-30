//! Public metadata extension contracts; HTTP differential evidence owns built-in schemas.
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

#[tokio::test]
async fn application_schema_and_plugin_annotations_reach_the_public_document_without_changing_routes()
 {
    for include_native in [false, true] {
        let config = AuthConfig::new("native-open-api-fixture-secret-at-least-32-chars")
            .base_url("https://app.fixture.test")
            .base_path("/identity")
            .disabled_path("/error");
        let database = Database::connect("sqlite::memory:").await.unwrap();
        let auth = Arc::new(
            AuthBuilder::<AppSchema>::new(config.clone())
                .store(SeaOrmStore::<AppSchema>::new(config, database))
                .plugin(AppPlugin)
                .plugin(OpenApiPlugin::with_config(
                    OpenApiConfig::default().include_native_extensions(include_native),
                ))
                .build()
                .await
                .unwrap(),
        );
        let item = auth
            .handle_request(AuthRequest::new(
                HttpMethod::Get,
                "/identity/items/fixture-id",
            ))
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&item.body).unwrap(),
            json!({"id":"fixture-id"})
        );
        let mut update_request = AuthRequest::new(HttpMethod::Post, "/identity/items/fixture-id");
        update_request.body = Some(serde_json::to_vec(&json!([7, "approved"])).unwrap());
        _ = update_request
            .headers
            .insert("content-type".into(), "application/json".into());
        let updated = auth.handle_request(update_request).await.unwrap();
        assert_eq!(updated.status, 200);
        assert_eq!(
            serde_json::from_slice::<Value>(&updated.body).unwrap(),
            json!({"id":"fixture-id","labels":[7,"approved"]})
        );
        let registered = auth.registered_routes();
        for path in [
            "/items/:id",
            "/internal",
            "/error",
            "/reference",
            "/open-api/generate-schema",
            "/__test/openapi.json",
        ] {
            assert!(
                registered.iter().any(|route| route.path == path),
                "actual registration must retain {path}"
            );
        }
        let embedded = auth
            .handle_request(AuthRequest::new(
                HttpMethod::Get,
                "/identity/__test/openapi.json",
            ))
            .await
            .unwrap();
        assert_eq!(embedded.status, 200);
        assert_eq!(
            serde_json::from_slice::<Value>(&embedded.body).unwrap(),
            auth.openapi_spec().to_value().unwrap()
        );
        let response = auth
            .handle_request(AuthRequest::new(
                HttpMethod::Get,
                "/identity/open-api/generate-schema",
            ))
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        let document: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            document,
            if include_native {
                auth.openapi_spec_with_native_extensions()
            } else {
                auth.openapi_spec()
            }
            .to_value()
            .unwrap()
        );
        assert_eq!(
            document["paths"].get("/__test/openapi.json").is_some(),
            include_native
        );
        assert_eq!(
            document["servers"],
            json!([{"url":"https://app.fixture.test/identity"}])
        );
        assert!(document["paths"].get("/error").is_none());
        assert!(document["paths"].get("/internal").is_none());
        assert!(document["paths"].get("/reference").is_none());
        let path = &document["paths"]["/items/{itemId}"];
        assert_eq!(path["get"]["operationId"], "items");
        assert_eq!(path["post"]["operationId"], "itemsPost");
        assert_eq!(
            path["get"]["parameters"],
            json!([{"name":"id","in":"query","schema":{"type":"string"}},{"name":"itemId","in":"path","required":true,"schema":{"type":"string"}}])
        );
        assert_eq!(path["post"]["tags"], json!(["Custom"]));
        assert_eq!(
            path["post"]["requestBody"],
            json!({"required":false,"content":{"application/json":{"schema":{"type":["array","null"],"items":{"anyOf":[{"type":"number"},{"type":"string","enum":["approved"]}]}}}}})
        );
        assert!(path["get"].get("requestBody").is_none());
        assert_eq!(
            document["components"]["schemas"]["User"]["properties"]["metadata"],
            json!({"type":"json","default":null,"readOnly":true})
        );
        assert!(
            !document["components"]["schemas"]["User"]["required"]
                .as_array()
                .unwrap()
                .contains(&json!("metadata"))
        );
        assert_eq!(
            document["components"]["schemas"]["Item"]["required"],
            json!(["id", "labels"])
        );
        assert_eq!(
            document["components"]["schemas"]["Item"]["properties"]["secret"],
            json!({"type":"string"})
        );
    }
}
