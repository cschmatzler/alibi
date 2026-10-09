//! Configured user fields and colliding operation ids in the generated OpenAPI document.
#![allow(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "tests assert independently specified wire fields and fixtures"
)]
use alibi::field_policy::FieldConfig;
use alibi::plugin::{AuthRoute, OpenApiEndpoint, PluginOpenApiMetadata};
use alibi::{AuthBuilder, AuthConfig};
use alibi::{
    AuthContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthSchema, HttpMethod,
};
use async_trait::async_trait;
use serde_json::{Value, json};

struct Duplicates;

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Duplicates {
    fn name(&self) -> &'static str {
        "duplicates"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        ["/a", "/b", "/c"]
            .into_iter()
            .map(|path| AuthRoute::get(path, "dup"))
            .collect()
    }
    fn static_openapi_metadata(&self) -> PluginOpenApiMetadata {
        ["/a", "/b", "/c"]
            .into_iter()
            .fold(PluginOpenApiMetadata::default(), |metadata, path| {
                metadata.endpoint(
                    HttpMethod::Get,
                    path,
                    OpenApiEndpoint {
                        operation_id: Some("dup".into()),
                        ..Default::default()
                    },
                )
            })
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

#[tokio::test]
async fn configured_fields_shape_sign_up_and_update_user_request_bodies() {
    let mut config = AuthConfig::new("openapi-fields-secret-at-least-32-characters");
    let fields = &mut config.user.additional_fields;
    for (name, field) in [
        (
            "tier",
            FieldConfig {
                required: true,
                ..FieldConfig::new(json!({"type":["free","pro"]}))
            },
        ),
        (
            "joinedAt",
            FieldConfig::new(json!({"type":"string","format":"date-time"})),
        ),
        (
            "tags",
            FieldConfig::new(json!({"type":"array","items":{"type":"string"}})),
        ),
        ("flags", FieldConfig::new(json!({"type":"array"}))),
        ("blob", FieldConfig::new(json!({"type":"json"}))),
        (
            "plan",
            FieldConfig::new(json!({"type":"string","enum":["a"]})).default_value(json!("a")),
        ),
        (
            "name",
            FieldConfig::new(json!({"type":"string","default":"Anonymous"})),
        ),
    ] {
        drop(fields.insert(name.into(), field));
    }
    let auth = AuthBuilder::without_database(config)
        .plugin(Duplicates)
        .build()
        .await
        .unwrap();
    let spec = serde_json::to_value(auth.openapi_spec()).unwrap();
    for path in ["/sign-up/email", "/update-user"] {
        let operation = spec["paths"][path]
            .as_object()
            .unwrap()
            .values()
            .next()
            .unwrap();
        let schema = &operation["requestBody"]["content"]["application/json"]["schema"];
        let properties = &schema["properties"];
        assert_eq!(
            properties["tier"],
            json!({"type":"string","enum":["free","pro"]})
        );
        assert_eq!(
            properties["joinedAt"],
            json!({"type":"string","format":"date-time"})
        );
        assert_eq!(
            properties["tags"],
            json!({"type":"array","items":{"type":"string"}})
        );
        assert_eq!(properties["flags"], json!({"type":"array","items":{}}));
        assert_eq!(properties["blob"], json!({}));
        assert_eq!(
            properties["plan"],
            json!({"type":"string","enum":["a"],"default":"a"})
        );
        let required = schema["required"].as_array().cloned().unwrap_or_default();
        assert_eq!(
            required.contains(&json!("tier")),
            path == "/sign-up/email",
            "{path}"
        );
        assert!(!required.contains(&json!("plan")));
    }
}

#[tokio::test]
async fn colliding_operation_ids_receive_method_and_numeric_suffixes() {
    let auth = AuthBuilder::without_database(AuthConfig::new(
        "openapi-duplicates-secret-at-least-32-characters",
    ))
    .plugin(Duplicates)
    .build()
    .await
    .unwrap();
    let spec = serde_json::to_value(auth.openapi_spec()).unwrap();
    let mut ids: Vec<String> = ["/a", "/b", "/c"]
        .iter()
        .map(|path| {
            spec["paths"][format!("/{}", &path[1..])]["get"]["operationId"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    ids.sort();
    assert_eq!(ids, ["dup", "dupGet", "dupGet2"]);
    let _: &Value = &spec;
}
