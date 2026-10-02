use super::*;

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
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
        drop(
            update_request
                .headers
                .insert("content-type".into(), "application/json".into()),
        );
        let updated = auth.handle_request(update_request).await.unwrap();
        assert_eq!(updated.status, 200);
        assert_eq!(
            serde_json::from_slice::<Value>(&updated.body).unwrap(),
            json!({"id":"fixture-id","labels":[7,"approved"]})
        );
        let session = auth
            .handle_request(AuthRequest::new(HttpMethod::Get, "/identity/get-session"))
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&session.body).unwrap(),
            json!({"source":"application"})
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
        assert_eq!(
            document["paths"]["/get-session"]["get"]["operationId"],
            "applicationSession"
        );
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
