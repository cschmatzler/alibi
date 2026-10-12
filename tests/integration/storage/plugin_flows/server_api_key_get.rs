//! Canonical API key reads authenticate owners and redact the stored secret.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{ApiKeyPlugin, api_key::ApiKeyConfig};
use alibi::utils::json::JsValue;

backend_tests!(server_api_key_read_delete_lifecycle_preserves_owner_authority);
async fn server_api_key_read_delete_lifecycle_preserves_owner_authority<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = Box::pin(
        AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(super::auth_probe::fast_password())
            .plugin(SessionManagementPlugin::new())
            .plugin(
                ApiKeyPlugin::builder()
                    .enable_metadata(true)
                    .build()
                    .configuration(ApiKeyConfig {
                        config_id: "secondary".into(),
                        enable_metadata: true,
                        ..Default::default()
                    }),
            )
            .build(),
    )
    .await?;
    let owner = Box::pin(signup(&auth, "key-read-owner@example.test")).await;
    let outsider = Box::pin(signup(&auth, "key-read-outsider@example.test")).await;
    let created = Box::pin(call(
        &auth,
        request(
            "/api-key/create",
            Some(json!({"name":"Read key","metadata":{"purpose":"read","nested":{"value":3}}})),
            &cookies(&owner),
        ),
        200,
    ))
    .await;
    let mut expected = body(&created);
    let key_id = expected["id"].as_str().unwrap().to_owned();
    _ = expected.as_object_mut().unwrap().remove("key");
    let expected = alibi::utils::json::parse_value(&expected.to_string())?;
    let credentials = |response: &AuthResponse| EndpointOptions {
        headers: Some([("cookie".into(), cookies(response))].into_iter().collect()),
        ..Default::default()
    };
    let endpoint = || ServerEndpoint::<JsValue>::new("api-key", "getApiKey");
    let before = db.tables(&["users", "sessions", "api_keys"]).await?;
    for config_id in [None, Some("default"), Some("unknown-config")] {
        let mut query = json!({"id":key_id,"ignored":{"nested":true}});
        if let Some(config_id) = config_id {
            query["configId"] = json!(config_id);
        }
        let output =
            Box::pin(auth.dispatch_endpoint(endpoint().with_query(&query)?, credentials(&owner)))
                .await?;
        assert_eq!(output.value(), &expected);
        assert!(output.value().get("key").is_none());
        assert_eq!(
            output.value().get("metadata"),
            Some(&alibi::utils::json::parse_value(
                r#"{"purpose":"read","nested":{"value":3}}"#
            )?)
        );
    }
    for (query, options, status, code) in [
        (None, EndpointOptions::default(), 400, "VALIDATION_ERROR"),
        (
            Some(json!({})),
            credentials(&owner),
            400,
            "VALIDATION_ERROR",
        ),
        (
            Some(json!({"id":42})),
            credentials(&owner),
            400,
            "VALIDATION_ERROR",
        ),
        (
            Some(json!({"id":key_id,"configId":42})),
            credentials(&owner),
            400,
            "VALIDATION_ERROR",
        ),
        (
            Some(json!({"id":key_id})),
            EndpointOptions::default(),
            401,
            "UNAUTHORIZED",
        ),
        (
            Some(json!({"id":key_id})),
            credentials(&outsider),
            404,
            "KEY_NOT_FOUND",
        ),
        (
            Some(json!({"id":"missing-key"})),
            credentials(&owner),
            404,
            "KEY_NOT_FOUND",
        ),
        (
            Some(json!({"id":key_id,"configId":"secondary"})),
            credentials(&owner),
            404,
            "KEY_NOT_FOUND",
        ),
    ] {
        let mut call = endpoint();
        if let Some(query) = query {
            call = call.with_query(&query)?;
        }
        let error = Box::pin(auth.dispatch_endpoint(call, options))
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), status);
        assert_eq!(body(&error.error.to_auth_response())["code"], code);
    }
    let typed = Box::pin(auth.dispatch_endpoint(
        ApiKeyPlugin::get_endpoint(&alibi::plugins::api_key::GetKeyQuery {
            config_id: None,
            id: key_id.clone(),
        })?,
        credentials(&owner),
    ))
    .await?;
    assert_eq!(typed.value(), &expected);
    assert_eq!(typed.decode()?.id, key_id);
    assert_eq!(db.tables(&["users", "sessions", "api_keys"]).await?, before);
    let deletion = || ServerEndpoint::<JsValue>::new("api-key", "deleteApiKey");
    for (input, options, status, code) in [
        (None, EndpointOptions::default(), 400, "VALIDATION_ERROR"),
        (
            Some(json!({})),
            credentials(&owner),
            400,
            "VALIDATION_ERROR",
        ),
        (
            Some(json!({"keyId":42})),
            credentials(&owner),
            400,
            "VALIDATION_ERROR",
        ),
        (
            Some(json!({"keyId":key_id,"configId":42})),
            credentials(&owner),
            400,
            "VALIDATION_ERROR",
        ),
        (
            Some(json!({"keyId":key_id})),
            EndpointOptions::default(),
            401,
            "UNAUTHORIZED",
        ),
        (
            Some(json!({"keyId":key_id})),
            credentials(&outsider),
            404,
            "KEY_NOT_FOUND",
        ),
        (
            Some(json!({"keyId":"missing-key"})),
            credentials(&owner),
            404,
            "KEY_NOT_FOUND",
        ),
        (
            Some(json!({"keyId":key_id,"configId":"secondary"})),
            credentials(&owner),
            404,
            "KEY_NOT_FOUND",
        ),
    ] {
        let mut call = deletion();
        if let Some(body) = input {
            call = call.with_body(&body)?;
        }
        let error = Box::pin(auth.dispatch_endpoint(call, options))
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), status);
        assert_eq!(body(&error.error.to_auth_response())["code"], code);
    }
    assert_eq!(db.tables(&["users", "sessions", "api_keys"]).await?, before);
    let removed = Box::pin(
        auth.dispatch_endpoint(
            ApiKeyPlugin::delete_endpoint(&alibi::plugins::api_key::DeleteKeyRequest {
                config_id: None,
                key_id: key_id.clone(),
            })?
            .with_body(&json!({"keyId":key_id,"ignored":{"nested":true}}))?,
            credentials(&owner),
        ),
    )
    .await?;
    assert_eq!(removed.value().get("success"), Some(&JsValue::Bool(true)));
    assert!(removed.decode()?.success);
    let after = db.tables(&["users", "sessions", "api_keys"]).await?;
    assert_eq!(&after[..2], &before[..2]);
    assert_eq!(after[2], "[]");
    for call in [
        deletion().with_body(&json!({"keyId":key_id}))?,
        endpoint().with_query(&json!({"id":key_id}))?,
    ] {
        let error = Box::pin(auth.dispatch_endpoint(call, credentials(&owner)))
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), 404);
        assert_eq!(
            body(&error.error.to_auth_response())["code"],
            "KEY_NOT_FOUND"
        );
    }
    assert_eq!(db.tables(&["users", "sessions", "api_keys"]).await?, after);
    B::close(connection).await
}
