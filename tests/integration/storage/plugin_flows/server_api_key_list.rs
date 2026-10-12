//! Canonical server key listing preserves pagination, configuration scope and secrets.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{ApiKeyPlugin, api_key::ApiKeyConfig};
use alibi::utils::json::JsValue;

backend_tests!(server_list_api_keys_preserves_configuration_and_coerced_pagination);
async fn server_list_api_keys_preserves_configuration_and_coerced_pagination<B: Backend>(
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
    let owner = Box::pin(signup(&auth, "key-list-owner@example.test")).await;
    let outsider = Box::pin(signup(&auth, "key-list-outsider@example.test")).await;
    for (name, config_id) in [
        ("Alpha", "default"),
        ("Beta", "secondary"),
        ("Gamma", "default"),
    ] {
        let _ = Box::pin(call(
            &auth,
            request(
                "/api-key/create",
                Some(json!({"name":name,"configId":config_id,"metadata":{"purpose":name}})),
                &cookies(&owner),
            ),
            200,
        ))
        .await;
    }
    let credentials = |response: &AuthResponse| EndpointOptions {
        headers: Some([("cookie".into(), cookies(response))].into_iter().collect()),
        ..Default::default()
    };
    let endpoint = || ServerEndpoint::<JsValue>::new("api-key", "listApiKeys");
    let before = db.tables(&["users", "sessions", "api_keys"]).await?;
    for (query, names, total, limit, offset) in [
        (None, vec!["Alpha", "Beta", "Gamma"], 3, None, None),
        (
            Some(json!({})),
            vec!["Alpha", "Beta", "Gamma"],
            3,
            None,
            None,
        ),
        (
            Some(json!({"ignored":{"nested":true}})),
            vec!["Alpha", "Beta", "Gamma"],
            3,
            None,
            None,
        ),
        (
            Some(json!({"sortBy":"name","sortDirection":"asc","offset":"1","limit":"1"})),
            vec!["Beta"],
            3,
            Some(1),
            Some(1),
        ),
        (
            Some(json!({"configId":"default","sortBy":"name","sortDirection":"desc"})),
            vec!["Gamma", "Alpha"],
            2,
            None,
            None,
        ),
        (
            Some(json!({"configId":"secondary"})),
            vec!["Beta"],
            1,
            None,
            None,
        ),
        (
            Some(json!({"configId":"unknown-config"})),
            vec![],
            0,
            None,
            None,
        ),
        (
            Some(json!({"sortBy":"name","offset":true,"limit":[1]})),
            vec!["Beta"],
            3,
            Some(1),
            Some(1),
        ),
        (Some(json!({"limit":null})), vec![], 3, Some(0), None),
        (Some(json!({"limit":""})), vec![], 3, Some(0), None),
        (
            Some(json!({"sortBy":"name","limit":"0x1"})),
            vec!["Alpha"],
            3,
            Some(1),
            None,
        ),
        (Some(json!({"offset":99})), vec![], 3, None, Some(99)),
    ] {
        let mut call = endpoint();
        if let Some(query) = query {
            call = call.with_query(&query)?;
        }
        let output = Box::pin(auth.dispatch_endpoint(call, credentials(&owner))).await?;
        let keys = output.value().get("apiKeys").unwrap().as_array().unwrap();
        let actual = keys
            .iter()
            .map(|key| key.get("name").unwrap().as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(actual, names);
        assert_eq!(
            output.value().get("total"),
            Some(&JsValue::Number(f64::from(total)))
        );
        assert_eq!(
            output.value().get("limit"),
            limit
                .map(|value| JsValue::Number(f64::from(value)))
                .as_ref()
        );
        assert_eq!(
            output.value().get("offset"),
            offset
                .map(|value| JsValue::Number(f64::from(value)))
                .as_ref()
        );
        for key in keys {
            assert!(key.get("key").is_none());
            assert_eq!(key.get("metadata").unwrap().get("purpose"), key.get("name"));
        }
    }
    for (query, status, code) in [
        (None, 401, "UNAUTHORIZED"),
        (Some(json!({"limit":-1})), 400, "VALIDATION_ERROR"),
        (Some(json!({"limit":1.5})), 400, "VALIDATION_ERROR"),
        (Some(json!({"limit":"bad-number"})), 400, "VALIDATION_ERROR"),
        (Some(json!({"limit":1e16})), 400, "VALIDATION_ERROR"),
        (Some(json!({"configId":null})), 400, "VALIDATION_ERROR"),
        (Some(json!({"organizationId":42})), 400, "VALIDATION_ERROR"),
        (Some(json!({"sortBy":null})), 400, "VALIDATION_ERROR"),
        (
            Some(json!({"sortDirection":"ASC"})),
            400,
            "VALIDATION_ERROR",
        ),
    ] {
        let mut call = endpoint();
        if let Some(query) = query {
            call = call.with_query(&query)?;
        }
        let error = Box::pin(auth.dispatch_endpoint(call, EndpointOptions::default()))
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), status);
        assert_eq!(body(&error.error.to_auth_response())["code"], code);
    }
    let typed = Box::pin(auth.dispatch_endpoint(
        ApiKeyPlugin::list_endpoint(&alibi::plugins::api_key::ListKeysQuery {
            config_id: Some("secondary".into()),
            ..Default::default()
        })?,
        credentials(&owner),
    ))
    .await?
    .decode()?;
    assert_eq!(typed.total, 1);
    assert_eq!(typed.api_keys[0].name.as_deref(), Some("Beta"));
    let empty = Box::pin(auth.dispatch_endpoint(endpoint(), credentials(&outsider))).await?;
    assert_eq!(
        empty
            .value()
            .get("apiKeys")
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(empty.value().get("total"), Some(&JsValue::Number(0.0)));
    assert_eq!(db.tables(&["users", "sessions", "api_keys"]).await?, before);
    B::close(connection).await
}
