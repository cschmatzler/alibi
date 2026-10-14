//! SDK Dates persist through provider creation, mutation and application restart.
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::SsoPlugin;
use alibi::store::SchemaMigrator;
use alibi::utils::json::JsValue;
backend_tests!(sso_date_fields_preserve_sdk_dates_and_reject_json_strings);
postgres_tests!(sso_date_fields_preserve_sdk_dates_and_reject_json_strings);
async fn sso_date_fields_preserve_sdk_dates_and_reject_json_strings<B: Backend>(
    db: Db,
) -> TestResult {
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    super::sso_date_fields_config::configure(&mut config);
    let connection = B::connect(&db.url, None).await?;
    let store = B::store(Arc::new(config.clone()), &connection);
    store.migrate().await?;
    let build = || {
        AuthBuilder::<B::Schema>::new(config.clone())
            .store(B::store(Arc::new(config.clone()), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(super::auth_probe::fast_password())
            .plugin(SessionManagementPlugin::new())
            .plugin(SsoPlugin::new())
            .build()
    };
    let auth = build().await?;
    let owner = signup(&auth, "date-owner@example.test").await;
    let owned = EndpointOptions {
        headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
        ..Default::default()
    };
    let first = "2030-01-02T03:04:05.678Z";
    let input = json!({"providerId":"date-provider","issuer":"https://idp.example.com","domain":"company.test","anniversary":first,"oidcConfig":{"clientId":"client","clientSecret":"secret","skipDiscovery":true,"pkce":true,"authorizationEndpoint":"https://idp.example.com/authorize","tokenEndpoint":"https://idp.example.com/token","jwksEndpoint":"https://idp.example.com/jwks"}});
    let mut actual = JsValue::from(input.clone());
    if let JsValue::Object(body) = &mut actual {
        _ = body.insert(
            "anniversary".into(),
            JsValue::Date(chrono::DateTime::parse_from_rfc3339(first)?.with_timezone(&chrono::Utc)),
        );
    }
    let created = match auth
        .dispatch_endpoint(
            SsoPlugin::register_sso_provider_endpoint(&input)?.with_body_value(actual),
            owned.clone(),
        )
        .await
    {
        Ok(output) => output.into_response()?,
        Err(error) => error.error.to_auth_response(),
    };
    assert_eq!(
        created.status,
        200,
        "{}",
        String::from_utf8_lossy(&created.body)
    );
    assert_eq!(body(&created)["anniversary"], first);
    for bad in [json!(first), json!(3), Value::Null] {
        let error = auth
            .dispatch_endpoint(
                SsoPlugin::update_sso_provider_endpoint(
                    &json!({"providerId":"date-provider","anniversary":bad}),
                )?,
                owned.clone(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), 400);
        let stored = auth
            .dispatch_endpoint(
                SsoPlugin::get_sso_provider_endpoint("date-provider")?,
                owned.clone(),
            )
            .await?
            .into_response()?;
        assert_eq!(body(&stored)["anniversary"], first);
    }
    let next = "2031-06-07T08:09:10.123Z";
    let update = json!({"providerId":"date-provider","anniversary":next});
    let mut actual = JsValue::from(update.clone());
    if let JsValue::Object(body) = &mut actual {
        _ = body.insert(
            "anniversary".into(),
            JsValue::Date(chrono::DateTime::parse_from_rfc3339(next)?.with_timezone(&chrono::Utc)),
        );
    }
    let updated = auth
        .dispatch_endpoint(
            SsoPlugin::update_sso_provider_endpoint(&update)?.with_body_value(actual),
            owned.clone(),
        )
        .await?
        .into_response()?;
    assert_eq!(body(&updated)["anniversary"], next);
    let physical: Value = serde_json::from_str(&db.table("ssoProvider").await?)?;
    let persisted = chrono::DateTime::parse_from_rfc3339(
        physical[0]["application_anniversary"].as_str().unwrap(),
    )?;
    assert_eq!(persisted, chrono::DateTime::parse_from_rfc3339(next)?);
    let auth = build().await?;
    let read = auth
        .dispatch_endpoint(
            SsoPlugin::get_sso_provider_endpoint("date-provider")?,
            owned.clone(),
        )
        .await?
        .into_response()?;
    assert_eq!(body(&read)["anniversary"], next);
    let list = auth
        .dispatch_endpoint(SsoPlugin::list_sso_providers_endpoint(), owned.clone())
        .await?
        .into_response()?;
    assert_eq!(body(&list)["providers"][0]["anniversary"], next);
    Ok(())
}
