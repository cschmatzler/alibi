//! Declared fields survive real provider mutation, storage and application restart.
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::{SessionManagementPlugin, SsoPlugin};
use alibi::store::{SchemaMigrator, SsoProviderStore};
backend_tests!(
    sso_additional_fields_validate_persist_and_filter_provider_operations,
    sso_fractional_provider_fields_survive_registration_and_update,
    sso_provider_field_collisions_fail_application_initialization,
    sso_provider_field_callbacks_run_at_storage_and_read_boundaries
);
postgres_tests!(
    sso_additional_fields_validate_persist_and_filter_provider_operations,
    sso_provider_field_callbacks_run_at_storage_and_read_boundaries
);
async fn sso_additional_fields_validate_persist_and_filter_provider_operations<B: Backend>(
    db: Db,
) -> TestResult {
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    super::sso_additional_fields_config::configure(&mut config);
    let connection = B::connect(&db.url, None).await?;
    let store = B::store(Arc::new(config.clone()), &connection);
    store.migrate().await?;
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
    let owner = signup(&auth, "extra-owner@example.test").await;
    let owned = EndpointOptions {
        headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
        ..Default::default()
    };
    let input = json!({"providerId":"extra-provider","issuer":"https://idp.example.com","domain":"company.test","label":"Initial","privateNote":"private","tags":["one","two"],"settings":{"enabled":true,"nested":[1,null]},"oidcConfig":{"clientId":"client","clientSecret":"secret","skipDiscovery":true,"pkce":true,"authorizationEndpoint":"https://idp.example.com/authorize","tokenEndpoint":"https://idp.example.com/token","jwksEndpoint":"https://idp.example.com/jwks"}});
    for (field, value, message) in [
        (
            "label",
            json!(3),
            "[body.label] Invalid input: expected string, received number",
        ),
        (
            "tags",
            json!(["one", 3]),
            "[body.tags.1] Invalid input: expected string, received number",
        ),
        ("managed", json!(false), "managed is not allowed to be set"),
        ("managed", Value::Null, "managed is not allowed to be set"),
    ] {
        let mut candidate = input.clone();
        candidate[field] = value;
        let response = match Box::pin(auth.dispatch_endpoint(
            SsoPlugin::register_sso_provider_endpoint(&candidate)?,
            owned.clone(),
        ))
        .await
        {
            Ok(response) => response.into_response()?,
            Err(error) => error.error.to_auth_response(),
        };
        assert_eq!(response.status, 400, "{field}");
        assert_eq!(body(&response)["message"], message);
        assert!(store.get_sso_provider("extra-provider").await?.is_none());
    }
    let created = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::register_sso_provider_endpoint(&input)?,
        owned.clone(),
    ))
    .await?
    .into_response()?;
    assert_eq!(created.status, 200);
    assert_eq!(body(&created)["label"], "Initial");
    assert_eq!(body(&created)["managed"], false);
    assert_eq!(body(&created)["tier"], 2);
    assert!(body(&created).get("privateNote").is_none());
    let physical: Value = serde_json::from_str(&db.table("ssoProvider").await?)?;
    assert_eq!(physical[0]["application_label"], "Initial");
    assert_eq!(physical[0]["privateNote"], "private");
    let stored = store.get_sso_provider("extra-provider").await?.unwrap();
    assert_eq!(stored.additional_fields["settings"], input["settings"]);
    assert_eq!(stored.additional_fields["tags"], input["tags"]);
    let updated=Box::pin(auth.dispatch_endpoint(SsoPlugin::update_sso_provider_endpoint(&json!({"providerId":"extra-provider","label":"Changed","privateNote":"new private","tier":4,"tags":[],"settings":null}))?,owned.clone())).await?.into_response()?;
    assert_eq!(updated.status, 200);
    assert_eq!(body(&updated)["label"], "Changed");
    assert_eq!(body(&updated)["tier"], 4);
    assert_eq!(body(&updated)["tags"], json!([]));
    assert!(body(&updated).get("privateNote").is_none());
    let auth = build().await?;
    let read = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::get_sso_provider_endpoint("extra-provider")?,
        owned.clone(),
    ))
    .await?
    .into_response()?;
    assert_eq!(body(&read), body(&updated));
    let listed = Box::pin(auth.dispatch_endpoint(SsoPlugin::list_sso_providers_endpoint(), owned))
        .await?
        .into_response()?;
    assert_eq!(body(&listed)["providers"], json!([body(&updated)]));
    let stored = store.get_sso_provider("extra-provider").await?.unwrap();
    assert_eq!(stored.additional_fields["privateNote"], "new private");
    assert!(stored.additional_fields["settings"].is_null());
    assert!(stored.oidc_config.unwrap().contains("secret"));
    Ok(())
}

async fn sso_fractional_provider_fields_survive_registration_and_update<B: Backend>(
    db: Db,
) -> TestResult {
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    super::sso_additional_fields_config::configure(&mut config);
    let connection = B::connect(&db.url, None).await?;
    let store = B::store(Arc::new(config.clone()), &connection);
    store.migrate().await?;
    let auth = AuthBuilder::<B::Schema>::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(SsoPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "fraction-owner@example.test").await;
    let owned = EndpointOptions {
        headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
        ..Default::default()
    };
    let input = json!({"providerId":"fraction-provider","issuer":"https://idp.example.com","domain":"company.test","label":"Fraction","tier":4.5,"oidcConfig":{"clientId":"client","clientSecret":"secret","skipDiscovery":true,"authorizationEndpoint":"https://idp.example.com/authorize","tokenEndpoint":"https://idp.example.com/token","jwksEndpoint":"https://idp.example.com/jwks"}});
    let created = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::register_sso_provider_endpoint(&input)?,
        owned.clone(),
    ))
    .await?
    .into_response()?;
    assert_eq!(created.status, 200);
    assert_eq!(body(&created)["tier"], 4.5);
    let physical: Value = serde_json::from_str(&db.table("ssoProvider").await?)?;
    assert_eq!(physical[0]["tier"], 4.5);
    for value in [-1.25, 0.0, 9.75] {
        let updated = Box::pin(auth.dispatch_endpoint(
            SsoPlugin::update_sso_provider_endpoint(
                &json!({"providerId":"fraction-provider","tier":value}),
            )?,
            owned.clone(),
        ))
        .await?
        .into_response()?;
        assert_eq!(updated.status, 200);
        assert_eq!(body(&updated)["tier"], value);
        let row = store.get_sso_provider("fraction-provider").await?.unwrap();
        assert_eq!(row.additional_fields["tier"], value);
        let read = Box::pin(auth.dispatch_endpoint(
            SsoPlugin::get_sso_provider_endpoint("fraction-provider")?,
            owned.clone(),
        ))
        .await?
        .into_response()?;
        assert_eq!(body(&read)["tier"], value);
    }
    Ok(())
}

async fn sso_provider_field_collisions_fail_application_initialization<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    for name in [
        "id",
        "issuer",
        "domain",
        "providerId",
        "userId",
        "organizationId",
        "oidcConfig",
        "samlConfig",
        "domainVerified",
        "type",
        "redirectURI",
        "spMetadataUrl",
        "domainVerificationToken",
        "custom",
    ] {
        let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
        let mut field = alibi::field_policy::FieldConfig::new(json!({"type":"string"}));
        if name == "custom" {
            field.field_name = Some("domain".into());
        }
        _ = config
            .advanced
            .database
            .sso_provider_fields
            .0
            .insert(name.into(), field);
        let result = AuthBuilder::<B::Schema>::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .plugin(SsoPlugin::new())
            .build()
            .await;
        let message = match result {
            Err(alibi::AuthError::Config(message)) => message,
            Err(error) => return Err(error.into()),
            Ok(_) => panic!("SSO accepted colliding field {name}"),
        };
        let expected = if name == "custom" {
            "ssoProvider additional field \"custom\" maps to built-in field \"domain\"".to_owned()
        } else if [
            "type",
            "redirectURI",
            "spMetadataUrl",
            "domainVerificationToken",
        ]
        .contains(&name)
        {
            format!(
                "ssoProvider additional field \"{name}\" conflicts with a returned provider field"
            )
        } else {
            format!("ssoProvider additional field \"{name}\" conflicts with a built-in field")
        };
        assert_eq!(message, expected);
    }
    for (physical, valid) in [("application_domain", false), ("domain", true)] {
        let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
        config.advanced.database.sso_provider = Some(alibi::config::SsoProviderDatabaseConfig {
            columns: [("domain".into(), "application_domain".into())]
                .into_iter()
                .collect(),
            ..Default::default()
        });
        let mut field = alibi::field_policy::FieldConfig::new(json!({"type":"string"}));
        field.field_name = Some(physical.into());
        _ = config
            .advanced
            .database
            .sso_provider_fields
            .0
            .insert("custom".into(), field);
        let result = AuthBuilder::<B::Schema>::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .plugin(SsoPlugin::new())
            .build()
            .await;
        if valid {
            assert!(result.is_ok());
        } else {
            let message = match result {
                Err(alibi::AuthError::Config(message)) => message,
                Err(error) => return Err(error.into()),
                Ok(_) => panic!("SSO accepted mapped collision"),
            };
            assert_eq!(
                message,
                "ssoProvider additional field \"custom\" maps to built-in field \"application_domain\""
            );
        }
    }
    Ok(())
}

async fn sso_provider_field_callbacks_run_at_storage_and_read_boundaries<B: Backend>(
    db: Db,
) -> TestResult {
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    super::sso_additional_fields_config::configure_callbacks(&mut config);
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
    let owner = signup(&auth, "callback-fields-owner@example.test").await;
    let owned = EndpointOptions {
        headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
        ..Default::default()
    };
    let input = json!({"providerId":"callback-fields","issuer":"https://idp.example.com","domain":"company.test","label":"Start","oidcConfig":{"clientId":"client","clientSecret":"secret","skipDiscovery":true,"pkce":true,"authorizationEndpoint":"https://idp.example.com/authorize","tokenEndpoint":"https://idp.example.com/token","jwksEndpoint":"https://idp.example.com/jwks"}});
    let created = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::register_sso_provider_endpoint(&input)?,
        owned.clone(),
    ))
    .await?
    .into_response()?;
    assert_eq!(created.status, 200);
    assert_eq!(body(&created)["label"], "output:input:input:Start");
    assert_eq!(body(&created)["stamp"], "generated");
    assert_eq!(body(&created)["tier"], 2);
    let physical: Value = serde_json::from_str(&db.table("ssoProvider").await?)?;
    assert_eq!(physical[0]["application_label"], "input:input:Start");
    assert_eq!(physical[0]["stamp"], "generated");
    let updated = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::update_sso_provider_endpoint(
            &json!({"providerId":"callback-fields","label":"Changed"}),
        )?,
        owned.clone(),
    ))
    .await?
    .into_response()?;
    assert_eq!(body(&updated)["label"], "output:input:input:Changed");
    assert_eq!(body(&updated)["tier"], 7);
    let physical: Value = serde_json::from_str(&db.table("ssoProvider").await?)?;
    assert_eq!(physical[0]["application_label"], "input:input:Changed");
    assert_eq!(physical[0]["tier"], 7);
    let unrelated = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::update_sso_provider_endpoint(
            &json!({"providerId":"callback-fields","domain":"changed.company.test"}),
        )?,
        owned.clone(),
    ))
    .await?
    .into_response()?;
    assert_eq!(body(&unrelated)["label"], "output:input:input:Changed");
    assert_eq!(body(&unrelated)["stamp"], "generated");
    let physical: Value = serde_json::from_str(&db.table("ssoProvider").await?)?;
    assert_eq!(physical[0]["application_label"], "input:input:Changed");
    let omitted = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::update_sso_provider_endpoint(
            &json!({"providerId":"callback-fields","label":"omit"}),
        )?,
        owned.clone(),
    ))
    .await?
    .into_response()?;
    assert_eq!(omitted.status, 200);
    assert_eq!(body(&omitted), body(&unrelated));
    let physical: Value = serde_json::from_str(&db.table("ssoProvider").await?)?;
    assert_eq!(physical[0]["application_label"], "input:input:Changed");
    let empty = match Box::pin(auth.dispatch_endpoint(
        SsoPlugin::update_sso_provider_endpoint(&json!({"providerId":"callback-fields"}))?,
        owned.clone(),
    ))
    .await
    {
        Ok(response) => response.into_response()?,
        Err(error) => error.error.to_auth_response(),
    };
    assert_eq!(empty.status, 400);
    assert_eq!(body(&empty)["message"], "No fields provided for update");
    let auth = build().await?;
    let read = Box::pin(auth.dispatch_endpoint(
        SsoPlugin::get_sso_provider_endpoint("callback-fields")?,
        owned.clone(),
    ))
    .await?
    .into_response()?;
    assert_eq!(body(&read), body(&unrelated));
    let listed = Box::pin(auth.dispatch_endpoint(SsoPlugin::list_sso_providers_endpoint(), owned))
        .await?
        .into_response()?;
    assert_eq!(body(&listed)["providers"], json!([body(&unrelated)]));
    assert_eq!(
        store
            .get_sso_provider("callback-fields")
            .await?
            .unwrap()
            .additional_fields["label"],
        "output:input:input:Changed"
    );
    Ok(())
}
