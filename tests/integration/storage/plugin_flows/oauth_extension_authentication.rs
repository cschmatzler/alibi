use super::*;
use alibi::endpoint::{EndpointCall, EndpointDefinition, EndpointOptions};
use alibi::plugins::{
    OAuthClientAuthenticationOptions, OAuthProviderConfig, OAuthProviderPlugin, jwt::JwtPlugin,
};
use alibi::utils::json::JsValue;
#[path = "../../../fixtures/oauth/extension-authentication.rs"]
mod extension_authentication;

backend_tests!(oauth_extension_authentication_returns_verified_identity_and_confirmation);
postgres_tests!(oauth_extension_authentication_returns_verified_identity_and_confirmation);

async fn oauth_extension_authentication_returns_verified_identity_and_confirmation<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let provider = OAuthProviderPlugin::with_config(OAuthProviderConfig {
        extensions: extension_authentication::extensions(),
        ..Default::default()
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(provider.clone())
        .build()
        .await?;
    let owner = signup(&auth, "extension-auth@example.test").await;
    let created=Box::pin(auth.dispatch_endpoint(OAuthProviderPlugin::admin_create_oauth_client_endpoint(&json!({
        "client_name":"Application client","redirect_uris":["https://app.fixture.test/callback"],
        "scope":"email","token_endpoint_auth_method":extension_authentication::METHOD
    }))?,EndpointOptions{headers:Some([("cookie".into(),cookies(&owner))].into_iter().collect()),..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 201);
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    assert!(
        auth.store()
            .get_oauth_client(&id)
            .await?
            .unwrap()
            .client_secret
            .is_none()
    );
    let path = "/native/authentication";
    let proof = extension_authentication::proof(&id, &format!("{ORIGIN}/api/auth{path}"));
    let call = EndpointCall::new(
        &EndpointDefinition {
            name: "nativeAuthentication",
            operation_id: "nativeAuthentication",
            path: Some(path.into()),
            method: HttpMethod::Post,
        },
        Some(JsValue::from(
            json!({"client_assertion":proof,"client_assertion_type":extension_authentication::ASSERTION}),
        )),
        None,
        EndpointOptions::default(),
    );
    let result = provider
        .authenticate_client(
            auth.context(),
            &call,
            Some("authorization_code"),
            &OAuthClientAuthenticationOptions {
                scopes: Some(vec!["email".into()]),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(result.client_id, id);
    assert_eq!(
        result.method.as_deref(),
        Some(extension_authentication::METHOD)
    );
    assert_eq!(
        result.confirmation,
        Some(json!({"x5t#S256":"application-certificate"}))
    );
    for (grant, scopes, code, description) in [
        (
            "client_credentials",
            vec!["email".into()],
            "unauthorized_client",
            "client is not authorized to use grant type client_credentials",
        ),
        (
            "authorization_code",
            vec!["admin".into()],
            "invalid_scope",
            "client does not allow scope admin",
        ),
    ] {
        let error = provider
            .authenticate_client(
                auth.context(),
                &call,
                Some(grant),
                &OAuthClientAuthenticationOptions {
                    scopes: Some(scopes),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.body.as_deref(),
            Some(&JsValue::from(
                json!({"error":code,"error_description":description})
            ))
        );
    }
    let mut metadata = auth.store().get_oauth_client(&id).await?.unwrap().metadata;
    for (field, value, description) in [
        (
            "token_endpoint_auth_method",
            json!("none"),
            "client registered for none cannot use application_assertion",
        ),
        ("disabled", json!(true), "client is disabled"),
    ] {
        metadata[field] = value;
        assert!(
            auth.store()
                .update_oauth_client_metadata(&id, metadata.clone(), chrono::Utc::now())
                .await?
                .is_some()
        );
        let error = provider
            .authenticate_client(
                auth.context(),
                &call,
                Some("authorization_code"),
                &OAuthClientAuthenticationOptions::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.body.as_deref(),
            Some(&JsValue::from(
                json!({"error":"invalid_client","error_description":description})
            ))
        );
    }
    Ok(())
}
