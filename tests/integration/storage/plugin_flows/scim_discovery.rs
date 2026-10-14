//! Public SCIM discovery is available without credentials and through the server API.
use super::*;
use alibi::endpoint::EndpointOptions;
backend_tests!(scim_service_provider_config_exposes_reference_capabilities);
async fn scim_service_provider_config_exposes_reference_capabilities<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(alibi::plugins::ScimPlugin::new())
        .build()
        .await?;
    let response = call(
        &auth,
        request("/scim/v2/ServiceProviderConfig", None, ""),
        200,
    )
    .await;
    assert_eq!(
        response.headers.get("content-type").map(String::as_str),
        Some("application/scim+json")
    );
    let expected = json!({
        "schemas":["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch":{"supported":true}, "bulk":{"supported":false,"maxOperations":0,"maxPayloadSize":0},
        "filter":{"supported":true,"maxResults":100}, "changePassword":{"supported":false},
        "sort":{"supported":false},"etag":{"supported":false},
        "authenticationSchemes":[{"name":"OAuth Bearer Token","description":"Authentication using a bearer token in the Authorization header.","specUri":"https://www.rfc-editor.org/info/rfc6750","type":"oauthbearertoken","primary":true}],
        "meta":{"resourceType":"ServiceProviderConfig","location":format!("{ORIGIN}/api/auth/scim/v2/ServiceProviderConfig")}
    });
    assert_eq!(body(&response), expected);
    let output = auth
        .dispatch_endpoint(
            alibi::plugins::ScimPlugin::service_provider_config_endpoint(),
            EndpointOptions::default(),
        )
        .await?;
    assert_eq!(
        output.value(),
        &alibi::utils::json::parse_value(&expected.to_string())?
    );
    Ok(())
}
