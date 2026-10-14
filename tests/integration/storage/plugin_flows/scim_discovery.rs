//! Public SCIM discovery is available without credentials and through the server API.
use super::*;
use alibi::endpoint::EndpointOptions;
backend_tests!(
    scim_service_provider_config_exposes_reference_capabilities,
    scim_resource_types_are_public_and_include_enterprise_user,
    scim_resource_type_lookup_matches_reference_errors
);
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

async fn scim_resource_types_are_public_and_include_enterprise_user<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(alibi::plugins::ScimPlugin::new())
        .build()
        .await?;
    let response = call(&auth, request("/scim/v2/ResourceTypes", None, ""), 200).await;
    assert_eq!(
        response.headers.get("content-type").map(String::as_str),
        Some("application/scim+json")
    );
    let expected = json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":2,"startIndex":1,"itemsPerPage":2,"Resources":[
        {"schemas":["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],"id":"User","name":"User","endpoint":"/Users","description":"User Account","schema":"urn:ietf:params:scim:schemas:core:2.0:User","schemaExtensions":[{"schema":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User","required":false}],"meta":{"resourceType":"ResourceType","location":format!("{ORIGIN}/api/auth/scim/v2/ResourceTypes/User")}},
        {"schemas":["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],"id":"Group","name":"Group","endpoint":"/Groups","description":"Group","schema":"urn:ietf:params:scim:schemas:core:2.0:Group","meta":{"resourceType":"ResourceType","location":format!("{ORIGIN}/api/auth/scim/v2/ResourceTypes/Group")}}
    ]});
    assert_eq!(body(&response), expected);
    let output = auth
        .dispatch_endpoint(
            alibi::plugins::ScimPlugin::resource_types_endpoint(),
            EndpointOptions::default(),
        )
        .await?;
    assert_eq!(
        output.value(),
        &alibi::utils::json::parse_value(&expected.to_string())?
    );
    Ok(())
}

async fn scim_resource_type_lookup_matches_reference_errors<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(alibi::plugins::ScimPlugin::new())
        .build()
        .await?;
    let group = json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],"id":"Group","name":"Group","endpoint":"/Groups","description":"Group","schema":"urn:ietf:params:scim:schemas:core:2.0:Group","meta":{"resourceType":"ResourceType","location":format!("{ORIGIN}/api/auth/scim/v2/ResourceTypes/Group")}});
    let response = call(
        &auth,
        request("/scim/v2/ResourceTypes/Group", None, ""),
        200,
    )
    .await;
    assert_eq!(body(&response), group);
    assert_eq!(
        response.headers.get("content-type").map(String::as_str),
        Some("application/scim+json")
    );
    let endpoint = |id: &str| alibi::plugins::ScimPlugin::resource_type_endpoint(id);
    let direct = auth
        .dispatch_endpoint(endpoint("Group")?, EndpointOptions::default())
        .await?;
    assert_eq!(
        direct.value(),
        &alibi::utils::json::parse_value(&group.to_string())?
    );
    let encoded = call(
        &auth,
        request("/scim/v2/ResourceTypes/%55ser", None, ""),
        404,
    )
    .await;
    assert_eq!(
        body(&encoded),
        json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"404","detail":"Resource type not found"})
    );
    for id in ["group", "Unknown", "%47roup"] {
        let error = auth
            .dispatch_endpoint(endpoint(id)?, EndpointOptions::default())
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), 404);
        let expected = json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"404","detail":"Resource type not found"});
        assert_eq!(
            error.body.as_deref(),
            Some(&alibi::utils::json::parse_value(&expected.to_string())?)
        );
        if id != "%47roup" {
            let response = call(
                &auth,
                request(&format!("/scim/v2/ResourceTypes/{id}"), None, ""),
                404,
            )
            .await;
            assert_eq!(body(&response), expected);
            assert_eq!(
                response.headers.get("content-type").map(String::as_str),
                Some("application/scim+json")
            );
        }
    }
    Ok(())
}
