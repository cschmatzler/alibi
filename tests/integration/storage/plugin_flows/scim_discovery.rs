//! Public SCIM discovery is available without credentials and through the server API.
use super::*;
use alibi::endpoint::EndpointOptions;
backend_tests!(
    scim_service_provider_config_exposes_reference_capabilities,
    scim_resource_types_are_public_and_include_enterprise_user,
    scim_resource_type_lookup_matches_reference_errors,
    scim_schema_listing_exposes_complete_standard_attribute_contracts
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

async fn scim_schema_listing_exposes_complete_standard_attribute_contracts<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(alibi::plugins::ScimPlugin::new())
        .build()
        .await?;
    let response = call(&auth, request("/scim/v2/Schemas", None, ""), 200).await;
    assert_eq!(
        response.headers.get("content-type").map(String::as_str),
        Some("application/scim+json")
    );
    let document = body(&response);
    assert_eq!(
        document["schemas"],
        json!(["urn:ietf:params:scim:api:messages:2.0:ListResponse"])
    );
    assert_eq!(document["totalResults"], 3);
    assert_eq!(document["itemsPerPage"], 3);
    assert_eq!(document["startIndex"], 1);
    let resources = document["Resources"].as_array().unwrap();
    assert_eq!(resources.len(), 3);
    for (schema, id, names) in [
        (
            &resources[0],
            "urn:ietf:params:scim:schemas:core:2.0:User",
            vec![
                "userName",
                "displayName",
                "active",
                "name",
                "emails",
                "title",
                "userType",
                "preferredLanguage",
                "locale",
                "timezone",
                "phoneNumbers",
                "addresses",
                "roles",
                "entitlements",
            ],
        ),
        (
            &resources[1],
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
            vec![
                "employeeNumber",
                "costCenter",
                "organization",
                "division",
                "department",
                "manager",
            ],
        ),
        (
            &resources[2],
            "urn:ietf:params:scim:schemas:core:2.0:Group",
            vec!["displayName", "members"],
        ),
    ] {
        assert_eq!(schema["id"], id);
        assert_eq!(
            schema["schemas"],
            json!(["urn:ietf:params:scim:schemas:core:2.0:Schema"])
        );
        assert_eq!(
            schema["meta"],
            json!({"resourceType":"Schema","location":format!("{ORIGIN}/api/auth/scim/v2/Schemas/{id}")})
        );
        assert_eq!(
            schema["attributes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|attribute| attribute["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            names
        );
    }
    assert_eq!(resources[0]["attributes"][0]["required"], true);
    assert_eq!(resources[0]["attributes"][0]["uniqueness"], "server");
    let manager = &resources[1]["attributes"][5];
    assert_eq!(manager["type"], "complex");
    assert_eq!(
        manager["subAttributes"][1]["referenceTypes"],
        json!(["User"])
    );
    assert_eq!(manager["subAttributes"][2]["mutability"], "readOnly");
    let members = &resources[2]["attributes"][1];
    assert_eq!(members["multiValued"], true);
    assert_eq!(members["subAttributes"][0]["required"], true);
    assert_eq!(members["subAttributes"][0]["mutability"], "immutable");
    assert_eq!(
        members["subAttributes"][3]["canonicalValues"],
        json!(["User"])
    );
    let output = auth
        .dispatch_endpoint(
            alibi::plugins::ScimPlugin::schemas_endpoint(),
            EndpointOptions::default(),
        )
        .await?;
    assert_eq!(
        output.value(),
        &alibi::utils::json::parse_value(&document.to_string())?
    );
    Ok(())
}
