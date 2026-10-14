//! Managed listing scopes durable metadata to one provisioning domain.
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::scim::{ScimManagedConnectionInput, ScimManagedConnectionOptions, ScimPlugin};
backend_tests!(scim_managed_listing_scopes_orders_and_redacts_after_restart);
postgres_tests!(scim_managed_listing_scopes_orders_and_redacts_after_restart);
async fn scim_managed_listing_scopes_orders_and_redacts_after_restart<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let build = || {
        builder::<B>(&connection)
            .plugin(
                ScimPlugin::new().managed_connections(ScimManagedConnectionOptions::new(
                    "managed-scim-credential-hmac-secret-32-chars",
                )),
            )
            .build()
    };
    let auth = build().await?;
    let list = |domain: &str| ScimPlugin::list_managed_connections_endpoint(domain);
    let empty = auth
        .dispatch_endpoint(list("tenant-a")?, EndpointOptions::default())
        .await;
    let response = match empty {
        Ok(output) => output.into_response()?,
        Err(error) => error.error.to_auth_response(),
    };
    assert_eq!(response.status, 200);
    assert_eq!(body(&response), json!({"connections":[]}));
    let mut created = Vec::new();
    for (request_id, domain) in [
        ("list-request-a-one", "tenant-a"),
        ("list-request-b-one", "tenant-b"),
        ("list-request-a-two", "tenant-a"),
    ] {
        let input = ScimManagedConnectionInput {
            creation_request_id: request_id.into(),
            provisioning_domain_id: domain.into(),
            actor_id: "operator".into(),
            scopes: vec!["scim.users.read".into()],
            expires_at: chrono::DateTime::parse_from_rfc3339("2035-01-02T03:04:05.678Z")?
                .with_timezone(&chrono::Utc),
        };
        let output = auth
            .dispatch_endpoint(
                ScimPlugin::create_managed_connection_endpoint(&input)?,
                EndpointOptions::default(),
            )
            .await?
            .into_response()?;
        created.push(body(&output)["connection"].clone());
    }
    db.set_timestamp(
        "scimManagedConnection",
        "createdAt",
        ("connectionId", created[0]["connectionId"].as_str().unwrap()),
        chrono::DateTime::parse_from_rfc3339("2000-01-01T00:00:00.000Z")?
            .with_timezone(&chrono::Utc),
    )
    .await?;
    created[0]["createdAt"] = json!("2000-01-01T00:00:00Z");
    let auth = build().await?;
    let a = auth
        .dispatch_endpoint(list("  tenant-a  ")?, EndpointOptions::default())
        .await?
        .into_response()?;
    let metadata = &body(&a)["connections"];
    assert_eq!(metadata.as_array().unwrap().len(), 2);
    assert_eq!(metadata[0]["connectionId"], created[2]["connectionId"]);
    assert_eq!(metadata[1]["connectionId"], created[0]["connectionId"]);
    for row in metadata.as_array().unwrap() {
        assert_eq!(row["provisioningDomainId"], "tenant-a");
        assert_eq!(row["status"], "active");
        assert_eq!(row["createdBy"], "operator");
        for field in ["id", "revision", "credentials", "token", "tokenDigest"] {
            assert!(row.get(field).is_none());
        }
    }
    let b = auth
        .dispatch_endpoint(list("tenant-b")?, EndpointOptions::default())
        .await?
        .into_response()?;
    assert_eq!(body(&b)["connections"], json!([created[1]]));
    let empty = auth
        .dispatch_endpoint(list("missing")?, EndpointOptions::default())
        .await?
        .into_response()?;
    assert_eq!(body(&empty), json!({"connections":[]}));
    Ok(())
}
