//! Trusted managed reads resolve the domain and expose current credential policy.
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::scim::{ScimManagedConnectionInput, ScimManagedConnectionOptions, ScimPlugin};
backend_tests!(scim_managed_get_redacts_scopes_expiry_and_domain_denials_after_restart);
postgres_tests!(scim_managed_get_redacts_scopes_expiry_and_domain_denials_after_restart);
async fn scim_managed_get_redacts_scopes_expiry_and_domain_denials_after_restart<B: Backend>(
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
    let input = ScimManagedConnectionInput {
        creation_request_id: "managed-get-request-001".into(),
        provisioning_domain_id: "tenant-a".into(),
        actor_id: "operator".into(),
        scopes: vec!["scim.users.read".into(), "scim.groups.write".into()],
        expires_at: chrono::DateTime::parse_from_rfc3339("2035-01-02T03:04:05.678Z")?
            .with_timezone(&chrono::Utc),
    };
    let created = auth
        .dispatch_endpoint(
            ScimPlugin::create_managed_connection_endpoint(&input)?,
            EndpointOptions::default(),
        )
        .await?
        .into_response()?;
    let created = body(&created);
    let cid = created["connection"]["connectionId"].as_str().unwrap();
    let kid = created["credential"]["credentialId"].as_str().unwrap();
    let get = |id: &str, domain: &str| {
        ScimPlugin::get_managed_connection_endpoint(id, domain)
    };
    let response = match auth
        .dispatch_endpoint(get(cid, "  tenant-a  ")?, EndpointOptions::default())
        .await
    {
        Ok(output) => output.into_response()?,
        Err(error) => error.error.to_auth_response(),
    };
    assert_eq!(response.status, 200);
    assert_eq!(
        body(&response),
        json!({"connection":created["connection"],"credentials":[created["credential"]]})
    );
    let before = db
        .tables(&[
            "scimManagedConnection",
            "scimManagedCredential",
            "scimManagedConnectionEvent",
        ])
        .await?;
    for (id, domain) in [
        (cid, "tenant-b"),
        ("ba_scim_connection_missing", "tenant-a"),
    ] {
        let error = auth
            .dispatch_endpoint(get(id, domain)?, EndpointOptions::default())
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), 404);
        assert_eq!(
            error.error.error_payload().2,
            "Managed SCIM connection not found"
        );
    }
    assert_eq!(
        db.tables(&[
            "scimManagedConnection",
            "scimManagedCredential",
            "scimManagedConnectionEvent"
        ])
        .await?,
        before
    );
    db.set_timestamp(
        "scimManagedCredential",
        "expiresAt",
        ("credentialId", kid),
        chrono::DateTime::parse_from_rfc3339("2000-01-01T00:00:00.000Z")?
            .with_timezone(&chrono::Utc),
    )
    .await?;
    let auth = build().await?;
    let expired = auth
        .dispatch_endpoint(get(cid, "tenant-a")?, EndpointOptions::default())
        .await?
        .into_response()?;
    let expired = body(&expired);
    assert_eq!(expired["connection"], created["connection"]);
    assert_eq!(expired["credentials"][0]["status"], "expired");
    assert_eq!(expired["credentials"][0]["scopes"], json!(input.scopes));
    assert_eq!(expired["credentials"][0]["credentialId"], kid);
    for field in [
        "id",
        "connectionRecordId",
        "tokenDigest",
        "hashVersion",
        "activeSlotKey",
        "serializedScopes",
        "decommissionedAt",
        "token",
    ] {
        assert!(expired["credentials"][0].get(field).is_none());
    }
    for policy in [
        "not-json",
        "[]",
        r#"["scim.users.read","scim.users.read"]"#,
        r#"["unknown"]"#,
    ] {
        _=db.execute("UPDATE \"scimManagedCredential\" SET \"serializedScopes\"=$1 WHERE \"credentialId\"=$2",&[policy,kid]).await?;
        let error = auth
            .dispatch_endpoint(get(cid, "tenant-a")?, EndpointOptions::default())
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), 500);
        assert_eq!(
            error.error.error_payload().2,
            "Managed SCIM credential scope policy is invalid"
        );
    }
    Ok(())
}
