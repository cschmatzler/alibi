//! Issued managed credentials authenticate SCIM reads and account for successful use.
use super::scim_group_read::read;
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::scim::{ScimManagedConnectionInput, ScimManagedConnectionOptions, ScimPlugin};
backend_tests!(scim_managed_bearer_authenticates_and_throttles_last_used_writes);
postgres_tests!(scim_managed_bearer_authenticates_and_throttles_last_used_writes);
async fn scim_managed_bearer_authenticates_and_throttles_last_used_writes<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(
            ScimPlugin::new().managed_connections(ScimManagedConnectionOptions::new(
                "managed-scim-credential-hmac-secret-32-chars",
            )),
        )
        .build()
        .await?;
    let created = Box::pin(
        auth.dispatch_endpoint(
            ScimPlugin::create_managed_connection_endpoint(&ScimManagedConnectionInput {
                creation_request_id: "managed-bearer-request-001".into(),
                provisioning_domain_id: "tenant-managed".into(),
                actor_id: "operator".into(),
                scopes: vec!["scim.groups.read".into()],
                expires_at: chrono::DateTime::parse_from_rfc3339("2035-01-02T03:04:05.000Z")?
                    .with_timezone(&chrono::Utc),
            })?,
            EndpointOptions::default(),
        ),
    )
    .await?
    .into_response()?;
    assert_eq!(created.status, 200);
    let created = body(&created);
    let cid = created["connection"]["connectionId"].as_str().unwrap();
    let kid = created["credential"]["credentialId"].as_str().unwrap();
    let token = created["token"].as_str().unwrap();
    _=db.execute("INSERT INTO \"scimGroup\" (\"id\",\"connectionId\",\"provisioningDomainId\",\"revision\",\"displayName\",\"displayNameKey\",\"orderKey\",\"createdAt\",\"updatedAt\") VALUES ('managed-group',$1,'tenant-managed',0,'Managed Staff','managed-group','managed-group','2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",&[cid]).await?;
    let invalid = format!("{kid}.wrong-secret");
    for token in [invalid.as_str(), "ba_scim_credential_malformed"] {
        assert_eq!(
            read(&auth, "managed-group", &json!({}), Some(token))
                .await?
                .status,
            401
        );
    }
    let unused: Value = serde_json::from_str(&db.table("scimManagedCredential").await?)?;
    assert_eq!(unused[0]["lastUsedAt"], Value::Null);
    assert_eq!(db.table("scimConnectionBinding").await?, "[]");
    let response = read(&auth, "managed-group", &json!({}), Some(token)).await?;
    assert_eq!(response.status, 200);
    assert_eq!(
        body(&response),
        json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"id":"managed-group","displayName":"Managed Staff","members":[],"meta":{"resourceType":"Group","created":"2026-01-02T03:04:05.000Z","lastModified":"2026-01-02T03:04:05.000Z","location":format!("{ORIGIN}/api/auth/scim/v2/Groups/managed-group")}})
    );
    let usage_snapshot = db.table("scimManagedCredential").await?;
    let used: Value = serde_json::from_str(&usage_snapshot)?;
    assert!(used[0]["lastUsedAt"].is_string());
    let again = read(&auth, "managed-group", &json!({}), Some(token)).await?;
    assert_eq!(again.status, 200);
    assert_eq!(db.table("scimManagedCredential").await?, usage_snapshot);
    _=db.execute("UPDATE \"scimManagedCredential\" SET \"serializedScopes\"='not-json',\"lastUsedAt\"=NULL WHERE \"credentialId\"=$1",&[kid]).await?;
    let corrupt = read(&auth, "managed-group", &json!({}), Some(token)).await?;
    assert_eq!(corrupt.status, 500);
    assert_eq!(
        body(&corrupt)["detail"],
        "Managed SCIM credential scope policy is invalid"
    );
    let recorded: Value = serde_json::from_str(&db.table("scimManagedCredential").await?)?;
    assert!(recorded[0]["lastUsedAt"].is_string());
    _=db.execute("UPDATE \"scimManagedCredential\" SET \"serializedScopes\"='[\"scim.groups.read\"]',\"lastUsedAt\"=NULL WHERE \"credentialId\"=$1",&[kid]).await?;
    if db.is_postgres() {
        _=db.execute(r#"CREATE FUNCTION reject_scim_usage() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW."lastUsedAt" IS NOT NULL AND NEW."lastUsedAt" IS DISTINCT FROM OLD."lastUsedAt" THEN RAISE EXCEPTION 'fixture rejected usage'; END IF; RETURN NEW; END $$"#,&[]).await?;
        _=db.execute("CREATE TRIGGER reject_scim_usage BEFORE UPDATE ON \"scimManagedCredential\" FOR EACH ROW EXECUTE FUNCTION reject_scim_usage()",&[]).await?;
    } else {
        _=db.execute("CREATE TRIGGER reject_scim_usage BEFORE UPDATE ON \"scimManagedCredential\" WHEN NEW.\"lastUsedAt\" IS NOT NULL BEGIN SELECT RAISE(ABORT,'fixture rejected usage'); END",&[]).await?;
    }
    assert_eq!(
        read(&auth, "managed-group", &json!({}), Some(token))
            .await?
            .status,
        200
    );
    let failed_usage: Value = serde_json::from_str(&db.table("scimManagedCredential").await?)?;
    assert_eq!(failed_usage[0]["lastUsedAt"], Value::Null);
    if db.is_postgres() {
        _ = db
            .execute(
                "DROP TRIGGER reject_scim_usage ON \"scimManagedCredential\"",
                &[],
            )
            .await?;
        _ = db.execute("DROP FUNCTION reject_scim_usage()", &[]).await?;
    } else {
        _ = db.execute("DROP TRIGGER reject_scim_usage", &[]).await?;
    }
    assert_eq!(
        read(&auth, "managed-group", &json!({}), Some(token))
            .await?
            .status,
        200
    );
    _=db.execute("UPDATE \"scimManagedCredential\" SET \"serializedScopes\"='[\"scim.users.read\"]' WHERE \"credentialId\"=$1",&[kid]).await?;
    let denied = read(&auth, "managed-group", &json!({}), Some(token)).await?;
    assert_eq!(denied.status, 403);
    assert!(denied.headers.get("www-authenticate").is_none());
    _=db.execute("UPDATE \"scimManagedCredential\" SET \"serializedScopes\"='[\"scim.groups.read\"]',\"hashVersion\"='v2' WHERE \"credentialId\"=$1",&[kid]).await?;
    assert_eq!(
        read(&auth, "managed-group", &json!({}), Some(token))
            .await?
            .status,
        401
    );
    _=db.execute("UPDATE \"scimManagedCredential\" SET \"hashVersion\"='v1',\"status\"='revoked' WHERE \"credentialId\"=$1",&[kid]).await?;
    assert_eq!(
        read(&auth, "managed-group", &json!({}), Some(token))
            .await?
            .status,
        401
    );
    _ = db
        .execute(
            "UPDATE \"scimManagedCredential\" SET \"status\"='active' WHERE \"credentialId\"=$1",
            &[kid],
        )
        .await?;
    db.set_timestamp(
        "scimManagedCredential",
        "expiresAt",
        ("credentialId", kid),
        chrono::DateTime::parse_from_rfc3339("2000-01-01T00:00:00Z")?.with_timezone(&chrono::Utc),
    )
    .await?;
    assert_eq!(
        read(&auth, "managed-group", &json!({}), Some(token))
            .await?
            .status,
        401
    );
    db.set_timestamp(
        "scimManagedCredential",
        "expiresAt",
        ("credentialId", kid),
        chrono::DateTime::parse_from_rfc3339("2035-01-02T03:04:05Z")?.with_timezone(&chrono::Utc),
    )
    .await?;
    _=db.execute("UPDATE \"scimManagedConnection\" SET \"status\"='decommissioned' WHERE \"connectionId\"=$1",&[cid]).await?;
    assert_eq!(
        read(&auth, "managed-group", &json!({}), Some(token))
            .await?
            .status,
        401
    );
    Ok(())
}
