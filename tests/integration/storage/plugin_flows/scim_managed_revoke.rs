//! Public revocation is idempotent and releases a durable credential slot.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::scim::{ScimManagedConnectionInput, ScimManagedConnectionOptions, ScimPlugin};
backend_tests!(scim_managed_revocation_is_idempotent_and_domain_scoped);
postgres_tests!(scim_managed_revocation_is_idempotent_and_domain_scoped);
async fn scim_managed_revocation_is_idempotent_and_domain_scoped<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(
            ScimPlugin::new().managed_connections(ScimManagedConnectionOptions::new(
                "managed-scim-credential-hmac-secret-32-chars",
            )),
        )
        .build()
        .await?;
    let expiry = chrono::DateTime::parse_from_rfc3339("2035-01-02T03:04:05.678Z")?
        .with_timezone(&chrono::Utc);
    let created = auth
        .dispatch_endpoint(
            ScimPlugin::create_managed_connection_endpoint(&ScimManagedConnectionInput {
                creation_request_id: "managed-revoke-request-001".into(),
                provisioning_domain_id: "tenant-a".into(),
                actor_id: "operator".into(),
                scopes: vec!["scim.users.read".into()],
                expires_at: expiry,
            })?,
            EndpointOptions::default(),
        )
        .await?
        .into_response()?;
    let created = body(&created);
    let cid = created["connection"]["connectionId"].as_str().unwrap();
    let kid = created["credential"]["credentialId"].as_str().unwrap();
    let revoke = |domain: &str, credential: &str| {
        ServerEndpoint::<Value>::new("scim","revokeSCIMManagedCredential").with_body(&json!({"connectionId":cid,"provisioningDomainId":domain,"credentialId":credential,"actorId":"  revocation-operator  "})).unwrap()
    };
    db.set_timestamp(
        "scimManagedCredential",
        "expiresAt",
        ("credentialId", kid),
        chrono::DateTime::parse_from_rfc3339("2000-01-01T00:00:00.000Z")?
            .with_timezone(&chrono::Utc),
    )
    .await?;
    let result = auth
        .dispatch_endpoint(revoke("  tenant-a  ", kid), EndpointOptions::default())
        .await;
    let response = match result {
        Ok(output) => output.into_response()?,
        Err(error) => error.error.to_auth_response(),
    };
    assert_eq!(response.status, 200);
    let state = body(&response);
    assert_eq!(state["connection"], created["connection"]);
    assert_eq!(state["credentials"][0]["status"], "revoked");
    assert_eq!(state["credentials"][0]["revokedBy"], "revocation-operator");
    assert!(
        chrono::DateTime::parse_from_rfc3339(
            state["credentials"][0]["revokedAt"].as_str().unwrap()
        )
        .is_ok()
    );
    let rows: Value = serde_json::from_str(&db.table("scimManagedCredential").await?)?;
    assert_eq!(rows[0]["activeSlotKey"], format!("{kid}:inactive"));
    let events: Value = serde_json::from_str(&db.table("scimManagedConnectionEvent").await?)?;
    let event = events
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["sequence"] == 3)
        .unwrap();
    assert_eq!(event["type"], "credential.revoked");
    assert_eq!(event["credentialId"], kid);
    let before = db
        .tables(&[
            "scimManagedConnection",
            "scimManagedCredential",
            "scimManagedConnectionEvent",
        ])
        .await?;
    let again = auth
        .dispatch_endpoint(revoke("tenant-a", kid), EndpointOptions::default())
        .await?
        .into_response()?;
    assert_eq!(body(&again), state);
    for (domain, credential) in [
        ("tenant-b", kid),
        ("tenant-a", "ba_scim_credential_missing"),
    ] {
        let error = auth
            .dispatch_endpoint(revoke(domain, credential), EndpointOptions::default())
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
    let other = auth
        .dispatch_endpoint(
            ScimPlugin::create_managed_connection_endpoint(&ScimManagedConnectionInput {
                creation_request_id: "managed-revoke-request-002".into(),
                provisioning_domain_id: "tenant-a".into(),
                actor_id: "operator".into(),
                scopes: vec!["scim.users.read".into()],
                expires_at: expiry,
            })?,
            EndpointOptions::default(),
        )
        .await?
        .into_response()?;
    let other = body(&other);
    let before = db
        .tables(&[
            "scimManagedConnection",
            "scimManagedCredential",
            "scimManagedConnectionEvent",
        ])
        .await?;
    if db.is_postgres() {
        _=db.execute("CREATE FUNCTION reject_scim_revocation_event() RETURNS trigger LANGUAGE plpgsql AS $function$ BEGIN IF NEW.\"actorId\"='rollback-operator' AND NEW.\"type\"='credential.revoked' THEN RAISE EXCEPTION 'fixture rejected revocation event'; END IF; RETURN NEW; END $function$",&[]).await?;
        _=db.execute("CREATE TRIGGER reject_scim_revocation_event BEFORE INSERT ON \"scimManagedConnectionEvent\" FOR EACH ROW EXECUTE FUNCTION reject_scim_revocation_event()",&[]).await?;
    } else {
        _=db.execute("CREATE TRIGGER reject_scim_revocation_event BEFORE INSERT ON scimManagedConnectionEvent WHEN NEW.actorId='rollback-operator' AND NEW.type='credential.revoked' BEGIN SELECT RAISE(ABORT,'fixture rejected revocation event'); END",&[]).await?;
    }
    let error = auth
        .dispatch_endpoint(
            ScimPlugin::revoke_managed_credential_endpoint(
                other["connection"]["connectionId"].as_str().unwrap(),
                "tenant-a",
                other["credential"]["credentialId"].as_str().unwrap(),
                "rollback-operator",
            )?,
            EndpointOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.error.status_code(), 500);
    assert!(
        error
            .to_string()
            .contains("fixture rejected revocation event")
    );
    assert_eq!(
        db.tables(&[
            "scimManagedConnection",
            "scimManagedCredential",
            "scimManagedConnectionEvent"
        ])
        .await?,
        before
    );
    Ok(())
}
