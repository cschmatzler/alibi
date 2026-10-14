//! Credential rotation fences one connection and reuses expired slots atomically.
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::scim::{ScimManagedConnectionInput, ScimManagedConnectionOptions, ScimManagedCredentialRotationInput, ScimPlugin};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
backend_tests!(scim_managed_rotation_enforces_slots_and_rolls_back_event_failure);
postgres_tests!(scim_managed_rotation_enforces_slots_and_rolls_back_event_failure);
async fn scim_managed_rotation_enforces_slots_and_rolls_back_event_failure<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut options =
        ScimManagedConnectionOptions::new("managed-scim-credential-hmac-secret-32-chars");
    options.max_active_credentials = 2;
    let auth = builder::<B>(&connection)
        .plugin(ScimPlugin::new().managed_connections(options))
        .build()
        .await?;
    let expiry = chrono::DateTime::parse_from_rfc3339("2035-01-02T03:04:05.678Z")?
        .with_timezone(&chrono::Utc);
    let created = auth
        .dispatch_endpoint(
            ScimPlugin::create_managed_connection_endpoint(&ScimManagedConnectionInput {
                creation_request_id: "managed-rotate-request-001".into(),
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
    let first = created["credential"]["credentialId"].as_str().unwrap();
    let rotate = |id:&str,domain:&str,actor:&str| ScimPlugin::rotate_managed_credential_endpoint(&ScimManagedCredentialRotationInput{connection_id:id.into(),provisioning_domain_id:domain.into(),actor_id:actor.into(),scopes:vec!["scim.groups.write".into()],expires_at:expiry}).unwrap();
    let response = match auth
        .dispatch_endpoint(
            rotate(cid, "  tenant-a  ", "  rotation-operator  "),
            EndpointOptions::default(),
        )
        .await
    {
        Ok(output) => output.into_response()?,
        Err(error) => error.error.to_auth_response(),
    };
    assert_eq!(response.status, 200);
    assert_eq!(
        response.headers.get("cache-control").map(String::as_str),
        Some("no-store")
    );
    assert_eq!(
        response.headers.get("pragma").map(String::as_str),
        Some("no-cache")
    );
    let rotated = body(&response);
    assert_eq!(rotated["connection"], created["connection"]);
    assert_eq!(rotated["credential"]["createdBy"], "rotation-operator");
    assert_eq!(
        rotated["credential"]["scopes"],
        json!(["scim.groups.write"])
    );
    assert_ne!(rotated["credential"]["credentialId"], first);
    assert_ne!(rotated["token"], created["token"]);
    let before = db
        .tables(&[
            "scimManagedConnection",
            "scimManagedCredential",
            "scimManagedConnectionEvent",
        ])
        .await?;
    let full = auth
        .dispatch_endpoint(
            rotate(cid, "tenant-a", "operator"),
            EndpointOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(full.error.status_code(), 409);
    assert_eq!(
        full.error.error_payload().2,
        "Managed SCIM connection has the maximum number of active credentials"
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
    for (id, domain) in [
        (cid, "tenant-b"),
        ("ba_scim_connection_missing", "tenant-a"),
    ] {
        let error = auth
            .dispatch_endpoint(rotate(id, domain, "operator"), EndpointOptions::default())
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), 404);
    }
    db.set_timestamp(
        "scimManagedCredential",
        "expiresAt",
        ("credentialId", first),
        chrono::DateTime::parse_from_rfc3339("2000-01-01T00:00:00.000Z")?
            .with_timezone(&chrono::Utc),
    )
    .await?;
    let recycled = auth
        .dispatch_endpoint(
            rotate(cid, "tenant-a", "operator"),
            EndpointOptions::default(),
        )
        .await?
        .into_response()?;
    let recycled = body(&recycled);
    let rows: Value = serde_json::from_str(&db.table("scimManagedCredential").await?)?;
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 3);
    let retired = rows
        .iter()
        .find(|row| row["credentialId"] == first)
        .unwrap();
    assert_eq!(retired["status"], "expired");
    assert_eq!(retired["activeSlotKey"], format!("{first}:inactive"));
    let fresh = rows
        .iter()
        .find(|row| row["credentialId"] == recycled["credential"]["credentialId"])
        .unwrap();
    let record_id = fresh["connectionRecordId"].as_str().unwrap();
    assert_eq!(fresh["activeSlotKey"], format!("{record_id}:active:0"));
    let token = recycled["token"].as_str().unwrap();
    let secret = b"managed-scim-credential-hmac-secret-32-chars";
    let mut key = [0_u8; 64];
    key[..secret.len()].copy_from_slice(secret);
    let mut inner = key.iter().map(|byte| byte ^ 0x36).collect::<Vec<_>>();
    inner.extend_from_slice(token.as_bytes());
    let mut outer = key.iter().map(|byte| byte ^ 0x5c).collect::<Vec<_>>();
    outer.extend_from_slice(&Sha256::digest(inner));
    assert_eq!(
        fresh["tokenDigest"],
        URL_SAFE_NO_PAD.encode(Sha256::digest(outer))
    );

    let connection_rows: Value = serde_json::from_str(&db.table("scimManagedConnection").await?)?;
    assert_eq!(connection_rows[0]["revision"], 4);
    let events: Value = serde_json::from_str(&db.table("scimManagedConnectionEvent").await?)?;
    assert_eq!(events.as_array().unwrap().len(), 4);
    for sequence in [3, 4] {
        let event = events
            .as_array()
            .unwrap()
            .iter()
            .find(|event| event["sequence"] == sequence)
            .unwrap();
        assert_eq!(event["type"], "credential.rotated");
    }
    let second = rotated["credential"]["credentialId"].as_str().unwrap();
    db.set_timestamp(
        "scimManagedCredential",
        "expiresAt",
        ("credentialId", second),
        chrono::DateTime::parse_from_rfc3339("2000-01-01T00:00:00.000Z")?
            .with_timezone(&chrono::Utc),
    )
    .await?;
    let before = db
        .tables(&[
            "scimManagedConnection",
            "scimManagedCredential",
            "scimManagedConnectionEvent",
        ])
        .await?;
    if db.is_postgres() {
        _=db.execute("CREATE FUNCTION reject_scim_rotation_event() RETURNS trigger LANGUAGE plpgsql AS $function$ BEGIN IF NEW.\"actorId\"='rollback-operator' AND NEW.\"type\"='credential.rotated' THEN RAISE EXCEPTION 'fixture rejected rotation event'; END IF; RETURN NEW; END $function$",&[]).await?;
        _=db.execute("CREATE TRIGGER reject_scim_rotation_event BEFORE INSERT ON \"scimManagedConnectionEvent\" FOR EACH ROW EXECUTE FUNCTION reject_scim_rotation_event()",&[]).await?;
    } else {
        _=db.execute("CREATE TRIGGER reject_scim_rotation_event BEFORE INSERT ON scimManagedConnectionEvent WHEN NEW.actorId='rollback-operator' AND NEW.type='credential.rotated' BEGIN SELECT RAISE(ABORT,'fixture rejected rotation event'); END",&[]).await?;
    }
    let error = auth
        .dispatch_endpoint(
            rotate(cid, "tenant-a", "rollback-operator"),
            EndpointOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.error.status_code(), 500);
    assert!(
        error
            .to_string()
            .contains("fixture rejected rotation event")
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
