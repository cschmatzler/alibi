//! Managed retirement disables credentials and records both durable lifecycle events.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::scim::{
    ScimManagedConnectionInput, ScimManagedConnectionOptions, ScimManagedCredentialRotationInput,
    ScimPlugin,
};
backend_tests!(scim_managed_decommission_retires_credentials_and_is_idempotent);
postgres_tests!(scim_managed_decommission_retires_credentials_and_is_idempotent);
async fn scim_managed_decommission_retires_credentials_and_is_idempotent<B: Backend>(
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
    let expiry = chrono::DateTime::parse_from_rfc3339("2035-01-02T03:04:05.678Z")?
        .with_timezone(&chrono::Utc);
    let created = Box::pin(auth.dispatch_endpoint(
        ScimPlugin::create_managed_connection_endpoint(&ScimManagedConnectionInput {
            creation_request_id: "managed-decommission-request-001".into(),
            provisioning_domain_id: "tenant-a".into(),
            actor_id: "creator".into(),
            scopes: vec!["scim.users.read".into()],
            expires_at: expiry,
        })?,
        EndpointOptions::default(),
    ))
    .await?
    .into_response()?;
    let created = body(&created);
    let cid = created["connection"]["connectionId"].as_str().unwrap();
    let first = created["credential"]["credentialId"].as_str().unwrap();
    let rotated = Box::pin(auth.dispatch_endpoint(
        ScimPlugin::rotate_managed_credential_endpoint(&ScimManagedCredentialRotationInput {
            connection_id: cid.into(),
            provisioning_domain_id: "tenant-a".into(),
            actor_id: "rotator".into(),
            scopes: vec!["scim.groups.write".into()],
            expires_at: expiry,
        })?,
        EndpointOptions::default(),
    ))
    .await?
    .into_response()?;
    let rotated = body(&rotated);
    let second = rotated["credential"]["credentialId"].as_str().unwrap();
    _ = Box::pin(auth.dispatch_endpoint(
        ScimPlugin::revoke_managed_credential_endpoint(cid, "tenant-a", first, "revoker")?,
        EndpointOptions::default(),
    ))
    .await?;
    let retire = |domain: &str| {
        ServerEndpoint::<Value>::new("scim","decommissionSCIMManagedConnection").with_body(&json!({"connectionId":cid,"provisioningDomainId":domain,"actorId":"  retirement-operator  "})).unwrap()
    };
    let result =
        Box::pin(auth.dispatch_endpoint(retire("  tenant-a  "), EndpointOptions::default())).await;
    let response = match result {
        Ok(output) => output.into_response()?,
        Err(error) => error.error.to_auth_response(),
    };
    assert_eq!(response.status, 200);
    let state = body(&response);
    assert_eq!(state["connection"]["status"], "decommissioned");
    assert_eq!(
        state["connection"]["decommissionStartedBy"],
        "retirement-operator"
    );
    assert_eq!(
        state["connection"]["decommissionedBy"],
        "retirement-operator"
    );
    assert_eq!(state["decommission"]["status"], "complete");
    assert_eq!(state["decommission"]["retryAfter"], Value::Null);
    let credentials = state["credentials"].as_array().unwrap();
    assert_eq!(
        credentials
            .iter()
            .find(|credential| credential["credentialId"] == first)
            .unwrap()["status"],
        "revoked"
    );
    assert_eq!(
        credentials
            .iter()
            .find(|credential| credential["credentialId"] == second)
            .unwrap()["status"],
        "decommissioned"
    );
    let rows: Value = serde_json::from_str(&db.table("scimManagedCredential").await?)?;
    let row = rows
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["credentialId"] == second)
        .unwrap();
    assert_eq!(row["activeSlotKey"], format!("{second}:inactive"));
    assert!(row["decommissionedAt"].is_string());
    let events: Value = serde_json::from_str(&db.table("scimManagedConnectionEvent").await?)?;
    for (sequence, kind) in [
        (5, "connection.decommissioning"),
        (6, "connection.decommissioned"),
    ] {
        let event = events
            .as_array()
            .unwrap()
            .iter()
            .find(|event| event["sequence"] == sequence)
            .unwrap();
        assert_eq!(event["type"], kind);
        assert_eq!(event["actorId"], "retirement-operator");
        assert_eq!(event["credentialId"], Value::Null);
    }
    let before = db
        .tables(&[
            "scimManagedConnection",
            "scimManagedCredential",
            "scimManagedConnectionEvent",
            "scimConnectionBinding",
        ])
        .await?;
    let again = Box::pin(auth.dispatch_endpoint(retire("tenant-a"), EndpointOptions::default()))
        .await?
        .into_response()?;
    assert_eq!(body(&again)["connection"], state["connection"]);
    assert_eq!(body(&again)["credentials"], state["credentials"]);
    assert_eq!(
        body(&again)["decommission"],
        json!({"status":"complete","retryAfter":null})
    );
    let denied = Box::pin(auth.dispatch_endpoint(retire("tenant-b"), EndpointOptions::default()))
        .await
        .unwrap_err();
    assert_eq!(denied.error.status_code(), 404);
    assert_eq!(
        db.tables(&[
            "scimManagedConnection",
            "scimManagedCredential",
            "scimManagedConnectionEvent",
            "scimConnectionBinding"
        ])
        .await?,
        before
    );
    if db.is_postgres() {
        _=db.execute("CREATE FUNCTION reject_scim_decommission_event() RETURNS trigger LANGUAGE plpgsql AS $function$ BEGIN IF (NEW.\"actorId\"='reject-begin' AND NEW.\"type\"='connection.decommissioning') OR (NEW.\"actorId\"='reject-complete' AND NEW.\"type\"='connection.decommissioned') THEN RAISE EXCEPTION 'fixture rejected decommission event'; END IF; RETURN NEW; END $function$",&[]).await?;
        _=db.execute("CREATE TRIGGER reject_scim_decommission_event BEFORE INSERT ON \"scimManagedConnectionEvent\" FOR EACH ROW EXECUTE FUNCTION reject_scim_decommission_event()",&[]).await?;
    } else {
        _=db.execute("CREATE TRIGGER reject_scim_decommission_event BEFORE INSERT ON scimManagedConnectionEvent WHEN (NEW.actorId='reject-begin' AND NEW.type='connection.decommissioning') OR (NEW.actorId='reject-complete' AND NEW.type='connection.decommissioned') BEGIN SELECT RAISE(ABORT,'fixture rejected decommission event'); END",&[]).await?;
    }
    for actor in ["reject-begin", "reject-complete"] {
        let fresh = Box::pin(auth.dispatch_endpoint(
            ScimPlugin::create_managed_connection_endpoint(&ScimManagedConnectionInput {
                creation_request_id: format!("managed-decommission-{actor}-request"),
                provisioning_domain_id: "tenant-a".into(),
                actor_id: "creator".into(),
                scopes: vec!["scim.users.read".into()],
                expires_at: expiry,
            })?,
            EndpointOptions::default(),
        ))
        .await?
        .into_response()?;
        let fresh = body(&fresh);
        let id = fresh["connection"]["connectionId"].as_str().unwrap();
        let credential = fresh["credential"]["credentialId"].as_str().unwrap();
        let before = db
            .tables(&[
                "scimManagedConnection",
                "scimManagedCredential",
                "scimManagedConnectionEvent",
                "scimConnectionBinding",
            ])
            .await?;
        let error = Box::pin(auth.dispatch_endpoint(
            ScimPlugin::decommission_managed_connection_endpoint(id, "tenant-a", actor)?,
            EndpointOptions::default(),
        ))
        .await
        .unwrap_err();
        assert_eq!(error.error.status_code(), 500);
        assert!(
            error
                .to_string()
                .contains("fixture rejected decommission event")
        );
        if actor == "reject-begin" {
            assert_eq!(
                db.tables(&[
                    "scimManagedConnection",
                    "scimManagedCredential",
                    "scimManagedConnectionEvent",
                    "scimConnectionBinding"
                ])
                .await?,
                before
            );
        } else {
            let pending = Box::pin(auth.dispatch_endpoint(
                ScimPlugin::get_managed_connection_endpoint(id, "tenant-a")?,
                EndpointOptions::default(),
            ))
            .await?
            .into_response()?;
            let pending = body(&pending);
            assert_eq!(pending["connection"]["status"], "decommissioning");
            assert_eq!(pending["connection"]["decommissionedAt"], Value::Null);
            assert_eq!(pending["credentials"][0]["status"], "decommissioned");
            assert_eq!(pending["credentials"][0]["credentialId"], credential);
            let history = Box::pin(auth.dispatch_endpoint(
                ScimPlugin::list_managed_connection_events_endpoint(id, "tenant-a")?,
                EndpointOptions::default(),
            ))
            .await?
            .into_response()?;
            assert_eq!(body(&history)["events"].as_array().unwrap().len(), 3);
            let resumed = Box::pin(auth.dispatch_endpoint(
                ScimPlugin::decommission_managed_connection_endpoint(
                    id,
                    "tenant-a",
                    "resume-operator",
                )?,
                EndpointOptions::default(),
            ))
            .await?
            .into_response()?;
            let resumed = body(&resumed);
            assert_eq!(resumed["connection"]["status"], "decommissioned");
            assert_eq!(
                resumed["connection"]["decommissionStartedBy"],
                "reject-complete"
            );
            assert_eq!(resumed["connection"]["decommissionedBy"], "resume-operator");
            let history = Box::pin(auth.dispatch_endpoint(
                ScimPlugin::list_managed_connection_events_endpoint(id, "tenant-a")?,
                EndpointOptions::default(),
            ))
            .await?
            .into_response()?;
            let history = body(&history);
            assert_eq!(history["events"].as_array().unwrap().len(), 4);
            assert_eq!(history["events"][3]["actorId"], "resume-operator");
        }
    }
    Ok(())
}
