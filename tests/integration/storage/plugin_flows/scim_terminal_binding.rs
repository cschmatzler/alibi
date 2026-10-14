//! Retiring a previously unused connection records a durable terminal domain binding.
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::scim::{ScimManagedConnectionOptions, ScimPlugin};
backend_tests!(scim_retirement_preserves_terminal_and_leased_bindings);
postgres_tests!(scim_retirement_preserves_terminal_and_leased_bindings);
async fn scim_retirement_preserves_terminal_and_leased_bindings<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(
            ScimPlugin::new().managed_connections(ScimManagedConnectionOptions::new(
                "managed-scim-credential-hmac-secret-32-chars",
            )),
        )
        .build()
        .await?;
    let retire = |domain: Option<&str>| {
        ScimPlugin::decommission_connection_endpoint("  external-provisioning  ", domain).unwrap()
    };
    let result =
        Box::pin(auth.dispatch_endpoint(retire(Some("  tenant-a  ")), EndpointOptions::default()))
            .await;
    let response = match result {
        Ok(output) => output.into_response()?,
        Err(error) => error.error.to_auth_response(),
    };
    assert_eq!(response.status, 200);
    let state = body(&response);
    assert_eq!(state["connectionId"], "external-provisioning");
    assert_eq!(state["provisioningDomainId"], "tenant-a");
    assert_eq!(state["status"], "complete");
    assert_eq!(state["retryAfter"], Value::Null);
    assert_eq!(state["reconciledUsers"], 0);
    assert_eq!(state["batches"], 0);
    assert_eq!(state["completedAt"], state["decommissionedAt"]);
    assert!(chrono::DateTime::parse_from_rfc3339(state["completedAt"].as_str().unwrap()).is_ok());
    let before = db.table("scimConnectionBinding").await?;
    let restart = builder::<B>(&connection)
        .plugin(
            ScimPlugin::new().managed_connections(ScimManagedConnectionOptions::new(
                "managed-scim-credential-hmac-secret-32-chars",
            )),
        )
        .build()
        .await?;
    let again = Box::pin(restart.dispatch_endpoint(retire(None), EndpointOptions::default()))
        .await?
        .into_response()?;
    assert_eq!(body(&again), state);
    assert_eq!(db.table("scimConnectionBinding").await?, before);
    _=db.execute("UPDATE \"scimConnectionBinding\" SET \"decommissionStatus\"='reconciling', \"decommissionLeaseId\"='other-worker', \"decommissionCompletedAt\"=NULL, \"decommissionReconciledUserCount\"=7, \"decommissionBatchCount\"=2",&[]).await?;
    let lease_expiry = chrono::DateTime::parse_from_rfc3339("2035-02-03T04:05:06.789Z")?
        .with_timezone(&chrono::Utc);
    db.set_timestamp(
        "scimConnectionBinding",
        "decommissionLeaseExpiresAt",
        ("connectionId", "external-provisioning"),
        lease_expiry,
    )
    .await?;
    let before = db.table("scimConnectionBinding").await?;
    let result =
        Box::pin(restart.dispatch_endpoint(retire(Some("tenant-a")), EndpointOptions::default()))
            .await;
    let response = match result {
        Ok(output) => output.into_response()?,
        Err(error) => error.error.to_auth_response(),
    };
    assert_eq!(response.status, 200);
    let pending = body(&response);
    assert_eq!(pending["status"], "reconciling");
    assert_eq!(pending["retryAfter"], "2035-02-03T04:05:06.789Z");
    assert_eq!(pending["completedAt"], Value::Null);
    assert_eq!(pending["decommissionedAt"], state["decommissionedAt"]);
    assert_eq!(pending["reconciledUsers"], 7);
    assert_eq!(pending["batches"], 2);
    assert_eq!(db.table("scimConnectionBinding").await?, before);
    db.set_timestamp(
        "scimConnectionBinding",
        "decommissionLeaseExpiresAt",
        ("connectionId", "external-provisioning"),
        chrono::DateTime::parse_from_rfc3339("2000-01-01T00:00:00.000Z")?
            .with_timezone(&chrono::Utc),
    )
    .await?;
    let result =
        Box::pin(restart.dispatch_endpoint(retire(None), EndpointOptions::default())).await;
    let response = match result {
        Ok(output) => output.into_response()?,
        Err(error) => error.error.to_auth_response(),
    };
    assert_eq!(response.status, 200);
    let completed = body(&response);
    assert_eq!(completed["status"], "complete");
    assert_eq!(completed["retryAfter"], Value::Null);
    assert_eq!(completed["reconciledUsers"], 7);
    assert_eq!(completed["batches"], 2);
    assert_eq!(completed["decommissionedAt"], state["decommissionedAt"]);
    assert!(
        chrono::DateTime::parse_from_rfc3339(completed["completedAt"].as_str().unwrap()).is_ok()
    );
    let rows: Value = serde_json::from_str(&db.table("scimConnectionBinding").await?)?;
    assert_eq!(rows[0]["decommissionRevision"], 2);
    assert_eq!(rows[0]["decommissionLeaseId"], Value::Null);
    assert_eq!(rows[0]["decommissionLeaseExpiresAt"], Value::Null);
    _=db.execute("UPDATE \"scimConnectionBinding\" SET \"decommissionStatus\"='reconciling',\"decommissionLeaseId\"='failed-worker',\"decommissionCompletedAt\"=NULL",&[]).await?;
    db.set_timestamp(
        "scimConnectionBinding",
        "decommissionLeaseExpiresAt",
        ("connectionId", "external-provisioning"),
        chrono::DateTime::parse_from_rfc3339("2000-01-01T00:00:00.000Z")?
            .with_timezone(&chrono::Utc),
    )
    .await?;
    if db.is_postgres() {
        _=db.execute("CREATE FUNCTION reject_scim_binding_completion() RETURNS trigger LANGUAGE plpgsql AS $function$ BEGIN IF NEW.\"decommissionStatus\"='complete' AND OLD.\"decommissionStatus\"='reconciling' THEN RAISE EXCEPTION 'fixture rejected binding completion'; END IF; RETURN NEW; END $function$",&[]).await?;
        _=db.execute("CREATE TRIGGER reject_scim_binding_completion BEFORE UPDATE ON \"scimConnectionBinding\" FOR EACH ROW EXECUTE FUNCTION reject_scim_binding_completion()",&[]).await?;
    } else {
        _=db.execute("CREATE TRIGGER reject_scim_binding_completion BEFORE UPDATE ON scimConnectionBinding WHEN NEW.decommissionStatus='complete' AND OLD.decommissionStatus='reconciling' BEGIN SELECT RAISE(ABORT,'fixture rejected binding completion'); END",&[]).await?;
    }
    let error = Box::pin(restart.dispatch_endpoint(retire(None), EndpointOptions::default()))
        .await
        .unwrap_err();
    assert_eq!(error.error.status_code(), 500);
    assert!(
        error
            .to_string()
            .contains("fixture rejected binding completion")
    );
    let rows: Value = serde_json::from_str(&db.table("scimConnectionBinding").await?)?;
    assert_eq!(rows[0]["decommissionRevision"], 4);
    assert_eq!(rows[0]["decommissionStatus"], "reconciling");
    assert_eq!(rows[0]["decommissionCompletedAt"], Value::Null);
    assert_eq!(rows[0]["decommissionLeaseId"], Value::Null);
    assert_eq!(rows[0]["decommissionLeaseExpiresAt"], Value::Null);
    if db.is_postgres() {
        _ = db
            .execute(
                "DROP TRIGGER reject_scim_binding_completion ON \"scimConnectionBinding\"",
                &[],
            )
            .await?;
    } else {
        _ = db
            .execute("DROP TRIGGER reject_scim_binding_completion", &[])
            .await?;
    }
    let completed = Box::pin(restart.dispatch_endpoint(retire(None), EndpointOptions::default()))
        .await?
        .into_response()?;
    assert_eq!(body(&completed)["status"], "complete");
    let rows: Value = serde_json::from_str(&db.table("scimConnectionBinding").await?)?;
    assert_eq!(rows[0]["decommissionRevision"], 6);
    Ok(())
}
