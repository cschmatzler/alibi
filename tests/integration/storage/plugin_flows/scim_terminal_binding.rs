//! Retiring a previously unused connection records a durable terminal domain binding.
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::scim::{ScimManagedConnectionOptions, ScimPlugin};
backend_tests!(scim_retirement_persists_an_unused_connection_domain);
postgres_tests!(scim_retirement_persists_an_unused_connection_domain);
async fn scim_retirement_persists_an_unused_connection_domain<B: Backend>(db: Db) -> TestResult {
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
    let result = auth
        .dispatch_endpoint(retire(Some("  tenant-a  ")), EndpointOptions::default())
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
    let again = restart
        .dispatch_endpoint(retire(None), EndpointOptions::default())
        .await?
        .into_response()?;
    assert_eq!(body(&again), state);
    assert_eq!(db.table("scimConnectionBinding").await?, before);
    Ok(())
}
