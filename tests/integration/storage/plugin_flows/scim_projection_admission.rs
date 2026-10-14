//! Projection registration preserves the reference's configuration admission failure.
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::scim::{ScimManagedConnectionOptions, ScimPlugin};
backend_tests!(scim_projection_reconciliation_requires_application_configuration);
postgres_tests!(scim_projection_reconciliation_requires_application_configuration);
async fn scim_projection_reconciliation_requires_application_configuration<B: Backend>(
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
    let before = db
        .tables(&[
            "scimConnectionBinding",
            "scimUser",
            "scimSubject",
            "scimProjectionGrant",
        ])
        .await?;
    let error = auth
        .dispatch_endpoint(
            ScimPlugin::reconcile_projection_endpoint("  tenant-a  ")?,
            EndpointOptions::default(),
        )
        .await
        .unwrap_err();
    let alibi::AuthError::Config(message) = error.error else {
        panic!("Expected a configuration exception");
    };
    assert_eq!(
        message,
        "SCIM projection reconciliation requires projection.reconcileUser to be configured."
    );
    assert_eq!(
        db.tables(&[
            "scimConnectionBinding",
            "scimUser",
            "scimSubject",
            "scimProjectionGrant"
        ])
        .await?,
        before
    );
    Ok(())
}
