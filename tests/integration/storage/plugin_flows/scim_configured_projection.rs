//! Configured reconciliation supplies complete domain state and shares callback writes with its transaction.
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::scim::{
    ScimManagedConnectionOptions, ScimPlugin, ScimProjectedUserState, ScimProjection,
};
use alibi::store::AuthTransaction;
use std::sync::atomic::{AtomicBool, Ordering};
backend_tests!(scim_configured_projection_reconciles_sources_and_rolls_back_callback_failure);
postgres_tests!(scim_configured_projection_reconciles_sources_and_rolls_back_callback_failure);
struct Projection {
    states: Arc<Mutex<Vec<ScimProjectedUserState>>>,
    fail: Arc<AtomicBool>,
}
#[async_trait::async_trait]
impl<S: AuthSchema> ScimProjection<S> for Projection {
    async fn reconcile_user(
        &self,
        input: &ScimProjectedUserState,
        database: &dyn AuthTransaction<S>,
    ) -> alibi::AuthResult<()> {
        _ = database
            .update_user(
                &input.user_id,
                alibi::UpdateUser {
                    name: Some(
                        if self.fail.load(Ordering::SeqCst) {
                            "Should roll back"
                        } else if input.active {
                            "Projected active"
                        } else {
                            "Projected inactive"
                        }
                        .into(),
                    ),
                    ..Default::default()
                },
            )
            .await?;
        self.states.lock().unwrap().push(input.clone());
        if self.fail.load(Ordering::SeqCst) {
            return Err(alibi::AuthError::internal(
                "application rejected projection",
            ));
        }
        Ok(())
    }
}
async fn scim_configured_projection_reconciles_sources_and_rolls_back_callback_failure<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let states = Arc::new(Mutex::new(Vec::new()));
    let fail = Arc::new(AtomicBool::new(false));
    let auth = builder::<B>(&connection)
        .plugin(
            ScimPlugin::new()
                .managed_connections(ScimManagedConnectionOptions::new(
                    "managed-scim-credential-hmac-secret-32-chars",
                ))
                .projection::<B::Schema>(Arc::new(Projection {
                    states: states.clone(),
                    fail: fail.clone(),
                })),
        )
        .build()
        .await?;
    let signed = signup(&auth, "projection-owner@example.com").await;
    let owner = body(&signed);
    let uid = owner["user"]["id"].as_str().unwrap();
    _=db.execute("INSERT INTO \"scimSubject\" (\"id\",\"userId\",\"revision\",\"createdAt\",\"updatedAt\") VALUES ('projection-subject',$1,0,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",&[uid]).await?;
    for (id, cid, domain, active) in [
        ("scim-alias-ä", "conn-a", "tenant-a", true),
        ("scim-alias-Z", "conn-b", "tenant-a", false),
        ("scim-alias-c", "conn-c", "tenant-b", true),
    ] {
        let sql = format!(
            "INSERT INTO \"scimUser\" (\"id\",\"connectionId\",\"provisioningDomainId\",\"userId\",\"connectionUserKey\",\"userName\",\"userNameKey\",\"primaryEmail\",\"workEmailValueIndex\",\"emailValueIndex\",\"displayName\",\"formattedName\",\"serializedEmails\",\"active\",\"orderKey\",\"createdAt\",\"updatedAt\") VALUES ($1,$2,$3,$4,$1,'projection-owner@example.com',$1,'projection-owner@example.com','[]','[]','Owner','Owner','[]',{},$1,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",
            if active { "true" } else { "false" }
        );
        _ = db.execute(&sql, &[id, cid, domain, uid]).await?;
    }
    _=db.execute("INSERT INTO \"scimProjectionGrant\" (\"id\",\"connectionId\",\"provisioningDomainId\",\"scimUserId\",\"userId\",\"sourceKind\",\"sourceId\",\"role\",\"grantKey\",\"createdAt\",\"updatedAt\") VALUES ($1,'conn-a','tenant-a','scim-alias-ä',$2,'group','retired-group','legacy-role',$1,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",&["legacy-grant",uid]).await?;
    let result = Box::pin(auth.dispatch_endpoint(
        ScimPlugin::reconcile_projection_endpoint("  tenant-a  ")?,
        EndpointOptions::default(),
    ))
    .await;
    let response = match result {
        Ok(output) => output.into_response()?,
        Err(error) => error.error.to_auth_response(),
    };
    assert_eq!(response.status, 200);
    assert_eq!(
        body(&response),
        json!({"provisioningDomainId":"tenant-a","reconciledUsers":1,"batches":1})
    );
    let observed = states.lock().unwrap().clone();
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].user_id, uid);
    assert!(observed[0].active);
    assert!(observed[0].grants.is_empty());
    assert_eq!(
        observed[0]
            .sources
            .iter()
            .map(|source| source.id.as_str())
            .collect::<Vec<_>>(),
        vec!["scim-alias-ä", "scim-alias-Z"]
    );
    let users: Value = serde_json::from_str(&db.table("user").await?)?;
    assert_eq!(users[0]["name"], "Projected active");
    let grants: Value = serde_json::from_str(&db.table("scimProjectionGrant").await?)?;
    assert!(grants.as_array().unwrap().is_empty());
    let subject: Value = serde_json::from_str(&db.table("scimSubject").await?)?;
    assert_eq!(subject[0]["revision"], 1);
    _ = Box::pin(auth.dispatch_endpoint(
        ScimPlugin::decommission_connection_endpoint("conn-a", Some("tenant-a"))?,
        EndpointOptions::default(),
    ))
    .await?;
    let inactive = Box::pin(auth.dispatch_endpoint(
        ScimPlugin::reconcile_projection_endpoint("tenant-a")?,
        EndpointOptions::default(),
    ))
    .await?
    .into_response()?;
    assert_eq!(body(&inactive)["reconciledUsers"], 1);
    let observed = states.lock().unwrap().clone();
    assert_eq!(observed.len(), 2);
    assert!(!observed[1].active);
    assert_eq!(
        observed[1]
            .sources
            .iter()
            .map(|source| source.id.as_str())
            .collect::<Vec<_>>(),
        vec!["scim-alias-Z"]
    );
    let users: Value = serde_json::from_str(&db.table("user").await?)?;
    assert_eq!(users[0]["name"], "Projected inactive");
    _=db.execute("INSERT INTO \"scimProjectionGrant\" (\"id\",\"connectionId\",\"provisioningDomainId\",\"scimUserId\",\"userId\",\"sourceKind\",\"sourceId\",\"role\",\"grantKey\",\"createdAt\",\"updatedAt\") VALUES ($1,'conn-a','tenant-a','scim-alias-ä',$2,'group','retired-group','legacy-role',$1,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",&["failure-grant",uid]).await?;
    fail.store(true, Ordering::SeqCst);
    let before = db
        .tables(&["user", "scimSubject", "scimUser", "scimProjectionGrant"])
        .await?;
    let error = Box::pin(auth.dispatch_endpoint(
        ScimPlugin::reconcile_projection_endpoint("tenant-a")?,
        EndpointOptions::default(),
    ))
    .await
    .unwrap_err();
    assert_eq!(error.error.status_code(), 500);
    assert_eq!(
        db.tables(&["user", "scimSubject", "scimUser", "scimProjectionGrant"])
            .await?,
        before
    );
    Ok(())
}
