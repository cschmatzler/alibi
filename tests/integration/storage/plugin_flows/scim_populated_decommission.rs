//! Populated retirement reconciles domain access without retiring a user active in another domain.
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::scim::{ScimPlugin, ScimProjectedUserState, ScimProjection};
use alibi::store::AuthTransaction;
use std::sync::atomic::{AtomicBool, Ordering};
backend_tests!(scim_populated_decommission_reconciles_access_and_global_session_lifecycle);
postgres_tests!(scim_populated_decommission_reconciles_access_and_global_session_lifecycle);
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
async fn scim_populated_decommission_reconciles_access_and_global_session_lifecycle<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let states = Arc::new(Mutex::new(Vec::new()));
    let fail = Arc::new(AtomicBool::new(false));
    let auth = builder::<B>(&connection)
        .plugin(
            ScimPlugin::new()
                .managed_connections(alibi::plugins::scim::ScimManagedConnectionOptions::new(
                    "native-scim-catalog-credential-hash-secret-32",
                ))
                .projection::<B::Schema>(Arc::new(Projection {
                    states: states.clone(),
                    fail: fail.clone(),
                })),
        )
        .build()
        .await?;
    let signed = signup(&auth, "retirement-owner@example.com").await;
    let owner = body(&signed);
    let uid = owner["user"]["id"].as_str().unwrap();
    _=db.execute("INSERT INTO \"scimSubject\" (\"id\",\"userId\",\"revision\",\"createdAt\",\"updatedAt\") VALUES ('retirement-subject',$1,0,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",&[uid]).await?;
    for (id, cid, domain, active) in [
        ("scim-alias-a", "conn-a", "tenant-a", true),
        ("scim-alias-b", "conn-b", "tenant-a", false),
        ("scim-alias-c", "conn-c", "tenant-b", true),
    ] {
        _=db.execute("INSERT INTO \"scimUser\" (\"id\",\"connectionId\",\"provisioningDomainId\",\"userId\",\"connectionUserKey\",\"userName\",\"userNameKey\",\"primaryEmail\",\"workEmailValueIndex\",\"emailValueIndex\",\"displayName\",\"formattedName\",\"serializedEmails\",\"active\",\"orderKey\",\"createdAt\",\"updatedAt\") VALUES ($1,$2,$3,$4,$1,'retirement-owner@example.com',$1,'retirement-owner@example.com','[]','[]','Owner','Owner','[]',false,$1,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",&[id,cid,domain,uid]).await?;
        if active {
            _ = db
                .execute(
                    "UPDATE \"scimUser\" SET \"active\"=true WHERE \"id\"=$1",
                    &[id],
                )
                .await?;
        }
        _ = Box::pin(auth.dispatch_endpoint(
            ScimPlugin::decommission_connection_endpoint(cid, Some(domain))?,
            EndpointOptions::default(),
        ))
        .await?;
        _=db.execute("UPDATE \"scimConnectionBinding\" SET \"decommissionStatus\"='active',\"decommissionedAt\"=NULL,\"decommissionCompletedAt\"=NULL WHERE \"connectionId\"=$1",&[cid]).await?;
    }
    fail.store(true, Ordering::SeqCst);
    let before = db.tables(&["user", "scimSubject", "session"]).await?;
    let error = Box::pin(auth.dispatch_endpoint(
        ScimPlugin::decommission_connection_endpoint("conn-a", Some("tenant-a"))?,
        EndpointOptions::default(),
    ))
    .await
    .unwrap_err();
    assert_eq!(error.error.status_code(), 500);
    assert_eq!(
        serde_json::to_value(error.body.as_ref().unwrap().as_ref())?,
        json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"500","detail":"SCIM projection reconciliation failed"})
    );
    assert_eq!(
        db.tables(&["user", "scimSubject", "session"]).await?,
        before
    );
    let bindings: Value = serde_json::from_str(&db.table("scimConnectionBinding").await?)?;
    let binding = bindings
        .as_array()
        .unwrap()
        .iter()
        .find(|binding| binding["connectionId"] == "conn-a")
        .unwrap();
    assert_eq!(binding["decommissionStatus"], "reconciling");
    assert_eq!(binding["decommissionLeaseId"], Value::Null);
    assert_eq!(binding["decommissionRevision"], 2);
    fail.store(false, Ordering::SeqCst);
    let sessions = db.table("session").await?;
    let result = Box::pin(auth.dispatch_endpoint(
        ScimPlugin::decommission_connection_endpoint("conn-a", Some("tenant-a"))?,
        EndpointOptions::default(),
    ))
    .await;
    let response = match result {
        Ok(output) => output.into_response()?,
        Err(error) => error.error.to_auth_response(),
    };
    assert_eq!(response.status, 200);
    let first = body(&response);
    assert_eq!(first["status"], "complete");
    assert_eq!(first["reconciledUsers"], 1);
    assert_eq!(first["batches"], 1);
    assert_eq!(db.table("session").await?, sessions);
    let observed = states.lock().unwrap().clone();
    assert_eq!(observed.len(), 2);
    assert!(!observed[1].active);
    assert_eq!(
        observed[1]
            .sources
            .iter()
            .map(|source| source.id.as_str())
            .collect::<Vec<_>>(),
        vec!["scim-alias-b"]
    );
    let second = Box::pin(auth.dispatch_endpoint(
        ScimPlugin::decommission_connection_endpoint("conn-c", Some("tenant-b"))?,
        EndpointOptions::default(),
    ))
    .await?
    .into_response()?;
    assert_eq!(body(&second)["status"], "complete");
    let sessions: Value = serde_json::from_str(&db.table("session").await?)?;
    assert!(sessions.as_array().unwrap().is_empty());
    let subject: Value = serde_json::from_str(&db.table("scimSubject").await?)?;
    assert_eq!(subject[0]["revision"], 2);
    Ok(())
}
