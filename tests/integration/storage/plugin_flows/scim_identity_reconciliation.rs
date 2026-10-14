//! Identity reconciliation receives global source state inside retirement's transaction.
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::scim::{ScimIdentity, ScimIdentityState, ScimPlugin};
use alibi::store::AuthTransaction;
use std::sync::atomic::{AtomicBool, Ordering};
backend_tests!(scim_identity_callback_receives_global_state_before_session_retirement);
postgres_tests!(scim_identity_callback_receives_global_state_before_session_retirement);
pub(super) struct Identity {
    pub(super) states: Arc<Mutex<Vec<ScimIdentityState>>>,
    pub(super) fail: Arc<AtomicBool>,
}
#[async_trait::async_trait]
impl<S: AuthSchema> ScimIdentity<S> for Identity {
    async fn reconcile_user(
        &self,
        input: &ScimIdentityState,
        database: &dyn AuthTransaction<S>,
    ) -> alibi::AuthResult<()> {
        _ = database
            .update_user(
                &input.user_id,
                alibi::UpdateUser {
                    name: Some(
                        if self.fail.load(Ordering::SeqCst) {
                            "Should roll back identity"
                        } else if input.active {
                            "Identity active"
                        } else {
                            "Identity inactive"
                        }
                        .into(),
                    ),
                    ..Default::default()
                },
            )
            .await?;
        self.states.lock().unwrap().push(input.clone());
        if self.fail.load(Ordering::SeqCst) {
            return Err(alibi::AuthError::internal("application rejected identity"));
        }
        Ok(())
    }
}
async fn scim_identity_callback_receives_global_state_before_session_retirement<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let states = Arc::new(Mutex::new(Vec::new()));
    let fail = Arc::new(AtomicBool::new(false));
    let auth = builder::<B>(&connection)
        .plugin(ScimPlugin::new().identity::<B::Schema>(Arc::new(Identity {
            states: states.clone(),
            fail: fail.clone(),
        })))
        .build()
        .await?;
    let signed = signup(&auth, "identity-owner@example.com").await;
    let owner = body(&signed);
    let uid = owner["user"]["id"].as_str().unwrap();
    _=db.execute("INSERT INTO \"scimSubject\" (\"id\",\"userId\",\"profileSourceId\",\"revision\",\"createdAt\",\"updatedAt\") VALUES ('identity-subject',$1,'scim-alias-a',0,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",&[uid]).await?;
    for (id, cid, domain, active) in [
        ("scim-alias-a", "conn-a", "tenant-a", true),
        ("scim-alias-ä", "conn-b", "tenant-a", false),
        ("scim-alias-Z", "conn-c", "tenant-b", true),
    ] {
        _=db.execute("INSERT INTO \"scimUser\" (\"id\",\"connectionId\",\"provisioningDomainId\",\"userId\",\"connectionUserKey\",\"userName\",\"userNameKey\",\"primaryEmail\",\"workEmailValueIndex\",\"emailValueIndex\",\"displayName\",\"formattedName\",\"serializedEmails\",\"active\",\"orderKey\",\"createdAt\",\"updatedAt\") VALUES ($1,$2,$3,$4,$1,'identity-owner@example.com',$1,'identity-owner@example.com','[]','[]','Owner','Owner','[]',true,$1,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",&[id,cid,domain,uid]).await?;
        if !active {
            _ = db
                .execute(
                    "UPDATE \"scimUser\" SET \"active\"=false WHERE \"id\"=$1",
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
    let sessions = db.table("session").await?;
    _ = Box::pin(auth.dispatch_endpoint(
        ScimPlugin::decommission_connection_endpoint("conn-a", Some("tenant-a"))?,
        EndpointOptions::default(),
    ))
    .await?;
    let observed = states.lock().unwrap().clone();
    assert_eq!(observed.len(), 1);
    assert!(observed[0].active);
    assert_eq!(observed[0].profile_source_id, None);
    assert_eq!(
        observed[0]
            .sources
            .iter()
            .map(|source| source.id.as_str())
            .collect::<Vec<_>>(),
        vec!["scim-alias-ä", "scim-alias-Z"]
    );
    assert_eq!(db.table("session").await?, sessions);
    fail.store(true, Ordering::SeqCst);
    let before = db.tables(&["user", "session", "scimSubject"]).await?;
    let error = Box::pin(auth.dispatch_endpoint(
        ScimPlugin::decommission_connection_endpoint("conn-c", Some("tenant-b"))?,
        EndpointOptions::default(),
    ))
    .await
    .unwrap_err();
    assert_eq!(error.error.status_code(), 500);
    assert_eq!(
        serde_json::to_value(error.body.as_ref().unwrap().as_ref())?,
        json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"500","detail":"SCIM identity reconciliation failed"})
    );
    assert_eq!(
        db.tables(&["user", "session", "scimSubject"]).await?,
        before
    );
    fail.store(false, Ordering::SeqCst);
    _ = Box::pin(auth.dispatch_endpoint(
        ScimPlugin::decommission_connection_endpoint("conn-c", Some("tenant-b"))?,
        EndpointOptions::default(),
    ))
    .await?;
    let sessions: Value = serde_json::from_str(&db.table("session").await?)?;
    assert!(sessions.as_array().unwrap().is_empty());
    let users: Value = serde_json::from_str(&db.table("user").await?)?;
    assert_eq!(users[0]["name"], "Identity inactive");
    Ok(())
}
