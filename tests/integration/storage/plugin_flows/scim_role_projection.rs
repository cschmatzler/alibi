//! Role projection normalizes mapped roles, verifies existence and persists source-aware grants.
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::scim::{
    ScimPlugin, ScimProjectedUserState, ScimProjection, ScimRoleExistenceInput,
    ScimRoleMappingInput, ScimRoleProjection,
};
use alibi::store::AuthTransaction;
use std::sync::atomic::{AtomicU8, Ordering};
backend_tests!(scim_role_projection_normalizes_roles_and_persists_grants);
postgres_tests!(scim_role_projection_normalizes_roles_and_persists_grants);
struct Callbacks {
    states: Arc<Mutex<Vec<ScimProjectedUserState>>>,
    exists: Arc<Mutex<Vec<String>>>,
    stage: Arc<AtomicU8>,
}
#[async_trait::async_trait]
impl<S: AuthSchema> ScimProjection<S> for Callbacks {
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
                        if input.active {
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
        Ok(())
    }
}
#[async_trait::async_trait]
impl<S: AuthSchema> ScimRoleProjection<S> for Callbacks {
    async fn map(
        &self,
        input: &ScimRoleMappingInput,
        database: &dyn AuthTransaction<S>,
    ) -> alibi::AuthResult<Option<Vec<String>>> {
        assert_eq!(input.connection_id, "conn-a");
        assert_eq!(input.scim_user_id, "scim-alias-a");
        if self.stage.load(Ordering::SeqCst) == 1 {
            _ = database
                .update_user(
                    &input.user_id,
                    alibi::UpdateUser {
                        name: Some("Should roll back mapping".into()),
                        ..Default::default()
                    },
                )
                .await?;
            return Err(alibi::AuthError::internal("application rejected mapping"));
        }
        Ok(Some(vec![
            " admin ".into(),
            "".into(),
            "admin".into(),
            "missing".into(),
        ]))
    }
    async fn exists(
        &self,
        input: &ScimRoleExistenceInput,
        _database: &dyn AuthTransaction<S>,
    ) -> alibi::AuthResult<bool> {
        if self.stage.load(Ordering::SeqCst) == 2 {
            return Err(alibi::AuthError::internal(
                "application rejected validation",
            ));
        }
        self.exists.lock().unwrap().push(input.role.clone());
        Ok(input.role == "admin")
    }
}
async fn scim_role_projection_normalizes_roles_and_persists_grants<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let states = Arc::new(Mutex::new(Vec::new()));
    let checks = Arc::new(Mutex::new(Vec::new()));
    let stage = Arc::new(AtomicU8::new(0));
    let callbacks = Arc::new(Callbacks {
        states: states.clone(),
        exists: checks.clone(),
        stage: stage.clone(),
    });
    let auth = builder::<B>(&connection)
        .plugin(
            ScimPlugin::new()
                .projection::<B::Schema>(callbacks.clone())
                .roles(callbacks),
        )
        .build()
        .await?;
    let signed = signup(&auth, "role-projection-owner@example.com").await;
    let owner = body(&signed);
    let uid = owner["user"]["id"].as_str().unwrap();
    _=db.execute("INSERT INTO \"scimSubject\" (\"id\",\"userId\",\"revision\",\"createdAt\",\"updatedAt\") VALUES ('role-subject',$1,0,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",&[uid]).await?;
    _=db.execute("INSERT INTO \"scimUser\" (\"id\",\"connectionId\",\"provisioningDomainId\",\"userId\",\"connectionUserKey\",\"userName\",\"userNameKey\",\"primaryEmail\",\"workEmailValueIndex\",\"emailValueIndex\",\"displayName\",\"formattedName\",\"serializedEmails\",\"active\",\"orderKey\",\"createdAt\",\"updatedAt\") VALUES ('scim-alias-a','conn-a','tenant-a',$1,'scim-alias-a','role-projection-owner@example.com','scim-alias-a','role-projection-owner@example.com','[]','[]','Owner','Owner','[]',true,'scim-alias-a','2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",&[uid]).await?;
    for (id, cid, domain, display, external) in [
        ("group-a", "conn-a", "tenant-a", "Admins", "administrators"),
        (
            "group-b",
            "conn-a",
            "tenant-a",
            "Admin backups",
            "administrators-b",
        ),
        (
            "group-c",
            "conn-a",
            "tenant-b",
            "Foreign domain",
            "foreign-domain",
        ),
        (
            "group-d",
            "conn-other",
            "tenant-a",
            "Foreign connection",
            "foreign-connection",
        ),
    ] {
        _=db.execute("INSERT INTO \"scimGroup\" (\"id\",\"connectionId\",\"provisioningDomainId\",\"revision\",\"displayName\",\"displayNameKey\",\"externalId\",\"externalIdKey\",\"orderKey\",\"createdAt\",\"updatedAt\") VALUES ($1,$2,$3,0,$4,$1,$5,$1,$1,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",&[id,cid,domain,display,external]).await?;
        _=db.execute("INSERT INTO \"scimGroupMember\" (\"id\",\"connectionId\",\"groupId\",\"scimUserId\",\"membershipKey\",\"createdAt\") VALUES ($1,'conn-a',$1,'scim-alias-a',$1,'2026-01-02T03:04:05.000Z')",&[id]).await?;
    }
    let response = Box::pin(auth.dispatch_endpoint(
        ScimPlugin::reconcile_projection_endpoint("tenant-a")?,
        EndpointOptions::default(),
    ))
    .await?
    .into_response()?;
    assert_eq!(response.status, 200);
    let observed = states.lock().unwrap().clone();
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].grants,json!([{"source":{"type":"group","id":"group-b","externalId":"administrators-b","displayName":"Admin backups"},"role":"admin"},{"source":{"type":"group","id":"group-a","externalId":"administrators","displayName":"Admins"},"role":"admin"}]).as_array().unwrap().clone());
    assert_eq!(*checks.lock().unwrap(), vec!["admin", "missing"]);
    let grants: Value = serde_json::from_str(&db.table("scimProjectionGrant").await?)?;
    assert_eq!(grants.as_array().unwrap().len(), 2);
    let first = grants
        .as_array()
        .unwrap()
        .iter()
        .find(|grant| grant["sourceId"] == "group-a")
        .unwrap();
    assert_eq!(first["role"], "admin");
    assert_eq!(
        first["grantKey"],
        "9Tx0iQLNX4FtaByHE8wsrYw7Wq1UZw9RN-k2civyJeA"
    );
    let second = grants
        .as_array()
        .unwrap()
        .iter()
        .find(|grant| grant["sourceId"] == "group-b")
        .unwrap();
    assert_eq!(
        second["grantKey"],
        "7ZkLKtmCXih1v0vRQ1ps_NJqnkzUJ4RJgdotg9ZGdUk"
    );
    assert_eq!(first["sourceValue"], "administrators");
    assert_eq!(first["scimUserId"], "scim-alias-a");
    let before = db.table("scimProjectionGrant").await?;
    _=db.execute("UPDATE \"scimGroup\" SET \"externalId\"='administrators-renamed' WHERE \"id\"='group-a'",&[]).await?;
    _ = Box::pin(auth.dispatch_endpoint(
        ScimPlugin::reconcile_projection_endpoint("tenant-a")?,
        EndpointOptions::default(),
    ))
    .await?;
    assert_eq!(db.table("scimProjectionGrant").await?, before);
    let observed = states.lock().unwrap().clone();
    assert_eq!(
        observed[1].grants[1]["source"]["externalId"],
        "administrators-renamed"
    );
    for (failure, detail) in [
        (1, "SCIM role mapping failed"),
        (2, "SCIM role validation failed"),
    ] {
        stage.store(failure, Ordering::SeqCst);
        let before = db
            .tables(&["user", "scimSubject", "scimProjectionGrant"])
            .await?;
        let error = Box::pin(auth.dispatch_endpoint(
            ScimPlugin::reconcile_projection_endpoint("tenant-a")?,
            EndpointOptions::default(),
        ))
        .await
        .unwrap_err();
        assert_eq!(error.error.status_code(), 500);
        assert_eq!(
            serde_json::to_value(error.body.as_ref().unwrap().as_ref())?,
            json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"500","detail":detail})
        );
        assert_eq!(
            db.tables(&["user", "scimSubject", "scimProjectionGrant"])
                .await?,
            before
        );
    }
    Ok(())
}
