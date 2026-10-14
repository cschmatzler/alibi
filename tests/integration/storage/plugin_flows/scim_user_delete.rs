//! User deletion preserves tombstones, reconciles access, and retires only globally inactive sessions.
use super::scim_group_create::{GroupProjection, create, seed};
use super::scim_identity_reconciliation::Identity;
use super::*;
use alibi::endpoint::{EndpointOptions, EndpointResponse};
use alibi::plugins::ScimPlugin;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};
backend_tests!(scim_user_delete_preserves_tombstones_and_retires_only_inactive_identity_sessions);
postgres_tests!(scim_user_delete_preserves_tombstones_and_retires_only_inactive_identity_sessions);
async fn delete<S: AuthSchema>(
    auth: &Alibi<S>,
    id: &str,
    token: Option<&str>,
) -> alibi::AuthResult<AuthResponse> {
    let result = Box::pin(auth.dispatch_endpoint(
        ScimPlugin::delete_user_endpoint(id)?.with_query(&json!({"attributes":1}))?,
        EndpointOptions {
            headers: token.map(|token| {
                [("authorization".into(), format!("Bearer {token}"))]
                    .into_iter()
                    .collect()
            }),
            ..Default::default()
        },
    ))
    .await;
    match result {
        Ok(output) => output.into_response(),
        Err(error) => {
            let mut response = EndpointResponse::error(error.error);
            if let Some(body) = error.body {
                response = response.with_error_body(*body);
            }
            if let Some(headers) = error.headers {
                response.merge_headers(headers);
            }
            response.to_response()
        }
    }
}
async fn snapshot(db: &Db) -> TestResult<Vec<(String, String)>> {
    let mut rows = Vec::new();
    for table in [
        "user",
        "session",
        "scimUser",
        "scimSubject",
        "scimGroup",
        "scimGroupMember",
        "scimProjectionGrant",
        "scimIdentityTombstone",
        "scimConnectionBinding",
    ] {
        rows.push((table.into(), db.table(table).await?));
    }
    Ok(rows)
}
async fn scim_user_delete_preserves_tombstones_and_retires_only_inactive_identity_sessions<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(ScimPlugin::new().connections(super::scim_group_read::connections()))
        .build()
        .await?;
    assert_eq!(delete(&auth, "missing", None).await?.status, 401);
    seed(&db, &auth).await?;
    let key = URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(&[
        "scim-user-external-id",
        "conn-a",
        "external-a",
    ])?));
    _=db.execute("UPDATE \"scimUser\" SET \"externalId\"='external-a',\"externalIdKey\"=$1,\"active\"=true WHERE \"id\"='member-a'",&[&key]).await?;
    _ = db
        .execute(
            "UPDATE \"scimUser\" SET \"active\"=true WHERE \"id\"='member-b'",
            &[],
        )
        .await?;
    _ = db
        .execute(
            "UPDATE \"scimSubject\" SET \"profileSourceId\"='member-a'",
            &[],
        )
        .await?;
    let group=body(&create(&auth,&json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"User members","members":[{"value":"member-a"},{"value":"member-c"}]}),&json!({}),Some("group-reader")).await?);
    let gid = group["id"].as_str().unwrap();
    assert_eq!(
        delete(&auth, "member-a", Some("users-reader"))
            .await?
            .status,
        403
    );
    assert_eq!(
        delete(&auth, "member-a", Some("other-reader"))
            .await?
            .status,
        404
    );
    assert_eq!(
        delete(&auth, "member-c", Some("group-reader"))
            .await?
            .status,
        409
    );
    let projection_fails = Arc::new(AtomicBool::new(true));
    let identity_fails = Arc::new(AtomicBool::new(false));
    let states = Arc::new(Mutex::new(Vec::new()));
    let configured = builder::<B>(&connection)
        .plugin(
            ScimPlugin::new()
                .connections(super::scim_group_read::connections())
                .projection::<B::Schema>(Arc::new(GroupProjection(projection_fails.clone())))
                .identity(Arc::new(Identity {
                    states: states.clone(),
                    fail: identity_fails.clone(),
                })),
        )
        .build()
        .await?;
    let before = snapshot(&db).await?;
    let failed = delete(&configured, "member-a", Some("group-reader")).await?;
    assert_eq!(failed.status, 500);
    assert_eq!(
        body(&failed)["detail"],
        "SCIM projection reconciliation failed"
    );
    assert_eq!(snapshot(&db).await?, before);
    projection_fails.store(false, Ordering::SeqCst);
    identity_fails.store(true, Ordering::SeqCst);
    let failed = delete(&configured, "member-a", Some("group-reader")).await?;
    assert_eq!(failed.status, 500);
    assert_eq!(
        body(&failed)["detail"],
        "SCIM identity reconciliation failed"
    );
    assert_eq!(snapshot(&db).await?, before);
    identity_fails.store(false, Ordering::SeqCst);
    let removed = delete(&configured, "member-a", Some("group-reader")).await?;
    assert_eq!(removed.status, 204);
    assert!(removed.body.is_empty());
    let tombstones: Value = serde_json::from_str(&db.table("scimIdentityTombstone").await?)?;
    assert_eq!(tombstones.as_array().unwrap().len(), 1);
    assert_eq!(tombstones[0]["connectionId"], "conn-a");
    assert_eq!(tombstones[0]["provisioningDomainId"], "tenant-a");
    assert_eq!(tombstones[0]["externalId"], "external-a");
    assert_eq!(tombstones[0]["profile"], "manage");
    let subject: Value = serde_json::from_str(&db.table("scimSubject").await?)?;
    assert_eq!(subject[0]["revision"], 3);
    assert!(subject[0]["profileSourceId"].is_null());
    let sessions: Value = serde_json::from_str(&db.table("session").await?)?;
    assert_eq!(sessions.as_array().unwrap().len(), 1);
    assert!(db.table("user").await?.contains("Identity active"));
    assert!(states.lock().unwrap().last().unwrap().active);
    assert!(
        states
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .profile_source_id
            .is_none()
    );
    let group = body(
        &super::scim_group_read::read(&configured, gid, &json!({}), Some("group-reader")).await?,
    );
    assert_eq!(group["members"].as_array().unwrap().len(), 1);
    assert_eq!(group["members"][0]["value"], "member-c");
    assert_eq!(
        delete(&configured, "member-a", Some("group-reader"))
            .await?
            .status,
        404
    );
    _=db.execute("UPDATE \"scimUser\" SET \"provisioningDomainId\"='tenant-a',\"externalId\"='external-a',\"externalIdKey\"=$1 WHERE \"id\"='member-c'",&[&key]).await?;
    _=db.execute("UPDATE \"scimIdentityTombstone\" SET \"connectionId\"='legacy-connection',\"provisioningDomainId\"='legacy-domain',\"externalId\"='legacy-external'",&[]).await?;
    let mut req = request("/scim/v2/Users/member-c", None, "");
    req.method = HttpMethod::Delete;
    _ = req
        .headers
        .insert("authorization".into(), "Bearer group-reader".into());
    let http = call(&configured, req, 204).await;
    assert!(http.body.is_empty());
    assert_eq!(
        http.headers.get("content-type").map(String::as_str),
        Some("application/scim+json")
    );
    let tombstones: Value = serde_json::from_str(&db.table("scimIdentityTombstone").await?)?;
    assert_eq!(tombstones.as_array().unwrap().len(), 1);
    assert_eq!(tombstones[0]["connectionId"], "legacy-connection");
    assert_eq!(tombstones[0]["provisioningDomainId"], "legacy-domain");
    assert_eq!(tombstones[0]["externalId"], "legacy-external");
    assert_eq!(tombstones[0]["profile"], "preserve");
    assert_eq!(db.table("scimGroupMember").await?, "[]");
    assert_eq!(
        delete(&configured, "member-b", Some("other-reader"))
            .await?
            .status,
        204
    );
    assert_eq!(db.table("scimUser").await?, "[]");
    assert_eq!(db.table("session").await?, "[]");
    assert!(db.table("user").await?.contains("Identity inactive"));
    let subject: Value = serde_json::from_str(&db.table("scimSubject").await?)?;
    assert_eq!(subject[0]["revision"], 5);
    let state = states.lock().unwrap().last().unwrap().clone();
    assert!(!state.active);
    assert!(state.sources.is_empty());
    Ok(())
}
