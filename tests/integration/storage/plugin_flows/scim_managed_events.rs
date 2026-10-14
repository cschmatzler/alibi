//! Event history is domain scoped, ordered, redacted and read-only.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::scim::{
    ScimManagedConnectionInput, ScimManagedConnectionOptions, ScimManagedCredentialRotationInput,
    ScimPlugin,
};
backend_tests!(scim_managed_event_history_is_ordered_and_domain_scoped);
postgres_tests!(scim_managed_event_history_is_ordered_and_domain_scoped);
async fn scim_managed_event_history_is_ordered_and_domain_scoped<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(
            ScimPlugin::new().managed_connections(ScimManagedConnectionOptions::new(
                "managed-scim-credential-hmac-secret-32-chars",
            )),
        )
        .build()
        .await?;
    let created = auth
        .dispatch_endpoint(
            ScimPlugin::create_managed_connection_endpoint(&ScimManagedConnectionInput {
                creation_request_id: "managed-event-request-001".into(),
                provisioning_domain_id: "tenant-a".into(),
                actor_id: "creator".into(),
                scopes: vec!["scim.users.read".into()],
                expires_at: chrono::DateTime::parse_from_rfc3339("2035-01-02T03:04:05.678Z")?
                    .with_timezone(&chrono::Utc),
            })?,
            EndpointOptions::default(),
        )
        .await?
        .into_response()?;
    let created = body(&created);
    let cid = created["connection"]["connectionId"].as_str().unwrap();
    let kid = created["credential"]["credentialId"].as_str().unwrap();
    _ = auth
        .dispatch_endpoint(
            ScimPlugin::revoke_managed_credential_endpoint(cid, "tenant-a", kid, "revoker")?,
            EndpointOptions::default(),
        )
        .await?;
    let list = |id: &str, domain: &str| {
        ServerEndpoint::<Value>::new("scim", "listSCIMManagedConnectionEvents")
            .with_body(&json!({"connectionId":id,"provisioningDomainId":domain}))
            .unwrap()
    };
    let before = db
        .tables(&[
            "scimManagedConnection",
            "scimManagedCredential",
            "scimManagedConnectionEvent",
        ])
        .await?;
    let result = auth
        .dispatch_endpoint(list(cid, "  tenant-a  "), EndpointOptions::default())
        .await;
    let response = match result {
        Ok(output) => output.into_response()?,
        Err(error) => error.error.to_auth_response(),
    };
    assert_eq!(response.status, 200);
    let history = body(&response);
    let events = history["events"].as_array().unwrap();
    assert_eq!(events.len(), 3);
    for (index, (kind, actor, credential)) in [
        ("connection.created", "creator", Value::Null),
        ("credential.issued", "creator", json!(kid)),
        ("credential.revoked", "revoker", json!(kid)),
    ]
    .into_iter()
    .enumerate()
    {
        let event = &events[index];
        assert_eq!(event["sequence"], index + 1);
        assert_eq!(event["type"], kind);
        assert_eq!(event["actorId"], actor);
        assert_eq!(event["credentialId"], credential);
        assert_eq!(event.as_object().unwrap().len(), 5);
        assert!(chrono::DateTime::parse_from_rfc3339(event["createdAt"].as_str().unwrap()).is_ok());
    }
    for (id, domain) in [
        (cid, "tenant-b"),
        ("ba_scim_connection_missing", "tenant-a"),
    ] {
        let error = auth
            .dispatch_endpoint(list(id, domain), EndpointOptions::default())
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), 404);
    }
    assert_eq!(
        db.tables(&[
            "scimManagedConnection",
            "scimManagedCredential",
            "scimManagedConnectionEvent"
        ])
        .await?,
        before
    );
    for _ in 0..51 {
        let rotated = auth
            .dispatch_endpoint(
                ScimPlugin::rotate_managed_credential_endpoint(
                    &ScimManagedCredentialRotationInput {
                        connection_id: cid.into(),
                        provisioning_domain_id: "tenant-a".into(),
                        actor_id: "rotator".into(),
                        scopes: vec!["scim.users.read".into()],
                        expires_at: chrono::DateTime::parse_from_rfc3339(
                            "2035-01-02T03:04:05.678Z",
                        )?
                        .with_timezone(&chrono::Utc),
                    },
                )?,
                EndpointOptions::default(),
            )
            .await?
            .into_response()?;
        let rotated = body(&rotated);
        _ = auth
            .dispatch_endpoint(
                ScimPlugin::revoke_managed_credential_endpoint(
                    cid,
                    "tenant-a",
                    rotated["credential"]["credentialId"].as_str().unwrap(),
                    "revoker",
                )?,
                EndpointOptions::default(),
            )
            .await?;
    }
    let limited = auth
        .dispatch_endpoint(
            ScimPlugin::list_managed_connection_events_endpoint(cid, "tenant-a")?,
            EndpointOptions::default(),
        )
        .await?
        .into_response()?;
    let limited = body(&limited);
    let events = limited["events"].as_array().unwrap();
    assert_eq!(events.len(), 100);
    for (index, event) in events.iter().enumerate() {
        assert_eq!(event["sequence"], index + 6);
    }
    Ok(())
}
