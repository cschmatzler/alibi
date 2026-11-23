//! Event history is domain scoped, ordered, redacted and read-only.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::scim::{
    ScimManagedConnectionInput, ScimManagedConnectionOptions, ScimManagedCredentialRotationInput,
    ScimPlugin,
};
backend_tests!(
    scim_managed_event_history_is_ordered_and_domain_scoped,
    scim_managed_event_history_pages_by_sequence
);
postgres_tests!(
    scim_managed_event_history_is_ordered_and_domain_scoped,
    scim_managed_event_history_pages_by_sequence
);
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
    assert_eq!(
        (&limited["limit"], &limited["offset"], &limited["total"]),
        (&json!(100), &json!(0), &json!(105))
    );
    Ok(())
}

async fn scim_managed_event_history_pages_by_sequence<B: Backend>(db: Db) -> TestResult {
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
                creation_request_id: "managed-event-page-request".into(),
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
    let record = db
        .text(
            "SELECT \"id\" FROM \"scimManagedConnection\" WHERE \"connectionId\" = $1",
            &[cid],
        )
        .await?
        .unwrap();
    // Sequences 1 and 2 come from creation; seed 3..=102 the way rotations record them.
    let rows = (3..=102)
        .map(|sequence| {
            format!(
                "('page-event-{sequence}','{record}','{record}:{sequence}',{sequence},'credential.rotated','rotator','{kid}','2026-01-01T00:{:02}:{:02}.000Z')",
                sequence / 60,
                sequence % 60
            )
        })
        .collect::<Vec<_>>();
    _ = db
        .execute(
            &format!(
                "INSERT INTO \"scimManagedConnectionEvent\" (\"id\",\"connectionRecordId\",\"eventKey\",\"sequence\",\"type\",\"actorId\",\"credentialId\",\"createdAt\") VALUES {}",
                rows.join(",")
            ),
            &[],
        )
        .await?;
    let list = async |page: Value| {
        let mut input = json!({"connectionId":cid,"provisioningDomainId":"tenant-a"});
        input
            .as_object_mut()
            .unwrap()
            .extend(page.as_object().unwrap().clone());
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("scim", "listSCIMManagedConnectionEvents")
                .with_body(&input)
                .unwrap(),
            EndpointOptions::default(),
        )
        .await
    };
    let page = async |input: Value| -> TestResult<(Value, Vec<i64>)> {
        let response = body(&list(input).await?.into_response()?);
        let sequences = response["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| event["sequence"].as_i64().unwrap())
            .collect();
        Ok((response, sequences))
    };
    let (first, sequences) = page(json!({})).await?;
    assert_eq!(
        first.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["events", "limit", "offset", "total"]
    );
    assert_eq!(
        (&first["limit"], &first["offset"], &first["total"]),
        (&json!(100), &json!(0), &json!(102))
    );
    assert_eq!(sequences, (3..=102).collect::<Vec<_>>());
    assert_eq!(page(json!({"offset":100})).await?.1, [1, 2]);
    let (newest, sequences) = page(json!({"limit":10,"sortDirection":"desc"})).await?;
    assert_eq!(sequences, (93..=102).rev().collect::<Vec<_>>());
    assert_eq!(
        (&newest["limit"], &newest["offset"], &newest["total"]),
        (&json!(10), &json!(0), &json!(102))
    );
    assert_eq!(
        page(json!({"limit":10,"sortDirection":"asc"})).await?.1,
        (1..=10).collect::<Vec<_>>()
    );
    assert_eq!(
        page(json!({"limit":10,"offset":95,"sortDirection":"asc"}))
            .await?
            .1,
        (96..=102).collect::<Vec<_>>()
    );
    assert_eq!(page(json!({"limit":3,"offset":1})).await?.1, [99, 100, 101]);
    let (beyond, sequences) = page(json!({"offset":980})).await?;
    assert!(sequences.is_empty());
    assert_eq!(
        (&beyond["offset"], &beyond["total"]),
        (&json!(980), &json!(102))
    );
    let before = db.table("scimManagedConnectionEvent").await?;
    let direction = r#"[body.sortDirection] Invalid option: expected one of "asc"|"desc""#;
    for (input, message) in [
        (json!({"limit":0}), "[body.limit] Too small: expected number to be >=1".to_owned()),
        (json!({"limit":101}), "[body.limit] Too big: expected number to be <=100".to_owned()),
        (json!({"limit":1.5}), "[body.limit] Invalid input: expected int, received number".to_owned()),
        (json!({"limit":"10"}), "[body.limit] Invalid input: expected number, received string".to_owned()),
        (json!({"limit":null}), "[body.limit] Invalid input: expected number, received null".to_owned()),
        (json!({"offset":-1}), "[body.offset] Too small: expected number to be >=0".to_owned()),
        (json!({"offset":0.5}), "[body.offset] Invalid input: expected int, received number".to_owned()),
        (json!({"sortDirection":"up"}), direction.to_owned()),
        (json!({"sortDirection":null}), direction.to_owned()),
        (
            json!({"limit":1e20,"offset":-1,"sortDirection":"ASC"}),
            format!("[body.limit] Too big: expected int to be <=9007199254740991; [body.limit] Too big: expected number to be <=100; [body.offset] Too small: expected number to be >=0; {direction}"),
        ),
        (
            json!({"connectionId":"missing","provisioningDomainId":" ","limit":0}),
            r#"[body.connectionId] Invalid string: must start with "ba_scim_connection_"; [body.provisioningDomainId] Too small: expected string to have >=1 characters; [body.limit] Too small: expected number to be >=1"#.to_owned(),
        ),
    ] {
        let error = list(input.clone()).await.unwrap_err();
        assert_eq!(error.error.status_code(), 400, "{input}");
        assert_eq!(error.error.error_payload().2, message, "{input}");
    }
    assert_eq!(db.table("scimManagedConnectionEvent").await?, before);
    Ok(())
}
