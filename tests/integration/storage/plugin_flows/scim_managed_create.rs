//! Managed connection creation persists credentials and its two ordered events atomically.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::scim::{ScimManagedConnectionInput, ScimManagedConnectionOptions, ScimPlugin};
use alibi::utils::json::JsValue;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
backend_tests!(scim_managed_connection_creation_persists_secret_digest_and_rejects_reuse);
postgres_tests!(scim_managed_connection_creation_persists_secret_digest_and_rejects_reuse);
const HASH_SECRET: &str = "managed-scim-credential-hmac-secret-32-chars";
async fn scim_managed_connection_creation_persists_secret_digest_and_rejects_reuse<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(
            ScimPlugin::new().managed_connections(ScimManagedConnectionOptions::new(HASH_SECRET)),
        )
        .build()
        .await?;
    let input = json!({"creationRequestId":"  request-creation-001  ","provisioningDomainId":"  tenant-one  ","actorId":"  operator  ","scopes":["scim.users.read","scim.users.write"],"expiresAt":"2035-01-02T03:04:05.678Z"});
    let mut actual = JsValue::from(input.clone());
    if let JsValue::Object(body) = &mut actual {
        _ = body.insert(
            "expiresAt".into(),
            JsValue::Date(
                chrono::DateTime::parse_from_rfc3339(input["expiresAt"].as_str().unwrap())?
                    .with_timezone(&chrono::Utc),
            ),
        );
    }
    let output = auth
        .dispatch_endpoint(
            ScimPlugin::create_managed_connection_endpoint(&ScimManagedConnectionInput {
                creation_request_id: input["creationRequestId"].as_str().unwrap().into(),
                provisioning_domain_id: input["provisioningDomainId"].as_str().unwrap().into(),
                actor_id: input["actorId"].as_str().unwrap().into(),
                scopes: vec!["scim.users.read".into(), "scim.users.write".into()],
                expires_at: chrono::DateTime::parse_from_rfc3339(
                    input["expiresAt"].as_str().unwrap(),
                )?
                .with_timezone(&chrono::Utc),
            })?,
            EndpointOptions::default(),
        )
        .await;
    let response = output?.into_response()?;
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    assert_eq!(
        response.headers.get("cache-control").map(String::as_str),
        Some("no-store")
    );
    assert_eq!(
        response.headers.get("pragma").map(String::as_str),
        Some("no-cache")
    );
    let created = body(&response);
    assert_eq!(
        created["connection"]["creationRequestId"],
        "request-creation-001"
    );
    assert_eq!(created["connection"]["provisioningDomainId"], "tenant-one");
    assert_eq!(created["connection"]["createdBy"], "operator");
    assert_eq!(created["connection"]["status"], "active");
    assert!(created["connection"].get("id").is_none());
    assert!(created["connection"].get("revision").is_none());
    let cid = created["connection"]["connectionId"].as_str().unwrap();
    assert!(cid.starts_with("ba_scim_connection_"));
    assert_eq!(cid.len(), "ba_scim_connection_".len() + 32);
    let credential = &created["credential"];
    let kid = credential["credentialId"].as_str().unwrap();
    assert!(kid.starts_with("ba_scim_credential_"));
    assert_eq!(kid.len(), "ba_scim_credential_".len() + 32);
    assert_eq!(credential["scopes"], input["scopes"]);
    assert_eq!(credential["expiresAt"], input["expiresAt"]);
    assert_eq!(credential["createdBy"], "operator");
    assert_eq!(credential["status"], "active");
    let token = created["token"].as_str().unwrap();
    assert!(token.starts_with(&format!("{kid}.")));
    assert_eq!(token.len(), kid.len() + 1 + 48);
    let rows: Value = serde_json::from_str(&db.table("scimManagedConnection").await?)?;
    assert_eq!(rows.as_array().unwrap().len(), 1);
    assert_eq!(rows[0]["connectionId"], cid);
    assert_eq!(rows[0]["revision"], 2);
    let credentials: Value = serde_json::from_str(&db.table("scimManagedCredential").await?)?;
    assert_eq!(credentials.as_array().unwrap().len(), 1);
    assert_eq!(credentials[0]["connectionRecordId"], rows[0]["id"]);
    assert_eq!(credentials[0]["credentialId"], kid);
    assert_eq!(credentials[0]["hashVersion"], "v1");
    assert_eq!(
        credentials[0]["activeSlotKey"],
        format!("{}:active:0", rows[0]["id"].as_str().unwrap())
    );
    let mut key = [0_u8; 64];
    key[..HASH_SECRET.len()].copy_from_slice(HASH_SECRET.as_bytes());
    let mut inner = key.iter().map(|byte| byte ^ 0x36).collect::<Vec<_>>();
    inner.extend_from_slice(token.as_bytes());
    let mut outer = key.iter().map(|byte| byte ^ 0x5c).collect::<Vec<_>>();
    outer.extend_from_slice(&Sha256::digest(inner));
    assert_eq!(
        credentials[0]["tokenDigest"],
        URL_SAFE_NO_PAD.encode(Sha256::digest(outer))
    );
    assert!(credential.get("tokenDigest").is_none());
    let events: Value = serde_json::from_str(&db.table("scimManagedConnectionEvent").await?)?;
    let events = events.as_array().unwrap();
    assert_eq!(events.len(), 2);
    for (sequence, kind) in [(1, "connection.created"), (2, "credential.issued")] {
        let event = events
            .iter()
            .find(|event| event["sequence"] == sequence)
            .unwrap();
        assert_eq!(event["type"], kind);
        assert_eq!(event["actorId"], "operator");
        assert_eq!(event["connectionRecordId"], rows[0]["id"]);
        assert_eq!(
            event["eventKey"],
            format!("{}:{sequence}", rows[0]["id"].as_str().unwrap())
        );
        assert_eq!(
            event["credentialId"],
            if sequence == 2 {
                json!(kid)
            } else {
                Value::Null
            }
        );
    }
    let before = db
        .tables(&[
            "scimManagedConnection",
            "scimManagedCredential",
            "scimManagedConnectionEvent",
        ])
        .await?;
    let reused = auth
        .dispatch_endpoint(
            ServerEndpoint::<Value>::new("scim", "createSCIMManagedConnection")
                .with_body_value(actual.clone()),
            EndpointOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(reused.error.status_code(), 409);
    assert_eq!(
        reused.error.error_payload().1,
        Some("SCIM_MANAGED_CREATION_REQUEST_ID_CONFLICT".into())
    );
    assert_eq!(
        db.tables(&[
            "scimManagedConnection",
            "scimManagedCredential",
            "scimManagedConnectionEvent"
        ])
        .await?,
        before
    );
    for (mut candidate, sdk_date, message) in [
        (
            json!({"creationRequestId":"another-request-001","provisioningDomainId":"tenant-one","actorId":"operator","scopes":["scim.users.read","scim.users.read"],"expiresAt":"2035-01-02T03:04:05.678Z"}),
            true,
            "Managed SCIM credential scopes must be unique",
        ),
        (
            json!({"creationRequestId":"another-request-002","provisioningDomainId":"tenant-one","actorId":"operator","scopes":["scim.users.read"],"expiresAt":"2000-01-01T00:00:00.000Z"}),
            true,
            "Managed SCIM credential expiry must be in the future",
        ),
        (
            input.clone(),
            false,
            "[body.expiresAt] Invalid input: expected date, received string",
        ),
    ] {
        candidate["creationRequestId"] = if sdk_date {
            candidate["creationRequestId"].clone()
        } else {
            json!("another-request-003")
        };
        let mut candidate = JsValue::from(candidate);
        if sdk_date && let JsValue::Object(values) = &mut candidate {
            let date = chrono::DateTime::parse_from_rfc3339(values["expiresAt"].as_str().unwrap())?
                .with_timezone(&chrono::Utc);
            _ = values.insert("expiresAt".into(), JsValue::Date(date));
        }
        let error = auth
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("scim", "createSCIMManagedConnection")
                    .with_body_value(candidate),
                EndpointOptions::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.error.status_code(), 400);
        assert_eq!(error.error.error_payload().2, message);
        assert_eq!(
            db.tables(&[
                "scimManagedConnection",
                "scimManagedCredential",
                "scimManagedConnectionEvent"
            ])
            .await?,
            before
        );
    }
    if db.is_postgres() {
        _=db.execute("CREATE FUNCTION reject_scim_late_event() RETURNS trigger LANGUAGE plpgsql AS $function$ BEGIN IF NEW.\"actorId\" = 'rollback-operator' AND NEW.\"sequence\" = 2 THEN RAISE EXCEPTION 'fixture rejected late event'; END IF; RETURN NEW; END $function$", &[]).await?;
        _=db.execute("CREATE TRIGGER reject_scim_late_event BEFORE INSERT ON \"scimManagedConnectionEvent\" FOR EACH ROW EXECUTE FUNCTION reject_scim_late_event()", &[]).await?;
    } else {
        _=db.execute("CREATE TRIGGER reject_scim_late_event BEFORE INSERT ON scimManagedConnectionEvent WHEN NEW.actorId='rollback-operator' AND NEW.sequence=2 BEGIN SELECT RAISE(ABORT,'fixture rejected late event'); END", &[]).await?;
    }
    let mut rejected = actual.clone();
    if let JsValue::Object(values) = &mut rejected {
        _ = values.insert(
            "creationRequestId".into(),
            JsValue::String("rollback-request-001".into()),
        );
        _ = values.insert(
            "actorId".into(),
            JsValue::String("rollback-operator".into()),
        );
    }
    let error = auth
        .dispatch_endpoint(
            ServerEndpoint::<Value>::new("scim", "createSCIMManagedConnection")
                .with_body_value(rejected),
            EndpointOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.error.status_code(), 500);
    assert!(error.to_string().contains("fixture rejected late event"));
    assert_eq!(
        db.tables(&[
            "scimManagedConnection",
            "scimManagedCredential",
            "scimManagedConnectionEvent"
        ])
        .await?,
        before
    );
    Ok(())
}
