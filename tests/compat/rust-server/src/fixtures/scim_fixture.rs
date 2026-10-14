use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::integrations::axum::AxumIntegration;
use alibi::plugins::ScimPlugin;
use alibi::plugins::scim::ScimManagedConnectionOptions;
use alibi::seaorm::sea_orm::DatabaseConnection;
use alibi::seaorm::sea_orm::{ConnectionTrait, Statement};
use alibi::utils::json::JsValue;
use alibi::{AuthBuilder, AuthConfig, AuthResult};
use axum::response::IntoResponse;
use axum::{Json, Router, extract::Query, routing::post};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
pub(crate) async fn router(base: &AuthConfig, database: DatabaseConnection) -> AuthResult<Router> {
    let path = "/__test/profiles/scim/api/auth";
    let config = base.clone().base_path(path);
    let auth = Arc::new(
        AuthBuilder::<crate::TestSchema>::new(config.clone())
            .store(crate::backend::store(config, database.clone()))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(ScimPlugin::new().managed_connections(managed_options()))
            .build()
            .await?,
    );
    let router = Router::new().nest(path, auth.clone().axum_router().with_state(auth.clone()));
    let restart_auth = Arc::new(tokio::sync::Mutex::new(auth.clone()));
    let restart_config = base.clone().base_path(path);
    Ok(router.route(
        "/__test/server-api/scim",
        post(move |Query(query): Query<HashMap<String, String>>, bytes: axum::body::Bytes| {
            let database=database.clone();
            let auth = restart_auth.clone();
            let config=restart_config.clone();
            async move {
                if query.get("operation").is_some_and(|operation|operation=="restart-managed") {
                    let fresh=AuthBuilder::<crate::TestSchema>::new(config.clone()).store(crate::backend::store(config,database.clone())).rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false)).plugin(ScimPlugin::new().managed_connections(managed_options())).build().await.unwrap();
                    *auth.lock().await=Arc::new(fresh);return Json(json!({"restarted":true})).into_response();
                }
                let auth=auth.lock().await.clone();
                if query.get("operation").is_some_and(|operation|operation=="age-connection") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();
                    _=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"UPDATE scimManagedConnection SET createdAt=? WHERE connectionId=?",["2000-01-01T00:00:00.000Z".into(),input["connectionId"].as_str().unwrap().into()])).await.unwrap();
                    return Json(json!({"aged":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="credential-state") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();
                    let (sql,value)=if let Some(policy)=input.get("policy"){("UPDATE scimManagedCredential SET serializedScopes=? WHERE credentialId=?",policy.as_str().unwrap())}else{("UPDATE scimManagedCredential SET expiresAt=? WHERE credentialId=?","2000-01-01T00:00:00.000Z")};
                    _=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),sql,[value.into(),input["credentialId"].as_str().unwrap().into()])).await.unwrap();
                    return Json(json!({"changed":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="reject-rotation-event") {
                    _=database.execute_unprepared("CREATE TRIGGER reject_scim_rotation_event BEFORE INSERT ON scimManagedConnectionEvent WHEN NEW.actorId='rollback-operator' AND NEW.type='credential.rotated' BEGIN SELECT RAISE(ABORT,'fixture rejected rotation event'); END").await.unwrap();return Json(json!({"installed":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="rotation-failure") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();let mut body=JsValue::from(input["body"].clone());if let JsValue::Object(values)=&mut body{let date=chrono::DateTime::parse_from_rfc3339(values["expiresAt"].as_str().unwrap()).unwrap().with_timezone(&chrono::Utc);_=values.insert("expiresAt".into(),JsValue::Date(date));}
                    let result=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("scim","rotateSCIMManagedCredential").with_body_value(body),EndpointOptions::default()).await;let failed=result.is_err();let rejected=result.err().is_some_and(|error|error.to_string().contains("fixture rejected rotation event"));return Json(json!({"failed":failed,"rejectedEvent":rejected})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="reject-revocation-event") {
                    _=database.execute_unprepared("CREATE TRIGGER reject_scim_revocation_event BEFORE INSERT ON scimManagedConnectionEvent WHEN NEW.actorId='rollback-operator' AND NEW.type='credential.revoked' BEGIN SELECT RAISE(ABORT,'fixture rejected revocation event'); END").await.unwrap();return Json(json!({"installed":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="revocation-failure") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();let result=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("scim","revokeSCIMManagedCredential").with_body(&input["body"]).unwrap(),EndpointOptions::default()).await;
                    let failed=result.is_err();let rejected=result.err().is_some_and(|error|error.to_string().contains("fixture rejected revocation event"));return Json(json!({"failed":failed,"rejectedEvent":rejected})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="revokeSCIMManagedCredential") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();
                    let result=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("scim","revokeSCIMManagedCredential").with_body(&input["body"]).unwrap(),EndpointOptions::default()).await;
                    return match result {Ok(output)=>output.into_response().unwrap().into_response(),Err(error)=>error.error.to_auth_response().into_response()};
                }
                if query.get("operation").is_some_and(|operation|operation=="rotateSCIMManagedCredential") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();let mut body=JsValue::from(input["body"].clone());if let JsValue::Object(values)=&mut body {let date=chrono::DateTime::parse_from_rfc3339(values["expiresAt"].as_str().unwrap()).unwrap().with_timezone(&chrono::Utc);_=values.insert("expiresAt".into(),JsValue::Date(date));}
                    let result=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("scim","rotateSCIMManagedCredential").with_body_value(body),EndpointOptions::default()).await;
                    return match result {Ok(output)=>output.into_response().unwrap().into_response(),Err(error)=>{let mut response=error.error.to_auth_response();if let Some(headers)=error.headers{for(name,value)in headers.iter(){response.headers.append(name,value);}}response.into_response()}};
                }
                if query.get("operation").is_some_and(|operation|operation=="binding-lease") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();_=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"UPDATE scimConnectionBinding SET decommissionStatus='reconciling',decommissionLeaseId='other-worker',decommissionCompletedAt=NULL,decommissionReconciledUserCount=7,decommissionBatchCount=2,decommissionLeaseExpiresAt=? WHERE connectionId=?",["2035-02-03T04:05:06.789Z".into(),input["connectionId"].as_str().unwrap().into()])).await.unwrap();return Json(json!({"leased":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="binding-storage") {return Json(physical_rows(&database,"scimConnectionBinding").await).into_response();}
                if query.get("operation").is_some_and(|operation|operation=="decommissionSCIMConnection") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();let result=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("scim","decommissionSCIMConnection").with_body(&input["body"]).unwrap(),EndpointOptions::default()).await;
                    return match result{Ok(output)=>output.into_response().unwrap().into_response(),Err(error)=>error.error.to_auth_response().into_response()};
                }
                if query.get("operation").is_some_and(|operation|matches!(operation.as_str(),"getSCIMManagedConnection"|"listSCIMManagedConnectionEvents")) {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();
                    let result=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("scim",if query.get("operation").is_some_and(|operation|operation=="listSCIMManagedConnectionEvents"){"listSCIMManagedConnectionEvents"}else{"getSCIMManagedConnection"}).with_body(&input["body"]).unwrap(),EndpointOptions::default()).await;
                    return match result {Ok(output)=>output.into_response().unwrap().into_response(),Err(error)=>error.error.to_auth_response().into_response()};
                }
                if query.get("operation").is_some_and(|operation|operation=="listSCIMManagedConnections") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();
                    let result=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("scim","listSCIMManagedConnections").with_body(&input["body"]).unwrap(),EndpointOptions::default()).await;
                    return match result {Ok(output)=>output.into_response().unwrap().into_response(),Err(error)=>error.error.to_auth_response().into_response()};
                }
                if query.get("operation").is_some_and(|operation|operation=="reject-late-event") {
                    _=database.execute_unprepared("CREATE TRIGGER reject_scim_late_event BEFORE INSERT ON scimManagedConnectionEvent WHEN NEW.actorId='rollback-operator' AND NEW.sequence=2 BEGIN SELECT RAISE(ABORT,'fixture rejected late event'); END").await.unwrap();
                    return Json(json!({"installed":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="managed-failure") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();let mut body=JsValue::from(input["body"].clone());
                    if let JsValue::Object(values)=&mut body {let date=chrono::DateTime::parse_from_rfc3339(values["expiresAt"].as_str().unwrap()).unwrap().with_timezone(&chrono::Utc);_=values.insert("expiresAt".into(),JsValue::Date(date));}
                    let result=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("scim","createSCIMManagedConnection").with_body_value(body),EndpointOptions::default()).await;
                    let failed=result.is_err();let rejected=result.err().is_some_and(|error|error.to_string().contains("fixture rejected late event"));
                    return Json(json!({"failed":failed,"rejectedLateEvent":rejected})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="managed-storage") {
                    let connections=physical_rows(&database,"scimManagedConnection").await;
                    let credentials=physical_rows(&database,"scimManagedCredential").await;
                    let events=physical_rows(&database,"scimManagedConnectionEvent").await;
                    return Json(json!({"connections":connections,"credentials":credentials,"events":events})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="createSCIMManagedConnection") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();let mut body=JsValue::from(input["body"].clone());
                    if input["sdkDate"]==true { if let JsValue::Object(body)=&mut body {let date=chrono::DateTime::parse_from_rfc3339(body["expiresAt"].as_str().unwrap()).unwrap().with_timezone(&chrono::Utc);_=body.insert("expiresAt".into(),JsValue::Date(date));}}
                    let result=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("scim","createSCIMManagedConnection").with_body_value(body),EndpointOptions::default()).await;
                    return match result {Ok(output)=>output.into_response().unwrap().into_response(),Err(error)=>{let mut response=error.error.to_auth_response();if let Some(headers)=error.headers {for(name,value)in headers.iter(){response.headers.append(name,value);}}response.into_response()}};
                }
                if query.get("operation").is_some_and(|operation| {
                    matches!(operation.as_str(), "getSCIMResourceType" | "getSCIMSchema")
                }) {
                    let output = auth
                        .dispatch_endpoint(
                            if query
                                .get("operation")
                                .is_some_and(|operation| operation == "getSCIMSchema")
                            {
                                ScimPlugin::schema_endpoint(
                                    query.get("id").map_or("", String::as_str),
                                )
                                .unwrap()
                            } else {
                                ScimPlugin::resource_type_endpoint(
                                    query.get("id").map_or("", String::as_str),
                                )
                                .unwrap()
                            },
                            EndpointOptions::default(),
                        )
                        .await;
                    return match output {
                        Ok(output) => (axum::http::StatusCode::OK, Json(output.value().clone())),
                        Err(error) => (
                            axum::http::StatusCode::from_u16(error.error.status_code()).unwrap(),
                            Json(*error.body.unwrap()),
                        ),
                    }.into_response();
                }
                let output = auth
                    .dispatch_endpoint(
                        if query
                            .get("operation")
                            .is_some_and(|operation| operation == "getSCIMSchemas")
                        {
                            ScimPlugin::schemas_endpoint()
                        } else if query
                            .get("operation")
                            .is_some_and(|operation| operation == "getSCIMResourceTypes")
                        {
                            ScimPlugin::resource_types_endpoint()
                        } else {
                            ScimPlugin::service_provider_config_endpoint()
                        },
                        EndpointOptions::default(),
                    )
                    .await
                    .unwrap();
                (axum::http::StatusCode::OK, Json(output.value().clone())).into_response()
            }
        }),
    ))
}

async fn physical_rows(database: &DatabaseConnection, table: &str) -> Value {
    let columns = match table {
        "scimConnectionBinding" => vec![
            "id",
            "connectionId",
            "connectionKey",
            "provisioningDomainId",
            "createdAt",
            "decommissionStatus",
            "decommissionCursorUserId",
            "decommissionReconciledUserCount",
            "decommissionBatchCount",
            "decommissionRevision",
            "decommissionedAt",
            "decommissionCompletedAt",
            "decommissionLeaseId",
            "decommissionLeaseExpiresAt",
        ],
        "scimManagedConnection" => vec![
            "id",
            "creationRequestId",
            "connectionId",
            "provisioningDomainId",
            "status",
            "revision",
            "createdAt",
            "createdBy",
            "decommissionStartedAt",
            "decommissionStartedBy",
            "decommissionedAt",
            "decommissionedBy",
        ],
        "scimManagedCredential" => vec![
            "id",
            "connectionRecordId",
            "credentialId",
            "tokenDigest",
            "hashVersion",
            "activeSlotKey",
            "status",
            "serializedScopes",
            "expiresAt",
            "createdAt",
            "createdBy",
            "lastUsedAt",
            "revokedAt",
            "revokedBy",
            "decommissionedAt",
        ],
        _ => vec![
            "id",
            "connectionRecordId",
            "eventKey",
            "sequence",
            "type",
            "actorId",
            "credentialId",
            "createdAt",
        ],
    };
    let fields = columns
        .iter()
        .map(|column| {
            let value = if column.ends_with("At") {
                format!("strftime('%Y-%m-%dT%H:%M:%fZ',\"{column}\")")
            } else {
                format!("\"{column}\"")
            };
            format!("'{column}',{value}")
        })
        .collect::<Vec<_>>()
        .join(",");
    let query = format!(
        "SELECT json_object({fields}) AS row FROM \"{table}\"{}",
        if table == "scimManagedConnectionEvent" {
            " ORDER BY sequence"
        } else {
            ""
        }
    );
    let rows = database
        .query_all_raw(Statement::from_string(
            database.get_database_backend(),
            query,
        ))
        .await
        .unwrap();
    Value::Array(
        rows.iter()
            .map(|row| serde_json::from_str(&row.try_get::<String>("", "row").unwrap()).unwrap())
            .collect(),
    )
}

fn managed_options() -> ScimManagedConnectionOptions {
    let mut options =
        ScimManagedConnectionOptions::new("managed-scim-credential-hmac-secret-32-chars");
    options.max_active_credentials = 2;
    options
}
