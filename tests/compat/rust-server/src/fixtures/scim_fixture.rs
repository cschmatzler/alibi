use alibi::AuthUser;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::integrations::axum::AxumIntegration;
use alibi::plugins::ScimPlugin;
use alibi::plugins::scim::{ScimBearerTokenVerificationInput, ScimBearerTokenVerifier};
use alibi::plugins::scim::{ScimConnectionOptions, ScimCredential};
use alibi::plugins::scim::{ScimIdentity, ScimIdentityState};
use alibi::plugins::scim::{ScimManagedConnectionOptions, ScimProjectedUserState, ScimProjection};
use alibi::plugins::scim::{ScimRoleExistenceInput, ScimRoleMappingInput, ScimRoleProjection};
use alibi::seaorm::sea_orm::DatabaseConnection;
use alibi::seaorm::sea_orm::{ConnectionTrait, Statement};
use alibi::store::AuthStore;
use alibi::store::AuthTransaction;
use alibi::utils::json::JsValue;
use alibi::{AuthBuilder, AuthConfig, AuthResult};
use axum::response::IntoResponse;
use axum::{Json, Router, extract::Query, routing::post};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicU8, Ordering},
};
use tower::ServiceExt;
pub(crate) async fn router(base: &AuthConfig, database: DatabaseConnection) -> AuthResult<Router> {
    let path = "/__test/profiles/scim/api/auth";
    let config = base.clone().base_path(path);
    let auth = Arc::new(
        AuthBuilder::<crate::TestSchema>::new(config.clone())
            .store(crate::backend::store(config, database.clone()))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(alibi::plugins::EmailPasswordPlugin::new())
            .plugin(
                ScimPlugin::new()
                    .managed_connections(managed_options())
                    .connections(resource_connections()),
            )
            .build()
            .await?,
    );
    let restart_auth = Arc::new(tokio::sync::Mutex::new(auth.clone()));
    let http_auth = restart_auth.clone();
    let router = Router::new().nest(
        path,
        Router::new().fallback(move |request: axum::extract::Request| {
            let auth = http_auth.clone();
            async move {
                let auth = auth.lock().await.clone();
                auth.clone()
                    .axum_router()
                    .with_state(auth)
                    .oneshot(request)
                    .await
                    .unwrap()
            }
        }),
    );
    let restart_config = base.clone().base_path(path);
    let projection_states = Arc::new(Mutex::new(Vec::<ScimProjectedUserState>::new()));
    let projection_fails = Arc::new(AtomicBool::new(false));
    let role_observations = Arc::new(Mutex::new(json!({"mapped":[],"checked":[]})));
    let role_stage = Arc::new(AtomicU8::new(0));
    let identity_states = Arc::new(Mutex::new(Vec::<ScimIdentityState>::new()));
    let identity_fails = Arc::new(AtomicBool::new(false));
    let verifier_inputs = Arc::new(Mutex::new(Vec::<Value>::new()));
    let verifier_claims = Arc::new(Mutex::new(None::<JsValue>));
    Ok(router.route(
        "/__test/server-api/scim",
        post(move |Query(query): Query<HashMap<String, String>>, bytes: axum::body::Bytes| {
            let database=database.clone();
            let verifier_inputs=verifier_inputs.clone();let verifier_claims=verifier_claims.clone();
            let auth = restart_auth.clone();
            let config=restart_config.clone();
            let projection_states=projection_states.clone();let projection_fails=projection_fails.clone();let role_observations=role_observations.clone();let role_stage=role_stage.clone();let identity_states=identity_states.clone();let identity_fails=identity_fails.clone();
            async move {
                if query.get("operation").is_some_and(|operation|operation=="configure-verifier") {
                    let plugin=ScimPlugin::new().connections(vec![ScimConnectionOptions{id:"declared".into(),provisioning_domain_id:Some("tenant-declared".into()),credentials:vec![ScimCredential::new("static","static-token")]}]).authentication::<crate::TestSchema>(Arc::new(FixtureVerifier{inputs:verifier_inputs.clone(),claims:verifier_claims.clone()}));
                    let fresh=AuthBuilder::<crate::TestSchema>::new(config.clone()).store(crate::backend::store(config,database.clone())).rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false)).plugin(alibi::plugins::EmailPasswordPlugin::new()).plugin(plugin).build().await.unwrap();*auth.lock().await=Arc::new(fresh);return Json(json!({"configured":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="verifier-claims") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();let mut claims=JsValue::from(input["claims"].clone());
                    if input["sdkDate"]==true {if let JsValue::Object(values)=&mut claims{let date=chrono::DateTime::parse_from_rfc3339(values["expiresAt"].as_str().unwrap()).unwrap().with_timezone(&chrono::Utc);_=values.insert("expiresAt".into(),JsValue::Date(date));}}
                    *verifier_claims.lock().unwrap()=Some(claims);return Json(json!({"changed":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="verifier-inputs") {let inputs=verifier_inputs.lock().unwrap().clone();return Json(inputs).into_response();}
                if query.get("operation").is_some_and(|operation|matches!(operation.as_str(),"configure-projection"|"configure-role-projection")) {
                    let mut plugin=ScimPlugin::new().managed_connections(managed_options()).projection::<crate::TestSchema>(Arc::new(FixtureProjection{states:projection_states.clone(),fails:projection_fails.clone()}));if query.get("operation").is_some_and(|operation|operation=="configure-role-projection"){plugin=plugin.roles(Arc::new(FixtureRoles{observations:role_observations.clone(),stage:role_stage.clone()}));}
                    let fresh=AuthBuilder::<crate::TestSchema>::new(config.clone()).store(crate::backend::store(config,database.clone())).rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false)).plugin(alibi::plugins::EmailPasswordPlugin::new()).plugin(plugin).build().await.unwrap();*auth.lock().await=Arc::new(fresh);return Json(json!({"configured":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="configure-identity") {
                    let fresh=AuthBuilder::<crate::TestSchema>::new(config.clone()).store(crate::backend::store(config,database.clone())).rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false)).plugin(alibi::plugins::EmailPasswordPlugin::new()).plugin(ScimPlugin::new().managed_connections(managed_options()).identity::<crate::TestSchema>(Arc::new(FixtureIdentity{states:identity_states.clone(),fails:identity_fails.clone()}))).build().await.unwrap();*auth.lock().await=Arc::new(fresh);return Json(json!({"configured":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="restart-managed") {
                    let fresh=AuthBuilder::<crate::TestSchema>::new(config.clone()).store(crate::backend::store(config,database.clone())).rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false)).plugin(ScimPlugin::new().managed_connections(managed_options())).build().await.unwrap();
                    *auth.lock().await=Arc::new(fresh);return Json(json!({"restarted":true})).into_response();
                }
                let auth=auth.lock().await.clone();
                if query.get("operation").is_some_and(|operation|operation=="seed-verifier-groups") {
                    let _owner=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("email-password","signUpEmail").with_body(&json!({"email":"verifier-owner@example.com","password":"a-native-password-123","name":"Verifier owner"})).unwrap(),EndpointOptions::default()).await.unwrap();
                    for(id,domain)in[("declared","tenant-declared"),("dynamic","tenant-dynamic")]{_=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"INSERT INTO scimGroup (id,connectionId,provisioningDomainId,revision,displayName,displayNameKey,orderKey,createdAt,updatedAt) VALUES (?,?,?,0,'Verified Group',?,?,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",[id.into(),id.into(),domain.into(),id.into(),id.into()])).await.unwrap();}return Json(json!({"seeded":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="verifier-user") {let rows=query_json_rows(&database,"SELECT json_object('name',name) AS row FROM user WHERE email='verifier-owner@example.com'").await;return Json(rows[0].clone()).into_response();}
                if query.get("operation").is_some_and(|operation|operation=="reject-managed-usage") {
                    _=database.execute_unprepared("CREATE TRIGGER reject_scim_usage BEFORE UPDATE ON scimManagedCredential WHEN NEW.lastUsedAt IS NOT NULL BEGIN SELECT RAISE(ABORT,'fixture rejected usage'); END").await.unwrap();return Json(json!({"installed":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="accept-managed-usage") {
                    _=database.execute_unprepared("DROP TRIGGER reject_scim_usage").await.unwrap();return Json(json!({"removed":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="seed-managed-group") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();
                    _=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"INSERT INTO scimGroup (id,connectionId,provisioningDomainId,revision,displayName,displayNameKey,orderKey,createdAt,updatedAt) VALUES ('managed-group',?,'tenant-managed',0,'Managed Staff','managed-group','managed-group','2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",[input["connectionId"].as_str().unwrap().into()])).await.unwrap();return Json(json!({"seeded":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="managed-bearer-policy") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();
                    for field in ["serializedScopes","hashVersion","status","expiresAt","lastUsedAt"] {
                        if let Some(value)=input.get(field) {
                            let value:alibi::seaorm::sea_orm::Value=if let Some(value)=value.as_str(){value.into()}else{Option::<String>::None.into()};
                            _=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),format!("UPDATE scimManagedCredential SET {field}=? WHERE credentialId=?"),[value,input["credentialId"].as_str().unwrap().into()])).await.unwrap();
                        }
                    }
                    if let Some(status)=input.get("connectionStatus"){_=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"UPDATE scimManagedConnection SET status=? WHERE connectionId=?",[status.as_str().unwrap().into(),input["connectionId"].as_str().unwrap().into()])).await.unwrap();}
                    return Json(json!({"changed":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="oversize-group-read") {
                    _=database.execute_unprepared("WITH RECURSIVE seq(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM seq WHERE n<1001) INSERT INTO scimGroupMember (id,connectionId,groupId,scimUserId,membershipKey,createdAt) SELECT 'cap-'||CAST(n AS TEXT),'conn-a','staff','member-a','cap-'||CAST(n AS TEXT),'2026-01-02T03:04:05.000Z' FROM seq").await.unwrap();return Json(json!({"oversized":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="drift-read-binding") { _=database.execute_unprepared("UPDATE scimConnectionBinding SET provisioningDomainId='drifted-domain' WHERE connectionId='conn-a'").await.unwrap();return Json(json!({"changed":true})).into_response(); }
                if query.get("operation").is_some_and(|operation|operation=="retire-read-binding") { _=database.execute_unprepared("UPDATE scimConnectionBinding SET provisioningDomainId='tenant-a',decommissionStatus='complete' WHERE connectionId='conn-a'").await.unwrap();return Json(json!({"retired":true})).into_response(); }
                if query.get("operation").is_some_and(|operation|operation=="getSCIMGroup") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();
                    let endpoint=ScimPlugin::group_endpoint(input["params"]["groupId"].as_str().unwrap()).unwrap().with_query(&input["query"]).unwrap();
                    let headers=input["token"].as_str().map(|token|[("authorization".into(),format!("Bearer {token}"))].into_iter().collect());
                    let result=auth.dispatch_endpoint(endpoint,EndpointOptions{headers,..Default::default()}).await;
                    return match result {Ok(output)=>output.into_response().unwrap().into_response(),Err(error)=>{
                        let mut response=alibi::endpoint::EndpointResponse::error(error.error);
                        if let Some(body)=error.body {response=response.with_error_body(*body);}
                        if let Some(headers)=error.headers {response.merge_headers(headers);}
                        response.to_response().unwrap().into_response()
                    }};
                }
                if query.get("operation").is_some_and(|operation|operation=="seed-group-read") {
                    let output=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("email-password","signUpEmail").with_body(&json!({"email":"group-read-owner@example.com","password":"a-native-password-123","name":"Group owner"})).unwrap(),EndpointOptions::default()).await.unwrap().into_response().unwrap();
                    let owner:Value=serde_json::from_slice(&output.body).unwrap();let uid=owner["user"]["id"].as_str().unwrap();
                    for(id,cid,domain,display)in[("member-a","conn-a","tenant-a","Inactive member"),("member-b","conn-b","tenant-a","Foreign member"),("member-c","conn-a","tenant-b","Other domain member")]{
                        _=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"INSERT INTO scimUser (id,connectionId,provisioningDomainId,userId,connectionUserKey,userName,userNameKey,primaryEmail,workEmailValueIndex,emailValueIndex,displayName,formattedName,serializedEmails,active,orderKey,createdAt,updatedAt) VALUES (?,?,?,?,?,?,?,'group-read-owner@example.com','[]','[]',?,?,'[]',false,?,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",vec![id.into(),cid.into(),domain.into(),uid.into(),id.into(),id.into(),id.into(),display.into(),display.into(),id.into()])).await.unwrap();
                    }
                    for(id,cid,domain)in[("staff","conn-a","tenant-a"),("other","conn-b","tenant-a"),("drift","conn-a","tenant-b")]{
                        _=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"INSERT INTO scimGroup (id,connectionId,provisioningDomainId,revision,displayName,displayNameKey,externalId,orderKey,createdAt,updatedAt) VALUES (?,?,?,0,'Staff',?,'external-staff',?,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",[id.into(),cid.into(),domain.into(),id.into(),id.into()])).await.unwrap();
                    }
                    for(id,time)in[("member-a","2026-01-02T03:04:05.001Z"),("member-b","2026-01-02T03:04:05.002Z"),("member-c","2026-01-02T03:04:05.003Z")]{
                        _=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"INSERT INTO scimGroupMember (id,connectionId,groupId,scimUserId,membershipKey,createdAt) VALUES (?,'conn-a','staff',?,?,?)",[id.into(),id.into(),id.into(),time.into()])).await.unwrap();
                    }
                    return Json(json!({"seeded":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="seed-role-groups") {
                    for(id,cid,domain,display,external)in[("group-a","conn-a","tenant-a","Admins","administrators"),("group-b","conn-a","tenant-a","Admin backups","administrators-b"),("group-e","conn-a","tenant-a","Editors","editors"),("group-g","conn-a","tenant-a","Guests","guests"),("group-c","conn-a","tenant-b","Foreign domain","foreign-domain"),("group-d","conn-other","tenant-a","Foreign connection","foreign-connection")]{
                        _=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"INSERT INTO scimGroup (id,connectionId,provisioningDomainId,revision,displayName,displayNameKey,externalId,externalIdKey,orderKey,createdAt,updatedAt) VALUES (?,?,?,0,?,?,?,?,?,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",vec![id.into(),cid.into(),domain.into(),display.into(),id.into(),external.into(),id.into(),id.into()])).await.unwrap();
                        _=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"INSERT INTO scimGroupMember (id,connectionId,groupId,scimUserId,membershipKey,createdAt) VALUES (?,'conn-a',?,'scim-alias-a',?,'2026-01-02T03:04:05.000Z')",[id.into(),id.into(),id.into()])).await.unwrap();
                    }
                    return Json(json!({"seeded":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="role-observations") {let observations=role_observations.lock().unwrap().clone();return Json(observations).into_response();}
                if query.get("operation").is_some_and(|operation|operation=="rename-role-source") {_=database.execute_unprepared("UPDATE scimGroup SET externalId='administrators-renamed' WHERE id='group-a'").await.unwrap();return Json(json!({"renamed":true})).into_response();}
                if query.get("operation").is_some_and(|operation|operation=="role-failure-stage") {let input:Value=serde_json::from_slice(&bytes).unwrap();let stage=input["stage"].as_u64().unwrap() as u8;role_stage.store(stage,Ordering::SeqCst);return Json(json!({"stage":stage})).into_response();}
                if query.get("operation").is_some_and(|operation|operation=="prepare-active-bindings") {
                    for(id,domain)in[("conn-a","tenant-a"),("conn-c","tenant-b")]{let _result=auth.dispatch_endpoint(ScimPlugin::decommission_connection_endpoint(id,Some(domain)).unwrap(),EndpointOptions::default()).await.unwrap();_=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"UPDATE scimConnectionBinding SET decommissionStatus='active',decommissionedAt=NULL,decommissionCompletedAt=NULL WHERE connectionId=?",[id.into()])).await.unwrap();}return Json(json!({"prepared":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="projection-toggle-failure") {let input:Value=serde_json::from_slice(&bytes).unwrap();let fail=input["fail"].as_bool().unwrap();projection_fails.store(fail,Ordering::SeqCst);return Json(json!({"failing":fail})).into_response();}
                if query.get("operation").is_some_and(|operation|operation=="identity-states") {let states=identity_states.lock().unwrap().clone();return Json(states).into_response();}
                if query.get("operation").is_some_and(|operation|operation=="identity-toggle-failure") {let input:Value=serde_json::from_slice(&bytes).unwrap();let fail=input["fail"].as_bool().unwrap();identity_fails.store(fail,Ordering::SeqCst);return Json(json!({"failing":fail})).into_response();}
                if query.get("operation").is_some_and(|operation|operation=="claim-profile-source") {_=database.execute_unprepared("UPDATE scimSubject SET profileSourceId='scim-alias-a'").await.unwrap();return Json(json!({"claimed":true})).into_response();}
                if query.get("operation").is_some_and(|operation|operation=="seed-projection") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();
                    let alias_a=input["sourceIds"][0].as_str().unwrap_or("scim-alias-a");
                    let alias_b=input["sourceIds"][1].as_str().unwrap_or("scim-alias-b");
                    let alias_c=input["sourceIds"][2].as_str().unwrap_or("scim-alias-c");
                    let output=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("email-password","signUpEmail").with_body(&json!({"email":"projection-owner@example.com","password":"a-native-password-123","name":"Native owner"})).unwrap(),EndpointOptions::default()).await.unwrap().into_response().unwrap();let signed:Value=serde_json::from_slice(&output.body).unwrap();let uid=signed["user"]["id"].as_str().unwrap();
                    _=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"INSERT INTO scimSubject (id,userId,revision,createdAt,updatedAt) VALUES ('projection-subject',?,0,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",[uid.into()])).await.unwrap();
                    for(id,cid,domain,active)in[(alias_a,"conn-a","tenant-a",true),(alias_b,"conn-b","tenant-a",false),(alias_c,"conn-c","tenant-b",true)]{
                        let sql="INSERT INTO scimUser (id,connectionId,provisioningDomainId,userId,connectionUserKey,userName,userNameKey,primaryEmail,workEmailValueIndex,emailValueIndex,displayName,formattedName,serializedEmails,active,orderKey,createdAt,updatedAt) VALUES (?,?,?,?,?,'projection-owner@example.com',?,'projection-owner@example.com','[]','[]','Owner','Owner','[]',?,?,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')";
                        _=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),sql,vec![id.into(),cid.into(),domain.into(),uid.into(),id.into(),id.into(),active.into(),id.into()])).await.unwrap();
                    }
                    _=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"INSERT INTO scimProjectionGrant (id,connectionId,provisioningDomainId,scimUserId,userId,sourceKind,sourceId,role,grantKey,createdAt,updatedAt) VALUES ('legacy-grant','conn-a','tenant-a','scim-alias-a',?,'group','retired-group','legacy-role','legacy-grant','2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",[uid.into()])).await.unwrap();
                    return Json(json!({"userId":uid})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="projection-fails") {let owners=query_json_rows(&database,"SELECT json_object('id',id) AS row FROM user WHERE email='projection-owner@example.com'").await;let uid=owners[0]["id"].as_str().unwrap();_=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"INSERT INTO scimProjectionGrant (id,connectionId,provisioningDomainId,scimUserId,userId,sourceKind,sourceId,role,grantKey,createdAt,updatedAt) VALUES ('failure-grant','conn-a','tenant-a','scim-alias-a',?,'group','retired-group','legacy-role','failure-grant','2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",[uid.into()])).await.unwrap();projection_fails.store(true,Ordering::SeqCst);return Json(json!({"failing":true})).into_response();}
                if query.get("operation").is_some_and(|operation|operation=="projection-states") {let states=projection_states.lock().unwrap().clone();return Json(states).into_response();}
                if query.get("operation").is_some_and(|operation|operation=="projection-storage") {
                    return Json(json!({"sessions":query_json_rows(&database,"SELECT json_object('id',id,'userId',userId) AS row FROM session WHERE userId IN (SELECT id FROM user WHERE email='projection-owner@example.com')").await,"users":query_json_rows(&database,"SELECT json_object('id',id,'name',name) AS row FROM user WHERE email='projection-owner@example.com'").await,"subjects":query_json_rows(&database,"SELECT json_object('id',id,'userId',userId,'revision',revision,'profileSourceId',profileSourceId,'createdAt',strftime('%Y-%m-%dT%H:%M:%fZ',createdAt),'updatedAt',strftime('%Y-%m-%dT%H:%M:%fZ',updatedAt)) AS row FROM scimSubject").await,"scimUsers":query_json_rows(&database,"SELECT json_object('id',id,'connectionId',connectionId,'provisioningDomainId',provisioningDomainId,'userId',userId,'active',active) AS row FROM scimUser").await,"grants":physical_rows(&database,"scimProjectionGrant").await})).into_response();
                }
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
                if query.get("operation").is_some_and(|operation|operation=="expire-binding-lease") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();_=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"UPDATE scimConnectionBinding SET decommissionLeaseExpiresAt=? WHERE connectionId=?",["2000-01-01T00:00:00.000Z".into(),input["connectionId"].as_str().unwrap().into()])).await.unwrap();return Json(json!({"expired":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="reject-binding-completion") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();_=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"UPDATE scimConnectionBinding SET decommissionStatus='reconciling',decommissionLeaseId='failed-worker',decommissionCompletedAt=NULL,decommissionLeaseExpiresAt=? WHERE connectionId=?",["2000-01-01T00:00:00.000Z".into(),input["connectionId"].as_str().unwrap().into()])).await.unwrap();
                    _=database.execute_unprepared("CREATE TRIGGER reject_scim_binding_completion BEFORE UPDATE ON scimConnectionBinding WHEN NEW.decommissionStatus='complete' AND OLD.decommissionStatus='reconciling' BEGIN SELECT RAISE(ABORT,'fixture rejected binding completion'); END").await.unwrap();return Json(json!({"installed":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="accept-binding-completion") {_=database.execute_unprepared("DROP TRIGGER reject_scim_binding_completion").await.unwrap();return Json(json!({"removed":true})).into_response();}
                if query.get("operation").is_some_and(|operation|operation=="binding-completion-failure") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();let result=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("scim","decommissionSCIMConnection").with_body(&input["body"]).unwrap(),EndpointOptions::default()).await;let failed=result.is_err();let rejected=result.err().is_some_and(|error|error.to_string().contains("fixture rejected binding completion"));return Json(json!({"failed":failed,"rejectedCompletion":rejected})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="binding-storage") {return Json(physical_rows(&database,"scimConnectionBinding").await).into_response();}
                if query.get("operation").is_some_and(|operation|operation=="reject-decommission-events") {
                    _=database.execute_unprepared("CREATE TRIGGER reject_scim_decommission_event BEFORE INSERT ON scimManagedConnectionEvent WHEN (NEW.actorId='reject-begin' AND NEW.type='connection.decommissioning') OR (NEW.actorId='reject-complete' AND NEW.type='connection.decommissioned') BEGIN SELECT RAISE(ABORT,'fixture rejected decommission event'); END").await.unwrap();return Json(json!({"installed":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="decommission-failure") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();let result=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("scim","decommissionSCIMManagedConnection").with_body(&input["body"]).unwrap(),EndpointOptions::default()).await;let failed=result.is_err();let rejected=result.err().is_some_and(|error|error.to_string().contains("fixture rejected decommission event"));return Json(json!({"failed":failed,"rejectedEvent":rejected})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="decommissionSCIMManagedConnection") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();let result=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("scim","decommissionSCIMManagedConnection").with_body(&input["body"]).unwrap(),EndpointOptions::default()).await;return match result {Ok(output)=>output.into_response().unwrap().into_response(),Err(error)=>error.error.to_auth_response().into_response()};
                }
                if query.get("operation").is_some_and(|operation|operation=="reconcileSCIMProjection") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();let result=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("scim","reconcileSCIMProjection").with_body(&input["body"]).unwrap(),EndpointOptions::default()).await;return match result{Ok(output)=>output.into_response().unwrap().into_response(),Err(error)=>{if let alibi::AuthError::Config(message)=&error.error{Json(json!({"failed":true,"message":message})).into_response()}else{let response=if let Some(body)=error.body{alibi::AuthResponse::json(error.error.status_code(),body.as_ref()).unwrap()}else{error.error.to_auth_response()};response.into_response()}}};
                }
                if query.get("operation").is_some_and(|operation|operation=="decommissionSCIMConnection") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();let result=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("scim","decommissionSCIMConnection").with_body(&input["body"]).unwrap(),EndpointOptions::default()).await;
                    return match result{Ok(output)=>output.into_response().unwrap().into_response(),Err(error)=>{let response=if let Some(body)=error.body{alibi::AuthResponse::json(error.error.status_code(),body.as_ref()).unwrap()}else{error.error.to_auth_response()};response.into_response()}};
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
        "scimProjectionGrant" => vec![
            "id",
            "connectionId",
            "provisioningDomainId",
            "scimUserId",
            "userId",
            "sourceKind",
            "sourceId",
            "sourceValue",
            "role",
            "grantKey",
            "createdAt",
            "updatedAt",
        ],
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

struct FixtureProjection {
    states: Arc<Mutex<Vec<ScimProjectedUserState>>>,
    fails: Arc<AtomicBool>,
}
#[async_trait::async_trait]
impl ScimProjection<crate::TestSchema> for FixtureProjection {
    async fn reconcile_user(
        &self,
        input: &ScimProjectedUserState,
        database: &dyn AuthTransaction<crate::TestSchema>,
    ) -> AuthResult<()> {
        _ = database
            .update_user(
                &input.user_id,
                alibi::UpdateUser {
                    name: Some(
                        if self.fails.load(Ordering::SeqCst) {
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
        if self.fails.load(Ordering::SeqCst) {
            return Err(alibi::AuthError::internal(
                "application rejected projection",
            ));
        }
        Ok(())
    }
}
async fn query_json_rows(database: &DatabaseConnection, sql: &str) -> Value {
    let rows = database
        .query_all_raw(Statement::from_string(
            database.get_database_backend(),
            sql.to_string(),
        ))
        .await
        .unwrap();
    Value::Array(
        rows.iter()
            .map(|row| serde_json::from_str(&row.try_get::<String>("", "row").unwrap()).unwrap())
            .collect(),
    )
}

struct FixtureRoles {
    observations: Arc<Mutex<Value>>,
    stage: Arc<AtomicU8>,
}
#[async_trait::async_trait]
impl ScimRoleProjection<crate::TestSchema> for FixtureRoles {
    async fn map(
        &self,
        input: &ScimRoleMappingInput,
        database: &dyn AuthTransaction<crate::TestSchema>,
    ) -> AuthResult<Option<Vec<String>>> {
        self.observations.lock().unwrap()["mapped"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::to_value(input).unwrap());
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
        _database: &dyn AuthTransaction<crate::TestSchema>,
    ) -> AuthResult<bool> {
        self.observations.lock().unwrap()["checked"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::to_value(input).unwrap());
        if self.stage.load(Ordering::SeqCst) == 2 {
            return Err(alibi::AuthError::internal(
                "application rejected validation",
            ));
        }
        Ok(input.role == "admin")
    }
}

struct FixtureIdentity {
    states: Arc<Mutex<Vec<ScimIdentityState>>>,
    fails: Arc<AtomicBool>,
}
#[async_trait::async_trait]
impl ScimIdentity<crate::TestSchema> for FixtureIdentity {
    async fn reconcile_user(
        &self,
        input: &ScimIdentityState,
        database: &dyn AuthTransaction<crate::TestSchema>,
    ) -> AuthResult<()> {
        _ = database
            .update_user(
                &input.user_id,
                alibi::UpdateUser {
                    name: Some(
                        if self.fails.load(Ordering::SeqCst) {
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
        if self.fails.load(Ordering::SeqCst) {
            return Err(alibi::AuthError::internal("application rejected identity"));
        }
        Ok(())
    }
}

fn resource_connections() -> Vec<ScimConnectionOptions> {
    let mut limited = ScimCredential::new("limited", "users-reader");
    limited.scopes = Some(vec!["scim.users.read".into()]);
    let mut expired = ScimCredential::new("expired", "expired-reader");
    expired.expires_at = Some(
        chrono::DateTime::parse_from_rfc3339("2000-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
    );
    vec![
        ScimConnectionOptions {
            id: "conn-a".into(),
            provisioning_domain_id: Some("tenant-a".into()),
            credentials: vec![
                ScimCredential::new("reader", "group-reader"),
                limited,
                expired,
            ],
        },
        ScimConnectionOptions {
            id: "conn-b".into(),
            provisioning_domain_id: Some("tenant-a".into()),
            credentials: vec![ScimCredential::new("reader", "other-reader")],
        },
    ]
}

struct FixtureVerifier {
    inputs: Arc<Mutex<Vec<Value>>>,
    claims: Arc<Mutex<Option<JsValue>>>,
}
#[async_trait::async_trait]
impl<S: alibi::AuthSchema> ScimBearerTokenVerifier<S> for FixtureVerifier {
    async fn verify_bearer_token(
        &self,
        input: &ScimBearerTokenVerificationInput,
        database: &dyn AuthStore<S>,
    ) -> AuthResult<Option<JsValue>> {
        self.inputs.lock().unwrap().push(json!({"token":input.token,"method":format!("{:?}",input.method).to_uppercase(),"path":input.path,"headers":input.headers}));
        let owner = database
            .get_user_by_email("verifier-owner@example.com")
            .await?
            .unwrap();
        _ = database
            .update_user(
                owner.id().as_ref(),
                alibi::UpdateUser {
                    name: Some("Verified remote".into()),
                    ..Default::default()
                },
            )
            .await?;
        if let Some(claims) = self.claims.lock().unwrap().clone() {
            return Ok(Some(claims));
        }
        Ok(Some(JsValue::from(if input.token == "oauth-dynamic" {
            json!({"connection":{"id":"dynamic","provisioningDomainId":"tenant-dynamic"},"credentialId":"remote","scopes":["scim.groups.read"]})
        } else {
            json!({"connectionId":"declared","credentialId":"remote","scopes":["scim.groups.read"]})
        })))
    }
}
