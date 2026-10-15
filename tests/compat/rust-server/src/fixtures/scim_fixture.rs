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
    let user_read_attributes = Arc::new(Mutex::new(String::new()));
    Ok(router.route(
        "/__test/server-api/scim",
        post(move |Query(query): Query<HashMap<String, String>>, bytes: axum::body::Bytes| {
            let database=database.clone();
            let user_read_attributes=user_read_attributes.clone();
            let verifier_inputs=verifier_inputs.clone();let verifier_claims=verifier_claims.clone();
            let auth = restart_auth.clone();
            let config=restart_config.clone();
            let projection_states=projection_states.clone();let projection_fails=projection_fails.clone();let role_observations=role_observations.clone();let role_stage=role_stage.clone();let identity_states=identity_states.clone();let identity_fails=identity_fails.clone();
            async move {
                if query.get("operation").is_some_and(|operation|operation=="configure-entra-group-compatibility") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();
                    let plugin=ScimPlugin::new().managed_connections(managed_options()).connections(resource_connections()).compatibility(alibi::plugins::scim::ScimCompatibilityOptions{microsoft_entra:Some(alibi::plugins::scim::ScimMicrosoftEntraCompatibilityOptions{accept_legacy_group_schema:input["enabled"]==true})});
                    let fresh=AuthBuilder::<crate::TestSchema>::new(config.clone()).store(crate::backend::store(config,database.clone())).rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false)).plugin(alibi::plugins::EmailPasswordPlugin::new()).plugin(plugin).build().await.unwrap();
                    *auth.lock().await=Arc::new(fresh);return Json(json!({"configured":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="configure-verifier") {
                    let plugin=ScimPlugin::new().connections(vec![ScimConnectionOptions{id:"declared".into(),provisioning_domain_id:Some("tenant-declared".into()),credentials:vec![ScimCredential::new("static","static-token")]}]).authentication::<crate::TestSchema>(Arc::new(FixtureVerifier{inputs:verifier_inputs.clone(),claims:verifier_claims.clone()}));
                    let fresh=AuthBuilder::<crate::TestSchema>::new(config.clone()).store(crate::backend::store(config,database.clone())).rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false)).plugin(alibi::plugins::EmailPasswordPlugin::new()).plugin(plugin).build().await.unwrap();*auth.lock().await=Arc::new(fresh);return Json(json!({"configured":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="verifier-claims") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();let mut claims=JsValue::from(input["claims"].clone());
                    if input["sdkDate"]==true {if let JsValue::Object(values)=&mut claims{let date=chrono::DateTime::parse_from_rfc3339(values["expiresAt"].as_str().unwrap()).unwrap().with_timezone(&chrono::Utc);_=values.insert("expiresAt".into(),JsValue::Date(date));}}
                    *verifier_claims.lock().unwrap()=Some(claims);return Json(json!({"changed":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="discovery-sdk") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();
                    let operation=match input["api"].as_str().unwrap(){"getSCIMServiceProviderConfig"=>"getSCIMServiceProviderConfig","getSCIMResourceTypes"=>"getSCIMResourceTypes","getSCIMSchemas"=>"getSCIMSchemas","getSCIMResourceType"=>"getSCIMResourceType","getSCIMSchema"=>"getSCIMSchema",_=>panic!("fixture discovery operation")};
                    let mut endpoint=ServerEndpoint::<Value>::new("scim",operation);
                    if let Some(params)=input.get("params"){endpoint=endpoint.with_params(params).unwrap();}
                    let auth=auth.lock().await.clone();
                    return match auth.dispatch_endpoint(endpoint,EndpointOptions::default()).await {
                        Ok(output)=>if input["mode"]=="headers" {let headers:serde_json::Map<String,Value>=output.headers().iter().map(|(name,value)|(name.clone(),json!(value))).collect();alibi::AuthResponse::json(200,&json!({"response":output.value(),"headers":headers})).unwrap().into_response()} else {output.into_response().unwrap().into_response()},
                        Err(error)=>{let mut response=alibi::endpoint::EndpointResponse::error(error.error);if let Some(body)=error.body{response=response.with_error_body(*body);}if let Some(headers)=error.headers{response.merge_headers(headers);}response.to_response().unwrap().into_response()},
                    };
                }
                if query.get("operation").is_some_and(|operation|operation=="probe-authentication-source") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();
                    let plugin=match input["mode"].as_str().unwrap(){"static"=>ScimPlugin::new().connections(resource_connections()),"managed"=>ScimPlugin::new().managed_connections(managed_options()),_=>ScimPlugin::new()};
                    let candidate=AuthBuilder::<crate::TestSchema>::new(config.clone()).store(crate::backend::store(config.clone(),database.clone())).plugin(plugin).build().await;
                    return match candidate {
                        Ok(candidate)=>{let output=candidate.dispatch_endpoint(ScimPlugin::resource_types_endpoint(),EndpointOptions::default()).await.unwrap();alibi::AuthResponse::json(200,output.value()).unwrap().into_response()},
                        Err(alibi::AuthError::Config(message))=>alibi::AuthResponse::json(400,&json!({"error":message})).unwrap().into_response(),
                        Err(error)=>error.to_auth_response().into_response(),
                    };
                }
                if query.get("operation").is_some_and(|operation|operation=="verifier-inputs") {let inputs=verifier_inputs.lock().unwrap().clone();return Json(inputs).into_response();}
                if query.get("operation").is_some_and(|operation|matches!(operation.as_str(),"configure-projection"|"configure-role-projection"|"configure-group-create-projection"|"configure-user-delete"|"configure-user-create")) {
                    let base=ScimPlugin::new().managed_connections(managed_options());let base=if query.get("operation").is_some_and(|operation|matches!(operation.as_str(),"configure-group-create-projection"|"configure-user-delete"|"configure-user-create")){base.connections(resource_connections())}else{base};let mut plugin=base.projection::<crate::TestSchema>(Arc::new(FixtureProjection{states:projection_states.clone(),fails:projection_fails.clone()}));if query.get("operation").is_some_and(|operation|operation=="configure-role-projection"){plugin=plugin.roles(Arc::new(FixtureRoles{observations:role_observations.clone(),stage:role_stage.clone()}));}
                    if query.get("operation").is_some_and(|operation|operation=="configure-user-create"){plugin=plugin.identity(Arc::new(CreateIdentity));}
                    if query.get("operation").is_some_and(|operation|operation=="configure-user-delete"){plugin=plugin.identity(Arc::new(FixtureIdentity{states:identity_states.clone(),fails:identity_fails.clone()}));}
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
                if query.get("operation").is_some_and(|operation|operation=="group-create-projection-fails") {let input:Value=serde_json::from_slice(&bytes).unwrap();let fail=input["fail"].as_bool().unwrap_or(true);projection_fails.store(fail,Ordering::SeqCst);return Json(json!({"failing":fail})).into_response();}
                if query.get("operation").is_some_and(|operation|operation=="group-create-owner") {let rows=query_json_rows(&database,"SELECT json_object('name',name) AS row FROM user WHERE email='group-create-owner@example.com'").await;return Json(rows[0].clone()).into_response();}
                if query.get("operation").is_some_and(|operation|operation=="deleteSCIMUser") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();let headers=input["token"].as_str().map(|token|[("authorization".into(),format!("Bearer {token}"))].into_iter().collect());
                    return match auth.dispatch_endpoint(ScimPlugin::delete_user_endpoint(input["params"]["userId"].as_str().unwrap()).unwrap().with_query(&input["query"]).unwrap(),EndpointOptions{headers,..Default::default()}).await{Ok(output)=>output.into_response().unwrap().into_response(),Err(error)=>{let mut response=alibi::endpoint::EndpointResponse::error(error.error);if let Some(body)=error.body{response=response.with_error_body(*body);}if let Some(headers)=error.headers{response.merge_headers(headers);}response.to_response().unwrap().into_response()}};
                }
                if query.get("operation").is_some_and(|operation|operation=="prepare-user-delete") {
                    use base64::Engine;use sha2::Digest;let key=base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(serde_json::to_vec(&["scim-user-external-id","conn-a","external-a"]).unwrap()));
                    _=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"UPDATE scimUser SET externalId='external-a',externalIdKey=?,active=true WHERE id='member-a'",[key.into()])).await.unwrap();for sql in ["UPDATE scimUser SET active=true WHERE id='member-b'","UPDATE scimSubject SET profileSourceId='member-a'"]{_=database.execute_raw(Statement::from_string(database.get_database_backend(),sql.to_owned())).await.unwrap();}return Json(json!({"prepared":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="reuse-user-delete-tombstone") {
                    use base64::Engine;use sha2::Digest;let key=base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(serde_json::to_vec(&["scim-user-external-id","conn-a","external-a"]).unwrap()));_=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"UPDATE scimUser SET provisioningDomainId='tenant-a',externalId='external-a',externalIdKey=? WHERE id='member-c'",[key.into()])).await.unwrap();_=database.execute_raw(Statement::from_string(database.get_database_backend(),"UPDATE scimIdentityTombstone SET connectionId='legacy-connection',provisioningDomainId='legacy-domain',externalId='legacy-external'".to_owned())).await.unwrap();return Json(json!({"changed":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="user-delete-state") {
                    let sessions=query_json_rows(&database,"SELECT json_object('n',COUNT(*)) AS row FROM session WHERE userId IN (SELECT id FROM user WHERE email='group-create-owner@example.com')").await;let owner=query_json_rows(&database,"SELECT json_object('name',name) AS row FROM user WHERE email='group-create-owner@example.com'").await;
                    return Json(json!({"users":query_json_rows(&database,"SELECT json_object('id',id,'connectionId',connectionId,'provisioningDomainId',provisioningDomainId) AS row FROM scimUser ORDER BY id").await,"groups":query_json_rows(&database,"SELECT json_object('id',id,'revision',revision) AS row FROM scimGroup ORDER BY id").await,"members":query_json_rows(&database,"SELECT json_object('groupId',groupId,'scimUserId',scimUserId) AS row FROM scimGroupMember ORDER BY groupId,scimUserId").await,"subjects":query_json_rows(&database,"SELECT json_object('revision',revision,'profileSourceId',profileSourceId) AS row FROM scimSubject").await,"tombstones":query_json_rows(&database,"SELECT json_object('connectionId',connectionId,'provisioningDomainId',provisioningDomainId,'externalId',externalId,'userId',userId,'profile',profile) AS row FROM scimIdentityTombstone ORDER BY externalIdKey").await,"sessions":sessions[0],"owner":owner[0]})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="patchSCIMGroup") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();let headers=input["token"].as_str().map(|token|[("authorization".into(),format!("Bearer {token}"))].into_iter().collect());
                    return match auth.dispatch_endpoint(ScimPlugin::patch_group_endpoint(input["params"]["groupId"].as_str().unwrap()).unwrap().with_body_value(trusted_user_body(&input)),EndpointOptions{headers,..Default::default()}).await{Ok(output)=>output.into_response().unwrap().into_response(),Err(error)=>{let mut response=alibi::endpoint::EndpointResponse::error(error.error);if let Some(body)=error.body{response=response.with_error_body(*body);}if let Some(headers)=error.headers{response.merge_headers(headers);}response.to_response().unwrap().into_response()}};
                }
                if query.get("operation").is_some_and(|operation|operation=="replaceSCIMGroup") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();let headers=input["token"].as_str().map(|token|[("authorization".into(),format!("Bearer {token}"))].into_iter().collect());
                    return match auth.dispatch_endpoint(ScimPlugin::replace_group_endpoint(input["params"]["groupId"].as_str().unwrap()).unwrap().with_body_value(trusted_user_body(&input)).with_query(&input["query"]).unwrap(),EndpointOptions{headers,..Default::default()}).await{Ok(output)=>output.into_response().unwrap().into_response(),Err(error)=>{let mut response=alibi::endpoint::EndpointResponse::error(error.error);if let Some(body)=error.body{response=response.with_error_body(*body);}if let Some(headers)=error.headers{response.merge_headers(headers);}response.to_response().unwrap().into_response()}};
                }
                if query.get("operation").is_some_and(|operation|operation=="group-replace-members") {let input:Value=serde_json::from_slice(&bytes).unwrap();let rows=database.query_all_raw(Statement::from_sql_and_values(database.get_database_backend(),"SELECT id,scimUserId FROM scimGroupMember WHERE connectionId='conn-a' AND groupId=? ORDER BY createdAt ASC",[input["id"].as_str().unwrap().into()])).await.unwrap().into_iter().map(|row|json!({"id":row.try_get::<String>("","id").unwrap(),"scimUserId":row.try_get::<String>("","scimUserId").unwrap()})).collect::<Vec<_>>();return Json(rows).into_response();}
                if query.get("operation").is_some_and(|operation|operation=="deleteSCIMGroup") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();let headers=input["token"].as_str().map(|token|[("authorization".into(),format!("Bearer {token}"))].into_iter().collect());
                    return match auth.dispatch_endpoint(ScimPlugin::delete_group_endpoint(input["params"]["groupId"].as_str().unwrap()).unwrap().with_query(&input["query"]).unwrap(),EndpointOptions{headers,..Default::default()}).await{Ok(output)=>output.into_response().unwrap().into_response(),Err(error)=>{let mut response=alibi::endpoint::EndpointResponse::error(error.error);if let Some(body)=error.body{response=response.with_error_body(*body);}if let Some(headers)=error.headers{response.merge_headers(headers);}response.to_response().unwrap().into_response()}};
                }
                if query.get("operation").is_some_and(|operation|operation=="user-create-state") {
                    let mut users=query_json_rows(&database,"SELECT json_object('id',id,'email',email,'name',name,'emailVerified',emailVerified) AS row FROM user ORDER BY email").await;
                    for row in users.as_array_mut().unwrap(){row["emailVerified"]=json!(row["emailVerified"].as_bool().unwrap_or_else(||row["emailVerified"].as_i64()==Some(1)));}
                    let mut state=json!({"users":users});for(table,key)in[("scimUser","sources"),("scimSubject","subjects"),("scimIdentityTombstone","tombstones")]{let rows=query_json_rows(&database,&format!("SELECT json_object('n',COUNT(*)) AS row FROM {table}")).await;state[key]=rows[0]["n"].clone();}return Json(state).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="drift-user-replace") {let input:Value=serde_json::from_slice(&bytes).unwrap();_=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"UPDATE scimUser SET provisioningDomainId='drifted' WHERE id=?",[input["id"].as_str().unwrap().into()])).await.unwrap();return Json(json!({"changed":true})).into_response();}
                if query.get("operation").is_some_and(|operation|operation=="prepare-user-replace") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();let rows=query_json_rows(&database,&format!("SELECT json_object('userId',userId) AS row FROM scimUser WHERE id='{}'",input["id"].as_str().unwrap().replace('\'',"''"))).await;let uid=rows[0]["userId"].as_str().unwrap();
                    _=auth.store().update_user(uid,alibi::UpdateUser{email_verified:Some(true),..Default::default()}).await.unwrap();_=auth.store().create_session(alibi::CreateSession{additional_fields:Default::default(),token:None,user_id:uid.into(),expires_at:chrono::Utc::now()+chrono::Duration::days(1),ip_address:None,user_agent:None,impersonated_by:None,active_organization_id:None,active_team_id:None}).await.unwrap();return Json(json!({"prepared":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="detach-user-profile") {let input:Value=serde_json::from_slice(&bytes).unwrap();_=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"UPDATE scimSubject SET profileSourceId=NULL WHERE profileSourceId=?",[input["id"].as_str().unwrap().into()])).await.unwrap();return Json(json!({"detached":true})).into_response();}
                if query.get("operation").is_some_and(|operation|operation=="user-replace-state") {let sessions=query_json_rows(&database,"SELECT json_object('n',COUNT(*)) AS row FROM session").await;let subjects=query_json_rows(&database,"SELECT json_object('revision',revision,'profileSourceId',profileSourceId) AS row FROM scimSubject ORDER BY id").await;return Json(json!({"sessions":sessions[0]["n"],"subjects":subjects})).into_response();}
                if query.get("operation").is_some_and(|operation|operation=="patchSCIMUser") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();let headers=input["token"].as_str().map(|token|[("authorization".into(),format!("Bearer {token}"))].into_iter().collect());
                    return match auth.dispatch_endpoint(ScimPlugin::patch_user_endpoint(input["params"]["userId"].as_str().unwrap()).unwrap().with_body_value(trusted_user_body(&input)).with_query(&input.get("query").cloned().unwrap_or_else(||json!({}))).unwrap(),EndpointOptions{headers,..Default::default()}).await{Ok(output)=>output.into_response().unwrap().into_response(),Err(error)=>{let mut response=alibi::endpoint::EndpointResponse::error(error.error);if let Some(body)=error.body{response=response.with_error_body(*body);}if let Some(headers)=error.headers{response.merge_headers(headers);}response.to_response().unwrap().into_response()}};
                }
                if query.get("operation").is_some_and(|operation|operation=="replaceSCIMUser") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();let headers=input["token"].as_str().map(|token|[("authorization".into(),format!("Bearer {token}"))].into_iter().collect());
                    return match auth.dispatch_endpoint(ScimPlugin::replace_user_endpoint(input["params"]["userId"].as_str().unwrap()).unwrap().with_body_value(trusted_user_body(&input)).with_query(&input.get("query").cloned().unwrap_or_else(||json!({}))).unwrap(),EndpointOptions{headers,..Default::default()}).await{Ok(output)=>output.into_response().unwrap().into_response(),Err(error)=>{let mut response=alibi::endpoint::EndpointResponse::error(error.error);if let Some(body)=error.body{response=response.with_error_body(*body);}if let Some(headers)=error.headers{response.merge_headers(headers);}response.to_response().unwrap().into_response()}};
                }
                if query.get("operation").is_some_and(|operation|operation=="createSCIMUser") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();let headers=input["token"].as_str().map(|token|[("authorization".into(),format!("Bearer {token}"))].into_iter().collect());
                    return match auth.dispatch_endpoint(ScimPlugin::create_user_endpoint().with_body_value(trusted_user_body(&input)).with_query(&input.get("query").cloned().unwrap_or_else(||json!({}))).unwrap(),EndpointOptions{headers,..Default::default()}).await{Ok(output)=>output.into_response().unwrap().into_response(),Err(error)=>{let mut response=alibi::endpoint::EndpointResponse::error(error.error);if let Some(body)=error.body{response=response.with_error_body(*body);}if let Some(headers)=error.headers{response.merge_headers(headers);}response.to_response().unwrap().into_response()}};
                }
                if query.get("operation").is_some_and(|operation|operation=="createSCIMGroup") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();let headers=input["token"].as_str().map(|token|[("authorization".into(),format!("Bearer {token}"))].into_iter().collect());
                    return match auth.dispatch_endpoint(ScimPlugin::create_group_endpoint().with_body_value(trusted_user_body(&input)).with_query(&input["query"]).unwrap(),EndpointOptions{headers,..Default::default()}).await{Ok(output)=>output.into_response().unwrap().into_response(),Err(error)=>{let mut response=alibi::endpoint::EndpointResponse::error(error.error);if let Some(body)=error.body{response=response.with_error_body(*body);}if let Some(headers)=error.headers{response.merge_headers(headers);}response.to_response().unwrap().into_response()}};
                }
                if query.get("operation").is_some_and(|operation|operation=="seed-group-create") {
                    let output=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("email-password","signUpEmail").with_body(&json!({"email":"group-create-owner@example.com","password":"a-native-password-123","name":"Group owner"})).unwrap(),EndpointOptions::default()).await.unwrap().into_response().unwrap();let owner:Value=serde_json::from_slice(&output.body).unwrap();let uid=owner["user"]["id"].as_str().unwrap();
                    _=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"INSERT INTO scimSubject (id,userId,revision,createdAt,updatedAt) VALUES ('group-create-subject',?,0,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",[uid.into()])).await.unwrap();
                    for(id,cid,domain,display)in[("member-a","conn-a","tenant-a","Inactive member"),("member-b","conn-b","tenant-a","Foreign member"),("member-c","conn-a","tenant-b","Other domain member")]{
                        _=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"INSERT INTO scimUser (id,connectionId,provisioningDomainId,userId,connectionUserKey,userName,userNameKey,primaryEmail,workEmailValueIndex,emailValueIndex,displayName,formattedName,serializedEmails,active,orderKey,createdAt,updatedAt) VALUES (?,?,?,?,?,?,?,'group-create-owner@example.com','[]','[]',?,?,'[]',false,?,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",[id.into(),cid.into(),domain.into(),uid.into(),id.into(),id.into(),id.into(),display.into(),display.into(),id.into()])).await.unwrap();
                    }
                    return Json(json!({"seeded":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="group-create-state") {
                    use alibi::seaorm::sea_orm::QueryResult;
                    let mut counts=Vec::new();for table in ["scimGroup","scimGroupMember"]{let value:QueryResult=database.query_one_raw(Statement::from_string(database.get_database_backend(),format!("SELECT COUNT(*) AS n FROM {table}"))).await.unwrap().unwrap();counts.push(value.try_get::<i64>("","n").unwrap());}
                    let subject=database.query_one_raw(Statement::from_string(database.get_database_backend(),"SELECT revision FROM scimSubject WHERE id='group-create-subject'".to_owned())).await.unwrap().unwrap().try_get::<i64>("","revision").unwrap();
                    return Json(json!({"groups":{"n":counts[0]},"members":{"n":counts[1]},"subject":{"revision":subject}})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="drift-created-group") {let input:Value=serde_json::from_slice(&bytes).unwrap();_=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"UPDATE scimGroup SET provisioningDomainId='drifted' WHERE id=?",[input["id"].as_str().unwrap().into()])).await.unwrap();return Json(json!({"changed":true})).into_response();}
                if query.get("operation").is_some_and(|operation|operation=="listSCIMUsers") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();let headers=input["token"].as_str().map(|token|[("authorization".into(),format!("Bearer {token}"))].into_iter().collect());
                    return match auth.dispatch_endpoint(ScimPlugin::users_endpoint().with_query(&input["query"]).unwrap(),EndpointOptions{headers,..Default::default()}).await{Ok(output)=>output.into_response().unwrap().into_response(),Err(error)=>{let mut response=alibi::endpoint::EndpointResponse::error(error.error);if let Some(body)=error.body{response=response.with_error_body(*body);}if let Some(headers)=error.headers{response.merge_headers(headers);}response.to_response().unwrap().into_response()}};
                }
                if query.get("operation").is_some_and(|operation|operation=="seed-user-list") {
                    use base64::Engine;use sha2::Digest;
                    let output=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("email-password","signUpEmail").with_body(&json!({"email":"user-list-owner@example.com","password":"a-native-password-123","name":"User owner"})).unwrap(),EndpointOptions::default()).await.unwrap().into_response().unwrap();let owner:Value=serde_json::from_slice(&output.body).unwrap();let uid=owner["user"]["id"].as_str().unwrap();
                    let key=|parts:&[&str]|base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(serde_json::to_vec(parts).unwrap()));
                    for(id,cid,name,order)in[("carol","conn-a","Carol","3"),("alice","conn-a","Alice","1"),("bob","conn-a","Bob","2"),("foreign","conn-b","Foreign","0")]{
                        let work=format!("work-{id}@example.com");let home=format!("home-{id}@example.com");let external=format!("external-{id}");let work_key=key(&["scim-email-value",&work]);let mut tokens=[work_key.clone(),key(&["scim-email-value",&home])];tokens.sort();let all=format!("|{}|",tokens.join("|"));let work_index=format!("|{work_key}|");let emails=json!([{"value":work,"type":"work","primary":true},{"value":home,"type":"home","primary":false}]).to_string();
                        _=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"INSERT INTO scimUser (id,connectionId,provisioningDomainId,userId,connectionUserKey,userName,userNameKey,primaryEmail,workEmailValueIndex,emailValueIndex,displayName,formattedName,serializedEmails,externalId,externalIdKey,active,orderKey,createdAt,updatedAt) VALUES (?,?,'tenant-a',?,?,?,?,?,?,?,?,?,?,?,?,true,?,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",[id.into(),cid.into(),uid.into(),id.into(),name.into(),key(&["scim-user-name",cid,&name.to_lowercase()]).into(),work.into(),work_index.into(),all.into(),name.into(),name.into(),emails.into(),external.clone().into(),key(&["scim-user-external-id",cid,&external]).into(),order.into()])).await.unwrap();
                    }return Json(json!({"seeded":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="corrupt-user-list") {_=database.execute_unprepared("UPDATE scimUser SET serializedAttributes='not-json' WHERE id='carol'").await.unwrap();return Json(json!({"corrupt":true})).into_response();}
                if query.get("operation").is_some_and(|operation|operation=="drift-user-list") {_=database.execute_unprepared("UPDATE scimUser SET provisioningDomainId='drifted' WHERE id='carol'").await.unwrap();return Json(json!({"changed":true})).into_response();}
                if query.get("operation").is_some_and(|operation|operation=="listSCIMGroups") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();let headers=input["token"].as_str().map(|token|[("authorization".into(),format!("Bearer {token}"))].into_iter().collect());
                    return match auth.dispatch_endpoint(ScimPlugin::groups_endpoint().with_query(&input["query"]).unwrap(),EndpointOptions{headers,..Default::default()}).await{Ok(output)=>output.into_response().unwrap().into_response(),Err(error)=>{let mut response=alibi::endpoint::EndpointResponse::error(error.error);if let Some(body)=error.body{response=response.with_error_body(*body);}if let Some(headers)=error.headers{response.merge_headers(headers);}response.to_response().unwrap().into_response()}};
                }
                if query.get("operation").is_some_and(|operation|operation=="seed-group-list") {
                    use base64::Engine;
                    use sha2::Digest;
                    for(id,cid,name,external,order)in[("group-c","conn-a","Third","EXTERNAL-C","3"),("group-a","conn-a","Staff and Crew","EXTERNAL-A","1"),("group-b","conn-a","Second","EXTERNAL-B","2"),("foreign","conn-b","Foreign","EXTERNAL-F","0")]{
                        let key=|parts:&[&str]|base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(serde_json::to_vec(parts).unwrap()));
                        _=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"INSERT INTO scimGroup (id,connectionId,provisioningDomainId,revision,displayName,displayNameKey,externalId,externalIdKey,orderKey,createdAt,updatedAt) VALUES (?,?,'tenant-a',0,?,?,?,?,?,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",[id.into(),cid.into(),name.into(),key(&["scim-group-display-name",cid,&name.to_lowercase()]).into(),external.into(),key(&["scim-group-external-id",cid,external]).into(),order.into()])).await.unwrap();
                    }
                    return Json(json!({"seeded":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="grow-group-list") {
                    use base64::Engine;use sha2::Digest;
                    for index in 0..101 {let id=format!("extra-{index:03}");let name=format!("Extra {index}");let order=format!("z{index:03}");let key=base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(serde_json::to_vec(&["scim-group-display-name","conn-a",&name.to_lowercase()]).unwrap()));
                        _=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"INSERT INTO scimGroup (id,connectionId,provisioningDomainId,revision,displayName,displayNameKey,orderKey,createdAt,updatedAt) VALUES (?,'conn-a','tenant-a',0,?,?,?,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",[id.into(),name.into(),key.into(),order.into()])).await.unwrap();
                    }return Json(json!({"grown":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="drift-group-list") {_=database.execute_unprepared("UPDATE scimGroup SET provisioningDomainId='drifted' WHERE id='group-c'").await.unwrap();return Json(json!({"changed":true})).into_response();}
                if query.get("operation").is_some_and(|operation|operation=="user-read-attributes") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();let serialized=if input["restore"]==true{user_read_attributes.lock().unwrap().clone()}else{input["serializedAttributes"].as_str().unwrap().to_owned()};
                    _=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"UPDATE scimUser SET serializedAttributes=? WHERE id='rich'",[serialized.into()])).await.unwrap();return Json(json!({"changed":true})).into_response();
                }
                if query.get("operation").is_some_and(|operation|operation=="getSCIMUser") {
                    let input:Value=serde_json::from_slice(&bytes).unwrap();let endpoint=ScimPlugin::user_endpoint(input["params"]["userId"].as_str().unwrap()).unwrap().with_query(&input["query"]).unwrap();
                    let headers=input["token"].as_str().map(|token|[("authorization".into(),format!("Bearer {token}"))].into_iter().collect());
                    return match auth.dispatch_endpoint(endpoint,EndpointOptions{headers,..Default::default()}).await{Ok(output)=>output.into_response().unwrap().into_response(),Err(error)=>{let mut response=alibi::endpoint::EndpointResponse::error(error.error);if let Some(body)=error.body{response=response.with_error_body(*body);}if let Some(headers)=error.headers{response.merge_headers(headers);}response.to_response().unwrap().into_response()}};
                }
                if query.get("operation").is_some_and(|operation|operation=="seed-user-read") {
                    let output=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("email-password","signUpEmail").with_body(&json!({"email":"user-read-owner@example.com","password":"a-native-password-123","name":"User owner"})).unwrap(),EndpointOptions::default()).await.unwrap().into_response().unwrap();let owner:Value=serde_json::from_slice(&output.body).unwrap();let uid=owner["user"]["id"].as_str().unwrap();
                    let attributes=json!({"schemas":["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User","urn:ietf:params:scim:schemas:core:2.0:User"],"name":{"formatted":" Alice Example ","givenName":" Alice ","ignored":"drop"},"emails":[{"value":"Alice@example.com","primary":true,"type":"WORK","ignored":"drop"}],"title":" Principal ","phoneNumbers":[{"value":" +1 555 ","type":"WORK","primary":true}],"addresses":[{"streetAddress":" 1 Road ","type":"WORK","primary":true}],"roles":[{"value":" admin ","display":" Admin ","type":"CUSTOM","primary":true}],"enterprise":{"employeeNumber":[" 42 "],"organization":" Example ","manager":{"value":" manager ","displayName":"drop"}},"userName":"spoof","active":true});
                    for(id,cid,domain)in[("rich","conn-a","tenant-a"),("legacy","conn-a","tenant-a"),("corrupt","conn-a","tenant-a"),("foreign","conn-b","tenant-a"),("drift","conn-a","tenant-b")]{
                        _=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"INSERT INTO scimUser (id,connectionId,provisioningDomainId,userId,connectionUserKey,userName,userNameKey,primaryEmail,workEmailValueIndex,emailValueIndex,displayName,formattedName,givenName,serializedEmails,active,orderKey,createdAt,updatedAt) VALUES (?,?,?,?,?,'alice',?,'Alice@example.com','[]','[]','Alice from row',' Legacy Name ',' Legacy ',?,false,?,'2026-01-02T03:04:05.000Z','2026-01-02T03:04:05.000Z')",[id.into(),cid.into(),domain.into(),uid.into(),id.into(),id.into(),json!([{"value":"legacy@example.com","primary":true}]).to_string().into(),id.into()])).await.unwrap();
                    }
                    *user_read_attributes.lock().unwrap()=attributes.to_string();
                    _=database.execute_raw(Statement::from_sql_and_values(database.get_database_backend(),"UPDATE scimUser SET serializedAttributes=?,externalId='external-alice' WHERE id='rich'",[attributes.to_string().into()])).await.unwrap();_=database.execute_unprepared("UPDATE scimUser SET serializedAttributes='not-json' WHERE id='corrupt'").await.unwrap();return Json(json!({"seeded":true})).into_response();
                }
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

struct CreateIdentity;
#[async_trait::async_trait]
impl<S:alibi::AuthSchema> alibi::plugins::scim::ScimIdentity<S> for CreateIdentity {
 async fn resolve_user(&self,input:&alibi::plugins::scim::ScimIdentityResolutionInput,database:&dyn alibi::store::AuthStore<S>)->alibi::AuthResult<alibi::plugins::scim::ScimIdentityResolution>{
  use alibi::{AuthUser,AuthError};use alibi::plugins::scim::ScimIdentityResolution as Resolution;
  let external=input.resource["externalId"].as_str().unwrap_or("");
  if external=="resolve-fails"{return Err(AuthError::internal("application rejected resolution"));}
  if external=="link-missing"{return Ok(Resolution::Link{user_id:"missing-user".into(),manage_profile:false});}
  if !matches!(input.resource["userName"].as_str(),Some("Alias"|"Alias2")) || input.resource["primaryEmail"]!="alias@example.com"{return Err(AuthError::internal("incorrect resolver resource"));}
  let user=database.get_user_by_email("new-work@example.com").await?.ok_or_else(||AuthError::internal("resolver target missing"))?;
  Ok(Resolution::Link{user_id:user.id().to_string(),manage_profile:external=="link-manage"})
 }
 async fn reconcile_user(&self,_input:&alibi::plugins::scim::ScimIdentityState,_database:&dyn alibi::store::AuthTransaction<S>)->alibi::AuthResult<()>{Ok(())}
}

fn trusted_user_body(input: &Value) -> alibi::utils::json::JsValue {
    use alibi::utils::json::JsValue;
    let mut body = JsValue::from(input["body"].clone());
    if let Some(path) = input["datePath"].as_array() {
        let mut target = &mut body;
        for key in path {
            let key = key.as_str().unwrap();
            target = match target {
                JsValue::Object(values) => values.get_mut(key).unwrap(),
                JsValue::Array(values) => &mut values[key.parse::<usize>().unwrap()],
                _ => panic!("trusted fixture date path"),
            };
        }
        let date = chrono::DateTime::parse_from_rfc3339(target.as_str().unwrap()).unwrap().to_utc();
        *target = JsValue::Date(date);
    }
    if let Some(path) = input["numberPath"].as_array() {
        let mut target = &mut body;
        for key in path {
            let key = key.as_str().unwrap();
            target = match target {
                JsValue::Object(values) => values.get_mut(key).unwrap(),
                JsValue::Array(values) => &mut values[key.parse::<usize>().unwrap()],
                _ => panic!("trusted fixture number path"),
            };
        }
        *target = JsValue::Number(match input["numberKind"].as_str().unwrap() {
            "NaN" => f64::NAN,
            "-Infinity" => f64::NEG_INFINITY,
            _ => f64::INFINITY,
        });
    }
    body
}
