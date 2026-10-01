//! Real removal callbacks, SQLite observations and signed-cookie server calls.
use crate::{organization_update_hooks_fixture::snapshot as base_snapshot, TestSchema};
use axum::{
    extract::Query,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use better_auth::{
    integrations::axum::AxumIntegration,
    middleware::RateLimitConfig,
    plugins::organization::{
        types::RemoveMemberRequest, OrganizationConfig, OrganizationMemberRemovalContext,
        OrganizationMemberRemovalHooks, TeamsConfig,
    },
    plugins::{EmailPasswordPlugin, OrganizationPlugin, SessionManagementPlugin},
    AuthBuilder, AuthConfig, AuthError, AuthResult, BetterAuth,
};
use better_auth_core::{
    store::{MemberStore, UserStore},
    UpdateUser,
};
use better_auth_seaorm::{
    sea_orm::{ConnectionTrait, DbBackend, Statement},
    DatabaseConnection, SeaOrmStore,
};
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, Notify};
async fn snapshot(database: &DatabaseConnection) -> AuthResult<Value> {
    let mut value = base_snapshot(database).await?;
    for (name,sql,columns) in [
 ("teams","SELECT id,organization_id AS organizationId,name,member_count AS memberCount FROM team ORDER BY name,id",&["id","organizationId","name","memberCount"][..]),
 ("teamMembers","SELECT m.id,m.team_id AS teamId,m.user_id AS userId FROM team_member m JOIN team t ON t.id=m.team_id JOIN users u ON u.id=m.user_id ORDER BY t.name,u.email,m.id",&["id","teamId","userId"][..])]{
  let rows=database.query_all_raw(Statement::from_string(DbBackend::Sqlite,sql)).await.map_err(|error|AuthError::internal(error.to_string()))?;
  let mut values=Vec::new();for row in rows{let mut object=serde_json::Map::new();for column in columns{let field=if *column=="memberCount"{json!(row.try_get::<i64>("",column).map_err(|error|AuthError::internal(error.to_string()))?)}else{json!(row.try_get::<Option<String>>("",column).map_err(|error|AuthError::internal(error.to_string()))?)};let _=object.insert((*column).into(),field);}values.push(Value::Object(object));}value[name]=Value::Array(values);
 }
    Ok(value)
}
struct Hooks {
    database: DatabaseConnection,
    store: Arc<SeaOrmStore<TestSchema>>,
    mode: Mutex<String>,
    receipts: Mutex<Vec<Value>>,
    gate: Mutex<Arc<Notify>>,
}
impl std::fmt::Debug for Hooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hooks").finish_non_exhaustive()
    }
}
impl Hooks {
    async fn note(
        &self,
        phase: &str,
        context: &OrganizationMemberRemovalContext,
    ) -> AuthResult<()> {
        tokio::task::yield_now().await;
        self.receipts.lock().await.push(json!({"phase":phase,"member":context.member,"user":context.user,"organization":context.organization,"snapshot":snapshot(&self.database).await?}));
        if *self.mode.lock().await == format!("reject-{phase}") {
            return Err(AuthError::Api {
                status: 400,
                code: Some("MEMBER_REMOVAL_HOOK_REJECTED".into()),
                message: format!("Rejected {phase}"),
            });
        }
        Ok(())
    }
}
#[async_trait::async_trait]
impl OrganizationMemberRemovalHooks for Hooks {
    async fn before_remove(&self, context: &OrganizationMemberRemovalContext) -> AuthResult<()> {
        self.note("before-remove", context).await?;
        let mode = self.mode.lock().await.clone();
        if mode == "pause-before" {
            let gate = self.gate.lock().await.clone();
            gate.notified().await;
        }
        if mode == "delete-row" {
            self.store
                .delete_member_with_context(
                    &context.member.member.id,
                    &context.member.member.organization_id,
                    &context.member.member.user_id,
                    false,
                )
                .await?;
        }
        if mode == "mutate-target" {
            let _ = self
                .store
                .update_user(
                    &context.user.id,
                    UpdateUser {
                        name: Some("Stored Removal Target".into()),
                        ..Default::default()
                    },
                )
                .await?;
            let _ = self
                .store
                .update_member_role(&context.member.member.id, "stored-independent-role")
                .await?;
        }
        Ok(())
    }
    async fn after_remove(&self, context: &OrganizationMemberRemovalContext) -> AuthResult<()> {
        self.note("after-remove", context).await
    }
}
pub(super) async fn router(
    base: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<Router<Arc<BetterAuth<TestSchema>>>> {
    let hooks = Arc::new(Hooks {
        database: database.clone(),
        store: Arc::new(SeaOrmStore::new(base.clone(), database)),
        mode: Mutex::new("record".into()),
        receipts: Mutex::new(Vec::new()),
        gate: Mutex::new(Arc::new(Notify::new())),
    });
    let mut router = Router::new();
    let mut default_auth = None;
    let mut default_plugin = None;
    for name in [
        "org-member-removal-hooks",
        "org-member-removal-hooks-teams-disabled",
        "org-member-removal-hooks-page-one",
        "org-member-removal-hooks-team-page-one",
    ] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut config = base.clone().base_path(&path);
        if name.ends_with("team-page-one") {
            config.advanced.database.default_find_many_limit = 1;
        }
        let organization_config = OrganizationConfig {
            member_removal_hooks: Some(hooks.clone()),
            membership_limit: Some(if name == "org-member-removal-hooks-page-one" {
                1
            } else {
                100
            }),
            teams: TeamsConfig {
                enabled: !name.ends_with("teams-disabled"),
                create_default_team: false,
                ..Default::default()
            },
            ..Default::default()
        };
        let plugin = OrganizationPlugin::with_config(organization_config.clone());
        if name == "org-member-removal-hooks" {
            default_plugin = Some(organization_config);
        }
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(SeaOrmStore::<TestSchema>::new(
                    config,
                    hooks.database.clone(),
                ))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(SessionManagementPlugin::new())
                .plugin(plugin)
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth.clone()));
        if name == "org-member-removal-hooks" {
            default_auth = Some(auth);
        }
    }
    let auth =
        default_auth.ok_or_else(|| AuthError::internal("Removal default fixture missing"))?;
    let plugin =
        default_plugin.ok_or_else(|| AuthError::internal("Removal plugin fixture missing"))?;
    let configure = hooks.clone();
    let release = hooks.clone();
    let state = hooks.clone();
    Ok(router.route("/__test/organization-member-removal-hooks-configure",post(move|Json(body):Json<Value>|{let hooks=configure.clone();async move{hooks.gate.lock().await.notify_one();*hooks.mode.lock().await=body["mode"].as_str().unwrap_or("record").to_owned();hooks.receipts.lock().await.clear();*hooks.gate.lock().await=Arc::new(Notify::new());Json(json!({"configured":true}))}}))
 .route("/__test/organization-member-removal-hooks-release",post(move||{let hooks=release.clone();async move{hooks.gate.lock().await.notify_one();Json(json!({"released":true}))}}))
 .route("/__test/organization-member-removal-hooks-state",get(move|Query(query):Query<HashMap<String,String>>|{let hooks=state.clone();async move{for _ in 0..100{let found=query.get("waitFor").is_none_or(|phase|hooks.receipts.try_lock().ok().is_some_and(|rows|rows.iter().any(|row|row["phase"].as_str()==Some(phase))));if found{break;}tokio::time::sleep(std::time::Duration::from_millis(10)).await;}Ok::<_,AuthError>(Json(json!({"receipts":hooks.receipts.lock().await.clone(),"snapshot":snapshot(&hooks.database).await?})))}}))
 .route("/__test/organization-member-removal-hooks-server",post(move|headers:HeaderMap,Json(body):Json<RemoveMemberRequest>|{let auth=auth.clone();let config=plugin.clone();async move{let headers=headers.iter().filter_map(|(name,value)|value.to_str().ok().map(|value|(name.to_string(),value.to_owned()))).collect();match OrganizationPlugin::with_config(config).remove_member_with_headers(auth.context(),&headers,&body).await{Ok(value)=>Json(value).into_response(),Err(error)=>{let status=StatusCode::from_u16(error.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);(status,Json({let (_,code,message)=error.error_payload();match code{Some(code)=>json!({"code":code,"message":message}),None=>json!({"message":message})}})).into_response()}}}})))
}
