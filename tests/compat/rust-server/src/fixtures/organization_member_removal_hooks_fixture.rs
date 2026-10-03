//! Real removal callbacks, SQLite observations and signed-cookie server calls.
use crate::{TestSchema, organization_update_hooks_fixture::snapshot as base_snapshot};
use axum::{
    Json, Router,
    extract::Query,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use better_auth::{
    AuthBuilder, AuthConfig, AuthError, AuthResult, BetterAuth,
    integrations::axum::AxumIntegration,
    middleware::RateLimitConfig,
    plugins::organization::{
        OrganizationConfig, OrganizationMemberRemovalContext, OrganizationMemberRemovalHooks,
        TeamsConfig, types::RemoveMemberRequest,
    },
    plugins::{EmailPasswordPlugin, OrganizationPlugin, SessionManagementPlugin},
};
use better_auth_core::{
    UpdateUser,
    store::{MemberStore, UserStore},
};
use better_auth_seaorm::{
    DatabaseConnection,
    sea_orm::{ConnectionTrait, DbBackend, Statement},
};
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, Notify};
async fn snapshot(database: &DatabaseConnection) -> AuthResult<Value> {
    let mut value = base_snapshot(database).await?;
    for (name, sql, columns) in [
        (
            "teams",
            "SELECT id,organization_id AS organizationId,name,member_count AS memberCount FROM team ORDER BY name,id",
            &["id", "organizationId", "name", "memberCount"][..],
        ),
        (
            "teamMembers",
            "SELECT m.id,m.team_id AS teamId,m.user_id AS userId FROM team_member m JOIN team t ON t.id=m.team_id JOIN users u ON u.id=m.user_id ORDER BY t.name,u.email,m.id",
            &["id", "teamId", "userId"][..],
        ),
    ] {
        let rows = database
            .query_all_raw(Statement::from_string(DbBackend::Sqlite, sql))
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let mut values = Vec::new();
        for row in rows {
            let mut object = serde_json::Map::new();
            for column in columns {
                let field = if *column == "memberCount" {
                    json!(
                        row.try_get::<i64>("", column)
                            .map_err(|error| AuthError::internal(error.to_string()))?
                    )
                } else {
                    json!(
                        row.try_get::<Option<String>>("", column)
                            .map_err(|error| AuthError::internal(error.to_string()))?
                    )
                };
                let _ = object.insert((*column).into(), field);
            }
            values.push(Value::Object(object));
        }
        value[name] = Value::Array(values);
    }
    Ok(value)
}
struct Hooks {
    database: DatabaseConnection,
    store: Arc<crate::backend::Store<TestSchema>>,
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
    async fn configure(&self, body: &Value) -> AuthResult<()> {
        let mode = body["mode"].as_str().unwrap_or("record");
        let target = if mode.starts_with("sql-") {
            let target = self
                .store
                .get_member_by_id(body["memberId"].as_str().unwrap_or_default())
                .await?
                .filter(|member| {
                    Some(member.user_id.as_str()) == body["userId"].as_str()
                        && Some(member.organization_id.as_str()) == body["organizationId"].as_str()
                })
                .ok_or_else(|| {
                    AuthError::bad_request("Guard must select an actual matching member")
                })?;
            Some(target)
        } else {
            None
        };
        for sql in [
            "DROP TRIGGER IF EXISTS member_removal_guard_member",
            "DROP TRIGGER IF EXISTS member_removal_guard_team",
            "DROP TRIGGER IF EXISTS member_removal_guard_user",
            "CREATE TABLE IF NOT EXISTS __test_member_removal_guard (memberId TEXT,userId TEXT,organizationId TEXT)",
            "DELETE FROM __test_member_removal_guard",
        ] {
            let _ = self
                .database
                .execute_unprepared(sql)
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
        }
        if let Some(target) = target {
            let _ = self.database.execute_raw(Statement::from_sql_and_values(DbBackend::Sqlite,"INSERT INTO __test_member_removal_guard (memberId,userId,organizationId) VALUES (?,?,?)",[target.id.into(),target.user_id.into(),target.organization_id.into()])).await.map_err(|error|AuthError::internal(error.to_string()))?;
        }
        let trigger = match mode {
            "sql-member-abort" => Some(
                "CREATE TRIGGER member_removal_guard_member BEFORE DELETE ON member WHEN OLD.id=(SELECT memberId FROM __test_member_removal_guard) BEGIN SELECT RAISE(ABORT,'member removal member veto'); END",
            ),
            "sql-member-ignore" => Some(
                "CREATE TRIGGER member_removal_guard_member BEFORE DELETE ON member WHEN OLD.id=(SELECT memberId FROM __test_member_removal_guard) BEGIN SELECT RAISE(IGNORE); END",
            ),
            "sql-team-abort" => Some(
                "CREATE TRIGGER member_removal_guard_team BEFORE DELETE ON team_member WHEN OLD.user_id=(SELECT userId FROM __test_member_removal_guard) AND OLD.team_id IN (SELECT id FROM team WHERE organization_id=(SELECT organizationId FROM __test_member_removal_guard)) BEGIN SELECT RAISE(ABORT,'member removal team veto'); END",
            ),
            "sql-before-error" | "sql-after-error" => Some(
                "CREATE TRIGGER member_removal_guard_user BEFORE UPDATE ON users WHEN OLD.id=(SELECT userId FROM __test_member_removal_guard) BEGIN SELECT RAISE(ABORT,'member removal user veto'); END",
            ),
            _ => None,
        };
        if let Some(trigger) = trigger {
            let _ = self
                .database
                .execute_unprepared(trigger)
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
        }
        self.gate.lock().await.notify_one();
        *self.mode.lock().await = mode.to_owned();
        self.receipts.lock().await.clear();
        *self.gate.lock().await = Arc::new(Notify::new());
        Ok(())
    }
    async fn note(
        &self,
        phase: &str,
        context: &OrganizationMemberRemovalContext,
    ) -> AuthResult<()> {
        tokio::task::yield_now().await;
        self.receipts.lock().await.push(json!({"phase":phase,"member":context.member,"user":context.user,"organization":context.organization,"snapshot":snapshot(&self.database).await?}));
        if *self.mode.lock().await == format!("public-500-{phase}") {
            return Err(AuthError::Api {
                status: 500,
                code: Some("PUBLIC_REMOVAL_500".into()),
                message: format!("Explicit public {phase} error"),
            });
        }
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
        if mode == "sql-before-error" {
            let _ = self
                .store
                .update_user(
                    &context.user.id,
                    UpdateUser {
                        name: Some("Attempted Before Name".into()),
                        ..Default::default()
                    },
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
        self.note("after-remove", context).await?;
        if *self.mode.lock().await == "sql-after-error" {
            let _ = self
                .store
                .update_user(
                    &context.user.id,
                    UpdateUser {
                        name: Some("Attempted After Name".into()),
                        ..Default::default()
                    },
                )
                .await?;
        }
        Ok(())
    }
}
pub(crate) async fn router(
    base: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<Router<Arc<BetterAuth<TestSchema>>>> {
    let hooks = Arc::new(Hooks {
        database: database.clone(),
        store: Arc::new(crate::backend::store(base.clone(), database)),
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
        "org-member-removal-no-hooks",
    ] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut config = base.clone().base_path(&path);
        if name.ends_with("team-page-one") {
            config.advanced.database.default_find_many_limit = 1;
        }
        let organization_config = OrganizationConfig {
            member_removal_hooks: if name == "org-member-removal-no-hooks" {
                None
            } else {
                Some(hooks.clone())
            },
            membership_limit: Some(better_auth::plugins::organization::MembershipLimit::Fixed(
                if name == "org-member-removal-hooks-page-one" {
                    1.0
                } else {
                    100.0
                },
            )),
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
                .store(crate::backend::store::<TestSchema>(
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
    Ok(router.route("/__test/organization-member-removal-hooks-configure",post(move|Json(body):Json<Value>|{let hooks=configure.clone();async move{hooks.configure(&body).await?;Ok::<_,AuthError>(Json(json!({"configured":true})))}}))
 .route("/__test/organization-member-removal-hooks-release",post(move||{let hooks=release.clone();async move{hooks.gate.lock().await.notify_one();Json(json!({"released":true}))}}))
 .route("/__test/organization-member-removal-hooks-state",get(move|Query(query):Query<HashMap<String,String>>|{let hooks=state.clone();async move{for _ in 0..100{let found=query.get("waitFor").is_none_or(|phase|hooks.receipts.try_lock().ok().is_some_and(|rows|rows.iter().any(|row|row["phase"].as_str()==Some(phase))));if found{break;}tokio::time::sleep(std::time::Duration::from_millis(10)).await;}Ok::<_,AuthError>(Json(json!({"receipts":hooks.receipts.lock().await.clone(),"snapshot":snapshot(&hooks.database).await?})))}}))
 .route("/__test/organization-member-removal-hooks-server",post(move|headers:HeaderMap,Json(body):Json<RemoveMemberRequest>|{let auth=auth.clone();let config=plugin.clone();async move{let headers=headers.iter().filter_map(|(name,value)|value.to_str().ok().map(|value|(name.to_string(),value.to_owned()))).collect();match OrganizationPlugin::with_config(config).remove_member_with_headers(auth.context(),&headers,&body).await{Ok(value)=>Json(value).into_response(),Err(error)=>{let status=StatusCode::from_u16(error.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);(status,Json({let (_,code,message)=error.error_payload();match code{Some(code)=>json!({"code":code,"message":message}),None=>json!({"message":message})}})).into_response()}}}})))
}
