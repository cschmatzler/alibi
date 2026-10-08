//! Application-owned server-only admission and genuine callback/storage observations.
use crate::{TestSchema, organization_update_hooks_fixture::snapshot as base_snapshot};
use alibi::plugins::organization::{
    OrganizationConfig, OrganizationMemberAddedContext, OrganizationMemberAdditionContext,
    OrganizationMemberAdditionHooks, OrganizationMemberCreatePatch, TeamsConfig,
    extensions::{OrganizationLimitResolver, TeamLimitContext},
    types::AddOrganizationMemberRequest,
};
use alibi::{
    AuthBuilder, AuthConfig, AuthError, AuthResult, BetterAuth,
    integrations::axum::AxumIntegration,
    middleware::RateLimitConfig,
    plugins::{EmailPasswordPlugin, OrganizationPlugin, SessionManagementPlugin},
};
use alibi_core::{
    CreateMember, CreateUser, UpdateUser,
    store::{MemberStore, OrganizationStore, UserStore},
};
use alibi_seaorm::{
    DatabaseConnection,
    sea_orm::{ConnectionTrait, DbBackend, Statement},
};
use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::Query,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, Notify};
async fn snapshot(database: &DatabaseConnection) -> AuthResult<Value> {
    let mut value = base_snapshot(database).await?;
    for (name, sql, columns) in [
        (
            "members",
            "SELECT m.id,m.organization_id AS organizationId,m.user_id AS userId,m.role FROM member m JOIN organization o ON o.id=m.organization_id JOIN users u ON u.id=m.user_id ORDER BY o.slug,u.email,m.created_at,m.rowid",
            &["id", "organizationId", "userId", "role"][..],
        ),
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
async fn full_snapshot(database: &DatabaseConnection) -> AuthResult<Value> {
    let mut result = serde_json::Map::new();
    let queries = [
        (
            "members",
            "SELECT id,organization_id AS organizationId,user_id AS userId,role,created_at AS createdAt FROM member ORDER BY rowid",
            &["id", "organizationId", "userId", "role", "createdAt"][..],
        ),
        (
            "teams",
            "SELECT id,name,organization_id AS organizationId,member_count AS memberCount,created_at AS createdAt,updated_at AS updatedAt FROM team ORDER BY rowid",
            &[
                "id",
                "name",
                "organizationId",
                "memberCount",
                "createdAt",
                "updatedAt",
            ][..],
        ),
        (
            "teamMembers",
            "SELECT id,team_id AS teamId,user_id AS userId,membership_key AS membershipKey,created_at AS createdAt FROM team_member ORDER BY rowid",
            &["id", "teamId", "userId", "membershipKey", "createdAt"][..],
        ),
    ];
    for (name, sql, columns) in queries {
        let rows = database
            .query_all_raw(Statement::from_string(DbBackend::Sqlite, sql))
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let mut values = Vec::new();
        for row in rows {
            let mut object = serde_json::Map::new();
            for column in columns {
                let value = match *column {
                    "memberCount" => json!(
                        row.try_get::<i64>("", column)
                            .map_err(|error| AuthError::internal(error.to_string()))?
                    ),
                    "createdAt" | "updatedAt" => json!(
                        row.try_get::<Option<chrono::DateTime<chrono::Utc>>>("", column)
                            .map_err(|error| AuthError::internal(error.to_string()))?
                            .map(|date| date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
                    ),
                    _ => json!(
                        row.try_get::<Option<String>>("", column)
                            .map_err(|error| AuthError::internal(error.to_string()))?
                    ),
                };
                let _ = object.insert((*column).to_owned(), value);
            }
            values.push(Value::Object(object));
        }
        let _ = result.insert(name.to_owned(), Value::Array(values));
    }
    Ok(Value::Object(result))
}
struct Application {
    database: DatabaseConnection,
    store: Arc<crate::backend::Store<TestSchema>>,
    mode: Mutex<String>,
    patch: Mutex<OrganizationMemberCreatePatch>,
    receipts: Mutex<Vec<Value>>,
    gate: Mutex<Arc<Notify>>,
    pair_gates: Mutex<Vec<Arc<Notify>>>,
}
impl std::fmt::Debug for Application {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemberAdmissionApplication")
            .finish_non_exhaustive()
    }
}
impl Application {
    async fn note(
        &self,
        phase: &str,
        member: Value,
        user: Value,
        organization: Value,
    ) -> AuthResult<()> {
        self.receipts.lock().await.push(json!({"phase":phase,"member":member,"user":user,"organization":organization,"snapshot":snapshot(&self.database).await?}));
        let mode = self.mode.lock().await.clone();
        if mode == format!("reject-{phase}") {
            return Err(AuthError::Api {
                status: 400,
                code: Some("ADDITION_HOOK_REJECTED".into()),
                message: format!("Rejected {phase}"),
            });
        }
        if mode == format!("public500-{phase}") {
            return Err(AuthError::Api {
                status: 500,
                code: Some("PUBLIC_ADDITION_500".into()),
                message: format!("Explicit public {phase} error"),
            });
        }
        Ok(())
    }
    async fn configure(&self, body: &Value) -> AuthResult<()> {
        let mode = body["mode"].as_str().unwrap_or("record");
        self.gate.lock().await.notify_one();
        *self.gate.lock().await = Arc::new(Notify::new());
        for gate in self.pair_gates.lock().await.drain(..) {
            gate.notify_one();
        }
        *self.mode.lock().await = mode.into();
        self.receipts.lock().await.clear();
        *self.patch.lock().await = OrganizationMemberCreatePatch {
            organization_id: body["organizationId"].as_str().map(str::to_owned),
            user_id: body["patchUserId"].as_str().map(str::to_owned),
            role: body["patchRole"].as_str().map(str::to_owned),
        };
        for sql in [
            "DROP TRIGGER IF EXISTS addition_guard_member",
            "DROP TRIGGER IF EXISTS addition_guard_team",
            "DROP TRIGGER IF EXISTS addition_guard_cleanup",
            "DROP TRIGGER IF EXISTS addition_guard_user",
            "CREATE TABLE IF NOT EXISTS __test_addition_guard(userId TEXT,organizationId TEXT,teamId TEXT)",
            "DELETE FROM __test_addition_guard",
        ] {
            let _ = self
                .database
                .execute_unprepared(sql)
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
        }
        if mode.starts_with("sql-") {
            let user_id = body["userId"].as_str().unwrap_or_default();
            let org_id = body["organizationId"].as_str().unwrap_or_default();
            if self.store.get_user_by_id(user_id).await?.is_none()
                || self.store.get_organization_by_id(org_id).await?.is_none()
            {
                return Err(AuthError::bad_request(
                    "Guard requires actual target user and organization",
                ));
            }
            let _ = self
                .database
                .execute_raw(Statement::from_sql_and_values(
                    DbBackend::Sqlite,
                    "INSERT INTO __test_addition_guard(userId,organizationId,teamId) VALUES(?,?,?)",
                    [
                        user_id.into(),
                        org_id.into(),
                        body["teamId"].as_str().map(str::to_owned).into(),
                    ],
                ))
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
            let sql = match mode {
                "sql-member-abort" => Some(
                    "CREATE TRIGGER addition_guard_member BEFORE INSERT ON member WHEN NEW.user_id=(SELECT userId FROM __test_addition_guard) BEGIN SELECT RAISE(ABORT,'actual admission member veto'); END",
                ),
                "sql-team-abort" => Some(
                    "CREATE TRIGGER addition_guard_team BEFORE INSERT ON team_member WHEN NEW.user_id=(SELECT userId FROM __test_addition_guard) BEGIN SELECT RAISE(ABORT,'actual admission team veto'); END",
                ),
                "sql-cleanup-abort" => Some(
                    "CREATE TRIGGER addition_guard_cleanup BEFORE DELETE ON member WHEN OLD.user_id=(SELECT userId FROM __test_addition_guard) BEGIN SELECT RAISE(ABORT,'actual admission cleanup veto'); END",
                ),
                "sql-before-error" | "sql-after-error" => Some(
                    "CREATE TRIGGER addition_guard_user BEFORE UPDATE ON users WHEN OLD.id=(SELECT userId FROM __test_addition_guard) BEGIN SELECT RAISE(ABORT,'actual admission callback veto'); END",
                ),
                _ => None,
            };
            if let Some(sql) = sql {
                let _ = self
                    .database
                    .execute_unprepared(sql)
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
            }
        }
        Ok(())
    }
}
#[async_trait]
impl OrganizationMemberAdditionHooks for Application {
    async fn before_add_member(
        &self,
        context: &OrganizationMemberAdditionContext,
    ) -> AuthResult<Option<OrganizationMemberCreatePatch>> {
        let mode = self.mode.lock().await.clone();
        if mode == "off" {
            return Ok(None);
        }
        let mut member = json!({"userId":context.member.user_id,"organizationId":context.member.organization_id,"role":context.member.role});
        if let Some(team) = &context.member.team_id {
            member["teamId"] = json!(team);
        }
        self.note(
            "before-add",
            member,
            serde_json::to_value(&context.user)?,
            serde_json::to_value(&context.organization)?,
        )
        .await?;
        if mode == "pause-before" {
            let gate = self.gate.lock().await.clone();
            gate.notified().await;
        }
        if mode == "pause-before-pair" {
            let gate = Arc::new(Notify::new());
            self.pair_gates.lock().await.push(gate.clone());
            gate.notified().await;
        }
        if mode == "mutate-target" || mode == "sql-before-error" {
            let _ = self
                .store
                .update_user(
                    &context.user.id,
                    UpdateUser {
                        name: Some(
                            if mode == "mutate-target" {
                                "Stored Addition Target"
                            } else {
                                "Attempted Before Name"
                            }
                            .into(),
                        ),
                        ..Default::default()
                    },
                )
                .await?;
        }
        Ok(match mode.as_str() {
            "patch-role" => Some(OrganizationMemberCreatePatch {
                role: Some("hook-unregistered-role".into()),
                ..Default::default()
            }),
            "patch-empty" => Some(OrganizationMemberCreatePatch {
                role: Some(String::new()),
                ..Default::default()
            }),
            "patch-target" | "patch-target-reject-team-limit" => {
                Some(self.patch.lock().await.clone())
            }
            _ => None,
        })
    }
    async fn after_add_member(&self, context: &OrganizationMemberAddedContext) -> AuthResult<()> {
        let mode = self.mode.lock().await.clone();
        if mode == "off" {
            return Ok(());
        }
        self.note(
            "after-add",
            serde_json::to_value(&context.member)?,
            serde_json::to_value(&context.user)?,
            serde_json::to_value(&context.organization)?,
        )
        .await?;
        if mode == "sql-after-error" {
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
#[async_trait]
impl OrganizationLimitResolver for Application {
    async fn maximum_team_members(&self, context: &TeamLimitContext) -> AuthResult<Option<f64>> {
        self.receipts.lock().await.push(json!({"phase":"team-limit","context":{"teamId":context.team_id,"organizationId":context.organization_id,"session":{"user":context.user,"session":context.session}},"snapshot":snapshot(&self.database).await?}));
        if matches!(
            self.mode.lock().await.as_str(),
            "reject-team-limit" | "patch-target-reject-team-limit"
        ) {
            return Err(AuthError::Api {
                status: 403,
                code: Some("TEAM_LIMIT_POLICY_REJECTED".into()),
                message: "Actual team-limit rejection".into(),
            });
        }
        Ok(Some(1.0))
    }
}
fn failure(error: AuthError) -> Response {
    let status =
        StatusCode::from_u16(error.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if matches!(error, AuthError::Unauthenticated | AuthError::Database(_)) {
        return status.into_response();
    }
    let (_, code, message) = error.error_payload();
    (
        status,
        Json(match code {
            Some(code) => json!({"code":code,"message":message}),
            None => json!({"message":message}),
        }),
    )
        .into_response()
}
pub(crate) async fn router(
    base: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<Router<Arc<BetterAuth<TestSchema>>>> {
    let application = Arc::new(Application {
        database: database.clone(),
        store: Arc::new(crate::backend::store(base.clone(), database)),
        mode: Mutex::new("off".into()),
        patch: Mutex::new(OrganizationMemberCreatePatch::default()),
        receipts: Mutex::new(Vec::new()),
        gate: Mutex::new(Arc::new(Notify::new())),
        pair_gates: Mutex::new(Vec::new()),
    });
    let mut router = Router::new();
    let mut profiles = HashMap::new();
    for name in [
        "org-member-addition",
        "org-member-addition-no-team",
        "org-member-addition-limit-one",
        "org-member-addition-zero",
        "org-member-addition-none",
        "org-member-addition-team-limit",
        "org-member-addition-team-callback",
        "org-member-addition-team-page-one",
        "org-member-addition-team-page-zero",
        "org-member-multiplicity",
        "org-member-multiplicity-page-zero",
        "org-member-multiplicity-page-one",
        "org-member-multiplicity-page-two",
    ] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut config = base.clone().base_path(&path);
        if name.contains("team-page") || name.contains("multiplicity-page") {
            config.advanced.database.default_find_many_limit = if name.ends_with("zero") {
                0
            } else if name.ends_with("two") {
                2
            } else {
                1
            };
        }
        let organization = OrganizationConfig {
            member_addition_hooks: Some(application.clone()),
            organization_limit: name.starts_with("org-member-multiplicity").then_some(3.0),
            membership_limit: match name {
                "org-member-addition-limit-one" => {
                    Some(alibi::plugins::organization::MembershipLimit::Fixed(1.0))
                }
                "org-member-addition-zero" => {
                    Some(alibi::plugins::organization::MembershipLimit::Fixed(0.0))
                }
                "org-member-addition-none" => None,
                _ => Some(alibi::plugins::organization::MembershipLimit::Fixed(100.0)),
            },
            teams: TeamsConfig {
                enabled: name != "org-member-addition-no-team",
                create_default_team: false,
                maximum_members_per_team: (name == "org-member-addition-team-limit").then_some(0.0),
                limit_resolver: (name.contains("team-callback") || name.contains("team-page"))
                    .then(|| application.clone() as Arc<dyn OrganizationLimitResolver>),
                ..Default::default()
            },
            ..Default::default()
        };
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(config.clone())
                .store(crate::backend::store::<TestSchema>(
                    config,
                    application.database.clone(),
                ))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(SessionManagementPlugin::new())
                .plugin(OrganizationPlugin::with_config(organization.clone()))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth.clone()));
        let _ = profiles.insert(name.to_owned(), (auth, organization));
    }
    let profiles = Arc::new(profiles);
    let configure = application.clone();
    let release = application.clone();
    let state = application.clone();
    let seed = application.clone();
    Ok(router.route("/__test/organization-member-addition/configure",post(move|Json(body):Json<Value>|{let application=configure.clone();async move{application.configure(&body).await?;Ok::<_,AuthError>(Json(json!({"configured":true})))}}))
 .route("/__test/organization-member-addition/release",post(move||{let application=release.clone();async move{if application.mode.lock().await.as_str()=="pause-before-pair" {let mut gates=application.pair_gates.lock().await;if !gates.is_empty(){gates.remove(0).notify_one();}}else{application.gate.lock().await.notify_one();}Json(json!({"released":true}))}}))
 .route("/__test/organization-member-addition/state",get(move|Query(query):Query<HashMap<String,String>>|{let application=state.clone();async move{for _ in 0..100{let ready=match query.get("waitFor").map(String::as_str){None|Some("full")=>true,Some("before-pair")=>application.pair_gates.lock().await.len()==2,Some(phase)=>application.receipts.try_lock().ok().is_some_and(|rows|rows.iter().any(|row|row["phase"].as_str()==Some(phase)))};if ready{break;}tokio::time::sleep(std::time::Duration::from_millis(10)).await;}let mut value=json!({"receipts":application.receipts.lock().await.clone(),"snapshot":snapshot(&application.database).await?});if query.get("waitFor").is_some_and(|phase|phase=="full"){value["full"]=full_snapshot(&application.database).await?;}Ok::<_,AuthError>(Json(value))}}))
 .route("/__test/organization-member-addition/server",post(move|headers:HeaderMap,Json(input):Json<Value>|{let profiles=profiles.clone();async move{let name=input["profile"].as_str().unwrap_or("org-member-addition");let Some((auth,config))=profiles.get(name)else{return StatusCode::NOT_FOUND.into_response();};let body=match serde_json::from_value::<AddOrganizationMemberRequest>(input["body"].clone()){Ok(body)=>body,Err(error)=>return failure(AuthError::bad_request(error.to_string()))};let headers=if input["useHeaders"].as_bool()==Some(true){headers.iter().filter_map(|(key,value)|value.to_str().ok().map(|value|(key.to_string(),value.to_owned()))).collect()}else{HashMap::new()};match OrganizationPlugin::with_config(config.clone()).add_member_with_headers(auth.context(),&headers,&body).await{Ok(value)=>Json(value).into_response(),Err(error)=>failure(error)}}}))
 .route("/__test/organization-member-addition/seed",post(move|Json(input):Json<Value>|{let application=seed.clone();async move{let organization_id=input["organizationId"].as_str().unwrap_or_default();let user_id=input["userId"].as_str().unwrap_or_default();if application.store.get_organization_by_id(organization_id).await?.is_none()||application.store.get_user_by_id(user_id).await?.is_none(){return Err(AuthError::bad_request("Actual seed owners required"));}match input["action"].as_str(){Some("padding")=>{for n in 0..input["count"].as_u64().unwrap_or(0){let user=application.store.create_user(CreateUser::new().with_email(format!("admission-padding-{n}@example.test")).with_name(format!("Admission padding {n}")).with_email_verified(false)).await?;let _=application.store.create_member(CreateMember::new(organization_id,&user.id,"member")).await?;}},Some("detach")=>{for member in application.store.list_organization_members(organization_id).await?{if member.user_id==user_id{application.store.delete_member_with_context(&member.id,organization_id,user_id,false).await?;}}},_=>return Err(AuthError::bad_request("Unknown actual setup action"))}Ok::<_,AuthError>(Json(json!({"seeded":true})))}})))
}
