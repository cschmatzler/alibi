//! Genuine application callbacks, barriers, and actual SQLite failure controls.
use crate::TestSchema;
use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::Query,
    http::StatusCode,
    routing::{get, post},
};
use better_auth::plugins::organization::{
    MembershipLimit, OrganizationConfig, OrganizationInvitationAcceptanceContext,
    OrganizationInvitationAcceptanceHooks, OrganizationInvitationAcceptedContext, TeamsConfig,
    extensions::{OrganizationLimitResolver, TeamLimitContext},
};
use better_auth::plugins::{EmailPasswordPlugin, OrganizationPlugin, SessionManagementPlugin};
use better_auth::{
    AuthBuilder, AuthConfig, AuthError, AuthResult, integrations::axum::AxumIntegration,
    middleware::RateLimitConfig,
};
use better_auth_seaorm::{
    DatabaseConnection, SeaOrmStore,
    sea_orm::{ConnectionTrait, DbBackend, Statement},
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};
use tokio::sync::{Mutex, oneshot};

async fn snapshot(database: &DatabaseConnection) -> AuthResult<Value> {
    let mut snapshot = serde_json::Map::new();
    for (name, sql, columns) in [
        (
            "invitations",
            "SELECT id,organization_id AS organizationId,email,role,team_id AS teamId,status,expires_at AS expiresAt,created_at AS createdAt,inviter_id AS inviterId FROM invitation ORDER BY rowid",
            &[
                "id",
                "organizationId",
                "email",
                "role",
                "teamId",
                "status",
                "expiresAt",
                "createdAt",
                "inviterId",
            ][..],
        ),
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
        (
            "sessions",
            "SELECT id,user_id AS userId,token,expires_at AS expiresAt,created_at AS createdAt,updated_at AS updatedAt,ip_address AS ipAddress,user_agent AS userAgent,impersonated_by AS impersonatedBy,active_organization_id AS activeOrganizationId,active_team_id AS activeTeamId FROM sessions ORDER BY rowid",
            &[
                "id",
                "userId",
                "token",
                "expiresAt",
                "createdAt",
                "updatedAt",
                "ipAddress",
                "userAgent",
                "impersonatedBy",
                "activeOrganizationId",
                "activeTeamId",
            ][..],
        ),
        (
            "organizations",
            "SELECT id,name,slug,logo,metadata,created_at AS createdAt FROM organization ORDER BY rowid",
            &["id", "name", "slug", "logo", "metadata", "createdAt"][..],
        ),
    ] {
        let rows = database
            .query_all_raw(Statement::from_string(DbBackend::Sqlite, sql))
            .await
            .map_err(|e| AuthError::internal(e.to_string()))?;
        let mut values = Vec::new();
        for row in rows {
            let mut object = serde_json::Map::new();
            for column in columns {
                let value = if *column == "memberCount" {
                    json!(
                        row.try_get::<i64>("", column)
                            .map_err(|e| AuthError::internal(e.to_string()))?
                    )
                } else if column.ends_with("At") {
                    json!(
                        row.try_get::<Option<DateTime<Utc>>>("", column)
                            .map_err(|e| AuthError::internal(e.to_string()))?
                            .map(|date| date.to_rfc3339_opts(SecondsFormat::Millis, true))
                    )
                } else {
                    json!(
                        row.try_get::<Option<String>>("", column)
                            .map_err(|e| AuthError::internal(e.to_string()))?
                    )
                };
                let _ = object.insert((*column).into(), value);
            }
            values.push(Value::Object(object));
        }
        let _ = snapshot.insert(name.into(), Value::Array(values));
    }
    Ok(Value::Object(snapshot))
}
struct Application {
    database: DatabaseConnection,
    invitation_status_observer: DatabaseConnection,
    mode: Mutex<String>,
    receipts: Mutex<Vec<Value>>,
    gates: Mutex<VecDeque<oneshot::Sender<()>>>,
}
impl std::fmt::Debug for Application {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvitationAcceptanceApplication")
            .finish_non_exhaustive()
    }
}
impl Application {
    async fn note(&self, phase: &str, context: Value) -> AuthResult<()> {
        self.receipts.lock().await.push(
            json!({"phase":phase,"context":context,"snapshot":snapshot(&self.database).await?}),
        );
        self.application_error(phase).await
    }
    async fn application_error(&self, phase: &str) -> AuthResult<()> {
        let mode = self.mode.lock().await.clone();
        if mode == format!("{phase}-error") || (mode == "sql-reset-api" && phase == "team-limit") {
            return Err(AuthError::Api {
                status: 403,
                code: Some("INVITATION_APPLICATION_REJECTED".into()),
                message: format!("Rejected {phase}"),
            });
        }
        if mode == format!("{phase}-internal") {
            return Err(AuthError::internal(format!(
                "Actual {phase} application failure"
            )));
        }
        if mode == format!("{phase}-public500") {
            return Err(AuthError::Api {
                status: 500,
                code: Some("PUBLIC_INVITATION_500".into()),
                message: format!("Explicit {phase} error"),
            });
        }
        Ok(())
    }
    async fn reset(&self) {
        for gate in self.gates.lock().await.drain(..) {
            let _ = gate.send(());
        }
        *self.mode.lock().await = "off".into();
        self.receipts.lock().await.clear();
        for name in [
            "invitation_stage_member",
            "invitation_stage_team",
            "invitation_stage_session",
            "invitation_stage_reset",
        ] {
            let _ = self
                .database
                .execute_raw(Statement::from_string(
                    DbBackend::Sqlite,
                    format!("DROP TRIGGER IF EXISTS {name}"),
                ))
                .await;
        }
    }
    async fn configure(&self, input: Value) -> AuthResult<Value> {
        self.reset().await;
        *self.mode.lock().await = input["mode"].as_str().unwrap_or("record").into();
        for name in [
            "invitation_stage_member",
            "invitation_stage_team",
            "invitation_stage_session",
            "invitation_stage_reset",
        ] {
            let _ = self
                .database
                .execute_raw(Statement::from_string(
                    DbBackend::Sqlite,
                    format!("DROP TRIGGER IF EXISTS {name}"),
                ))
                .await
                .map_err(|e| AuthError::internal(e.to_string()))?;
        }
        let _=self.database.execute_raw(Statement::from_string(DbBackend::Sqlite,"CREATE TABLE IF NOT EXISTS __test_invitation_stage_guard(invitationId TEXT,userId TEXT)".to_owned())).await.map_err(|e|AuthError::internal(e.to_string()))?;
        let _ = self
            .database
            .execute_raw(Statement::from_string(
                DbBackend::Sqlite,
                "DELETE FROM __test_invitation_stage_guard".to_owned(),
            ))
            .await
            .map_err(|e| AuthError::internal(e.to_string()))?;
        let mode = self.mode.lock().await.clone();
        if mode.starts_with("sql-") {
            let invitation = input["invitationId"]
                .as_str()
                .ok_or_else(|| AuthError::bad_request("Actual invitation required"))?;
            let user = input["userId"]
                .as_str()
                .ok_or_else(|| AuthError::bad_request("Actual user required"))?;
            let actual=self.database.query_one_raw(Statement::from_sql_and_values(DbBackend::Sqlite,"SELECT invitation.id FROM invitation JOIN users ON users.id=? WHERE invitation.id=?",[user.into(),invitation.into()])).await.map_err(|e|AuthError::internal(e.to_string()))?;
            if actual.is_none() {
                return Err(AuthError::bad_request(
                    "Guard requires actual invitation and user",
                ));
            }
            let _ = self
                .database
                .execute_raw(Statement::from_sql_and_values(
                    DbBackend::Sqlite,
                    "INSERT INTO __test_invitation_stage_guard(invitationId,userId) VALUES(?,?)",
                    [invitation.into(), user.into()],
                ))
                .await
                .map_err(|e| AuthError::internal(e.to_string()))?;
            let mut sql = Vec::new();
            if mode == "sql-member" || mode == "sql-reset" {
                sql.push("CREATE TRIGGER invitation_stage_member BEFORE INSERT ON member WHEN NEW.user_id=(SELECT userId FROM __test_invitation_stage_guard) BEGIN SELECT RAISE(ABORT,'actual acceptance member veto'); END");
            }
            if mode == "sql-team" {
                sql.push("CREATE TRIGGER invitation_stage_team BEFORE INSERT ON team_member WHEN NEW.user_id=(SELECT userId FROM __test_invitation_stage_guard) BEGIN SELECT RAISE(ABORT,'actual acceptance team veto'); END");
            }
            if mode == "sql-session" {
                sql.push("CREATE TRIGGER invitation_stage_session BEFORE UPDATE OF active_organization_id ON sessions WHEN OLD.user_id=(SELECT userId FROM __test_invitation_stage_guard) AND NEW.active_organization_id IS NOT NULL BEGIN SELECT RAISE(ABORT,'actual acceptance session veto'); END");
            }
            if mode == "sql-reset" || mode == "sql-reset-api" {
                sql.push("CREATE TRIGGER invitation_stage_reset BEFORE UPDATE OF status ON invitation WHEN OLD.id=(SELECT invitationId FROM __test_invitation_stage_guard) AND OLD.status='accepted' AND NEW.status='pending' BEGIN SELECT RAISE(ABORT,'actual pending restoration veto'); END");
            }
            for query in sql {
                let _ = self
                    .database
                    .execute_raw(Statement::from_string(DbBackend::Sqlite, query.to_owned()))
                    .await
                    .map_err(|e| AuthError::internal(e.to_string()))?;
            }
        }
        Ok(json!({"configured":true}))
    }
}
#[async_trait]
impl OrganizationInvitationAcceptanceHooks for Application {
    async fn before_accept_invitation(
        &self,
        context: &OrganizationInvitationAcceptanceContext,
    ) -> AuthResult<()> {
        if *self.mode.lock().await == "off" {
            return Ok(());
        }
        self.note("before-accept",json!({"invitation":context.invitation,"user":context.user,"organization":context.organization})).await?;
        if *self.mode.lock().await == "pause-before" {
            let (sender, receiver) = oneshot::channel();
            self.gates.lock().await.push_back(sender);
            let _ = receiver.await;
        }
        Ok(())
    }
    async fn after_accept_invitation(
        &self,
        context: &OrganizationInvitationAcceptedContext,
    ) -> AuthResult<()> {
        let mode = self.mode.lock().await.clone();
        if mode != "off" {
            self.note("after-accept",json!({"invitation":context.invitation,"member":context.member,"user":context.user,"organization":context.organization})).await?;
        }
        Ok(())
    }
}
#[async_trait]
impl OrganizationLimitResolver for Application {
    async fn maximum_team_members(&self, context: &TeamLimitContext) -> AuthResult<Option<usize>> {
        let mode = self.mode.lock().await.clone();
        if mode != "off" {
            let email = context
                .user
                .as_ref()
                .and_then(|user| user.email.as_deref())
                .ok_or_else(|| AuthError::internal("Authenticated callback user email required"))?
                .to_lowercase();
            let rows=self.invitation_status_observer.query_all_raw(Statement::from_sql_and_values(DbBackend::Sqlite,"SELECT id,status FROM invitation WHERE organization_id=? AND email=? ORDER BY rowid",[context.organization_id.clone().into(),email.into()])).await.map_err(|error|AuthError::internal(error.to_string()))?;
            let mut statuses = Vec::new();
            for row in rows {
                statuses.push(json!({"id":row.try_get::<String>("","id").map_err(|error|AuthError::internal(error.to_string()))?,"status":row.try_get::<String>("","status").map_err(|error|AuthError::internal(error.to_string()))?}));
            }
            self.receipts.lock().await.push(json!({"phase":"team-limit","context":{"teamId":context.team_id,"session":{"session":context.session,"user":context.user},"organizationId":context.organization_id},"invitationStatus":statuses}));
            self.application_error("team-limit").await?;
        }
        Ok(Some(if mode == "team-full" { 1 } else { 100 }))
    }
}
#[derive(Clone)]
pub(crate) struct Reset(Arc<Application>);
impl Reset {
    pub(crate) async fn reset(&self) {
        self.0.reset().await;
    }
}
pub(crate) async fn router(
    config: &AuthConfig,
    database: DatabaseConnection,
    invitation_status_observer: DatabaseConnection,
) -> AuthResult<(Router, Reset)> {
    let application = Arc::new(Application {
        database: database.clone(),
        invitation_status_observer,
        mode: Mutex::new("off".into()),
        receipts: Mutex::new(Vec::new()),
        gates: Mutex::new(VecDeque::new()),
    });
    let mut router = Router::new();
    for name in [
        "org-invitation-stage",
        "org-invitation-stage-no-team",
        "org-invitation-stage-limit-two",
    ] {
        let path = format!("/__test/profiles/{name}/api/auth");
        let settings = config.clone().base_path(&path);
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(settings.clone())
                .store(SeaOrmStore::<TestSchema>::new(settings, database.clone()))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(SessionManagementPlugin::new())
                .plugin(OrganizationPlugin::with_config(OrganizationConfig {
                    invitation_acceptance_hooks: Some(application.clone()),
                    membership_limit: Some(MembershipLimit::Fixed(
                        if name.ends_with("limit-two") {
                            2.0
                        } else {
                            100.0
                        },
                    )),
                    teams: TeamsConfig {
                        enabled: !name.ends_with("no-team"),
                        create_default_team: false,
                        limit_resolver: Some(application.clone()),
                        ..Default::default()
                    },
                    ..Default::default()
                }))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let control = application.clone();
    let observer = application.clone();
    let release = application.clone();
    router = router
        .route(
            "/__test/organization-invitation-stage/configure",
            post(move |Json(input): Json<Value>| {
                let app = control.clone();
                async move {
                    app.configure(input)
                        .await
                        .map(Json)
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
                }
            }),
        )
        .route(
            "/__test/organization-invitation-stage/release",
            post(move || {
                let app = release.clone();
                async move {
                    let gate = app.gates.lock().await.pop_front();
                    match gate {
                        Some(gate) => {
                            let _ = gate.send(());
                            Ok(Json(json!({"released":true})))
                        }
                        None => Err(StatusCode::BAD_REQUEST),
                    }
                }
            }),
        )
        .route(
            "/__test/organization-invitation-stage/state",
            get(move |Query(query): Query<HashMap<String, String>>| {
                let app = observer.clone();
                async move {
                    if let Some(count) = query.get("waitFor").and_then(|v| v.parse::<usize>().ok())
                    {
                        for _ in 0..100 {
                            if app.gates.lock().await.len() >= count {
                                break;
                            }
                            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                        }
                    }
                    let receipts = app.receipts.lock().await.clone();
                    let waiting = app.gates.lock().await.len();
                    snapshot(&app.database)
                        .await
                        .map(|snapshot| {
                            Json(json!({"receipts":receipts,"snapshot":snapshot,"waiting":waiting}))
                        })
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
                }
            }),
        );
    Ok((router, Reset(application)))
}
