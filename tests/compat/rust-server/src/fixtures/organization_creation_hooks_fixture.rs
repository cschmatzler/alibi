//! Application-owned callbacks and observations of their actual SQLite effects.
use crate::TestSchema;
use axum::{
    Json, Router,
    extract::Query,
    http::StatusCode,
    routing::{get, post},
};
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::organization::{
    OrganizationConfig, OrganizationCreatePatch, OrganizationCreatedContext,
    OrganizationCreationHooks, OrganizationDraftContext, OrganizationMemberCreatePatch,
    OrganizationMemberDraftContext, OrganizationTeamHooks, TeamsConfig,
    extensions::TeamHookContext, types::CreatedOrganizationResponse,
};
use alibi::plugins::{EmailPasswordPlugin, OrganizationPlugin, SessionManagementPlugin};
use alibi::{AuthBuilder, AuthConfig, AuthError, AuthResult, BetterAuth};
use alibi_core::{CreateTeam, Organization, Team, store::MemberStore, wire::UserView};
use alibi_seaorm::{
    DatabaseConnection,
    sea_orm::{ConnectionTrait, DbBackend, Statement},
};
use serde_json::{Map, Value, json};
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};

async fn snapshot(database: &DatabaseConnection) -> AuthResult<Value> {
    let mut value = Map::new();
    for (name, sql, columns) in [
        (
            "organizations",
            "SELECT id,name,slug,logo,metadata FROM organization ORDER BY slug,id",
            &["id", "name", "slug", "logo", "metadata"][..],
        ),
        (
            "members",
            "SELECT m.id,m.organization_id AS organizationId,m.user_id AS userId,m.role FROM member m JOIN organization o ON o.id=m.organization_id JOIN users u ON u.id=m.user_id ORDER BY o.slug,u.email,m.id",
            &["id", "organizationId", "userId", "role"][..],
        ),
        (
            "teams",
            "SELECT t.id,t.organization_id AS organizationId,t.name FROM team t JOIN organization o ON o.id=t.organization_id ORDER BY o.slug,t.name,t.id",
            &["id", "organizationId", "name"][..],
        ),
        (
            "teamMembers",
            "SELECT m.id,m.team_id AS teamId,m.user_id AS userId FROM team_member m JOIN team t ON t.id=m.team_id JOIN organization o ON o.id=t.organization_id JOIN users u ON u.id=m.user_id ORDER BY o.slug,t.name,u.email,m.id",
            &["id", "teamId", "userId"][..],
        ),
        (
            "sessions",
            "SELECT s.id,s.user_id AS userId,s.active_organization_id AS activeOrganizationId,s.active_team_id AS activeTeamId FROM sessions s JOIN users u ON u.id=s.user_id ORDER BY u.email,s.created_at,s.id",
            &["id", "userId", "activeOrganizationId", "activeTeamId"][..],
        ),
        (
            "users",
            "SELECT id,email,name FROM users ORDER BY email,id",
            &["id", "email", "name"][..],
        ),
    ] {
        let rows = database
            .query_all_raw(Statement::from_string(DbBackend::Sqlite, sql))
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let mut values = Vec::new();
        for row in rows {
            let mut object = Map::new();
            for column in columns {
                let field = row
                    .try_get::<Option<String>>("", column)
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                let _ = object.insert((*column).to_owned(), json!(field));
            }
            values.push(Value::Object(object));
        }
        let _ = value.insert(name.to_owned(), Value::Array(values));
    }
    Ok(Value::Object(value))
}
struct Hooks {
    database: DatabaseConnection,
    store: Arc<crate::backend::Store<TestSchema>>,
    plan: Mutex<Value>,
    receipts: Mutex<Vec<Value>>,
    release: Mutex<Arc<Notify>>,
}
impl std::fmt::Debug for Hooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hooks").finish_non_exhaustive()
    }
}
impl Hooks {
    async fn mode(&self) -> String {
        self.plan.lock().await["mode"]
            .as_str()
            .unwrap_or("record")
            .to_owned()
    }
    async fn note(&self, phase: &str, user: &UserView, mut data: Value) -> AuthResult<()> {
        data["phase"] = json!(phase);
        data["user"] = json!({"id":user.id,"email":user.email,"name":user.name});
        data["snapshot"] = snapshot(&self.database).await?;
        self.receipts.lock().await.push(data);
        if self.mode().await == format!("reject-{phase}") {
            return Err(AuthError::Api {
                status: 400,
                code: Some("CREATION_HOOK_REJECTED".into()),
                message: format!("Rejected {phase}"),
            });
        }
        Ok(())
    }
}
fn organization_data(organization: &Organization) -> Value {
    serde_json::to_value(CreatedOrganizationResponse::from_organization(organization)).unwrap()
}
#[async_trait::async_trait]
impl OrganizationCreationHooks for Hooks {
    async fn before_create(
        &self,
        context: &OrganizationDraftContext,
    ) -> AuthResult<Option<OrganizationCreatePatch>> {
        let org = &context.organization;
        let mut draft = json!({"name":org.name,"slug":org.slug});
        if let Some(logo) = &org.logo {
            draft["logo"] = json!(logo);
        }
        if let Some(metadata) = &org.metadata {
            draft["metadata"] = metadata.clone();
        }
        self.note("before-org", &context.user, json!({"organization":draft}))
            .await?;
        Ok(match self.mode().await.as_str() {
            "patch" => Some(OrganizationCreatePatch {
                id: self.plan.lock().await["id"].as_str().map(str::to_owned),
                name: Some("Hooked Organization".into()),
                slug: Some(format!("{}-hooked", org.slug)),
                logo: Some(None),
                metadata: Some(Some(Map::from_iter([("guard".into(), json!("hooked"))]))),
            }),
            "clear-metadata" => Some(OrganizationCreatePatch {
                logo: Some(None),
                metadata: Some(None),
                ..Default::default()
            }),
            "empty-metadata" => Some(OrganizationCreatePatch {
                metadata: Some(Some(Map::new())),
                ..Default::default()
            }),
            "absent-metadata" => Some(OrganizationCreatePatch {
                name: Some("Patched Without Metadata".into()),
                ..Default::default()
            }),
            "empty-name" => Some(OrganizationCreatePatch {
                name: Some(String::new()),
                ..Default::default()
            }),
            _ => None,
        })
    }
    async fn before_add_member(
        &self,
        context: &OrganizationMemberDraftContext,
    ) -> AuthResult<Option<OrganizationMemberCreatePatch>> {
        let member = &context.member;
        self.note("before-member",&context.user,json!({"organization":organization_data(&context.organization),"member":{"organizationId":member.organization_id,"userId":member.user_id,"role":member.role}})).await?;
        Ok(match self.mode().await.as_str() {
            "patch" => Some(OrganizationMemberCreatePatch {
                role: Some("member".into()),
                ..Default::default()
            }),
            "empty-member" => Some(OrganizationMemberCreatePatch {
                role: Some(String::new()),
                ..Default::default()
            }),
            "member-authority" => {
                let plan = self.plan.lock().await;
                Some(OrganizationMemberCreatePatch {
                    role: Some("member".into()),
                    user_id: plan["userId"].as_str().map(str::to_owned),
                    organization_id: plan["organizationId"].as_str().map(str::to_owned),
                })
            }
            _ => None,
        })
    }
    async fn after_add_member(&self, context: &OrganizationCreatedContext) -> AuthResult<()> {
        self.note("after-member",&context.user,json!({"organization":organization_data(&context.organization),"member":context.member})).await?;
        match self.mode().await.as_str() {
            "stored-member" => {
                let _ = self
                    .store
                    .update_member_role(&context.member.id, "admin")
                    .await?;
            }
            "pause-after-member" => {
                let gate = self.release.lock().await.clone();
                gate.notified().await;
            }
            _ => {}
        }
        Ok(())
    }
    async fn after_create(&self, context: &OrganizationCreatedContext) -> AuthResult<()> {
        self.note("after-org",&context.user,json!({"organization":organization_data(&context.organization),"member":context.member})).await
    }
}
#[async_trait::async_trait]
impl OrganizationTeamHooks for Hooks {
    async fn before_create(
        &self,
        team: &mut CreateTeam,
        context: &TeamHookContext,
    ) -> AuthResult<()> {
        self.note("before-team",context.user.as_ref().unwrap(),json!({"organization":organization_data(&context.organization),"team":{"name":team.name,"organizationId":team.organization_id}})).await
    }
    async fn after_create(&self, team: &Team, context: &TeamHookContext) -> AuthResult<()> {
        self.note("after-team",context.user.as_ref().unwrap(),json!({"organization":organization_data(&context.organization),"team":{"id":team.id,"name":team.name,"organizationId":team.organization_id}})).await
    }
}
fn failure(error: AuthError) -> (StatusCode, Json<Value>) {
    let status = StatusCode::from_u16(error.status_code()).unwrap();
    let body = match error {
        AuthError::Api { code, message, .. } => match code {
            Some(code) => json!({"code":code,"message":message}),
            None => json!({"message":message}),
        },
        AuthError::Upstream { code, message, .. } => json!({"code":code,"message":message}),
        AuthError::Unauthenticated => Value::Null,
        error => json!({"message":error.to_string()}),
    };
    (status, Json(body))
}
pub(crate) async fn router(
    base: &AuthConfig,
    database: DatabaseConnection,
    transport: crate::fixtures::organization_transport_probe::Probe,
) -> AuthResult<Router<Arc<BetterAuth<TestSchema>>>> {
    let hooks = Arc::new(Hooks {
        database: database.clone(),
        store: Arc::new(crate::backend::store(base.clone(), database)),
        plan: Mutex::new(json!({"mode":"record"})),
        receipts: Mutex::new(Vec::new()),
        release: Mutex::new(Arc::new(Notify::new())),
    });
    let mut router = Router::new();
    let mut profiles = Vec::new();
    for name in [
        "org-creation-hooks",
        "org-creation-hooks-no-team",
        "org-creation-hooks-denied",
    ] {
        let config = OrganizationConfig {
            allow_user_to_create_organization: name != "org-creation-hooks-denied",
            creation_hooks: Some(hooks.clone()),
            teams: TeamsConfig {
                enabled: name != "org-creation-hooks-no-team",
                hooks: Some(hooks.clone()),
                ..Default::default()
            },
            ..Default::default()
        };
        let path = format!("/__test/profiles/{name}/api/auth");
        let auth_config = base.clone().base_path(&path);
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(auth_config.clone())
                .store(crate::backend::store::<TestSchema>(
                    auth_config,
                    hooks.database.clone(),
                ))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(SessionManagementPlugin::new())
                .plugin(OrganizationPlugin::with_config(config.clone()))
                .plugin(transport.clone())
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth.clone()));
        profiles.push((name, auth, config));
    }
    let configure = hooks.clone();
    router = router.route(
        "/__test/organization-hooks-configure",
        post(move |Json(body): Json<Value>| {
            let hooks = configure.clone();
            async move {
                let mut gate = hooks.release.lock().await;
                gate.notify_waiters();
                *gate = Arc::new(Notify::new());
                drop(gate);
                *hooks.plan.lock().await = body;
                hooks.receipts.lock().await.clear();
                Json(json!({"configured":true}))
            }
        }),
    );
    let release = hooks.clone();
    router = router.route(
        "/__test/organization-hooks-release",
        post(move || {
            let hooks = release.clone();
            async move {
                hooks.release.lock().await.notify_one();
                Json(json!({"released":true}))
            }
        }),
    );
    router = router.route("/__test/organization-hooks-state",get(move |Query(query): Query<std::collections::HashMap<String,String>>| {
        let hooks=hooks.clone();async move {
            if let Some(phase)=query.get("waitFor") {
                for _ in 0..100 {
                    if hooks.receipts.lock().await.iter().any(|receipt|receipt["phase"]==*phase) { break; }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
            Json(json!({"receipts":hooks.receipts.lock().await.clone(),"snapshot":snapshot(&hooks.database).await.unwrap()}))
        }
    }));
    Ok(router.route(
        "/__test/organization-hooks-create",
        post(move |Json(body): Json<Value>| {
            let profiles = profiles.clone();
            async move {
                let Some((_, auth, config)) = profiles
                    .iter()
                    .find(|(name, _, _)| body["profile"] == *name)
                else {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"message":"Unknown fixture profile"})),
                    );
                };
                let data = alibi::plugins::organization::types::CreateOrganizationRequest {
                    additional_fields: Default::default(),
                    name: body["name"].as_str().unwrap_or_default().into(),
                    slug: body["slug"].as_str().unwrap_or_default().into(),
                    logo: body["logo"].as_str().map(str::to_owned),
                    metadata: body.get("metadata").cloned(),
                    keep_current_active_organization: None,
                };
                match OrganizationPlugin::with_config(config.clone())
                    .create_organization_for_user(
                        auth.context(),
                        body["userId"].as_str().unwrap_or_default(),
                        &data,
                    )
                    .await
                {
                    Ok(value) => (StatusCode::OK, Json(serde_json::to_value(value).unwrap())),
                    Err(error) => failure(error),
                }
            }
        }),
    ))
}
