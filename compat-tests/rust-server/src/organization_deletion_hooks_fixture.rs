//! Configured application callbacks, real row observations and trusted cookie calls.
use crate::TestSchema;
use axum::{
    Json, Router,
    extract::Query,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::middleware::RateLimitConfig;
use better_auth::plugins::organization::{
    OrganizationConfig, OrganizationDeleteContext, OrganizationDeletionHooks, TeamsConfig,
    types::DeleteOrganizationRequest,
};
use better_auth::plugins::{EmailPasswordPlugin, OrganizationPlugin, SessionManagementPlugin};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult, BetterAuth};
use better_auth_core::UpdateOrganization;
use better_auth_core::store::OrganizationStore;
use better_auth_seaorm::{
    DatabaseConnection, SeaOrmStore,
    sea_orm::{ConnectionTrait, DbBackend, Statement},
};
use serde_json::{Map, Value, json};
use std::{collections::HashMap, sync::Arc};
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
            "SELECT m.id,m.organization_id AS organizationId,m.user_id AS userId,m.role FROM member m JOIN users u ON u.id=m.user_id ORDER BY u.email,m.role,m.id",
            &["id", "organizationId", "userId", "role"][..],
        ),
        (
            "invitations",
            "SELECT id,organization_id AS organizationId,status,email FROM invitation ORDER BY email,id",
            &["id", "organizationId", "status", "email"][..],
        ),
        (
            "teams",
            "SELECT id,organization_id AS organizationId,name FROM team ORDER BY name,id",
            &["id", "organizationId", "name"][..],
        ),
        (
            "teamMembers",
            "SELECT m.id,m.team_id AS teamId,m.user_id AS userId FROM team_member m JOIN team t ON t.id=m.team_id JOIN users u ON u.id=m.user_id ORDER BY t.name,u.email,m.id",
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
                let _ = object.insert((*column).into(), json!(field));
            }
            values.push(Value::Object(object));
        }
        let _ = value.insert(name.into(), Value::Array(values));
    }
    Ok(Value::Object(value))
}
struct Hooks {
    database: DatabaseConnection,
    store: Arc<SeaOrmStore<TestSchema>>,
    mode: Mutex<String>,
    receipts: Mutex<Vec<Value>>,
    release: Mutex<Arc<Notify>>,
}
impl std::fmt::Debug for Hooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hooks").finish_non_exhaustive()
    }
}
fn header(headers: &HashMap<String, String>) -> Option<&str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("x-delete-hook"))
        .map(|(_, value)| value.as_str())
}
impl Hooks {
    async fn note(&self, phase: &str, context: &OrganizationDeleteContext) -> AuthResult<()> {
        let session = &context.session;
        self.receipts.lock().await.push(json!({"phase":phase,"organization":context.organization,"user":{"id":context.user.id,"email":context.user.email,"name":context.user.name},"session":{"id":session.id,"userId":session.user_id,"activeOrganizationId":session.active_organization_id,"activeTeamId":session.active_team_id},"header":header(&context.headers),"request":context.request.as_ref().map(|request|json!({"method":format!("{:?}",request.method).to_uppercase(),"path":request.path,"header":header(&request.headers)})),"snapshot":snapshot(&self.database).await?}));
        if *self.mode.lock().await == format!("reject-{phase}") {
            return Err(AuthError::Api {
                status: 400,
                code: Some("DELETION_HOOK_REJECTED".into()),
                message: format!("Rejected {phase}"),
            });
        }
        Ok(())
    }
}
#[async_trait::async_trait]
impl OrganizationDeletionHooks for Hooks {
    async fn before_delete(&self, context: &OrganizationDeleteContext) -> AuthResult<()> {
        if *self.mode.lock().await == "write-before" {
            let _ = self
                .store
                .update_organization(
                    &context.organization.id,
                    UpdateOrganization {
                        name: Some("Written By Hook".into()),
                        ..Default::default()
                    },
                )
                .await?;
        }
        self.note("before", context).await?;
        if *self.mode.lock().await == "pause-before" {
            let gate = self.release.lock().await.clone();
            gate.notified().await;
        }
        Ok(())
    }
    async fn after_delete(&self, context: &OrganizationDeleteContext) -> AuthResult<()> {
        self.note("after", context).await
    }
}
fn failure(error: AuthError) -> Response {
    let status = StatusCode::from_u16(error.status_code()).unwrap();
    match error {
        AuthError::Unauthenticated | AuthError::SessionNotFound => {
            (status, [("content-type", "application/json")]).into_response()
        }
        AuthError::Api { code, message, .. } => (
            status,
            Json(match code {
                Some(code) => json!({"code":code,"message":message}),
                None => json!({"message":message}),
            }),
        )
            .into_response(),
        AuthError::Upstream { code, message, .. } => {
            (status, Json(json!({"code":code,"message":message}))).into_response()
        }
        error => (status, Json(json!({"message":error.to_string()}))).into_response(),
    }
}
pub(super) async fn router(
    base: &AuthConfig,
    database: DatabaseConnection,
    transport: crate::organization_transport_probe::Probe,
) -> AuthResult<Router<Arc<BetterAuth<TestSchema>>>> {
    let hooks = Arc::new(Hooks {
        database: database.clone(),
        store: Arc::new(SeaOrmStore::new(base.clone(), database)),
        mode: Mutex::new("record".into()),
        receipts: Mutex::new(Vec::new()),
        release: Mutex::new(Arc::new(Notify::new())),
    });
    let mut router = Router::new();
    let mut profiles = Vec::new();
    for name in ["org-deletion-hooks", "org-deletion-hooks-disabled"] {
        let config = OrganizationConfig {
            deletion_hooks: Some(hooks.clone()),
            disable_organization_deletion: name.ends_with("disabled"),
            teams: TeamsConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let path = format!("/__test/profiles/{name}/api/auth");
        let auth_config = base.clone().base_path(path.clone());
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(auth_config.clone())
                .store(SeaOrmStore::new(auth_config, hooks.database.clone()))
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
        "/__test/organization-delete-hooks-configure",
        post(move |Json(body): Json<Value>| {
            let hooks = configure.clone();
            async move {
                let mut gate = hooks.release.lock().await;
                gate.notify_waiters();
                *gate = Arc::new(Notify::new());
                drop(gate);
                *hooks.mode.lock().await = body["mode"].as_str().unwrap_or("record").into();
                hooks.receipts.lock().await.clear();
                Json(json!({"configured":true}))
            }
        }),
    );
    let release = hooks.clone();
    router = router.route(
        "/__test/organization-delete-hooks-release",
        post(move || {
            let hooks = release.clone();
            async move {
                hooks.release.lock().await.notify_one();
                Json(json!({"released":true}))
            }
        }),
    );
    router=router.route("/__test/organization-delete-hooks-state",get(move|Query(query):Query<HashMap<String,String>>|{let hooks=hooks.clone();async move{if let Some(phase)=query.get("waitFor"){for _ in 0..100{if hooks.receipts.lock().await.iter().any(|receipt|receipt["phase"]==*phase){break;}tokio::time::sleep(std::time::Duration::from_millis(10)).await;}}Json(json!({"receipts":hooks.receipts.lock().await.clone(),"snapshot":snapshot(&hooks.database).await.unwrap()}))}}));
    Ok(router.route(
        "/__test/organization-delete-hooks-server",
        post(move |headers: HeaderMap, Json(body): Json<Value>| {
            let profiles = profiles.clone();
            async move {
                let Some((_, auth, config)) = profiles
                    .iter()
                    .find(|(name, _, _)| body["profile"] == *name)
                else {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"message":"Unknown fixture profile"})),
                    )
                        .into_response();
                };
                let headers = headers
                    .iter()
                    .filter_map(|(key, value)| {
                        value.to_str().ok().map(|value| {
                            (
                                if body["headerCase"] == "mixed" && key.as_str() == "cookie" {
                                    "Cookie".into()
                                } else if body["headerCase"] == "mixed"
                                    && key.as_str() == "x-delete-hook"
                                {
                                    "X-Delete-Hook".into()
                                } else {
                                    key.as_str().into()
                                },
                                value.into(),
                            )
                        })
                    })
                    .collect();
                let data = DeleteOrganizationRequest {
                    organization_id: body["organizationId"].as_str().unwrap_or_default().into(),
                };
                match OrganizationPlugin::with_config(config.clone())
                    .delete_organization_with_headers(auth.context(), &headers, &data)
                    .await
                {
                    Ok(Some(value)) => Json(value).into_response(),
                    Ok(None) => (
                        StatusCode::BAD_REQUEST,
                        [("content-type", "application/json")],
                    )
                        .into_response(),
                    Err(error) => failure(error),
                }
            }
        }),
    ))
}
