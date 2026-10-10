//! Real application callbacks and observations of their SQLite effects.
use crate::TestSchema;
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::organization::{
    OrganizationConfig, OrganizationUpdateContext, OrganizationUpdateHooks,
    OrganizationUpdatePatch, OrganizationUpdatedContext,
};
use alibi::plugins::{EmailPasswordPlugin, OrganizationPlugin, SessionManagementPlugin};
use alibi::seaorm::{
    DatabaseConnection,
    sea_orm::{ConnectionTrait, DbBackend, Statement},
};
use alibi::{Alibi, AuthBuilder, AuthConfig, AuthError, AuthResult};
use alibi::{
    Member, UpdateUser,
    store::{MemberStore, OrganizationStore, UserStore},
    wire::UserView,
};
use axum::{
    Json, Router,
    extract::Query,
    routing::{get, post},
};
use serde_json::{Map, Value, json};
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};

pub(crate) async fn snapshot(database: &DatabaseConnection) -> AuthResult<Value> {
    let mut value = Map::new();
    for (name, sql, columns) in [
        (
            "organizations",
            "SELECT id,name,slug,logo,metadata FROM organization ORDER BY slug,id",
            &["id", "name", "slug", "logo", "metadata"][..],
        ),
        (
            "members",
            "SELECT m.id,m.organization_id AS organizationId,m.user_id AS userId,m.role FROM member m LEFT JOIN organization o ON o.id=m.organization_id JOIN users u ON u.id=m.user_id ORDER BY o.slug,u.email,m.id",
            &["id", "organizationId", "userId", "role"][..],
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
        organization: Value,
        user: &UserView,
        member: &Member,
    ) -> AuthResult<()> {
        self.receipts.lock().await.push(json!({"phase":phase,"organization":organization,"user":{"id":user.id,"email":user.email,"name":user.name},"member":{"id":member.id,"organizationId":member.organization_id,"userId":member.user_id,"role":member.role},"snapshot":snapshot(&self.database).await?}));
        if *self.mode.lock().await == format!("reject-{phase}") {
            return Err(AuthError::Api {
                status: 400,
                code: Some("UPDATE_HOOK_REJECTED".into()),
                message: format!("Rejected {phase}"),
            });
        }
        Ok(())
    }
}
#[async_trait::async_trait]
impl OrganizationUpdateHooks for Hooks {
    async fn before_update(
        &self,
        context: &OrganizationUpdateContext,
    ) -> AuthResult<Option<OrganizationUpdatePatch>> {
        let mut input = Map::new();
        if let Some(value) = &context.organization.name {
            let _ = input.insert("name".into(), json!(value));
        }
        if let Some(value) = &context.organization.slug {
            let _ = input.insert("slug".into(), json!(value));
        }
        if let Some(value) = &context.organization.logo {
            let _ = input.insert("logo".into(), json!(value));
        }
        if let Some(value) = &context.organization.metadata {
            let _ = input.insert(
                "metadata".into(),
                alibi::utils::json::JsValue::Object(value.clone()).to_json_value()?,
            );
        }
        self.note(
            "before-update",
            Value::Object(input),
            &context.user,
            &context.member,
        )
        .await?;
        let mode = self.mode.lock().await.clone();
        if mode == "pause-before" {
            let gate = self.gate.lock().await.clone();
            gate.notified().await;
        }
        if mode == "raw-metadata" {
            let n = context
                .organization
                .metadata
                .as_ref()
                .and_then(|map| map.get("n"))
                .cloned()
                .unwrap_or(alibi::utils::json::JsValue::Null);
            let numeric = n.as_f64();
            let negative_zero =
                numeric.is_some_and(|value| value == 0.0 && value.is_sign_negative());
            let number_class = if numeric == Some(f64::INFINITY) {
                "positive-infinity"
            } else if numeric == Some(f64::NEG_INFINITY) {
                "negative-infinity"
            } else if negative_zero {
                "negative-zero"
            } else {
                "other"
            };
            return Ok(Some(OrganizationUpdatePatch {
                name: Some(number_class.into()),
                metadata: Some(Some(
                    [
                        ("original".into(), n.clone()),
                        ("patched".into(), n),
                        (
                            "negativeZero".into(),
                            alibi::utils::json::JsValue::Bool(negative_zero),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                )),
                ..Default::default()
            }));
        }
        let patch = match mode.as_str() {
            "patch" => Some(OrganizationUpdatePatch {
                name: Some("Hooked Update".into()),
                logo: Some(None),
                metadata: Some(Some(
                    [("guard".into(), json!("hooked-update").into())]
                        .into_iter()
                        .collect(),
                )),
                ..Default::default()
            }),
            "null-metadata" => Some(OrganizationUpdatePatch {
                logo: Some(None),
                metadata: Some(None),
                ..Default::default()
            }),
            "empty-metadata" => Some(OrganizationUpdatePatch {
                metadata: Some(Some(Default::default())),
                ..Default::default()
            }),
            "absent-metadata" => Some(OrganizationUpdatePatch {
                name: Some("Patched Without Metadata".into()),
                ..Default::default()
            }),
            "empty-name" => Some(OrganizationUpdatePatch {
                name: Some(String::new()),
                ..Default::default()
            }),
            _ => None,
        };
        if mode == "mutate-authority" {
            let _ = self
                .store
                .update_user(
                    &context.user.id,
                    UpdateUser {
                        name: Some("Stored New Name".into()),
                        ..Default::default()
                    },
                )
                .await?;
            let _ = self
                .store
                .update_member_role(&context.member.id, "member")
                .await?;
        }
        if mode == "delete-row" {
            self.store
                .delete_organization(&context.member.organization_id)
                .await?;
        }
        Ok(patch)
    }
    async fn after_update(&self, context: &OrganizationUpdatedContext) -> AuthResult<()> {
        self.note(
            "after-update",
            serde_json::to_value(&context.organization)?,
            &context.user,
            &context.member,
        )
        .await
    }
}
pub(crate) async fn router(
    base: &AuthConfig,
    database: DatabaseConnection,
) -> AuthResult<Router<Arc<Alibi<TestSchema>>>> {
    let hooks = Arc::new(Hooks {
        database: database.clone(),
        store: Arc::new(crate::backend::store(base.clone(), database)),
        mode: Mutex::new("record".into()),
        receipts: Mutex::new(Vec::new()),
        gate: Mutex::new(Arc::new(Notify::new())),
    });
    let path = "/__test/profiles/org-update-hooks/api/auth";
    let auth_config = base.clone().base_path(path);
    let auth = Arc::new(
        AuthBuilder::<TestSchema>::new(auth_config.clone())
            .store(crate::backend::store::<TestSchema>(
                auth_config,
                hooks.database.clone(),
            ))
            .rate_limit(RateLimitConfig::new().enabled(false))
            .plugin(EmailPasswordPlugin::new().enable_username(false))
            .plugin(SessionManagementPlugin::new())
            .plugin(OrganizationPlugin::with_config(OrganizationConfig {
                update_hooks: Some(hooks.clone()),
                ..Default::default()
            }))
            .build()
            .await?,
    );
    let configure = hooks.clone();
    let state = hooks.clone();
    let release = hooks.clone();
    let storage = hooks.clone();
    Ok(Router::new().nest(path,auth.clone().axum_router().with_state(auth.clone()))
        .route("/__test/organization-update-hooks-configure",post(move|Json(body):Json<Value>|{let hooks=configure.clone();async move {
            hooks.gate.lock().await.notify_one();
            *hooks.mode.lock().await=body["mode"].as_str().unwrap_or("record").to_owned();
            hooks.receipts.lock().await.clear();*hooks.gate.lock().await=Arc::new(Notify::new());Json(json!({"configured":true}))
        }}))
        .route("/__test/organization-update-storage",post(move|Json(body):Json<Value>|{let hooks=storage.clone();async move {
            hooks.database.execute_unprepared("DROP TRIGGER IF EXISTS default_organization_update").await.map_err(|error|AuthError::internal(error.to_string()))?;
            if let Some(mode @ ("delete" | "ignore" | "veto")) = body["mode"].as_str() {
                let id=body["organizationId"].as_str().unwrap_or_default().replace('\'',"''");
                let action=match mode { "delete"=>"DELETE FROM member WHERE organization_id=OLD.id; DELETE FROM invitation WHERE organization_id=OLD.id; DELETE FROM organization WHERE id=OLD.id; SELECT RAISE(IGNORE);", "ignore"=>"SELECT RAISE(IGNORE);", _=>"SELECT RAISE(ABORT,'organization update veto');" };
                hooks.database.execute_unprepared(&format!("CREATE TRIGGER default_organization_update BEFORE UPDATE ON organization WHEN OLD.id='{id}' BEGIN {action} END")).await.map_err(|error|AuthError::internal(error.to_string()))?;
            }
            Ok::<_,AuthError>(Json(json!({"configured":true})))
        }}))
        .route("/__test/organization-update-hooks-release",post(move||{let hooks=release.clone();async move { hooks.gate.lock().await.notify_one();Json(json!({"released":true})) }}))
        .route("/__test/organization-update-hooks-state",get(move|Query(query):Query<std::collections::HashMap<String,String>>|{let hooks=state.clone();async move {
            for _ in 0..100 { let found=query.get("waitFor").is_none_or(|phase|hooks.receipts.try_lock().ok().is_some_and(|rows|rows.iter().any(|row|row["phase"].as_str()==Some(phase))));if found {break;}tokio::time::sleep(std::time::Duration::from_millis(10)).await; }
            Ok::<_,AuthError>(Json(json!({"receipts":hooks.receipts.lock().await.clone(),"snapshot":snapshot(&hooks.database).await?})))
        }})))
}
