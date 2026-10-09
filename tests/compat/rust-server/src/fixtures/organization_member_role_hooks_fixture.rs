//! Real application callbacks and observations of their SQLite effects.
use crate::TestSchema;
use crate::fixtures::organization_update_hooks_fixture::snapshot;
use alibi::integrations::axum::AxumIntegration;
use alibi::middleware::RateLimitConfig;
use alibi::plugins::organization::{
    OrganizationConfig, OrganizationMemberRoleContext, OrganizationMemberRoleHooks,
    OrganizationMemberRolePatch, OrganizationMemberRoleUpdatedContext,
};
use alibi::plugins::{EmailPasswordPlugin, OrganizationPlugin, SessionManagementPlugin};
use alibi::{AuthBuilder, AuthConfig, AuthError, AuthResult, BetterAuth};
use alibi::{
    Member, UpdateUser,
    store::{MemberStore, UserStore},
    wire::UserView,
};
use alibi::seaorm::DatabaseConnection;
use axum::{
    Json, Router,
    extract::Query,
    routing::{get, post},
};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};

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
        new_role: Option<&str>,
        previous_role: Option<&str>,
    ) -> AuthResult<()> {
        self.receipts.lock().await.push(json!({"phase":phase,"newRole":new_role,"previousRole":previous_role,"organization":organization,"user":{"id":user.id,"email":user.email,"name":user.name},"member":{"id":member.id,"organizationId":member.organization_id,"userId":member.user_id,"role":member.role},"snapshot":snapshot(&self.database).await?}));
        if *self.mode.lock().await == format!("reject-{phase}") {
            return Err(AuthError::Api {
                status: 400,
                code: Some("ROLE_HOOK_REJECTED".into()),
                message: format!("Rejected {phase}"),
            });
        }
        Ok(())
    }
}
#[async_trait::async_trait]
impl OrganizationMemberRoleHooks for Hooks {
    async fn before_update(
        &self,
        context: &OrganizationMemberRoleContext,
    ) -> AuthResult<Option<OrganizationMemberRolePatch>> {
        self.note(
            "before-role",
            serde_json::to_value(&context.organization)?,
            &context.user,
            &context.member,
            Some(&context.new_role),
            None,
        )
        .await?;
        let mode = self.mode.lock().await.clone();
        if mode == "pause-before" {
            let gate = self.gate.lock().await.clone();
            gate.notified().await;
        }
        if mode == "delete-row" {
            self.store.delete_member(&context.member.id).await?;
        }
        if mode == "mutate-target" {
            let _ = self
                .store
                .update_user(
                    &context.user.id,
                    UpdateUser {
                        name: Some("Stored Target Name".into()),
                        ..Default::default()
                    },
                )
                .await?;
            let _ = self
                .store
                .update_member_role(&context.member.id, "member")
                .await?;
        }
        Ok(match mode.as_str() {
            "patch" => Some(OrganizationMemberRolePatch {
                role: Some("hook-unregistered-role".into()),
            }),
            "empty" => Some(OrganizationMemberRolePatch {
                role: Some(String::new()),
            }),
            "absent" => Some(OrganizationMemberRolePatch::default()),
            _ => None,
        })
    }
    async fn after_update(&self, context: &OrganizationMemberRoleUpdatedContext) -> AuthResult<()> {
        self.note(
            "after-role",
            serde_json::to_value(&context.organization)?,
            &context.user,
            &context.member,
            None,
            Some(&context.previous_role),
        )
        .await
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
    let path = "/__test/profiles/org-member-role-hooks/api/auth";
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
                member_role_hooks: Some(hooks.clone()),
                ..Default::default()
            }))
            .build()
            .await?,
    );
    let configure = hooks.clone();
    let state = hooks.clone();
    let release = hooks.clone();
    Ok(Router::new().nest(path,auth.clone().axum_router().with_state(auth.clone()))
        .route("/__test/organization-member-role-hooks-configure",post(move|Json(body):Json<Value>|{let hooks=configure.clone();async move {
            hooks.gate.lock().await.notify_one();
            *hooks.mode.lock().await=body["mode"].as_str().unwrap_or("record").to_owned();
            hooks.receipts.lock().await.clear();*hooks.gate.lock().await=Arc::new(Notify::new());Json(json!({"configured":true}))
        }}))
        .route("/__test/organization-member-role-hooks-release",post(move||{let hooks=release.clone();async move { hooks.gate.lock().await.notify_one();Json(json!({"released":true})) }}))
        .route("/__test/organization-member-role-hooks-state",get(move|Query(query):Query<std::collections::HashMap<String,String>>|{let hooks=state.clone();async move {
            for _ in 0..100 { let found=query.get("waitFor").is_none_or(|phase|hooks.receipts.try_lock().ok().is_some_and(|rows|rows.iter().any(|row|row["phase"].as_str()==Some(phase))));if found {break;}tokio::time::sleep(std::time::Duration::from_millis(10)).await; }
            Ok::<_,AuthError>(Json(json!({"receipts":hooks.receipts.lock().await.clone(),"snapshot":snapshot(&hooks.database).await?})))
        }})))
}
