//! Application-owned invitation receipts over the actual configured store.
use super::organization_invitation_acceptance_fixture::snapshot;
use crate::TestSchema;
use alibi::plugins::organization::{
    InvitationLimit, OrganizationConfig, OrganizationInvitationContext,
    OrganizationInvitationCreatePatch, OrganizationInvitationCreationContext,
    OrganizationInvitationDelivery, OrganizationInvitationEmailSender, OrganizationInvitationHooks,
    OrganizationInvitationLimitContext, OrganizationInvitationLimitResolver, TeamsConfig,
};
use alibi::plugins::{EmailPasswordPlugin, OrganizationPlugin, SessionManagementPlugin};
use alibi::{
    AuthBuilder, AuthConfig, AuthError, AuthResult, BackgroundTaskCompletion,
    BackgroundTaskHandler, CallbackContext, integrations::axum::AxumIntegration,
    middleware::RateLimitConfig,
};
use alibi_seaorm::DatabaseConnection;
use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::Query,
    routing::{get, post},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::{Mutex, oneshot};

struct Application {
    database: DatabaseConnection,
    mode: Mutex<String>,
    receipts: Mutex<Vec<Value>>,
    gates: Mutex<Vec<oneshot::Sender<()>>>,
    completions: StdMutex<Vec<BackgroundTaskCompletion>>,
    limit: Mutex<f64>,
    reject_observation: AtomicBool,
}
impl std::fmt::Debug for Application {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvitationApplication")
            .finish_non_exhaustive()
    }
}
impl Application {
    async fn note(&self, phase: &str, context: Value) -> AuthResult<()> {
        let mode = self.mode.lock().await.clone();
        if mode == "off" {
            return Ok(());
        }
        self.receipts.lock().await.push(
            json!({"phase":phase,"context":context,"snapshot":snapshot(&self.database).await?}),
        );
        if mode == format!("{phase}-error") {
            return Err(AuthError::Api {
                status: 403,
                code: Some("INVITATION_APPLICATION_REJECTED".into()),
                message: format!("Rejected {phase}"),
            });
        }
        if mode == format!("{phase}-internal")
            || (phase == "delivery-end" && mode == "hold-delivery-end-internal")
        {
            return Err(AuthError::internal(format!(
                "Actual {phase} application failure"
            )));
        }
        Ok(())
    }
    async fn reset(&self) {
        *self.mode.lock().await = "off".into();
        self.receipts.lock().await.clear();
        for gate in self.gates.lock().await.drain(..) {
            let _ = gate.send(());
        }
        self.completions.lock().unwrap().clear();
        *self.limit.lock().await = 1.0;
        self.reject_observation.store(false, Ordering::SeqCst);
    }
    async fn release(&self) {
        for gate in self.gates.lock().await.drain(..) {
            let _ = gate.send(());
        }
        let completions = std::mem::take(&mut *self.completions.lock().unwrap());
        for completion in completions {
            let _ = completion.await;
        }
    }
}
fn context(ctx: &OrganizationInvitationContext, key: &str) -> Value {
    json!({"invitation":ctx.invitation,key:ctx.user,"organization":ctx.organization})
}
#[async_trait]
impl OrganizationInvitationHooks for Application {
    async fn before_create_invitation(
        &self,
        ctx: &OrganizationInvitationCreationContext,
    ) -> AuthResult<Option<OrganizationInvitationCreatePatch>> {
        self.note("before-create", json!({"invitation":{"email":ctx.invitation.email,"role":ctx.invitation.role,"organizationId":ctx.invitation.organization_id,"inviterId":ctx.invitation.inviter_id,"teamIds":ctx.invitation.team_ids,"teamId":ctx.invitation.team_ids.first()},"inviter":ctx.inviter,"organization":ctx.organization})).await?;
        Ok(if *self.mode.lock().await == "patch-role" {
            Some(OrganizationInvitationCreatePatch {
                role: Some("admin".into()),
                ..Default::default()
            })
        } else if *self.mode.lock().await == "patch-persisted" {
            let date = |value| {
                chrono::DateTime::parse_from_rfc3339(value)
                    .map(|date| date.with_timezone(&chrono::Utc))
                    .map_err(|error| AuthError::internal(error.to_string()))
            };
            Some(OrganizationInvitationCreatePatch {
                id: Some(format!("trusted-{}", ctx.invitation.organization_id)),
                role: Some("admin".into()),
                email: Some(ctx.invitation.email.to_uppercase()),
                status: Some(alibi_core::InvitationStatus::Rejected),
                created_at: Some(date("2020-01-02T03:04:05.123Z")?),
                expires_at: Some(date("2020-01-03T03:04:05.456Z")?),
                ..Default::default()
            })
        } else {
            None
        })
    }
    async fn after_create_invitation(&self, ctx: &OrganizationInvitationContext) -> AuthResult<()> {
        self.note("after-create", context(ctx, "inviter")).await
    }
    async fn before_reject_invitation(
        &self,
        ctx: &OrganizationInvitationContext,
    ) -> AuthResult<()> {
        self.note("before-reject", context(ctx, "user")).await
    }
    async fn after_reject_invitation(&self, ctx: &OrganizationInvitationContext) -> AuthResult<()> {
        self.note("after-reject", context(ctx, "user")).await
    }
    async fn before_cancel_invitation(
        &self,
        ctx: &OrganizationInvitationContext,
    ) -> AuthResult<()> {
        self.note("before-cancel", context(ctx, "cancelledBy"))
            .await
    }
    async fn after_cancel_invitation(&self, ctx: &OrganizationInvitationContext) -> AuthResult<()> {
        self.note("after-cancel", context(ctx, "cancelledBy")).await
    }
}
#[async_trait]
impl OrganizationInvitationLimitResolver for Application {
    async fn invitation_limit(
        &self,
        context: &OrganizationInvitationLimitContext,
        _: &CallbackContext,
    ) -> AuthResult<f64> {
        let mut member = json!(context.member);
        member["user"] = json!({"id":context.member_user.id,"name":context.member_user.name,"email":context.member_user.email,"image":context.member_user.image});
        self.note(
            "limit",
            json!({"user":context.user,"organization":context.organization,"member":member}),
        )
        .await?;
        Ok(*self.limit.lock().await)
    }
}
#[async_trait]
impl OrganizationInvitationEmailSender for Application {
    async fn send_invitation_email(
        &self,
        delivery: &OrganizationInvitationDelivery,
        callback: &CallbackContext,
    ) -> AuthResult<()> {
        if *self.mode.lock().await == "off" {
            return Ok(());
        }
        let request = callback.request.as_ref().map(|request| json!({"method":format!("{:?}",request.method()).to_uppercase(),"path":request.url().map(|url|url.path()),"marker":request.headers.get("x-invitation-marker")}));
        let mut inviter = serde_json::to_value(&delivery.inviter)
            .map_err(|error| AuthError::internal(error.to_string()))?;
        inviter["user"] = json!(delivery.user);
        self.note("delivery-start",json!({"id":delivery.invitation.id,"role":delivery.invitation.role,"email":delivery.email(),"organization":delivery.organization,"inviter":inviter,"invitation":delivery.invitation,"request":request})).await?;
        if self.mode.lock().await.starts_with("hold-delivery") {
            let (sender, receiver) = oneshot::channel();
            self.gates.lock().await.push(sender);
            let _ = receiver.await;
        }
        self.note(
            "delivery-end",
            json!({"id":delivery.invitation.id,"email":delivery.email()}),
        )
        .await
    }
}
impl BackgroundTaskHandler for Application {
    fn handle(&self, completion: BackgroundTaskCompletion) -> AuthResult<()> {
        self.completions.lock().unwrap().push(completion);
        if self.reject_observation.load(Ordering::SeqCst) {
            Err(AuthError::internal("Actual background observer failure"))
        } else {
            Ok(())
        }
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
) -> AuthResult<(Router, Reset)> {
    let app = Arc::new(Application {
        database: database.clone(),
        mode: Mutex::new("off".into()),
        receipts: Mutex::default(),
        gates: Mutex::default(),
        completions: StdMutex::default(),
        limit: Mutex::new(1.0),
        reject_observation: AtomicBool::new(false),
    });
    let mut router = Router::new();
    for name in [
        "org-invite-life",
        "org-invite-reinvite",
        "org-invite-background",
        "org-invite-limit-none",
        "org-invite-limit-zero",
        "org-invite-limit-fractional",
        "org-invite-limit-negative",
        "org-invite-limit-nan",
        "org-invite-limit-infinity",
        "org-invite-limit-resolver",
        "org-invite-page-one",
        "org-invite-expiry-zero",
        "org-invite-expiry-negative",
        "org-invite-expiry-fractional",
        "org-invite-expiry-nan",
    ] {
        let fixed = if name.ends_with("zero") {
            0.0
        } else if name.ends_with("fractional") {
            1.5
        } else if name.ends_with("negative") {
            -0.5
        } else if name.ends_with("nan") {
            f64::NAN
        } else if name.ends_with("infinity") {
            f64::INFINITY
        } else {
            1.0
        };
        let path = format!("/__test/profiles/{name}/api/auth");
        let mut settings = config.clone().base_path(&path);
        if name == "org-invite-page-one" {
            settings.advanced.database.default_find_many_limit = 1;
        }
        if name == "org-invite-background" {
            settings.background_tasks = Some(app.clone());
        }
        let auth = Arc::new(
            AuthBuilder::<TestSchema>::new(settings.clone())
                .store(crate::backend::store::<TestSchema>(
                    settings,
                    database.clone(),
                ))
                .rate_limit(RateLimitConfig::new().enabled(false))
                .plugin(EmailPasswordPlugin::new().enable_username(false))
                .plugin(SessionManagementPlugin::new())
                .plugin(OrganizationPlugin::with_config(OrganizationConfig {
                    invitation_limit: if name == "org-invite-limit-resolver" {
                        Some(InvitationLimit::Resolver(app.clone()))
                    } else if name == "org-invite-limit-none" {
                        None
                    } else {
                        Some(InvitationLimit::Fixed(if name.contains("expiry") {
                            100.0
                        } else {
                            fixed
                        }))
                    },
                    invitation_expires_in: Some(if name.contains("expiry") {
                        if name.ends_with("fractional") {
                            0.125
                        } else {
                            fixed
                        }
                    } else {
                        7200.0
                    }),
                    cancel_pending_invitations_on_reinvite: name == "org-invite-reinvite",
                    invitation_hooks: Some(app.clone()),
                    send_invitation_email: Some(app.clone()),
                    teams: TeamsConfig {
                        enabled: true,
                        create_default_team: false,
                        ..Default::default()
                    },
                    ..Default::default()
                }))
                .build()
                .await?,
        );
        router = router.nest(&path, auth.clone().axum_router().with_state(auth));
    }
    let control = app.clone();
    let observer = app.clone();
    let release = app.clone();
    router = router.route("/__test/organization-invitation-life/configure",post(move |Json(body):Json<Value>| { let app = control.clone(); async move { *app.mode.lock().await = body["mode"].as_str().unwrap_or("record").into(); *app.limit.lock().await = body["limit"].as_f64().unwrap_or_else(||match body["limit"].as_str(){Some("nan")=>f64::NAN,Some("infinity")=>f64::INFINITY,_=>1.0}); app.receipts.lock().await.clear(); app.reject_observation.store(*app.mode.lock().await == "hold-delivery-observer-error", Ordering::SeqCst); Json(json!({"configured":true})) } }))
        .route("/__test/organization-invitation-life/state",get(move |Query(query):Query<HashMap<String,String>>| { let app = observer.clone(); async move { if query.contains_key("wait") { for _ in 0..100 { if !app.gates.lock().await.is_empty() { break; } tokio::time::sleep(std::time::Duration::from_millis(10)).await; } } let snapshot = snapshot(&app.database).await.unwrap(); Json(json!({"receipts":*app.receipts.lock().await,"snapshot":snapshot,"waiting":app.gates.lock().await.len()})) } }))
        .route("/__test/organization-invitation-life/release",post(move || { let app = release.clone(); async move { app.release().await; Json(json!({"released":true})) } }));
    Ok((router, Reset(app)))
}
