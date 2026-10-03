//! Invitation admission, delivery and non-accept callbacks over immutable snapshots.
use super::types::OrganizationResponse;
use async_trait::async_trait;
use better_auth_core::{
    AuthResult, CallbackContext, Member,
    wire::{InvitationView, UserView},
};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum InvitationLimit {
    Fixed(f64),
    Resolver(Arc<dyn OrganizationInvitationLimitResolver>),
}
#[derive(Debug, Clone)]
pub struct OrganizationInvitationLimitContext {
    pub user: UserView,
    pub organization: OrganizationResponse,
    pub member: Member,
    /// Actual adapter-joined user, independent of the authenticated session snapshot.
    pub member_user: UserView,
}
#[async_trait]
pub trait OrganizationInvitationLimitResolver: std::fmt::Debug + Send + Sync {
    async fn invitation_limit(
        &self,
        context: &OrganizationInvitationLimitContext,
        callback: &CallbackContext,
    ) -> AuthResult<f64>;
}
#[derive(Debug, Clone)]
pub struct OrganizationInvitationDraft {
    pub email: String,
    pub role: String,
    pub organization_id: String,
    pub inviter_id: String,
    pub team_ids: Vec<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub options: better_auth_core::store::InvitationCreateOptions,
}
#[derive(Debug, Clone, Default)]
pub struct OrganizationInvitationCreatePatch {
    pub email: Option<String>,
    pub role: Option<String>,
    pub organization_id: Option<String>,
    pub inviter_id: Option<String>,
    pub team_ids: Option<Vec<String>>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub id: Option<String>,
    pub status: Option<better_auth_core::InvitationStatus>,
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}
impl OrganizationInvitationCreatePatch {
    pub(super) fn apply(self, draft: &mut OrganizationInvitationDraft) {
        if let Some(value) = self.email {
            draft.email = value;
        }
        if let Some(value) = self.role {
            draft.role = value;
        }
        if let Some(value) = self.organization_id {
            draft.organization_id = value;
        }
        if let Some(value) = self.inviter_id {
            draft.inviter_id = value;
        }
        if let Some(value) = self.expires_at {
            draft.expires_at = Some(value);
        }
        if let Some(value) = self.id {
            draft.options.id = Some(value);
        }
        if let Some(value) = self.status {
            draft.options.status = Some(value);
        }
        if let Some(value) = self.created_at {
            draft.options.created_at = Some(value);
        }
        if let Some(value) = self.team_ids {
            draft.team_ids = value;
        }
    }
}
#[derive(Debug, Clone)]
pub struct OrganizationInvitationCreationContext {
    pub invitation: OrganizationInvitationDraft,
    pub inviter: UserView,
    pub organization: OrganizationResponse,
}
#[derive(Debug, Clone)]
pub struct OrganizationInvitationContext {
    pub invitation: InvitationView,
    /// Inviter for create, recipient for reject, cancelling principal for cancel.
    pub user: UserView,
    pub organization: OrganizationResponse,
}
/// Hooks run in Source order, outside transactions. After failures retain writes.
#[async_trait]
pub trait OrganizationInvitationHooks: std::fmt::Debug + Send + Sync {
    async fn before_create_invitation(
        &self,
        _context: &OrganizationInvitationCreationContext,
    ) -> AuthResult<Option<OrganizationInvitationCreatePatch>> {
        Ok(None)
    }
    async fn after_create_invitation(
        &self,
        _context: &OrganizationInvitationContext,
    ) -> AuthResult<()> {
        Ok(())
    }
    async fn before_reject_invitation(
        &self,
        _context: &OrganizationInvitationContext,
    ) -> AuthResult<()> {
        Ok(())
    }
    async fn after_reject_invitation(
        &self,
        _context: &OrganizationInvitationContext,
    ) -> AuthResult<()> {
        Ok(())
    }
    async fn before_cancel_invitation(
        &self,
        _context: &OrganizationInvitationContext,
    ) -> AuthResult<()> {
        Ok(())
    }
    async fn after_cancel_invitation(
        &self,
        _context: &OrganizationInvitationContext,
    ) -> AuthResult<()> {
        Ok(())
    }
}
#[derive(Debug, Clone)]
pub struct OrganizationInvitationDelivery {
    pub invitation: InvitationView,
    pub organization: OrganizationResponse,
    pub inviter: Member,
    pub user: UserView,
}
impl OrganizationInvitationDelivery {
    /// Source always sends to the lowercase address, including a trusted draft override.
    #[must_use]
    pub fn email(&self) -> String {
        self.invitation.email.to_lowercase()
    }
}
/// Invoked with the original transport context. Delivery errors are logged and
/// consumed by Source's runInBackgroundOrAwait; creation still runs its after hook.
#[async_trait]
pub trait OrganizationInvitationEmailSender: std::fmt::Debug + Send + Sync {
    async fn send_invitation_email(
        &self,
        delivery: &OrganizationInvitationDelivery,
        callback: &CallbackContext,
    ) -> AuthResult<()>;
}

pub(super) async fn deliver<S: better_auth_core::AuthSchema>(
    config: &super::OrganizationConfig,
    delivery: OrganizationInvitationDelivery,
    ctx: &better_auth_core::AuthContext<S>,
) -> AuthResult<()> {
    let Some(sender) = config.send_invitation_email.clone() else {
        return Ok(());
    };
    let callback = CallbackContext::new(ctx, None);
    let work = async move {
        if let Err(error) = sender.send_invitation_email(&delivery, &callback).await {
            tracing::error!(%error, "Failed to run background task");
        }
        Ok(())
    };
    if let Some(handler) = &ctx.config.background_tasks {
        let completion = better_auth_core::start_background_task(work).await?;
        if let Err(error) = handler.handle(completion) {
            tracing::error!(%error, "Failed to run background task");
        }
    } else {
        work.await?;
    }
    Ok(())
}

#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    reason = "ECMAScript Date truncates the absolute millisecond timestamp"
)]
pub(super) fn expiry(seconds: Option<f64>) -> AuthResult<chrono::DateTime<chrono::Utc>> {
    let span = seconds
        .filter(|value| super::membership_policy::truthy_number(*value))
        .unwrap_or(172_800.0);
    let milliseconds = chrono::Utc::now().timestamp_millis() as f64 + span * 1000.0;
    // ECMAScript TimeClip bounds. Rust dates cannot represent Invalid Date.
    if !milliseconds.is_finite() || milliseconds.abs() > 8_640_000_000_000_000.0 {
        return Err(better_auth_core::AuthError::Config(
            "Invitation expiry is outside the representable date range".into(),
        ));
    }
    chrono::DateTime::from_timestamp_millis(milliseconds as i64).ok_or_else(|| {
        better_auth_core::AuthError::Config(
            "Invitation expiry is outside the representable date range".into(),
        )
    })
}
