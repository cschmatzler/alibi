use crate::organization::types::OrganizationResponse;
use alibi_core::AuthResult;
use alibi_core::CallbackContext;
use alibi_core::Member;
use alibi_core::wire::InvitationView;
use alibi_core::wire::UserView;
use async_trait::async_trait;
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
    pub options: alibi_core::store::InvitationCreateOptions,
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
    pub status: Option<alibi_core::InvitationStatus>,
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}
impl OrganizationInvitationCreatePatch {
    pub(in crate::organization) fn apply(self, draft: &mut OrganizationInvitationDraft) {
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

pub(in crate::organization) async fn deliver<S: alibi_core::AuthSchema>(
    config: &crate::organization::OrganizationConfig,
    delivery: OrganizationInvitationDelivery,
    ctx: &alibi_core::AuthContext<S>,
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
        let completion = alibi_core::start_background_task(work).await?;
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
pub(in crate::organization) fn expiry(
    seconds: Option<f64>,
) -> AuthResult<chrono::DateTime<chrono::Utc>> {
    let span = seconds
        .filter(|value| crate::organization::policy::truthy_number(*value))
        .unwrap_or(172_800.0);
    let milliseconds = chrono::Utc::now().timestamp_millis() as f64 + span * 1000.0;
    // ECMAScript TimeClip bounds. Rust dates cannot represent Invalid Date.
    if !milliseconds.is_finite() || milliseconds.abs() > 8_640_000_000_000_000.0 {
        return Err(alibi_core::AuthError::Config(
            "Invitation expiry is outside the representable date range".into(),
        ));
    }
    chrono::DateTime::from_timestamp_millis(milliseconds as i64).ok_or_else(|| {
        alibi_core::AuthError::Config(
            "Invitation expiry is outside the representable date range".into(),
        )
    })
}

#[derive(Debug, Clone)]
pub struct OrganizationInvitationAcceptanceContext {
    pub invitation: InvitationView,
    pub user: UserView,
    /// The originally looked-up organization, including its stored metadata.
    pub organization: OrganizationResponse,
}

#[derive(Debug, Clone)]
pub struct OrganizationInvitationAcceptedContext {
    pub invitation: InvitationView,
    pub member: Member,
    pub user: UserView,
    pub organization: OrganizationResponse,
}

/// Before errors prevent the conditional claim.
///
/// After errors retain accepted
/// status and committed memberships/session scope. Returned JavaScript callback
/// values do not patch acceptance; immutable snapshots express this contract.
#[async_trait]
pub trait OrganizationInvitationAcceptanceHooks: std::fmt::Debug + Send + Sync {
    async fn before_accept_invitation(
        &self,
        _context: &OrganizationInvitationAcceptanceContext,
    ) -> AuthResult<()> {
        Ok(())
    }
    async fn after_accept_invitation(
        &self,
        _context: &OrganizationInvitationAcceptedContext,
    ) -> AuthResult<()> {
        Ok(())
    }
}
