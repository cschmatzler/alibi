use super::extension_common::org_error;
use super::invitation::require_verified_invitation_email;
use crate::plugins::organization::extensions::TeamLimitContext;
use crate::plugins::organization::types::{
    AcceptInvitationRequest, AcceptInvitationResponse, BasicMemberResponse, OrganizationResponse,
};
use crate::plugins::organization::{
    OrganizationConfig, OrganizationInvitationAcceptanceContext,
    OrganizationInvitationAcceptedContext,
};
use better_auth_core::entity::{AuthInvitation, AuthSession, AuthUser};
use better_auth_core::session::SessionRequest;
use better_auth_core::store::transaction;
use better_auth_core::types::AddTeamMemberResult;
use better_auth_core::wire::InvitationView;
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResult, AuthSchema, CreateMember, InvitationStatus,
};
/// Source acceptance claims before its subsequent membership transaction.
use std::sync::Arc;

/// Keep only headers emitted by this accepted request's lifecycle removable.
#[derive(Clone)]
pub(in crate::plugins::organization) struct AcceptanceTransport {
    request: Option<AuthRequest>,
    call: Option<better_auth_core::endpoint::EndpointCall>,
    cookie_header: Option<String>,
    cookies: Arc<std::sync::Mutex<Vec<String>>>,
}

impl AcceptanceTransport {
    pub(in crate::plugins::organization) fn new(request: &AuthRequest) -> Self {
        Self {
            request: Some(request.clone()),
            call: None,
            cookie_header: request.header("cookie").cloned(),
            cookies: Arc::default(),
        }
    }
    pub(in crate::plugins::organization) fn native(
        call: &better_auth_core::endpoint::EndpointCall,
    ) -> Self {
        Self {
            request: None,
            call: Some(call.clone()),
            cookie_header: call.session_headers().get("cookie").cloned(),
            cookies: Arc::default(),
        }
    }
    fn issue_cookie(&self, value: String) {
        if let Some(request) = &self.request {
            request.queue_response_header("set-cookie", &value);
        }
        if let Some(call) = &self.call {
            call.queue_response_header("set-cookie", &value);
        }
        self.cookies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(value);
    }
    pub(in crate::plugins::organization) fn discard_cookies(&self) {
        let mut headers: Vec<_> = self
            .request
            .as_ref()
            .map(AuthRequest::take_response_headers)
            .or_else(|| {
                self.call
                    .as_ref()
                    .map(better_auth_core::endpoint::EndpointCall::take_response_headers)
            })
            .unwrap_or_default()
            .into_iter()
            .collect();
        for cookie in self
            .cookies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .rev()
        {
            if let Some(index) = headers.iter().rposition(|(name, value)| {
                name.eq_ignore_ascii_case("set-cookie") && value == cookie
            }) {
                drop(headers.remove(index));
            }
        }
        for (name, value) in headers {
            if let Some(request) = &self.request {
                request.queue_response_header(&name, &value);
            }
            if let Some(call) = &self.call {
                call.queue_response_header(name, value);
            }
        }
    }
}

fn acceptance_error(status: u16, code: &'static str) -> AuthError {
    let message = match code {
        "INVITATION_NOT_FOUND" => "Invitation not found",
        "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION" => {
            "You are not the recipient of the invitation"
        }
        "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED" => "Organization membership limit reached",
        _ => return org_error(status, code),
    };
    AuthError::Upstream {
        status,
        code,
        message,
    }
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
#[expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    reason = "Preserve JavaScript Number rounding at the compatibility boundary"
)]
#[expect(
    clippy::too_many_lines,
    reason = "Keep invitation claims, membership transactions, and lifecycle callbacks in order"
)]
pub(in crate::plugins::organization) async fn accept<S: AuthSchema>(
    body: &AcceptInvitationRequest,
    user: &impl AuthUser,
    session: &impl AuthSession,
    config: &OrganizationConfig,
    ctx: &AuthContext<S>,
    transport: &AcceptanceTransport,
) -> AuthResult<AcceptInvitationResponse<InvitationView, BasicMemberResponse>> {
    let invitation = ctx
        .database
        .get_invitation_by_id(&body.invitation_id)
        .await?
        .filter(|invitation| invitation.is_pending() && !invitation.is_expired())
        .ok_or_else(|| acceptance_error(400, "INVITATION_NOT_FOUND"))?;
    let email = user
        .email()
        .ok_or_else(|| AuthError::bad_request("User has no email"))?;
    if invitation.email().to_lowercase() != email.to_lowercase() {
        return Err(acceptance_error(
            403,
            "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION",
        ));
    }
    require_verified_invitation_email(
        user,
        config,
        ctx,
        "Email verification required before accepting or rejecting invitation",
    )?;
    let count = ctx
        .database
        .count_organization_members(invitation.organization_id().as_ref())
        .await?;
    let organization = ctx
        .database
        .get_organization_by_id(invitation.organization_id().as_ref())
        .await?
        .ok_or_else(|| acceptance_error(400, "ORGANIZATION_NOT_FOUND"))?;
    let original_user = ctx.user_view(user);
    let original_organization = OrganizationResponse::from_stored_organization(&organization)?;
    let limit = crate::plugins::organization::policy::admission_limit(
        config.membership_limit.as_ref(),
        &original_user,
        &original_organization,
    )
    .await?;
    if count as f64 >= limit {
        return Err(acceptance_error(
            403,
            "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED",
        ));
    }
    if let Some(hooks) = &config.invitation_acceptance_hooks {
        hooks
            .before_accept_invitation(&OrganizationInvitationAcceptanceContext {
                invitation: ctx.invitation_view(&invitation),
                user: original_user.clone(),
                organization: original_organization.clone(),
            })
            .await?;
    }
    // Exact-ID status claim commits outside the transaction, preventing two
    // already-authorized requests from both completing one invitation.
    let accepted = ctx
        .database
        .update_invitation_status_if_status(
            &body.invitation_id,
            InvitationStatus::Pending,
            InvitationStatus::Accepted,
        )
        .await?
        .ok_or_else(|| acceptance_error(400, "INVITATION_NOT_FOUND"))?;
    let accepted_for_tx = accepted.clone();
    let original_session = ctx.session_view(session);
    let token = session.token().to_owned();
    let teams = config.teams.clone();
    let tx_user = original_user.clone();
    let tx_transport = transport.clone();
    let auth_config = Arc::clone(&ctx.config);
    let result = transaction(ctx.database.as_ref(), move |tx| {
        Box::pin(async move {
            let team_ids: Vec<_> = if teams.enabled {
                accepted_for_tx
                    .team_id
                    .as_deref()
                    .filter(|ids| !ids.is_empty())
                    .map(|ids| ids.split(',').collect())
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            for team_id in &team_ids {
                if tx
                    .get_team(&accepted_for_tx.organization_id, team_id)
                    .await?
                    .is_none()
                {
                    return Err(acceptance_error(400, "TEAM_NOT_FOUND"));
                }
                let maximum = if let Some(resolver) = &teams.limit_resolver {
                    resolver
                        .maximum_team_members(&TeamLimitContext {
                            organization_id: accepted_for_tx.organization_id.clone(),
                            team_id: Some((*team_id).to_owned()),
                            session: Some(original_session.clone()),
                            user: Some(tx_user.clone()),
                            request: None,
                        })
                        .await?
                } else {
                    teams.maximum_members_per_team
                };
                if matches!(
                    tx.add_team_member(team_id, &tx_user.id, maximum).await?,
                    AddTeamMemberResult::LimitReached
                ) {
                    return Err(acceptance_error(403, "TEAM_MEMBER_LIMIT_REACHED"));
                }
            }
            if team_ids.len() == 1 {
                use better_auth_core::utils::cookie_utils::{
                    create_session_cookie_with_max_age, create_session_like_cookie,
                    related_cookie_name, sign_cookie_value, verify_cookie_value,
                };

                let updated = tx
                    .update_session_active_team_record(&token, team_ids.first().copied())
                    .await?;

                let preference = related_cookie_name(&auth_config, "dont_remember");
                let dont_remember = tx_transport
                    .cookie_header
                    .as_deref()
                    .and_then(|header| {
                        cookie::Cookie::split_parse(header)
                            .flatten()
                            .find(|cookie| cookie.name() == preference)
                            .map(|cookie| cookie.value().to_owned())
                    })
                    .and_then(|value| verify_cookie_value(&value, auth_config.current_secret()))
                    .is_some_and(|value| !value.is_empty());
                tx_transport.issue_cookie(create_session_cookie_with_max_age(
                    Some(updated.token()),
                    (!dont_remember).then(|| auth_config.session.expires_in.num_seconds()),
                    &auth_config,
                )?);
                if dont_remember {
                    tx_transport.issue_cookie(create_session_like_cookie(
                        &preference,
                        &sign_cookie_value("true", auth_config.current_secret()),
                        None,
                        &auth_config,
                    )?);
                }
            }
            let member = tx
                .create_member(CreateMember {
                    organization_id: accepted_for_tx.organization_id.clone(),
                    user_id: tx_user.id,
                    role: accepted_for_tx
                        .role
                        .ok_or_else(|| AuthError::bad_request("Invitation role is missing"))?,
                })
                .await?;
            drop(
                tx.update_session_active_organization_record(
                    &token,
                    Some(&accepted_for_tx.organization_id),
                )
                .await?,
            );
            Ok(member)
        })
    })
    .await;
    let member = match result {
        Ok(member) => member,
        Err(error) => {
            // A reset error replaces the original transaction error. A missing
            // or independently transitioned row is a successful conditional no-op.
            drop(
                ctx.database
                    .update_invitation_status_if_status(
                        &body.invitation_id,
                        InvitationStatus::Accepted,
                        InvitationStatus::Pending,
                    )
                    .await?,
            );
            return Err(error);
        }
    };
    let view = ctx.invitation_view(&accepted);
    if let Some(hooks) = &config.invitation_acceptance_hooks {
        hooks
            .after_accept_invitation(&OrganizationInvitationAcceptedContext {
                invitation: view.clone(),
                member: member.clone(),
                user: original_user,
                organization: original_organization,
            })
            .await?;
    }
    Ok(AcceptInvitationResponse {
        invitation: view,
        member: BasicMemberResponse::from_member(&member),
    })
}
