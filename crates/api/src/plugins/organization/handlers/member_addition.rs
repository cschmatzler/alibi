//! Privileged server-only admission; intentionally no public HTTP route.
use super::extension_common::org_error;
use crate::plugins::organization::{
    OrganizationConfig, OrganizationMemberAddedContext, OrganizationMemberAdditionContext,
    OrganizationMemberAdditionDraft,
    extensions::TeamLimitContext,
    types::{AddOrganizationMemberRequest, BasicMemberResponse, OrganizationResponse},
};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResult, AuthSchema, CreateMember,
    entity::{AuthSession, AuthUser},
    types::{AddTeamMemberResult, HttpMethod},
};
use std::collections::HashMap;

#[expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
#[expect(
    clippy::too_many_lines,
    reason = "Keep membership authorization and its transaction callbacks in one ordered operation"
)]
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn add_member<S: AuthSchema>(
    body: &AddOrganizationMemberRequest,
    headers: &HashMap<String, String>,
    config: &OrganizationConfig,
    ctx: &AuthContext<S>,
) -> AuthResult<BasicMemberResponse> {
    // Source catches only its nested optional getSession call, including storage
    // errors from that call. Subsequent target/admission storage errors propagate.
    let session = if body.user_id.is_empty() {
        None
    } else {
        let mut resolution = AuthRequest::new(HttpMethod::Post, "/organization/add-member");
        resolution.headers = headers
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
            .collect();
        ctx.require_cached_session(&resolution).await.ok()
    };
    let organization_id = body
        .organization_id
        .as_deref()
        .filter(|id| !id.is_empty())
        .or_else(|| {
            let (_, session) = session.as_ref()?;
            session.active_organization_id()
        })
        .filter(|id| !id.is_empty())
        .ok_or_else(|| org_error(400, "NO_ACTIVE_ORGANIZATION"))?;
    let team_id = body.team_id.as_deref().filter(|id| !id.is_empty());
    if team_id.is_some() && !config.teams.enabled {
        return Err(AuthError::Api {
            status: 400,
            code: None,
            message: "Teams are not enabled".into(),
        });
    }
    let user = ctx
        .database
        .get_user_by_id(&body.user_id)
        .await?
        .ok_or(AuthError::Upstream {
            status: 400,
            code: "USER_NOT_FOUND",
            message: "User not found",
        })?;
    // Upstream's duplicate lookup resolves the target's lowercased email first.
    let email = user
        .email()
        .ok_or_else(|| AuthError::internal("Member admission requires a target email"))?;
    if let Some(email_user) = ctx
        .database
        .get_user_by_email(&email.to_lowercase())
        .await?
        && ctx
            .database
            .get_member(organization_id, &email_user.id())
            .await?
            .is_some()
    {
        return Err(AuthError::Upstream {
            status: 400,
            code: "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION",
            message: "User is already a member of this organization",
        });
    }
    if let Some(team_id) = team_id
        && ctx
            .database
            .get_team(Some(organization_id), team_id)
            .await?
            .is_none()
    {
        return Err(org_error(400, "TEAM_NOT_FOUND"));
    }
    let count = ctx
        .database
        .count_organization_members(organization_id)
        .await?;
    let organization = ctx
        .database
        .get_organization_by_id(organization_id)
        .await?
        .ok_or_else(|| org_error(400, "ORGANIZATION_NOT_FOUND"))?;
    let original_user = ctx.user_view(&user);
    let original_organization = OrganizationResponse::from_stored_organization(&organization)?;
    let limit = crate::plugins::organization::membership_policy::admission_limit(
        config.membership_limit.as_ref(),
        &original_user,
        &original_organization,
    )
    .await?;
    if count as f64 >= limit {
        return Err(AuthError::Upstream {
            status: 403,
            code: "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED",
            message: "Organization membership limit reached",
        });
    }
    let mut draft = CreateMember {
        organization_id: organization_id.to_owned(),
        user_id: user.id().into_owned(),
        role: body.role.joined(),
    };
    if let Some(hooks) = &config.member_addition_hooks {
        let context = OrganizationMemberAdditionContext {
            member: OrganizationMemberAdditionDraft {
                user_id: draft.user_id.clone(),
                organization_id: draft.organization_id.clone(),
                role: draft.role.clone(),
                team_id: body.team_id.clone(),
            },
            user: original_user.clone(),
            organization: original_organization.clone(),
        };
        if let Some(patch) = hooks.before_add_member(&context).await? {
            patch.apply(&mut draft);
        }
    }
    let member = ctx.database.create_member(draft).await?;
    if let Some(team_id) = team_id {
        let admission = async {
            let maximum = if let Some(resolver) = &config.teams.limit_resolver {
                let (actor, actor_session) = session.as_ref().ok_or(AuthError::Unauthenticated)?;
                resolver
                    .maximum_team_members(&TeamLimitContext {
                        organization_id: organization_id.to_owned(),
                        team_id: Some(team_id.to_owned()),
                        session: Some(actor_session.clone()),
                        user: Some(ctx.user_view(actor)),
                        request: None,
                    })
                    .await?
            } else {
                config.teams.maximum_members_per_team
            };
            match ctx
                .database
                .add_team_member(team_id, &user.id(), maximum)
                .await?
            {
                AddTeamMemberResult::Added(_) | AddTeamMemberResult::Existing(_) => Ok(()),
                AddTeamMemberResult::LimitReached => {
                    Err(org_error(403, "TEAM_MEMBER_LIMIT_REACHED"))
                }
            }
        }
        .await;
        if let Err(error) = admission {
            ctx.database
                .delete_member_with_context(
                    &member.id,
                    organization_id,
                    &user.id(),
                    config.teams.enabled,
                )
                .await?;
            return Err(error);
        }
    }
    if let Some(hooks) = &config.member_addition_hooks {
        hooks
            .after_add_member(&OrganizationMemberAddedContext {
                member: member.clone(),
                user: original_user,
                organization: original_organization,
            })
            .await?;
    }
    Ok(BasicMemberResponse::from_member(&member))
}
