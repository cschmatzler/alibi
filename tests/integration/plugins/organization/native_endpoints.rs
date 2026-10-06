#![expect(
    clippy::indexing_slicing,
    reason = "Assert public JSON response fields by their documented paths"
)]
//! Public native organization calls retain typed values, lifecycle, and cookies.
use async_trait::async_trait;
use better_auth::plugins::{
    EmailPasswordPlugin,
    organization::{
        DynamicAccessControlConfig, OrganizationConfig, OrganizationPlugin, TeamsConfig,
        default_organization_statements, types::*,
    },
};
use better_auth::{AuthBuilder, AuthConfig, BetterAuth};
use better_auth_core::endpoint::{
    BeforeEndpointAction, EndpointCall, EndpointContextPatch, EndpointHook, EndpointOptions,
    EndpointResponse,
};
use better_auth_core::utils::json::JsValue;
use better_auth_core::{AuthContext, AuthRequest, AuthResult, AuthSchema, HttpMethod};
use serde_json::json;

fn credentials(cookie: &str) -> EndpointOptions {
    EndpointOptions {
        headers: Some([("cookie".into(), cookie.into())].into()),
        ..Default::default()
    }
}
async fn signup<S: AuthSchema>(auth: &BetterAuth<S>, email: &str) -> (String, String) {
    let mut request = AuthRequest::new(HttpMethod::Post, "/sign-up/email");
    drop(
        request
            .headers
            .insert("content-type".into(), "application/json".into()),
    );
    request.body = Some(
        serde_json::to_vec(&json!({"email":email,"name":email,"password":"Password123!"})).unwrap(),
    );
    let response = Box::pin(auth.handle_request(request)).await.unwrap();
    assert_eq!(response.status, 200);
    let cookie = response
        .headers
        .get_all("set-cookie")
        .map(|value| value.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ");
    let id = serde_json::from_slice::<serde_json::Value>(&response.body).unwrap()["user"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    (cookie, id)
}
struct Patch;
#[async_trait]
impl<S: AuthSchema> EndpointHook<S> for Patch {
    fn matches_before(&self, call: &EndpointCall, _: &AuthContext<S>) -> AuthResult<bool> {
        Ok(call.operation_id() == "updateOrganization")
    }
    async fn before(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeEndpointAction>> {
        assert!(call.request().is_none());
        Ok(Some(BeforeEndpointAction::Patch(Box::new(
            EndpointContextPatch {
                body: Some(JsValue::from(json!({"data":{"name":"Patched"}}))),
                ..Default::default()
            },
        ))))
    }
    async fn after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        response: EndpointResponse,
    ) -> AuthResult<EndpointResponse> {
        if call.operation_id() == "setActiveOrganization" {
            return Ok(response
                .with_header("set-cookie", "application=after; Path=/")
                .with_header("x-organization-hook", "ran"));
        }
        Ok(response)
    }
}

#[tokio::test]
async fn native_organization_workflow_preserves_typed_state_and_cookie_publication() {
    let auth = AuthBuilder::without_database(AuthConfig::new(
        "organization-native-at-least-32-char-secret",
    ))
    .plugin(EmailPasswordPlugin::new())
    .plugin(OrganizationPlugin::with_config(OrganizationConfig {
        teams: TeamsConfig {
            enabled: true,
            create_default_team: false,
            allow_removing_all_teams: true,
            ..Default::default()
        },
        access_control: Some(default_organization_statements()),
        dynamic_access_control: DynamicAccessControlConfig {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    }))
    .endpoint_hook(Patch)
    .build()
    .await
    .unwrap();
    let (owner, _) = signup(&auth, "owner@example.test").await;
    let (recipient, recipient_id) = signup(&auth, "recipient@example.test").await;
    let created = Box::pin(
        auth.dispatch_endpoint(
            OrganizationPlugin::create_endpoint(
                &CreateOrganizationRequest {
                    additional_fields: Default::default(),
                    name: "Original".into(),
                    slug: "native".into(),
                    logo: Some("https://example.test/original.png".into()),
                    metadata: None,
                    keep_current_active_organization: None,
                },
                None,
            )
            .unwrap(),
            credentials(&owner),
        ),
    )
    .await
    .unwrap()
    .decode()
    .unwrap();
    let id = created.organization.id;
    let updated = Box::pin(
        auth.dispatch_endpoint(
            OrganizationPlugin::update_endpoint(&UpdateOrganizationRequest {
                organization_id: Some(id.clone()),
                data: UpdateOrganizationData {
                    additional_fields: Default::default(),
                    name: Some("Caller".into()),
                    slug: None,
                    logo: Some(None),
                    metadata: None,
                },
            })
            .unwrap(),
            credentials(&owner),
        ),
    )
    .await
    .unwrap()
    .decode()
    .unwrap()
    .unwrap();
    assert_eq!(updated.name, "Patched");
    assert_eq!(updated.logo, None);
    let selected = Box::pin(
        auth.dispatch_endpoint(
            OrganizationPlugin::set_active_endpoint(&SetActiveOrganizationRequest {
                organization_id: NullableStringField::Value(id.clone()),
                organization_slug: None,
            })
            .unwrap(),
            credentials(&owner),
        ),
    )
    .await
    .unwrap();
    assert_eq!(selected.decode().unwrap().unwrap().id, id);
    assert_eq!(
        selected
            .headers()
            .get("x-organization-hook")
            .map(String::as_str),
        Some("ran")
    );
    let cookies: Vec<_> = selected.headers().get_all("set-cookie").collect();
    let active_owner = cookies
        .iter()
        .map(|value| value.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ");
    assert!(cookies.iter().any(|value| value.contains("session_token=")));
    assert!(
        cookies
            .iter()
            .any(|value| value.starts_with("application=after"))
    );
    let list = Box::pin(auth.dispatch_endpoint(
        OrganizationPlugin::list_organizations_endpoint(),
        credentials(&owner),
    ))
    .await
    .unwrap()
    .decode()
    .unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, "Patched");
    let mut team_credentials = credentials(&owner);
    let mut original_request = AuthRequest::new(HttpMethod::Post, "/original-http-request");
    original_request.body =
        Some(serde_json::to_vec(&json!({"name":"Decoy","organizationId":"wrong"})).unwrap());
    team_credentials.request = Some(original_request);
    let team = Box::pin(
        auth.dispatch_endpoint(
            OrganizationPlugin::create_team_endpoint(&CreateTeamRequest {
                name: "Review".into(),
                organization_id: Some(id.clone()),
            })
            .unwrap(),
            team_credentials,
        ),
    )
    .await
    .unwrap()
    .decode()
    .unwrap();
    assert_eq!(team.name, "Review");
    let invitation = Box::pin(
        auth.dispatch_endpoint(
            OrganizationPlugin::invite_member_endpoint(&InviteMemberRequest {
                email: "recipient@example.test".into(),
                role: RoleInput::One("member".into()),
                organization_id: Some(id.clone()),
                team_id: Some(TeamInput::One(team.id.clone())),
                resend: None,
            })
            .unwrap(),
            credentials(&owner),
        ),
    )
    .await
    .unwrap()
    .decode()
    .unwrap();
    let read = Box::pin(
        auth.dispatch_endpoint(
            OrganizationPlugin::get_invitation_endpoint(&GetInvitationQuery {
                id: invitation.id.clone(),
            })
            .unwrap(),
            credentials(&recipient),
        ),
    )
    .await
    .unwrap()
    .decode()
    .unwrap();
    assert_eq!(read.organization_name, "Patched");
    let accepted = Box::pin(
        auth.dispatch_endpoint(
            OrganizationPlugin::accept_invitation_endpoint(&AcceptInvitationRequest {
                invitation_id: invitation.id.clone(),
            })
            .unwrap(),
            credentials(&recipient),
        ),
    )
    .await
    .unwrap();
    assert!(accepted.headers().get_all("set-cookie").next().is_some());
    assert_eq!(accepted.decode().unwrap().member.user_id, recipient_id);
    let denial = Box::pin(
        auth.dispatch_endpoint(
            OrganizationPlugin::accept_invitation_endpoint(&AcceptInvitationRequest {
                invitation_id: invitation.id,
            })
            .unwrap(),
            credentials(&recipient),
        ),
    )
    .await
    .unwrap_err();
    assert_eq!(denial.error.status_code(), 400);
    let page = Box::pin(
        auth.dispatch_endpoint(
            OrganizationPlugin::list_members_endpoint(&ListMembersQuery {
                organization_id: Some(id.clone()),
                limit: Some(1.0),
                ..Default::default()
            })
            .unwrap(),
            credentials(&owner),
        ),
    )
    .await
    .unwrap()
    .decode()
    .unwrap();
    assert_eq!(page.total, 2);
    assert_eq!(page.members.len(), 1);
    // Role updates share the HTTP handler's validation and error codes.
    let member_id = accepted.decode().unwrap().member.id;
    let update_role = |role: &str, organization_id: Option<&str>| {
        OrganizationPlugin::update_member_role_endpoint(&UpdateMemberRoleRequest {
            member_id: member_id.clone(),
            role: RoleInput::One(role.into()),
            organization_id: organization_id.map(Into::into),
        })
        .unwrap()
    };
    for role in ["", " , "] {
        let empty =
            Box::pin(auth.dispatch_endpoint(update_role(role, Some(&id)), credentials(&owner)))
                .await
                .unwrap_err();
        assert_eq!(empty.error.status_code(), 400);
    }
    let unknown = Box::pin(auth.dispatch_endpoint(
        update_role("nonexistent-role", Some(&id)),
        credentials(&owner),
    ))
    .await
    .unwrap_err();
    assert_eq!(unknown.error.status_code(), 400);
    assert_eq!(
        unknown.body.unwrap().to_json_value().unwrap()["code"],
        "ROLE_NOT_FOUND"
    );
    let promoted = Box::pin(
        auth.dispatch_endpoint(update_role("admin", Some("")), credentials(&active_owner)),
    )
    .await
    .unwrap()
    .decode()
    .unwrap();
    assert_eq!(promoted.organization_id, id);
    assert_eq!(promoted.role, "admin");
    let removed = Box::pin(
        auth.dispatch_endpoint(
            OrganizationPlugin::remove_member_endpoint(&RemoveMemberRequest {
                member_id_or_email: accepted.decode().unwrap().member.id,
                organization_id: Some(id.clone()),
            })
            .unwrap(),
            credentials(&owner),
        ),
    )
    .await
    .unwrap()
    .decode()
    .unwrap();
    assert_eq!(removed.member.member.user_id, recipient_id);
    let role = Box::pin(
        auth.dispatch_endpoint(
            OrganizationPlugin::create_role_endpoint(&CreateRoleRequest {
                organization_id: Some(id.clone()),
                role: "reviewer".into(),
                permission: [("organization".into(), vec!["update".into()])].into(),
            })
            .unwrap(),
            credentials(&owner),
        ),
    )
    .await
    .unwrap()
    .decode()
    .unwrap();
    assert!(role.success);
    assert_eq!(
        role.role_data.permission.unwrap()["organization"],
        vec!["update"]
    );
    let read = Box::pin(
        auth.dispatch_endpoint(
            OrganizationPlugin::get_role_endpoint(&RoleQuery {
                organization_id: Some(id.clone()),
                role_id: Some(role.role_data.id),
                ..Default::default()
            })
            .unwrap(),
            credentials(&owner),
        ),
    )
    .await
    .unwrap()
    .decode()
    .unwrap();
    assert_eq!(read.role, "reviewer");
    let removed_team = Box::pin(
        auth.dispatch_endpoint(
            OrganizationPlugin::remove_team_endpoint(&RemoveTeamRequest {
                team_id: team.id,
                organization_id: Some(id.clone()),
            })
            .unwrap(),
            credentials(&owner),
        ),
    )
    .await
    .unwrap()
    .decode()
    .unwrap();
    assert_eq!(removed_team.message, "Team removed successfully.");
    let deleted = Box::pin(
        auth.dispatch_endpoint(
            OrganizationPlugin::delete_endpoint(&DeleteOrganizationRequest {
                organization_id: id,
            })
            .unwrap(),
            credentials(&owner),
        ),
    )
    .await
    .unwrap()
    .decode()
    .unwrap()
    .unwrap();
    assert_eq!(deleted.name, "Patched");
    assert!(
        Box::pin(auth.dispatch_endpoint(
            OrganizationPlugin::list_organizations_endpoint(),
            credentials(&owner)
        ))
        .await
        .unwrap()
        .decode()
        .unwrap()
        .is_empty()
    );
}

#[tokio::test]
async fn native_invitation_transitions_and_logical_errors_keep_their_public_contract() {
    let auth = AuthBuilder::without_database(AuthConfig::new(
        "organization-native-at-least-32-char-secret",
    ))
    .plugin(EmailPasswordPlugin::new())
    .plugin(OrganizationPlugin::new())
    .endpoint_hook(Patch)
    .build()
    .await
    .unwrap();
    let (owner, _) = signup(&auth, "owner2@example.test").await;
    let (recipient, _) = signup(&auth, "recipient2@example.test").await;
    let created = Box::pin(
        auth.dispatch_endpoint(
            OrganizationPlugin::create_endpoint(
                &CreateOrganizationRequest {
                    additional_fields: Default::default(),
                    name: "Transitions".into(),
                    slug: "transitions".into(),
                    logo: None,
                    metadata: None,
                    keep_current_active_organization: None,
                },
                None,
            )
            .unwrap(),
            credentials(&owner),
        ),
    )
    .await
    .unwrap()
    .decode()
    .unwrap();
    let id = created.organization.id;
    let denied = Box::pin(
        auth.dispatch_endpoint(
            OrganizationPlugin::set_active_endpoint(&SetActiveOrganizationRequest {
                organization_id: NullableStringField::Value("missing".into()),
                organization_slug: None,
            })
            .unwrap(),
            credentials(&owner),
        ),
    )
    .await
    .unwrap_err();
    assert_eq!(denied.error.status_code(), 403);
    assert!(
        denied
            .headers
            .unwrap()
            .get_all("set-cookie")
            .any(|value| value.starts_with("application=after"))
    );
    // Before hooks run before validation; the invalid slug must still prevent the write.
    let invalid = Box::pin(
        auth.dispatch_endpoint(
            OrganizationPlugin::update_endpoint(&UpdateOrganizationRequest {
                organization_id: Some(id.clone()),
                data: UpdateOrganizationData {
                    additional_fields: Default::default(),
                    name: None,
                    slug: Some(String::new()),
                    logo: None,
                    metadata: None,
                },
            })
            .unwrap(),
            credentials(&owner),
        ),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(invalid.error,better_auth_core::AuthError::Api { ref code, .. } if code.as_deref()==Some("VALIDATION_ERROR"))
    );
    let read = Box::pin(
        auth.dispatch_endpoint(
            OrganizationPlugin::get_organization_endpoint(&GetOrganizationQuery {
                organization_id: Some(id.clone()),
                ..Default::default()
            })
            .unwrap(),
            credentials(&owner),
        ),
    )
    .await
    .unwrap()
    .decode()
    .unwrap()
    .unwrap();
    assert_eq!(read.name, "Transitions");
    let invitation = Box::pin(
        auth.dispatch_endpoint(
            OrganizationPlugin::invite_member_endpoint(&InviteMemberRequest {
                email: "recipient2@example.test".into(),
                role: RoleInput::One("member".into()),
                organization_id: Some(id.clone()),
                team_id: None,
                resend: None,
            })
            .unwrap(),
            credentials(&owner),
        ),
    )
    .await
    .unwrap()
    .decode()
    .unwrap();
    let pending = Box::pin(
        auth.dispatch_endpoint(
            OrganizationPlugin::list_user_invitations_endpoint(&ListUserInvitationsQuery {
                email: Some("recipient2@example.test".into()),
            })
            .unwrap(),
            Default::default(),
        ),
    )
    .await
    .unwrap()
    .decode()
    .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].invitation.id, invitation.id);
    let rejected = Box::pin(
        auth.dispatch_endpoint(
            OrganizationPlugin::reject_invitation_endpoint(&RejectInvitationRequest {
                invitation_id: invitation.id.clone(),
            })
            .unwrap(),
            credentials(&recipient),
        ),
    )
    .await
    .unwrap()
    .decode()
    .unwrap();
    assert_eq!(
        rejected.invitation.status,
        better_auth_core::InvitationStatus::Rejected
    );
    assert!(rejected.member.is_none());
    let listed = Box::pin(
        auth.dispatch_endpoint(
            OrganizationPlugin::list_invitations_endpoint(&ListInvitationsQuery {
                organization_id: Some(id.clone()),
            })
            .unwrap(),
            credentials(&owner),
        ),
    )
    .await
    .unwrap()
    .decode()
    .unwrap();
    assert_eq!(
        listed[0].status,
        better_auth_core::InvitationStatus::Rejected
    );
    let invitation = Box::pin(
        auth.dispatch_endpoint(
            OrganizationPlugin::invite_member_endpoint(&InviteMemberRequest {
                email: "recipient2@example.test".into(),
                role: RoleInput::One("member".into()),
                organization_id: Some(id.clone()),
                team_id: None,
                resend: None,
            })
            .unwrap(),
            credentials(&owner),
        ),
    )
    .await
    .unwrap()
    .decode()
    .unwrap();
    let canceled = Box::pin(
        auth.dispatch_endpoint(
            OrganizationPlugin::cancel_invitation_endpoint(&CancelInvitationRequest {
                invitation_id: invitation.id,
            })
            .unwrap(),
            credentials(&owner),
        ),
    )
    .await
    .unwrap()
    .decode()
    .unwrap();
    assert_eq!(
        canceled.status,
        better_auth_core::InvitationStatus::Canceled
    );
    let mut client = credentials(&recipient);
    client.request = Some(AuthRequest::new(HttpMethod::Get, "/original-client"));
    let rejected_selector = Box::pin(
        auth.dispatch_endpoint(
            OrganizationPlugin::list_user_invitations_endpoint(&ListUserInvitationsQuery {
                email: Some("recipient2@example.test".into()),
            })
            .unwrap(),
            client,
        ),
    )
    .await
    .unwrap_err();
    assert_eq!(rejected_selector.error.status_code(), 400);
    let disabled = Box::pin(
        auth.dispatch_endpoint(
            OrganizationPlugin::create_team_endpoint(&CreateTeamRequest {
                name: "Disabled".into(),
                organization_id: Some(id),
            })
            .unwrap(),
            credentials(&owner),
        ),
    )
    .await
    .unwrap_err();
    assert_eq!(disabled.error.status_code(), 404);
}
