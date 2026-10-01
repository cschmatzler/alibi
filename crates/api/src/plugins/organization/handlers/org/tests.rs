use better_auth_core::types::{CreateOrganization, CreateUser, HttpMethod};

use chrono::Duration;

use crate::plugins::organization::OrganizationConfig;

use crate::plugins::test_helpers::{
    create_auth_json_request_no_query, create_test_context, create_user, create_user_and_session,
};

use super::{get_full_organization_core, handle_create_organization};

use crate::plugins::organization::types::GetFullOrganizationQuery;

fn test_config() -> OrganizationConfig {
        OrganizationConfig {
            allow_user_to_create_organization: true,
            organization_limit: None,
            creation_policy: None,
            creation_hooks: None,
            update_hooks: None,
            member_role_hooks: None,
            member_removal_hooks: None,
            member_addition_hooks: None,
            invitation_acceptance_hooks: None,
            deletion_hooks: None,
            membership_limit: Some(crate::plugins::organization::MembershipLimit::Fixed(100.0)),
            creator_role: "owner".to_string(),
            invitation_expires_in: 60 * 60 * 48,
            invitation_limit: Some(100),
            disable_organization_deletion: false,
            roles: None,
            require_email_verification_on_invitation: None,
            teams: Default::default(),
            dynamic_access_control: Default::default(),
            access_control: None,
        }
    }

fn test_user(email: &str, name: &str) -> CreateUser {
    CreateUser {
        email: Some(email.to_owned()),
        name: Some(name.to_owned()),
        ..CreateUser::default()
    }
}

#[tokio::test]
async fn create_organization_keeps_current_active_organization_when_requested() {
    let ctx = create_test_context().await;
    let config = test_config();
    let (user, session) = create_user_and_session(
        &ctx,
        test_user("owner@example.com", "Owner"),
        Duration::hours(1),
    )
    .await;
    let existing = ctx
        .database
        .create_organization(CreateOrganization {
            id: None,
            name: "Existing".to_owned(),
            slug: "existing".to_owned(),
            logo: None,
            metadata: None,
        })
        .await
        .expect("organization should be created");
    ctx.database
        .update_session_active_organization(&session.token, Some(&existing.id))
        .await
        .expect("active organization should update");

    let request = create_auth_json_request_no_query(
        HttpMethod::Post,
        "/organization/create",
        Some(&session.token),
        Some(serde_json::json!({
            "name": "Next",
            "slug": "next",
            "keepCurrentActiveOrganization": true
        })),
    );

    handle_create_organization(&request, &ctx, &config)
        .await
        .expect("request should succeed");

    let updated_session = ctx
        .database
        .get_session(&session.token)
        .await
        .expect("session lookup should succeed")
        .expect("session should exist");
    assert_eq!(updated_session.active_organization_id, Some(existing.id));
    assert_eq!(user.id, session.user_id);
}

#[tokio::test]
async fn create_organization_updates_active_organization_by_default() {
    let ctx = create_test_context().await;
    let config = test_config();
    let (_, session) = create_user_and_session(
        &ctx,
        test_user("owner2@example.com", "Owner"),
        Duration::hours(1),
    )
    .await;

    let request = create_auth_json_request_no_query(
        HttpMethod::Post,
        "/organization/create",
        Some(&session.token),
        Some(serde_json::json!({
            "name": "Created",
            "slug": "created"
        })),
    );

    let response = handle_create_organization(&request, &ctx, &config)
        .await
        .expect("request should succeed");
    let body: serde_json::Value =
        serde_json::from_slice(&response.body).expect("response should be JSON");
    let created_id = (*(body).get("id").unwrap_or(&serde_json::Value::Null))
        .as_str()
        .expect("response should contain organization id");

    let updated_session = ctx
        .database
        .get_session(&session.token)
        .await
        .expect("session lookup should succeed")
        .expect("session should exist");
    assert_eq!(
        updated_session.active_organization_id.as_deref(),
        Some(created_id)
    );
}

#[tokio::test]
async fn get_full_organization_respects_members_limit() {
        let ctx = create_test_context().await;
        let config = test_config();
        let (user, session) = create_user_and_session(
            &ctx,
            test_user("owner3@example.com", "Owner"),
            Duration::hours(1),
        )
        .await;
        let organization = ctx
            .database
            .create_organization(CreateOrganization {
                id: None,
                name: "Team".to_string(),
                slug: "team".to_string(),
                logo: None,
                metadata: None,
            })
            .await
            .expect("organization should be created");
        ctx.database
            .create_member(better_auth_core::types::CreateMember {
                organization_id: organization.id.clone(),
                user_id: user.id.clone(),
                role: config.creator_role.clone(),
            })
            .await
            .expect("owner member should be created");

        let extra_user = create_user(&ctx, test_user("member@example.com", "Member")).await;
        ctx.database
            .create_member(better_auth_core::types::CreateMember {
                organization_id: organization.id.clone(),
                user_id: extra_user.id.clone(),
                role: "member".to_string(),
            })
            .await
            .expect("extra member should be created");

        let response = get_full_organization_core(
            &GetFullOrganizationQuery {
                organization_id: Some(organization.id.clone()),
                organization_slug: None,
                members_limit: Some(1.0),
            },
            &user,
            &session,
            &config,
            &ctx,
        )
        .await
        .expect("request should succeed")
        .expect("organization should exist");

        assert_eq!(response.members.len(), 1);
    }
