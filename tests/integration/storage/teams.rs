//! Teams, dynamic roles and compound invitation acceptance.

use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use better_auth::{AuthConfig, AuthSchema};
use better_auth_core::entity::{AuthSession, AuthUser};
use better_auth_core::store::SchemaMigrator;
use better_auth_core::store::{
    AuthStore, InvitationStore, MemberStore, OrganizationRoleStore, SessionStore, TeamStore,
    UserStore,
};
use better_auth_core::types::{
    AddTeamMemberResult, CreateInvitation, CreateMember, CreateOrganization,
    CreateOrganizationRole, CreateSession, CreateTeam, CreateUser, Invitation, InvitationStatus,
    OrganizationRoleSelector, Team, UpdateOrganizationRole,
};
use better_auth_core::{AuthError, AuthResult};
use chrono::{Duration, Utc};
use std::sync::Arc;
use tokio::{sync::Barrier, task::JoinSet};

backend_tests!(
    configured_query_limit_bounds_public_lists_without_truncating_owned_deletion,
    invitation_acceptance_is_atomic_for_capacity_identity_and_tenant_failures,
    invitation_expiry_and_membership_limit_preserve_pending_state_and_single_team_updates_session,
    deleting_team_prunes_only_live_pending_invitation_links,
    member_and_user_deletion_clean_team_links_and_release_capacity,
    dynamic_roles_scope_reads_and_mutations_and_persist_json_permission_values,
    independent_stores_enforce_team_capacity_and_one_invitation_acceptance_winner,
);
postgres_tests!(
    configured_query_limit_bounds_public_lists_without_truncating_owned_deletion,
    invitation_acceptance_is_atomic_for_capacity_identity_and_tenant_failures,
    invitation_expiry_and_membership_limit_preserve_pending_state_and_single_team_updates_session,
    deleting_team_prunes_only_live_pending_invitation_links,
    member_and_user_deletion_clean_team_links_and_release_capacity,
    dynamic_roles_scope_reads_and_mutations_and_persist_json_permission_values,
    independent_stores_enforce_team_capacity_and_one_invitation_acceptance_winner,
);

const SECRET: &str = "organization-storage-local-test-secret-32-chars";

async fn organization<S: AuthSchema>(store: &dyn AuthStore<S>, slug: &str) -> AuthResult<String> {
    Ok(store
        .create_organization(CreateOrganization::new(slug, slug))
        .await?
        .id)
}

async fn user<S: AuthSchema>(store: &dyn AuthStore<S>, prefix: &str) -> AuthResult<String> {
    Ok(store
        .create_user(CreateUser::new().with_email(format!("{prefix}@example.com")))
        .await?
        .id()
        .into_owned())
}

async fn room<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    organization_id: &str,
    name: &str,
) -> AuthResult<Team> {
    store
        .create_team(CreateTeam {
            name: name.to_owned(),
            organization_id: organization_id.to_owned(),
            updated_at: None,
        })
        .await
}

async fn session<S: AuthSchema>(store: &dyn AuthStore<S>, user_id: &str) -> AuthResult<String> {
    Ok(store
        .create_session(CreateSession {
            additional_fields: better_auth_core::field_policy::FieldValues::default(),
            token: None,
            user_id: user_id.to_owned(),
            expires_at: Utc::now() + Duration::hours(1),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
        })
        .await?
        .token()
        .to_owned())
}

async fn invite<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    organization_id: &str,
    inviter_id: &str,
    email: &str,
    teams: &[&str],
) -> AuthResult<Invitation> {
    let mut data = CreateInvitation::new(
        organization_id,
        email,
        "member",
        inviter_id,
        Utc::now() + Duration::hours(1),
    );
    data.team_id = (!teams.is_empty()).then(|| teams.join(","));
    store.create_invitation(data).await
}

async fn stored_count<S: AuthSchema>(store: &dyn AuthStore<S>, team_id: &str) -> AuthResult<i64> {
    Ok(store
        .get_team(None, team_id)
        .await?
        .ok_or_else(|| AuthError::internal("Team disappeared"))?
        .member_count)
}

async fn configured_query_limit_bounds_public_lists_without_truncating_owned_deletion<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let mut config = AuthConfig::new(SECRET);
    config.advanced.database.default_find_many_limit = 2;
    let limited = B::store(Arc::new(config), &connection);
    let org = organization(&store, "configured-query-limit").await?;
    let principal = user(&store, "query-limit-principal").await?;
    let first = room(&store, &org, "First").await?;
    let second = room(&store, &org, "Second").await?;
    let third = room(&store, &org, "Third").await?;
    for team in [&third, &first, &second] {
        drop(store.add_team_member(&team.id, &principal, None).await?);
    }
    for prefix in ["limit-other-one", "limit-other-two"] {
        let member = user(&store, prefix).await?;
        drop(store.add_team_member(&first.id, &member, None).await?);
    }
    for name in ["first-role", "second-role", "third-role"] {
        drop(
            store
                .create_organization_role(CreateOrganizationRole {
                    organization_id: org.clone(),
                    role: name.to_owned(),
                    permission: better_auth_core::OrganizationPermissions::default(),
                })
                .await?,
        );
    }
    assert_eq!(
        limited
            .list_teams(&org)
            .await?
            .iter()
            .map(|row| row.name.as_str())
            .collect::<Vec<_>>(),
        vec!["First", "Second"]
    );
    assert_eq!(limited.list_team_members(&first.id).await?.len(), 2);
    assert_eq!(
        limited
            .list_user_teams(&principal)
            .await?
            .iter()
            .map(|row| row.name.as_str())
            .collect::<Vec<_>>(),
        vec!["Third", "First"]
    );
    assert_eq!(
        limited
            .list_organization_roles(&org)
            .await?
            .iter()
            .map(|row| row.role.as_str())
            .collect::<Vec<_>>(),
        vec!["first-role", "second-role"]
    );
    assert_eq!(limited.count_organization_roles(&org).await?, 3);
    assert_eq!(stored_count(&limited, &first.id).await?, 3);
    limited.delete_user(&principal).await?;
    for team in [&first, &second, &third] {
        assert!(store.get_team_member(&team.id, &principal).await?.is_none());
    }
    assert_eq!(stored_count(&store, &first.id).await?, 2);
    assert_eq!(stored_count(&store, &second.id).await?, 0);
    assert_eq!(stored_count(&store, &third.id).await?, 0);
    B::close(connection).await
}

async fn invitation_acceptance_is_atomic_for_capacity_identity_and_tenant_failures<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let org = organization(&store, "compound-invitation").await?;
    let other_org = organization(&store, "other-organization").await?;
    let inviter = user(&store, "inviter").await?;
    let recipient = user(&store, "invitee").await?;
    let wrong_user = user(&store, "wrong-user").await?;
    let blocker = user(&store, "seat-blocker").await?;
    let first = room(&store, &org, "First").await?;
    let second = room(&store, &org, "Second").await?;
    let foreign = room(&store, &other_org, "Foreign").await?;
    let token = session(&store, &recipient).await?;
    let wrong_token = session(&store, &wrong_user).await?;
    let invitation = invite(
        &store,
        &org,
        &inviter,
        "invitee@example.com",
        &[&first.id, &second.id],
    )
    .await?;
    drop(
        store
            .add_team_member(&second.id, &blocker, Some(1.0))
            .await?,
    );
    let limits = vec![
        (first.id.clone(), Some(1.0)),
        (second.id.clone(), Some(1.0)),
    ];

    assert!(
        store
            .accept_invitation_with_teams(&invitation.id, &recipient, &token, &limits, None)
            .await
            .is_err()
    );
    assert!(
        store
            .get_team_member(&first.id, &recipient)
            .await?
            .is_none()
    );
    assert!(
        store
            .get_team_member(&second.id, &recipient)
            .await?
            .is_none()
    );
    assert!(store.get_member(&org, &recipient).await?.is_none());
    assert_eq!(stored_count(&store, &first.id).await?, 0);
    assert_eq!(stored_count(&store, &second.id).await?, 1);
    assert_eq!(
        store
            .get_invitation_by_id(&invitation.id)
            .await?
            .map(|row| row.status),
        Some(InvitationStatus::Pending)
    );
    let unchanged = store
        .get_session(&token)
        .await?
        .ok_or("Session disappeared")?;
    assert!(unchanged.active_organization_id().is_none());
    assert!(unchanged.active_team_id().is_none());

    let tenant_invitation = invite(
        &store,
        &org,
        &inviter,
        "invitee@example.com",
        &[&first.id, &foreign.id],
    )
    .await?;
    assert!(
        store
            .accept_invitation_with_teams(&tenant_invitation.id, &recipient, &token, &[], None)
            .await
            .is_err()
    );
    assert!(
        store
            .get_team_member(&first.id, &recipient)
            .await?
            .is_none()
    );
    assert!(
        store
            .get_team_member(&foreign.id, &recipient)
            .await?
            .is_none()
    );
    assert_eq!(
        store
            .get_invitation_by_id(&tenant_invitation.id)
            .await?
            .map(|row| row.status),
        Some(InvitationStatus::Pending)
    );

    assert_eq!(store.remove_team_member(&second.id, &blocker).await?, 1);
    // Available seats ensure these failures prove ownership and session
    // checks, rather than accidentally succeeding at a later capacity guard.
    assert!(matches!(
        store.accept_invitation_with_teams(&invitation.id, &wrong_user, &wrong_token, &limits, None).await,
        Err(AuthError::Forbidden(message)) if message == "This invitation is not for you"
    ));
    assert!(matches!(
        store
            .accept_invitation_with_teams(&invitation.id, &recipient, &wrong_token, &limits, None)
            .await,
        Err(AuthError::SessionNotFound)
    ));
    assert!(store.get_member(&org, &wrong_user).await?.is_none());
    assert!(
        store
            .get_team_member(&first.id, &wrong_user)
            .await?
            .is_none()
    );
    assert!(
        store
            .get_team_member(&second.id, &wrong_user)
            .await?
            .is_none()
    );
    let wrong_session = store
        .get_session(&wrong_token)
        .await?
        .ok_or("Wrong-user session disappeared")?;
    assert!(wrong_session.active_organization_id().is_none());
    assert!(wrong_session.active_team_id().is_none());

    let expired_token = session(&store, &recipient).await?;
    db.set_timestamp(
        "sessions",
        "expires_at",
        ("token", &expired_token),
        Utc::now() - Duration::minutes(1),
    )
    .await?;
    assert!(matches!(
        store
            .accept_invitation_with_teams(&invitation.id, &recipient, &expired_token, &limits, None)
            .await,
        Err(AuthError::SessionNotFound)
    ));
    // A persisted, revoked session cannot authorize the compound transition.
    // Capacity is available here so a missing active predicate cannot hide
    // behind the team's capacity rejection.
    let revoked_token = session(&store, &recipient).await?;
    _ = db
        .execute(
            "UPDATE sessions SET active=FALSE WHERE token=$1",
            &[&revoked_token],
        )
        .await?;
    assert!(matches!(
        store
            .accept_invitation_with_teams(&invitation.id, &recipient, &revoked_token, &limits, None)
            .await,
        Err(AuthError::SessionNotFound)
    ));
    assert!(store.get_member(&org, &recipient).await?.is_none());
    assert!(
        store
            .get_team_member(&first.id, &recipient)
            .await?
            .is_none()
    );
    assert!(
        store
            .get_team_member(&second.id, &recipient)
            .await?
            .is_none()
    );
    assert_eq!(
        store
            .get_invitation_by_id(&invitation.id)
            .await?
            .map(|row| row.status),
        Some(InvitationStatus::Pending)
    );
    let accepted = store
        .accept_invitation_with_teams(&invitation.id, &recipient, &token, &limits, None)
        .await?
        .ok_or("Invitation was not accepted")?;
    assert_eq!(accepted.0.status, InvitationStatus::Accepted);
    assert_eq!(accepted.1.organization_id, org);
    assert_eq!(accepted.1.user_id, recipient);
    assert_eq!(stored_count(&store, &first.id).await?, 1);
    assert_eq!(stored_count(&store, &second.id).await?, 1);
    assert!(
        store
            .get_team_member(&first.id, &recipient)
            .await?
            .is_some()
    );
    assert!(
        store
            .get_team_member(&second.id, &recipient)
            .await?
            .is_some()
    );
    let changed = store
        .get_session(&token)
        .await?
        .ok_or("Session disappeared")?;
    assert_eq!(changed.active_organization_id(), Some(org.as_str()));
    assert!(changed.active_team_id().is_none());
    assert!(
        store
            .accept_invitation_with_teams(&invitation.id, &recipient, &token, &limits, None)
            .await?
            .is_none()
    );
    assert_eq!(store.list_organization_members(&org).await?.len(), 1);
    B::close(connection).await
}

async fn invitation_expiry_and_membership_limit_preserve_pending_state_and_single_team_updates_session<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let org = organization(&store, "single-team-invitation").await?;
    let inviter = user(&store, "single-inviter").await?;
    let recipient = user(&store, "single-invitee").await?;
    let team = room(&store, &org, "Only").await?;
    let token = session(&store, &recipient).await?;
    let expired = store
        .create_invitation(CreateInvitation::new(
            &org,
            "single-invitee@example.com",
            "member",
            &inviter,
            Utc::now() - Duration::minutes(1),
        ))
        .await?;
    assert!(
        store
            .accept_invitation_with_teams(&expired.id, &recipient, &token, &[], None)
            .await?
            .is_none()
    );
    let invitation = invite(
        &store,
        &org,
        &inviter,
        "single-invitee@example.com",
        &[&team.id],
    )
    .await?;
    assert!(
        store
            .accept_invitation_with_teams(&invitation.id, &recipient, &token, &[], Some(0))
            .await
            .is_err()
    );
    assert!(store.list_team_members(&team.id).await?.is_empty());
    assert_eq!(
        store
            .get_invitation_by_id(&invitation.id)
            .await?
            .map(|row| row.status),
        Some(InvitationStatus::Pending)
    );
    drop(
        store
            .accept_invitation_with_teams(&invitation.id, &recipient, &token, &[], Some(1))
            .await?
            .ok_or("Expected accepted invitation")?,
    );
    let persisted = store
        .get_session(&token)
        .await?
        .ok_or("Session disappeared")?;
    assert_eq!(persisted.active_team_id(), Some(team.id.as_str()));
    assert_eq!(persisted.active_organization_id(), Some(org.as_str()));
    B::close(connection).await
}

async fn deleting_team_prunes_only_live_pending_invitation_links<B: Backend>(db: Db) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let org = organization(&store, "team-delete").await?;
    let other_org = organization(&store, "team-delete-other").await?;
    let inviter = user(&store, "delete-inviter").await?;
    let first = room(&store, &org, "First").await?;
    let remaining = room(&store, &org, "Remaining").await?;
    let linked = invite(
        &store,
        &org,
        &inviter,
        "linked@example.com",
        &[&first.id, &remaining.id],
    )
    .await?;
    let only = invite(&store, &org, &inviter, "only@example.com", &[&first.id]).await?;
    let accepted = invite(&store, &org, &inviter, "accepted@example.com", &[&first.id]).await?;
    drop(
        store
            .update_invitation_status(&accepted.id, InvitationStatus::Accepted)
            .await?,
    );
    let mut expired_data = CreateInvitation::new(
        &org,
        "expired@example.com",
        "member",
        &inviter,
        Utc::now() - Duration::minutes(1),
    );
    expired_data.team_id = Some(first.id.clone());
    let expired = store.create_invitation(expired_data).await?;
    drop(store.add_team_member(&first.id, &inviter, None).await?);
    assert!(!store.delete_team(&other_org, &first.id).await?);
    assert!(store.get_team(Some(&org), &first.id).await?.is_some());
    assert!(store.delete_team(&org, &first.id).await?);
    assert!(store.list_team_members(&first.id).await?.is_empty());
    let team_of = |invitation: Option<Invitation>| invitation.and_then(|row| row.team_id);
    assert_eq!(
        team_of(store.get_invitation_by_id(&linked.id).await?),
        Some(remaining.id)
    );
    assert_eq!(team_of(store.get_invitation_by_id(&only.id).await?), None);
    assert_eq!(
        team_of(store.get_invitation_by_id(&accepted.id).await?),
        Some(first.id.clone())
    );
    assert_eq!(
        team_of(store.get_invitation_by_id(&expired.id).await?),
        Some(first.id)
    );
    B::close(connection).await
}

async fn member_and_user_deletion_clean_team_links_and_release_capacity<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let first_org = organization(&store, "cleanup-first").await?;
    let second_org = organization(&store, "cleanup-second").await?;
    let principal = user(&store, "cleanup-principal").await?;
    let replacement = user(&store, "cleanup-replacement").await?;
    let first_member = store
        .create_member(CreateMember::new(&first_org, &principal, "member"))
        .await?;
    drop(
        store
            .create_member(CreateMember::new(&second_org, &principal, "member"))
            .await?,
    );
    let first = room(&store, &first_org, "First").await?;
    let second = room(&store, &second_org, "Second").await?;
    drop(
        store
            .add_team_member(&second.id, &principal, Some(1.0))
            .await?,
    );
    drop(
        store
            .add_team_member(&first.id, &principal, Some(1.0))
            .await?,
    );
    // Joined user-team lists follow membership insertion, even when team
    // creation order differs. Sorting the teams would change this contract.
    assert_eq!(
        store
            .list_user_teams(&principal)
            .await?
            .iter()
            .map(|team| team.id.as_str())
            .collect::<Vec<_>>(),
        vec![second.id.as_str(), first.id.as_str()]
    );
    store.delete_member(&first_member.id).await?;
    assert!(
        store
            .get_team_member(&first.id, &principal)
            .await?
            .is_none()
    );
    assert!(
        store
            .get_team_member(&second.id, &principal)
            .await?
            .is_some()
    );
    assert_eq!(stored_count(&store, &first.id).await?, 0);
    assert_eq!(stored_count(&store, &second.id).await?, 1);
    assert!(matches!(
        store
            .add_team_member(&first.id, &replacement, Some(1.0))
            .await?,
        AddTeamMemberResult::Added(_)
    ));
    store.delete_user(&principal).await?;
    assert!(store.list_user_teams(&principal).await?.is_empty());
    assert_eq!(stored_count(&store, &second.id).await?, 0);
    B::close(connection).await
}

async fn dynamic_roles_scope_reads_and_mutations_and_persist_json_permission_values<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let org = organization(&store, "role-storage").await?;
    let foreign = organization(&store, "role-storage-foreign").await?;
    let role = store
        .create_organization_role(CreateOrganizationRole {
            organization_id: org.clone(),
            role: "manager".to_owned(),
            permission: [(
                "team".to_owned(),
                vec!["create".to_owned(), "update".to_owned()],
            )]
            .into(),
        })
        .await?;
    assert!(role.updated_at.is_none());
    let selector = OrganizationRoleSelector::Id(role.id.clone());
    assert!(
        store
            .get_organization_role(&foreign, &selector)
            .await?
            .is_none()
    );
    assert!(!store.delete_organization_role(&foreign, &selector).await?);
    assert!(
        store
            .update_organization_role(
                &foreign,
                &selector,
                UpdateOrganizationRole {
                    role: Some("renamed".to_owned()),
                    permission: None
                }
            )
            .await
            .is_err()
    );
    let updated = store
        .update_organization_role(
            &org,
            &selector,
            UpdateOrganizationRole {
                role: Some("renamed".to_owned()),
                permission: Some([("member".to_owned(), vec!["update".to_owned()])].into()),
            },
        )
        .await?;
    assert_eq!(updated.role, "renamed");
    assert!(
        updated
            .updated_at
            .is_some_and(|timestamp| timestamp >= role.created_at)
    );
    assert!(
        store
            .get_organization_role(&org, &OrganizationRoleSelector::Name("manager".to_owned()))
            .await?
            .is_none()
    );
    assert_eq!(
        db.text(
            "SELECT permission FROM organization_role WHERE id=$1",
            &[&role.id]
        )
        .await?,
        Some(r#"{"member":["update"]}"#.to_owned())
    );
    assert!(
        store
            .delete_organization_role(&org, &OrganizationRoleSelector::Name("renamed".to_owned()))
            .await?
    );
    assert!(store.list_organization_roles(&org).await?.is_empty());
    B::close(connection).await
}

// These requests use independent connection pools. The seat limit and one-use
// invitation transition must be enforced by SQL across service instances.
async fn independent_stores_enforce_team_capacity_and_one_invitation_acceptance_winner<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let config = Arc::new(AuthConfig::new(
        "organization-race-local-test-secret-32-chars",
    ));
    let mut connections = Vec::new();
    let mut stores = Vec::new();
    for index in 0..8 {
        let connection = B::connect(&db.url, Some(1)).await?;
        let store = B::store(Arc::clone(&config), &connection);
        if index == 0 {
            store.migrate().await?;
        }
        stores.push(Arc::new(store));
        connections.push(connection);
    }
    let primary = stores[0].as_ref();
    let org = organization(primary, "team-race").await?;
    let team = room(primary, &org, "Capacity").await?;
    let mut user_ids = Vec::new();
    for index in 0..8 {
        user_ids.push(user(primary, &format!("seat-{index}")).await?);
    }
    let maximum = if db.is_postgres() { 2.0 } else { 1.5 };
    if db.is_postgres() {
        let physical_before = db
            .text(
                "SELECT row_to_json(t)::text FROM team t WHERE id = $1",
                &[&team.id],
            )
            .await?;
        for number in [1.5, f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 1e-7, 1e21] {
            assert!(
                matches!(
                    primary
                        .add_team_member(&team.id, &user_ids[0], Some(number))
                        .await,
                    Err(AuthError::Database(_))
                ),
                "PostgreSQL must reject the actual Number text: {number}"
            );
            assert_eq!(
                db.text(
                    "SELECT row_to_json(t)::text FROM team t WHERE id = $1",
                    &[&team.id]
                )
                .await?,
                physical_before
            );
            assert_eq!(
                db.count_where(
                    "SELECT COUNT(*) FROM team_member WHERE team_id = $1",
                    &[&team.id]
                )
                .await?,
                0
            );
        }
        for number in [0.0, -1.0] {
            assert!(matches!(
                primary
                    .add_team_member(&team.id, &user_ids[0], Some(number))
                    .await?,
                AddTeamMemberResult::LimitReached
            ));
            assert_eq!(
                db.text(
                    "SELECT row_to_json(t)::text FROM team t WHERE id = $1",
                    &[&team.id]
                )
                .await?,
                physical_before
            );
        }
    }
    let barrier = Arc::new(Barrier::new(8));
    let mut tasks = JoinSet::new();
    for (store, user_id) in stores.iter().zip(&user_ids) {
        let store = Arc::clone(store);
        let user_id = user_id.clone();
        let team_id = team.id.clone();
        let barrier = Arc::clone(&barrier);
        drop(tasks.spawn(async move {
            _ = barrier.wait().await;
            store
                .add_team_member(&team_id, &user_id, Some(maximum))
                .await
        }));
    }
    let mut admitted = Vec::new();
    let mut rejected = 0;
    while let Some(result) = tasks.join_next().await {
        match result?? {
            AddTeamMemberResult::Added(row) => admitted.push(row),
            AddTeamMemberResult::LimitReached => rejected += 1,
            AddTeamMemberResult::Existing(_) => return Err("Unexpected existing membership".into()),
        }
    }
    assert_eq!(admitted.len(), 2);
    assert_eq!(rejected, 6);
    assert_eq!(stored_count(primary, &team.id).await?, 2);
    assert_eq!(primary.list_team_members(&team.id).await?.len(), 2);
    assert_eq!(
        admitted
            .iter()
            .filter_map(|row| row.membership_key.as_deref())
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        2
    );
    for membership in &admitted {
        let AddTeamMemberResult::Existing(existing) = primary
            .add_team_member(&team.id, &membership.user_id, Some(maximum))
            .await?
        else {
            return Err("Repeated admission created a second membership".into());
        };
        assert_eq!(existing.id, membership.id);
        assert_eq!(existing.membership_key, membership.membership_key);
    }
    assert_eq!(stored_count(primary, &team.id).await?, 2);
    let first = &admitted[0];
    assert_eq!(
        primary.remove_team_member(&team.id, &first.user_id).await?,
        1
    );
    assert_eq!(
        primary.remove_team_member(&team.id, &first.user_id).await?,
        0
    );
    assert_eq!(stored_count(primary, &team.id).await?, 1);
    assert!(matches!(
        primary
            .add_team_member(&team.id, &first.user_id, Some(maximum))
            .await?,
        AddTeamMemberResult::Added(_)
    ));
    let invitee = user(primary, "race-invitee").await?;
    let target = room(primary, &org, "Invitation").await?;
    let invitation = invite(
        primary,
        &org,
        &user_ids[0],
        "race-invitee@example.com",
        &[&target.id],
    )
    .await?;
    let token = session(primary, &invitee).await?;
    let barrier = Arc::new(Barrier::new(8));
    let mut tasks = JoinSet::new();
    for store in &stores {
        let store = Arc::clone(store);
        let barrier = Arc::clone(&barrier);
        let invite_id = invitation.id.clone();
        let user_id = invitee.clone();
        let token = token.clone();
        let team_id = target.id.clone();
        drop(tasks.spawn(async move {
            _ = barrier.wait().await;
            store
                .accept_invitation_with_teams(
                    &invite_id,
                    &user_id,
                    &token,
                    &[(team_id, Some(1.0))],
                    None,
                )
                .await
        }));
    }
    let mut winners = 0;
    while let Some(result) = tasks.join_next().await {
        if result??.is_some() {
            winners += 1;
        }
    }
    assert_eq!(winners, 1);
    assert_eq!(primary.list_organization_members(&org).await?.len(), 1);
    assert_eq!(primary.list_team_members(&target.id).await?.len(), 1);
    assert_eq!(stored_count(primary, &target.id).await?, 1);
    assert_eq!(
        primary
            .get_invitation_by_id(&invitation.id)
            .await?
            .map(|row| row.status),
        Some(InvitationStatus::Accepted)
    );
    drop(stores);
    for connection in connections {
        B::close(connection).await?;
    }
    Ok(())
}
