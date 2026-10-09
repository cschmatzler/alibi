//! Conditional invitation claims remain separate from membership transactions.

use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use alibi::AuthConfig;
use alibi::entity::{AuthSession, AuthUser};
use alibi::field_policy::FieldValues;
use alibi::store::SchemaMigrator;
use alibi::store::{
    AuthStore, InvitationStore, MemberStore, OrganizationStore, SessionStore, TeamStore, UserStore,
    transaction,
};
use alibi::{
    AuthError, AuthResult, CreateInvitation, CreateMember, CreateOrganization, CreateSession,
    CreateTeam, CreateUser, InvitationStatus,
};
use chrono::{Duration, Utc};
use std::sync::Arc;
use tokio::sync::Barrier;

backend_tests!(
    staged_claim_survives_real_transaction_abort_and_reset_veto_then_retry_commits,
    independent_connections_have_one_exact_invitation_claim_winner,
    pending_invitation_count_excludes_expired_and_non_pending_rows,
    get_pending_invitation_ignores_expired_rows,
);
postgres_tests!(
    independent_connections_have_one_exact_invitation_claim_winner,
    pending_invitation_count_excludes_expired_and_non_pending_rows,
    get_pending_invitation_ignores_expired_rows,
);

struct Seeded {
    user: String,
    org: String,
    foreign: String,
    team: String,
    invitation: String,
    token: String,
}

async fn seed<S: alibi::AuthSchema>(store: &dyn AuthStore<S>) -> AuthResult<Seeded> {
    let user = store
        .create_user(CreateUser::new().with_email("actual@invitation-stage.test"))
        .await?;
    let org = store
        .create_organization(CreateOrganization::new("Actual", "actual-stage"))
        .await?;
    let foreign = store
        .create_organization(CreateOrganization::new("Foreign", "foreign-stage"))
        .await?;
    let team = store
        .create_team(CreateTeam {
            name: "Actual team".into(),
            organization_id: org.id.clone(),
            updated_at: None,
        })
        .await?;
    let session = store
        .create_session(CreateSession {
            user_id: user.id().into_owned(),
            token: None,
            expires_at: Utc::now() + Duration::hours(1),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
            additional_fields: FieldValues::default(),
        })
        .await?;
    let mut input = CreateInvitation::new(
        &org.id,
        "actual@invitation-stage.test",
        "member",
        user.id(),
        Utc::now() + Duration::hours(1),
    );
    input.team_id = Some(team.id.clone());
    let invitation = store.create_invitation(input).await?;
    Ok(Seeded {
        user: user.id().into_owned(),
        org: org.id,
        foreign: foreign.id,
        team: team.id,
        invitation: invitation.id,
        token: session.token().to_owned(),
    })
}

async fn staged_claim_survives_real_transaction_abort_and_reset_veto_then_retry_commits<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("invitation-stage-real-storage-local-secret")
        .await?;
    let Seeded {
        user,
        org,
        foreign,
        team,
        invitation,
        token,
    } = seed(&store).await?;
    let before = store
        .get_session(&token)
        .await?
        .ok_or("missing initial session")?;
    let claimed = store
        .update_invitation_status_if_status(
            &invitation,
            InvitationStatus::Pending,
            InvitationStatus::Accepted,
        )
        .await?
        .ok_or("claim failed")?;
    assert_eq!(claimed.status, InvitationStatus::Accepted);
    _ = db.execute("CREATE TRIGGER stage_member_veto BEFORE INSERT ON member BEGIN SELECT RAISE(ABORT,'actual staged member veto'); END", &[]).await?;
    let (tx_user, tx_org, tx_foreign, tx_team, tx_token) = (
        user.clone(),
        org.clone(),
        foreign.clone(),
        team.clone(),
        token.clone(),
    );
    let result: AuthResult<()> = transaction(&store, move |tx| {
        Box::pin(async move {
            assert!(tx.get_team(&tx_foreign, &tx_team).await?.is_none());
            assert_eq!(
                tx.get_team(&tx_org, &tx_team)
                    .await?
                    .ok_or_else(|| AuthError::internal("missing actual team"))?
                    .id,
                tx_team
            );
            drop(tx.add_team_member(&tx_team, &tx_user, Some(1.0)).await?);
            drop(
                tx.update_session_active_team(&tx_token, Some(&tx_team))
                    .await?,
            );
            drop(
                tx.create_member(CreateMember {
                    organization_id: tx_org,
                    user_id: tx_user,
                    role: "member".into(),
                })
                .await?,
            );
            Ok(())
        })
    })
    .await;
    assert!(matches!(result, Err(AuthError::Database(_))));
    assert!(store.get_member(&org, &user).await?.is_none());
    assert!(store.get_team_member(&team, &user).await?.is_none());
    let after = store
        .get_session(&token)
        .await?
        .ok_or("session missing after rollback")?;
    assert_eq!(
        serde_json::to_value(&after)?,
        serde_json::to_value(&before)?
    );
    assert_eq!(
        store
            .get_invitation_by_id(&invitation)
            .await?
            .ok_or("missing accepted row")?
            .status,
        InvitationStatus::Accepted
    );
    _ = db.execute("CREATE TRIGGER stage_reset_veto BEFORE UPDATE OF status ON invitation WHEN OLD.status='accepted' AND NEW.status='pending' BEGIN SELECT RAISE(ABORT,'actual conditional reset veto'); END", &[]).await?;
    assert!(matches!(
        store
            .update_invitation_status_if_status(
                &invitation,
                InvitationStatus::Accepted,
                InvitationStatus::Pending
            )
            .await,
        Err(AuthError::Database(_))
    ));
    assert_eq!(
        store
            .get_invitation_by_id(&invitation)
            .await?
            .ok_or("missing row after reset veto")?
            .status,
        InvitationStatus::Accepted
    );
    for trigger in ["stage_reset_veto", "stage_member_veto"] {
        _ = db.execute(&format!("DROP TRIGGER {trigger}"), &[]).await?;
    }
    assert!(
        store
            .update_invitation_status_if_status(
                &invitation,
                InvitationStatus::Accepted,
                InvitationStatus::Pending
            )
            .await?
            .is_some()
    );
    assert!(
        store
            .update_invitation_status_if_status(
                &invitation,
                InvitationStatus::Accepted,
                InvitationStatus::Rejected
            )
            .await?
            .is_none()
    );
    assert_eq!(
        store
            .get_invitation_by_id(&invitation)
            .await?
            .ok_or("missing conditional no-op row")?
            .status,
        InvitationStatus::Pending
    );
    drop(
        store
            .update_invitation_status_if_status(
                &invitation,
                InvitationStatus::Pending,
                InvitationStatus::Accepted,
            )
            .await?
            .ok_or("retry claim failed")?,
    );
    let (tx_user, tx_org, tx_team, tx_token) =
        (user.clone(), org.clone(), team.clone(), token.clone());
    let created = transaction(&store, move |tx| {
        Box::pin(async move {
            drop(tx.add_team_member(&tx_team, &tx_user, Some(1.0)).await?);
            drop(
                tx.update_session_active_team(&tx_token, Some(&tx_team))
                    .await?,
            );
            let member = tx
                .create_member(CreateMember {
                    organization_id: tx_org.clone(),
                    user_id: tx_user,
                    role: "member".into(),
                })
                .await?;
            drop(
                tx.update_session_active_organization(&tx_token, Some(&tx_org))
                    .await?,
            );
            Ok(member)
        })
    })
    .await?;
    assert_eq!(created.user_id, user);
    assert_eq!(created.organization_id, org);
    assert!(store.get_team_member(&team, &user).await?.is_some());
    let final_session = store
        .get_session(&token)
        .await?
        .ok_or("missing selected session")?;
    assert_eq!(final_session.token(), before.token());
    assert_eq!(final_session.active_team_id(), Some(team.as_str()));
    assert_eq!(final_session.active_organization_id(), Some(org.as_str()));
    assert!(store.get_member(&foreign, &user).await?.is_none());
    B::close(connection).await
}

async fn independent_connections_have_one_exact_invitation_claim_winner<B: Backend>(
    db: Db,
) -> TestResult {
    let config = Arc::new(AuthConfig::new("invitation-stage-independent-secret"));
    let first_db = B::connect(&db.url, Some(1)).await?;
    let first = Arc::new(B::store(Arc::clone(&config), &first_db));
    first.migrate().await?;
    let seeded = seed(first.as_ref()).await?;
    let id = seeded.invitation;
    let before = first
        .get_invitation_by_id(&id)
        .await?
        .ok_or("missing initial invitation")?;
    let other = B::connect(&db.url, None).await?;
    let second = Arc::new(B::store(config, &other));
    let barrier = Arc::new(Barrier::new(2));
    let mut tasks = tokio::task::JoinSet::new();
    for store in [Arc::clone(&first), second] {
        let id = id.clone();
        let barrier = Arc::clone(&barrier);
        drop(tasks.spawn(async move {
            _ = barrier.wait().await;
            store
                .update_invitation_status_if_status(
                    &id,
                    InvitationStatus::Pending,
                    InvitationStatus::Accepted,
                )
                .await
        }));
    }
    let mut winners = 0;
    while let Some(result) = tasks.join_next().await {
        if let Some(row) = result?? {
            assert_eq!(row.id, id);
            assert_eq!(row.status, InvitationStatus::Accepted);
            winners += 1;
        }
    }
    assert_eq!(winners, 1);
    let mut expected = before;
    expected.status = InvitationStatus::Accepted;
    assert_eq!(
        serde_json::to_value(
            first
                .get_invitation_by_id(&id)
                .await?
                .ok_or("missing final row")?
        )?,
        serde_json::to_value(expected)?
    );
    assert!(
        first
            .update_invitation_status_if_status(
                "missing",
                InvitationStatus::Pending,
                InvitationStatus::Accepted
            )
            .await?
            .is_none()
    );
    drop(first);
    B::close(first_db).await?;
    B::close(other).await
}

async fn pending_invitation_count_excludes_expired_and_non_pending_rows<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("test-secret-key-at-least-32-chars-long")
        .await?;
    let org_id = "org-1";
    drop(
        store
            .create_organization(CreateOrganization {
                additional_fields: Default::default(),
                id: Some(org_id.to_owned()),
                name: "Org".to_owned(),
                slug: "org".to_owned(),
                logo: None,
                metadata: None,
            })
            .await?,
    );
    drop(
        store
            .create_user(CreateUser {
                id: Some("inviter-1".to_owned()),
                email: Some("inviter@example.com".to_owned()),
                ..CreateUser::default()
            })
            .await?,
    );
    drop(
        store
            .create_invitation(CreateInvitation::new(
                org_id,
                "first@example.com",
                "member",
                "inviter-1",
                Utc::now() + Duration::hours(1),
            ))
            .await?,
    );
    let canceled = store
        .create_invitation(CreateInvitation::new(
            org_id,
            "second@example.com",
            "member",
            "inviter-1",
            Utc::now() + Duration::hours(1),
        ))
        .await?;
    drop(
        store
            .update_invitation_status(&canceled.id, InvitationStatus::Canceled)
            .await?,
    );
    drop(
        store
            .create_invitation(CreateInvitation::new(
                org_id,
                "expired@example.com",
                "member",
                "inviter-1",
                Utc::now() - Duration::hours(1),
            ))
            .await?,
    );
    assert_eq!(
        store.count_pending_organization_invitations(org_id).await?,
        1
    );
    B::close(connection).await
}

async fn get_pending_invitation_ignores_expired_rows<B: Backend>(db: Db) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("test-secret-key-at-least-32-chars-long")
        .await?;
    let org_id = "org-1";
    drop(
        store
            .create_organization(CreateOrganization {
                additional_fields: Default::default(),
                id: Some(org_id.to_owned()),
                name: "Org".to_owned(),
                slug: "org-second".to_owned(),
                logo: None,
                metadata: None,
            })
            .await?,
    );
    drop(
        store
            .create_user(CreateUser {
                id: Some("inviter-1".to_owned()),
                email: Some("inviter@example.com".to_owned()),
                ..CreateUser::default()
            })
            .await?,
    );
    drop(
        store
            .create_invitation(CreateInvitation::new(
                org_id,
                "expired@example.com",
                "member",
                "inviter-1",
                Utc::now() - Duration::hours(1),
            ))
            .await?,
    );
    assert!(
        store
            .get_pending_invitation(org_id, "expired@example.com")
            .await?
            .is_none()
    );
    B::close(connection).await
}
