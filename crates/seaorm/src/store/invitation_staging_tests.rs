//! Conditional invitation claims remain separate from membership transactions.
#![expect(
    clippy::panic_in_result_fn,
    reason = "public storage tests assert persisted invariants and propagate setup failures"
)]
use super::{SeaOrmStore, bundled_schema::BundledSchema, migrator::run_migrations};
use better_auth_core::entity::{AuthSession, AuthUser};
use better_auth_core::store::{
    InvitationStore, MemberStore, OrganizationStore, SessionStore, TeamStore, UserStore,
    transaction,
};
use better_auth_core::{
    AuthConfig, AuthError, AuthResult, CreateInvitation, CreateMember, CreateOrganization,
    CreateSession, CreateTeam, CreateUser, InvitationStatus,
};
use chrono::{Duration, Utc};
use sea_orm::{ConnectOptions, ConnectionTrait, Database, DbBackend, Statement};
use std::sync::Arc;
use tokio::sync::Barrier;

type TestResult = Result<(), Box<dyn std::error::Error>>;
async fn store() -> Result<SeaOrmStore<BundledSchema>, Box<dyn std::error::Error>> {
    let db = Database::connect("sqlite::memory:").await?;
    run_migrations(&db).await?;
    Ok(SeaOrmStore::new(
        AuthConfig::new("invitation-stage-real-storage-local-secret"),
        db,
    ))
}
async fn seed(
    store: &SeaOrmStore<BundledSchema>,
) -> AuthResult<(String, String, String, String, String)> {
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
            additional_fields: Default::default(),
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
    Ok((
        user.id().into_owned(),
        org.id,
        foreign.id,
        team.id,
        format!("{}!{}", invitation.id, session.token()),
    ))
}

#[tokio::test]
async fn staged_claim_survives_real_transaction_abort_and_reset_veto_then_retry_commits()
-> TestResult {
    let store = store().await?;
    let (user, org, foreign, team, handles) = seed(&store).await?;
    let (invitation, token) = handles.split_once('!').ok_or("missing setup handles")?;
    let before = store
        .get_session(token)
        .await?
        .ok_or("missing initial session")?;
    let claimed = store
        .update_invitation_status_if_status(
            invitation,
            InvitationStatus::Pending,
            InvitationStatus::Accepted,
        )
        .await?
        .ok_or("claim failed")?;
    assert_eq!(claimed.status, InvitationStatus::Accepted);
    let _ = store.connection().execute_raw(Statement::from_string(DbBackend::Sqlite,"CREATE TRIGGER stage_member_veto BEFORE INSERT ON member BEGIN SELECT RAISE(ABORT,'actual staged member veto'); END".to_owned())).await?;
    let (tx_user, tx_org, tx_foreign, tx_team, tx_token) = (
        user.clone(),
        org.clone(),
        foreign.clone(),
        team.clone(),
        token.to_owned(),
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
            let _ = tx.add_team_member(&tx_team, &tx_user, Some(1)).await?;
            let _ = tx
                .update_session_active_team(&tx_token, Some(&tx_team))
                .await?;
            let _ = tx
                .create_member(CreateMember {
                    organization_id: tx_org,
                    user_id: tx_user,
                    role: "member".into(),
                })
                .await?;
            Ok(())
        })
    })
    .await;
    assert!(matches!(result, Err(AuthError::Database(_))));
    assert!(store.get_member(&org, &user).await?.is_none());
    assert!(store.get_team_member(&team, &user).await?.is_none());
    let after = store
        .get_session(token)
        .await?
        .ok_or("session missing after rollback")?;
    assert_eq!(
        serde_json::to_value(&after)?,
        serde_json::to_value(&before)?
    );
    assert_eq!(
        store
            .get_invitation_by_id(invitation)
            .await?
            .ok_or("missing accepted row")?
            .status,
        InvitationStatus::Accepted
    );
    let _ = store.connection().execute_raw(Statement::from_string(DbBackend::Sqlite,"CREATE TRIGGER stage_reset_veto BEFORE UPDATE OF status ON invitation WHEN OLD.status='accepted' AND NEW.status='pending' BEGIN SELECT RAISE(ABORT,'actual conditional reset veto'); END".to_owned())).await?;
    assert!(matches!(
        store
            .update_invitation_status_if_status(
                invitation,
                InvitationStatus::Accepted,
                InvitationStatus::Pending
            )
            .await,
        Err(AuthError::Database(_))
    ));
    assert_eq!(
        store
            .get_invitation_by_id(invitation)
            .await?
            .ok_or("missing row after reset veto")?
            .status,
        InvitationStatus::Accepted
    );
    for trigger in ["stage_reset_veto", "stage_member_veto"] {
        let _ = store
            .connection()
            .execute_raw(Statement::from_string(
                DbBackend::Sqlite,
                format!("DROP TRIGGER {trigger}"),
            ))
            .await?;
    }
    assert!(
        store
            .update_invitation_status_if_status(
                invitation,
                InvitationStatus::Accepted,
                InvitationStatus::Pending
            )
            .await?
            .is_some()
    );
    assert!(
        store
            .update_invitation_status_if_status(
                invitation,
                InvitationStatus::Accepted,
                InvitationStatus::Rejected
            )
            .await?
            .is_none()
    );
    assert_eq!(
        store
            .get_invitation_by_id(invitation)
            .await?
            .ok_or("missing conditional no-op row")?
            .status,
        InvitationStatus::Pending
    );
    let _ = store
        .update_invitation_status_if_status(
            invitation,
            InvitationStatus::Pending,
            InvitationStatus::Accepted,
        )
        .await?
        .ok_or("retry claim failed")?;
    let (tx_user, tx_org, tx_team, tx_token) =
        (user.clone(), org.clone(), team.clone(), token.to_owned());
    let created = transaction(&store, move |tx| {
        Box::pin(async move {
            let _ = tx.add_team_member(&tx_team, &tx_user, Some(1)).await?;
            let _ = tx
                .update_session_active_team(&tx_token, Some(&tx_team))
                .await?;
            let member = tx
                .create_member(CreateMember {
                    organization_id: tx_org.clone(),
                    user_id: tx_user,
                    role: "member".into(),
                })
                .await?;
            let _ = tx
                .update_session_active_organization(&tx_token, Some(&tx_org))
                .await?;
            Ok(member)
        })
    })
    .await?;
    assert_eq!(created.user_id, user);
    assert_eq!(created.organization_id, org);
    assert!(store.get_team_member(&team, &user).await?.is_some());
    let final_session = store
        .get_session(token)
        .await?
        .ok_or("missing selected session")?;
    assert_eq!(final_session.token(), before.token());
    assert_eq!(final_session.active_team_id(), Some(team.as_str()));
    assert_eq!(final_session.active_organization_id(), Some(org.as_str()));
    assert!(store.get_member(&foreign, &user).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn independent_connections_have_one_exact_invitation_claim_winner() -> TestResult {
    let path = std::env::temp_dir().join(format!(
        "invitation-stage-cas-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    let url = format!("sqlite:{}?mode=rwc", path.display());
    let mut options = ConnectOptions::new(url.clone());
    let _ = options.max_connections(1);
    let db = Database::connect(options).await?;
    run_migrations(&db).await?;
    let first = Arc::new(SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("invitation-stage-independent-secret"),
        db.clone(),
    ));
    let (_, _, _, _, handles) = seed(&first).await?;
    let (id, _) = handles.split_once('!').ok_or("missing handles")?;
    let before = first
        .get_invitation_by_id(id)
        .await?
        .ok_or("missing initial invitation")?;
    let other = Database::connect(url).await?;
    let second = Arc::new(SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("invitation-stage-independent-secret"),
        other.clone(),
    ));
    let barrier = Arc::new(Barrier::new(2));
    let mut tasks = tokio::task::JoinSet::new();
    for store in [first.clone(), second] {
        let id = id.to_owned();
        let barrier = barrier.clone();
        let _ = tasks.spawn(async move {
            let _ = barrier.wait().await;
            store
                .update_invitation_status_if_status(
                    &id,
                    InvitationStatus::Pending,
                    InvitationStatus::Accepted,
                )
                .await
        });
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
                .get_invitation_by_id(id)
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
    db.close().await?;
    other.close().await?;
    std::fs::remove_file(path)?;
    Ok(())
}
