use super::SeaOrmStore;
use crate::Database;
use crate::store::__private_test_support::bundled_schema::BundledSchema;
use crate::store::__private_test_support::migrator::run_migrations;
use better_auth_core::config::AuthConfig;
use better_auth_core::store::{InvitationStore, OrganizationStore, UserStore};
use better_auth_core::types::CreateUser;
use better_auth_core::{CreateInvitation, CreateOrganization, InvitationStatus};
use chrono::{Duration, Utc};
use std::sync::Arc;

async fn test_store() -> SeaOrmStore<BundledSchema> {
    let database = Database::connect("sqlite::memory:")
        .await
        .expect("sqlite test database should connect");
    run_migrations(&database)
        .await
        .expect("sqlite test migrations should run");
    SeaOrmStore::new(
        Arc::new(AuthConfig::new("test-secret-key-at-least-32-chars-long")),
        database,
    )
}

#[tokio::test]
async fn pending_invitation_count_excludes_expired_and_non_pending_rows() {
    let store = test_store().await;
    let org_id = "org-1";
    let _organization = store
        .create_organization(CreateOrganization {
            id: Some(org_id.to_owned()),
            name: "Org".to_owned(),
            slug: "org".to_owned(),
            logo: None,
            metadata: None,
        })
        .await
        .expect("organization should be created");
    let _inviter = store
        .create_user(CreateUser {
            id: Some("inviter-1".to_owned()),
            email: Some("inviter@example.com".to_owned()),
            ..CreateUser::default()
        })
        .await
        .expect("inviter should be created");

    drop(
        store
            .create_invitation(CreateInvitation::new(
                org_id,
                "first@example.com",
                "member",
                "inviter-1",
                Utc::now() + Duration::hours(1),
            ))
            .await
            .expect("pending invitation should be created"),
    );
    let canceled = store
        .create_invitation(CreateInvitation::new(
            org_id,
            "second@example.com",
            "member",
            "inviter-1",
            Utc::now() + Duration::hours(1),
        ))
        .await
        .expect("cancelable invitation should be created");
    drop(
        store
            .update_invitation_status(&canceled.id, InvitationStatus::Canceled)
            .await
            .expect("invitation should be canceled"),
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
            .await
            .expect("expired invitation should be created"),
    );

    let count = store
        .count_pending_organization_invitations(org_id)
        .await
        .expect("pending invitation count should succeed");

    assert_eq!(count, 1);
}

#[tokio::test]
async fn get_pending_invitation_ignores_expired_rows() {
    let store = test_store().await;
    let org_id = "org-1";
    let _organization = store
        .create_organization(CreateOrganization {
            id: Some(org_id.to_owned()),
            name: "Org".to_owned(),
            slug: "org-second".to_owned(),
            logo: None,
            metadata: None,
        })
        .await
        .expect("organization should be created");
    let _inviter = store
        .create_user(CreateUser {
            id: Some("inviter-1".to_owned()),
            email: Some("inviter@example.com".to_owned()),
            ..CreateUser::default()
        })
        .await
        .expect("inviter should be created");

    drop(
        store
            .create_invitation(CreateInvitation::new(
                org_id,
                "expired@example.com",
                "member",
                "inviter-1",
                Utc::now() - Duration::hours(1),
            ))
            .await
            .expect("expired invitation should be created"),
    );

    let invitation = store
        .get_pending_invitation(org_id, "expired@example.com")
        .await
        .expect("lookup should succeed");

    assert!(invitation.is_none());
}
