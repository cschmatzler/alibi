use std::sync::Arc;

use better_auth_core::config::AuthConfig;
use better_auth_core::store::{
    ListOrganizationMembersParams, MemberStore, OrganizationStore, UserStore,
};
use better_auth_core::types::{CreateMember, CreateOrganization, CreateUser};

use crate::Database;
use crate::store::__private_test_support::bundled_schema::BundledSchema;
use crate::store::__private_test_support::migrator::run_migrations;

use super::SeaOrmStore;

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
async fn query_organization_members_applies_filter_sort_and_pagination() {
    let store = test_store().await;
    let org_id = "org-1".to_owned();
    let _organization = store
        .create_organization(CreateOrganization {
            id: Some(org_id.clone()),
            name: "Org".to_owned(),
            slug: "org".to_owned(),
            logo: None,
            metadata: None,
        })
        .await
        .expect("organization should be created");
    let _owner = store
        .create_user(CreateUser {
            id: Some("user-owner".to_owned()),
            email: Some("owner@example.com".to_owned()),
            ..CreateUser::default()
        })
        .await
        .expect("owner should be created");
    let _member = store
        .create_user(CreateUser {
            id: Some("user-member".to_owned()),
            email: Some("member@example.com".to_owned()),
            ..CreateUser::default()
        })
        .await
        .expect("member should be created");
    let _admin = store
        .create_user(CreateUser {
            id: Some("user-admin".to_owned()),
            email: Some("admin@example.com".to_owned()),
            ..CreateUser::default()
        })
        .await
        .expect("admin should be created");

    drop(
        store
            .create_member(CreateMember::new(&org_id, "user-owner", "owner"))
            .await
            .expect("owner should be created"),
    );
    drop(
        store
            .create_member(CreateMember::new(&org_id, "user-member", "member"))
            .await
            .expect("member should be created"),
    );
    drop(
        store
            .create_member(CreateMember::new(&org_id, "user-admin", "admin"))
            .await
            .expect("admin should be created"),
    );

    let params = ListOrganizationMembersParams {
        organization_id: org_id,
        limit: Some(1),
        offset: Some(1),
        sort_by: Some("role".to_owned()),
        sort_direction: Some("asc".to_owned()),
        filter_field: Some("role".to_owned()),
        filter_value: Some("owner".to_owned()),
        filter_operator: Some("ne".to_owned()),
    };

    let (members, total) = store
        .query_organization_members(&params)
        .await
        .expect("member query should succeed");

    assert_eq!(total, 2);
    assert_eq!(members.len(), 1);
    assert_eq!(
        (members)
            .first()
            .expect("fixture contains the requested index")
            .role,
        "member"
    );
}
