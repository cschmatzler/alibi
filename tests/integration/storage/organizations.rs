//! Organization metadata, optional updates, patches and deletion boundaries.

use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use better_auth_core::store::{
    ApiKeyStore, InvitationStore, MemberStore, OrganizationRoleStore, OrganizationStore, TeamStore,
    UserStore,
};
use better_auth_core::types::CreateOrganizationRole;
use better_auth_core::{
    AuthError, AuthUser, CreateApiKey, CreateInvitation, CreateMember, CreateOrganization,
    CreateTeam, CreateUser, UpdateOrganization,
};
use chrono::{Duration, Utc};
use serde_json::{Value, json};

backend_tests!(
    public_store_distinguishes_omitted_and_literal_null_metadata,
    optional_organization_update_distinguishes_absence_from_database_write_failure,
    organization_database_patch_retains_unrequested_native_columns,
    public_organization_delete_retains_extensions_and_rolls_back_all_scoped_writes,
);
postgres_tests!(organization_database_patch_retains_unrequested_native_columns,);

async fn raw_metadata(db: &Db, id: &str) -> TestResult<Option<String>> {
    db.text("SELECT metadata FROM organization WHERE id = $1", &[id])
        .await
}

async fn public_store_distinguishes_omitted_and_literal_null_metadata<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("nullable-organization-metadata-public-store-secret")
        .await?;
    let absent = store
        .create_organization(CreateOrganization::new("Absent", "absent"))
        .await?;
    assert_eq!(absent.metadata, None);
    assert_eq!(raw_metadata(&db, &absent.id).await?, None);
    let literal = store
        .create_organization(
            CreateOrganization::new("Literal", "literal").with_metadata(Value::Null),
        )
        .await?;
    assert_eq!(literal.metadata, Some(Value::Null));
    assert_eq!(raw_metadata(&db, &literal.id).await?, Some("null".into()));
    for organization in [&absent, &literal] {
        let renamed = store
            .update_organization(
                &organization.id,
                UpdateOrganization {
                    name: Some("Renamed".into()),
                    ..Default::default()
                },
            )
            .await?;
        assert_eq!(renamed.metadata, organization.metadata);
        assert_eq!(renamed.slug, organization.slug);
        assert_eq!(renamed.created_at, organization.created_at);
    }
    for value in [
        json!({}),
        json!({"guard": [null, true, "kept"]}),
        Value::Null,
    ] {
        let updated = store
            .update_organization(
                &absent.id,
                UpdateOrganization {
                    metadata: Some(value.clone()),
                    ..Default::default()
                },
            )
            .await?;
        assert_eq!(updated.metadata, Some(value.clone()));
        assert_eq!(
            raw_metadata(&db, &absent.id).await?,
            Some(better_auth_core::utils::json::to_string(&value)?)
        );
        let read = store
            .get_organization_by_id(&absent.id)
            .await?
            .ok_or("organization disappeared")?;
        assert_eq!(read.metadata, Some(value));
    }
    assert_eq!(
        store
            .get_organization_by_slug("literal")
            .await?
            .map(|row| row.metadata),
        Some(Some(Value::Null))
    );
    let rows = store
        .list_organizations_by_ids(&[absent.id, literal.id])
        .await?;
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|row| row.metadata == Some(Value::Null)));
    B::close(connection).await
}

async fn optional_organization_update_distinguishes_absence_from_database_write_failure<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("optional-organization-update-public-store-secret")
        .await?;
    let target = store
        .create_organization(CreateOrganization::new("Original", "optional-target"))
        .await?;
    let foreign = store
        .create_organization(
            CreateOrganization::new("Unrelated", "optional-foreign")
                .with_metadata(json!({"private":"retained"})),
        )
        .await?;
    let updated = store
        .update_organization_if_present(
            &target.id,
            UpdateOrganization {
                name: Some("Updated".into()),
                ..Default::default()
            },
        )
        .await?
        .ok_or("existing update must return its actual row")?;
    assert_eq!(updated.name, "Updated");
    assert_eq!(updated.id, target.id);
    assert_eq!(updated.created_at, target.created_at);
    assert_eq!(updated.logo, target.logo);
    assert_eq!(updated.metadata, target.metadata);
    assert_eq!(
        serde_json::to_value(store.get_organization_by_id(&target.id).await?)?,
        serde_json::to_value(Some(&updated))?
    );
    _ = db.execute("CREATE TRIGGER veto_optional_organization BEFORE UPDATE ON organization WHEN OLD.slug='optional-target' BEGIN SELECT RAISE(ABORT,'optional organization storage veto'); END", &[]).await?;
    let veto = store
        .update_organization_if_present(
            &target.id,
            UpdateOrganization {
                name: Some("Must Not Persist".into()),
                ..Default::default()
            },
        )
        .await;
    assert!(veto.is_err(), "database veto is not a missing-row success");
    assert_eq!(
        serde_json::to_value(store.get_organization_by_id(&target.id).await?)?,
        serde_json::to_value(Some(&updated))?
    );
    _ = db
        .execute("DROP TRIGGER veto_optional_organization", &[])
        .await?;
    _ = db.execute("CREATE TRIGGER ignore_optional_organization BEFORE UPDATE ON organization WHEN OLD.slug='optional-target' BEGIN SELECT RAISE(IGNORE); END", &[]).await?;
    assert!(
        store
            .update_organization_if_present(
                &target.id,
                UpdateOrganization {
                    name: Some("Ignored By Adapter".into()),
                    ..Default::default()
                }
            )
            .await?
            .is_none(),
        "a real zero-row UPDATE is absence, not a database failure"
    );
    assert_eq!(
        serde_json::to_value(store.get_organization_by_id(&target.id).await?)?,
        serde_json::to_value(Some(&updated))?
    );
    store.delete_organization(&target.id).await?;
    assert!(
        store
            .update_organization_if_present(
                &target.id,
                UpdateOrganization {
                    name: Some("Deleted".into()),
                    ..Default::default()
                }
            )
            .await?
            .is_none()
    );
    assert!(
        store
            .update_organization(&target.id, UpdateOrganization::default())
            .await
            .is_err(),
        "original public update retains its missing-row error contract"
    );
    assert_eq!(
        serde_json::to_value(store.get_organization_by_id(&foreign.id).await?)?,
        serde_json::to_value(Some(&foreign))?
    );
    B::close(connection).await
}

async fn organization_database_patch_retains_unrequested_native_columns<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("organization-database-patch-native-store-secret")
        .await?;
    let original = store
        .create_organization(
            CreateOrganization::new("Original", "database-patch")
                .with_logo("https://example.test/original.png")
                .with_metadata(json!({"nested":[true,null]})),
        )
        .await?;
    let updated = store
        .patch_organization_if_present(
            &original.id,
            UpdateOrganization {
                name: Some("Updated".into()),
                logo: Some(None),
                ..Default::default()
            },
        )
        .await?
        .ok_or("patch must return its matching row")?;
    assert_eq!(updated.name, "Updated");
    assert_eq!(updated.logo, None);
    assert_eq!(updated.metadata, original.metadata);
    assert_eq!(updated.created_at, original.created_at);
    assert_eq!(updated.updated_at, original.updated_at);
    assert!(
        matches!(
            store
                .patch_organization_if_present(&original.id, UpdateOrganization::default())
                .await,
            Err(AuthError::Database(_))
        ),
        "an actual empty prepared UPDATE remains a database error"
    );
    assert_eq!(
        serde_json::to_value(store.get_organization_by_id(&original.id).await?)?,
        serde_json::to_value(Some(&updated))?
    );
    store.delete_organization(&original.id).await?;
    assert!(
        store
            .patch_organization_if_present(
                &original.id,
                UpdateOrganization {
                    name: Some("Gone".into()),
                    ..Default::default()
                }
            )
            .await?
            .is_none()
    );
    B::close(connection).await
}

const DELETION_TABLES: [&str; 8] = [
    "users",
    "organization",
    "member",
    "invitation",
    "team",
    "team_member",
    "organization_role",
    "api_keys",
];

async fn public_organization_delete_retains_extensions_and_rolls_back_all_scoped_writes<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("organization-delete-store-local-proof-secret")
        .await?;
    let mut records = Vec::new();
    for slug in ["target", "unrelated"] {
        let user = store
            .create_user(CreateUser::new().with_email(format!("{slug}@deletion.fixture.test")))
            .await?;
        let user = user.id().into_owned();
        let org = store
            .create_organization(CreateOrganization::new(slug, slug))
            .await?;
        let member = store
            .create_member(CreateMember {
                organization_id: org.id.clone(),
                user_id: user.clone(),
                role: "owner".into(),
            })
            .await?;
        let invitation = store
            .create_invitation(CreateInvitation::new(
                &org.id,
                format!("invited-{slug}@deletion.fixture.test"),
                "member",
                &user,
                Utc::now() + Duration::days(1),
            ))
            .await?;
        let team = store
            .create_team(CreateTeam {
                name: slug.into(),
                organization_id: org.id.clone(),
                updated_at: None,
            })
            .await?;
        drop(store.add_team_member(&team.id, &user, None).await?);
        drop(
            store
                .create_organization_role(CreateOrganizationRole {
                    organization_id: org.id.clone(),
                    role: "retained".into(),
                    permission: better_auth_core::OrganizationPermissions::default(),
                })
                .await?,
        );
        drop(
            store
                .create_api_key(CreateApiKey {
                    reference_id: org.id.clone(),
                    config_id: "organization".into(),
                    name: Some(slug.into()),
                    prefix: None,
                    key_hash: format!("{slug}-local-key-hash"),
                    start: None,
                    expires_at: None,
                    remaining: None,
                    rate_limit_enabled: false,
                    rate_limit_time_window: None,
                    rate_limit_max: None,
                    refill_interval: None,
                    refill_amount: None,
                    permissions: None,
                    metadata: None,
                    enabled: true,
                })
                .await?,
        );
        records.push((org, member, invitation));
    }
    let (target, unrelated) = (&records[0], &records[1]);
    let before = db.tables(&DELETION_TABLES).await?;
    _ = db.execute("CREATE TRIGGER app_refuse_organization_delete BEFORE DELETE ON organization WHEN OLD.slug='target' BEGIN SELECT RAISE(ABORT,'application deletion denied'); END", &[]).await?;
    assert!(store.delete_organization(&target.0.id).await.is_err());
    assert_eq!(
        db.tables(&DELETION_TABLES).await?,
        before,
        "a failed final organization write must roll back members/invitations and retain every key/extension row"
    );
    _ = db
        .execute("DROP TRIGGER app_refuse_organization_delete", &[])
        .await?;
    store.delete_organization(&target.0.id).await?;
    assert!(store.get_organization_by_id(&target.0.id).await?.is_none());
    assert!(store.get_member_by_id(&target.1.id).await?.is_none());
    assert!(store.get_invitation_by_id(&target.2.id).await?.is_none());
    assert_eq!(
        store
            .get_organization_by_id(&unrelated.0.id)
            .await?
            .map(|org| org.slug),
        Some(unrelated.0.slug.clone())
    );
    assert!(store.get_member_by_id(&unrelated.1.id).await?.is_some());
    assert!(store.get_invitation_by_id(&unrelated.2.id).await?.is_some());
    let after = db.tables(&DELETION_TABLES).await?;
    for (index, table) in DELETION_TABLES.iter().enumerate() {
        if [
            "users",
            "team",
            "team_member",
            "organization_role",
            "api_keys",
        ]
        .contains(table)
        {
            assert_eq!(
                after[index], before[index],
                "retained {table} rows must preserve all physical fields"
            );
        }
    }
    store.delete_organization("missing-organization").await?;
    assert_eq!(
        db.tables(&DELETION_TABLES).await?,
        after,
        "missing organization deletion is a scoped no-op"
    );
    B::close(connection).await
}
