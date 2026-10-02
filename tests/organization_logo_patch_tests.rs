#![cfg(test)]
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
//! The public storage patch distinguishes omission, SQL NULL, and an empty string.

use better_auth::AuthConfig;
use better_auth_core::store::OrganizationStore;
use better_auth_core::{CreateOrganization, UpdateOrganization};
use better_auth_seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};
use better_auth_seaorm::{Database, SeaOrmStore};
use serde_json::json;

type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn public_organization_store_logo_patch_preserves_omission_and_clears_sql_null() {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
            .await
            .unwrap();
        let store = SeaOrmStore::<Schema>::new(
            AuthConfig::new("organization-logo-storage-fixture-secret-at-least-32-characters"),
            database.clone(),
        );
        let organization = store
            .create_organization(
                CreateOrganization::new("Stored Logo", "stored-logo")
                    .with_logo("https://fixture.test/original.png")
                    .with_metadata(json!({"guard":"unchanged","payload":[null,true,"literal"]})),
            )
            .await
            .unwrap();
        for (logo, expected) in [
            (None, Some("https://fixture.test/original.png")),
            (Some(None), None),
            (Some(Some(String::new())), Some("")),
            (
                Some(Some("https://fixture.test/replaced.png".into())),
                Some("https://fixture.test/replaced.png"),
            ),
        ] {
            let updated = store
                .update_organization(
                    &organization.id,
                    UpdateOrganization {
                        name: Some("Changed Name".into()),
                        logo,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(updated.logo.as_deref(), expected);
            assert_eq!(updated.id, organization.id);
            assert_eq!(updated.slug, organization.slug);
            assert_eq!(updated.created_at, organization.created_at);
            assert_eq!(updated.metadata, organization.metadata);
            let row = database
                .query_one_raw(Statement::from_sql_and_values(
                    DbBackend::Sqlite,
                    "SELECT logo, metadata FROM organization WHERE id = ?",
                    [organization.id.clone().into()],
                ))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                row.try_get::<Option<String>>("", "logo")
                    .unwrap()
                    .as_deref(),
                expected
            );
            assert_eq!(
                row.try_get::<String>("", "metadata").unwrap(),
                "{\"guard\":\"unchanged\",\"payload\":[null,true,\"literal\"]}"
            );
        }
    }
}
