//! Disabled organization features must omit their public server operations.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{
    OrganizationPlugin,
    organization::{DynamicAccessControlConfig, OrganizationConfig, TeamsConfig},
};
backend_tests!(organization_disabled_features_omit_server_operations);
postgres_tests!(organization_disabled_features_omit_server_operations);
async fn organization_disabled_features_omit_server_operations<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    for (teams, roles) in [(false, false), (true, false), (false, true), (true, true)] {
        let auth = builder::<B>(&connection)
            .plugin(OrganizationPlugin::with_config(OrganizationConfig {
                teams: TeamsConfig {
                    enabled: teams,
                    create_default_team: false,
                    ..Default::default()
                },
                dynamic_access_control: DynamicAccessControlConfig {
                    enabled: roles,
                    ..Default::default()
                },
                ..Default::default()
            }))
            .build()
            .await?;
        for (operations, expected) in [
            (
                &[
                    "createTeam",
                    "updateTeam",
                    "removeTeam",
                    "listOrganizationTeams",
                    "listUserTeams",
                    "listTeamMembers",
                    "setActiveTeam",
                    "addTeamMember",
                    "removeTeamMember",
                ][..],
                teams,
            ),
            (
                &[
                    "createOrgRole",
                    "getOrgRole",
                    "listOrgRoles",
                    "deleteOrgRole",
                    "updateOrgRole",
                ][..],
                roles,
            ),
        ] {
            for operation in operations {
                let result = Box::pin(auth.dispatch_endpoint(
                    ServerEndpoint::<Value>::new("organization", operation),
                    EndpointOptions::default(),
                ))
                .await;
                let available = match result {
                    Ok(_) => true,
                    Err(error) => error.error.status_code() != 404,
                };
                assert_eq!(
                    available, expected,
                    "{operation} with teams={teams}, roles={roles}"
                );
            }
        }
    }
    Ok(())
}
