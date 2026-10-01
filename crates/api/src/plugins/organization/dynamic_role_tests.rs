use super::extension_tests::{actor, assert_error, body, call, configured_context, id};
use super::*;
use crate::plugins::test_helpers::create_test_config;
use better_auth_core::types::{
    CreateMember, CreateOrganizationRole, OrganizationPermissions, OrganizationRoleSelector,
};
use better_auth_core::wire::SessionView;
use better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Debug, Default)]
struct PausingRoleLimits {
    pause: std::sync::atomic::AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait]
impl OrganizationLimitResolver for PausingRoleLimits {
    async fn maximum_roles(&self, _organization_id: &str) -> AuthResult<Option<usize>> {
        if self.pause.swap(false, std::sync::atomic::Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        Ok(Some(100))
    }
}

#[derive(Debug)]
struct RoleLimits(std::sync::Arc<std::sync::Mutex<HashMap<String, usize>>>);

#[async_trait]
impl OrganizationLimitResolver for RoleLimits {
    async fn maximum_roles(&self, organization_id: &str) -> AuthResult<Option<usize>> {
        let policies = self
            .0
            .lock()
            .map_err(|_error| better_auth_core::AuthError::internal("Role policy unavailable"))?;
        Ok(Some(policies.get(organization_id).copied().unwrap_or(0)))
    }
}

fn configuration() -> OrganizationConfig {
    OrganizationConfig {
        teams: TeamsConfig {
            enabled: true,
            create_default_team: false,
            ..Default::default()
        },
        access_control: Some(default_organization_statements()),
        dynamic_access_control: DynamicAccessControlConfig {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    }
}

async fn organization(
    plugin: &OrganizationPlugin,
    ctx: &AuthContext<BundledSchema>,
    session: &SessionView,
    slug: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = call(
        plugin,
        ctx,
        Some(&session.token),
        HttpMethod::Post,
        "/organization/create",
        Some(json!({"name":slug,"slug":slug})),
        &[],
    )
    .await?;
    assert_eq!(response.status, 200);
    Ok(id(&body::<Value>(&response)?)?.to_owned())
}

fn permission(resource: &str, action: &str) -> OrganizationPermissions {
    [(resource.to_owned(), vec![action.to_owned()])].into()
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn dynamic_role_mutations_scope_the_tenant_and_apply_name_selectors_to_all_legacy_rows()
-> TestResult {
    let plugin = OrganizationPlugin::with_config(configuration());
    let ctx = configured_context(&plugin, create_test_config()).await?;
    let (_, owner) = actor(&ctx, "role-owner").await;
    let (_, foreign) = actor(&ctx, "role-foreign").await;
    let org = organization(&plugin, &ctx, &owner, "native-role-mutations").await?;
    let other = organization(&plugin, &ctx, &foreign, "native-role-foreign").await?;
    let mut rows = Vec::new();
    for organization_id in [&org, &org, &other] {
        rows.push(
            ctx.database
                .create_organization_role(CreateOrganizationRole {
                    organization_id: organization_id.clone(),
                    role: "legacy-editor".to_owned(),
                    permission: permission("team", "create"),
                })
                .await?,
        );
    }
    let wrong_scope = call(
        &plugin,
        &ctx,
        Some(&foreign.token),
        HttpMethod::Get,
        "/organization/get-role",
        None,
        &[
            ("organizationId", &other),
            (
                "roleId",
                &(rows)
                    .first()
                    .expect("fixture contains the requested index")
                    .id,
            ),
        ],
    )
    .await?;
    assert_error(&wrong_scope, 400, "ROLE_NOT_FOUND")?;
    let unauthorized_update = call(&plugin, &ctx, Some(&foreign.token), HttpMethod::Post,
        "/organization/update-role", Some(json!({"organizationId":org,"roleId":(rows).first().expect("fixture contains the requested index").id,"data":{"permission":{"team":["delete"]}}})), &[]).await?;
    assert_error(
        &unauthorized_update,
        403,
        "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
    )?;
    assert_eq!(
        ctx.database
            .get_organization_role(
                &org,
                &OrganizationRoleSelector::Id(
                    (rows)
                        .first()
                        .expect("fixture contains the requested index")
                        .id
                        .clone()
                )
            )
            .await?
            .ok_or("Role missing")?
            .permission,
        permission("team", "create")
    );

    let by_id = call(&plugin, &ctx, Some(&owner.token), HttpMethod::Post,
        "/organization/update-role", Some(json!({"organizationId":org,"roleId":(rows).first().expect("fixture contains the requested index").id,"data":{"permission":{"team":["update"]}}})), &[]).await?;
    assert_eq!(by_id.status, 200);
    assert_eq!(
        (*(*(body::<Value>(&by_id)?)
            .get("roleData")
            .unwrap_or(&Value::Null))
        .get("updatedAt")
        .unwrap_or(&Value::Null)),
        Value::Null
    );
    let first_snapshot = ctx
        .database
        .get_organization_role(
            &org,
            &OrganizationRoleSelector::Id(
                (rows)
                    .first()
                    .expect("fixture contains the requested index")
                    .id
                    .clone(),
            ),
        )
        .await?
        .ok_or("Role missing")?;
    assert_eq!(first_snapshot.permission, permission("team", "update"));
    assert!(first_snapshot.updated_at.is_some());
    assert_eq!(
        ctx.database
            .get_organization_role(
                &org,
                &OrganizationRoleSelector::Id(
                    (rows)
                        .get(1)
                        .expect("fixture contains the requested index")
                        .id
                        .clone()
                )
            )
            .await?
            .ok_or("Role missing")?
            .permission,
        permission("team", "create")
    );

    let by_name = call(&plugin, &ctx, Some(&owner.token), HttpMethod::Post,
        "/organization/update-role", Some(json!({"organizationId":org,"roleName":"legacy-editor","data":{"permission":{"member":["update"]}}})), &[]).await?;
    assert_eq!(by_name.status, 200);
    assert_eq!(
        (*(*(body::<Value>(&by_name)?)
            .get("roleData")
            .unwrap_or(&Value::Null))
        .get("id")
        .unwrap_or(&Value::Null)),
        (rows)
            .first()
            .expect("fixture contains the requested index")
            .id
    );
    assert_eq!(
        (*(*(body::<Value>(&by_name)?)
            .get("roleData")
            .unwrap_or(&Value::Null))
        .get("updatedAt")
        .unwrap_or(&Value::Null)),
        (*(serde_json::to_value(first_snapshot)?)
            .get("updatedAt")
            .unwrap_or(&Value::Null))
    );
    let updated = ctx.database.list_organization_roles(&org).await?;
    assert_eq!(updated.len(), 2);
    assert!(
        updated
            .iter()
            .all(|row| row.permission == permission("member", "update"))
    );
    assert!(
        (updated)
            .first()
            .expect("persisted rows contain the requested index")
            .updated_at
            .is_some()
    );
    assert_eq!(
        (updated)
            .first()
            .expect("persisted rows contain the requested index")
            .updated_at,
        (updated)
            .get(1)
            .expect("persisted rows contain the requested index")
            .updated_at
    );
    let unaffected = ctx
        .database
        .get_organization_role(
            &other,
            &OrganizationRoleSelector::Id(
                (rows)
                    .get(2)
                    .expect("fixture contains the requested index")
                    .id
                    .clone(),
            ),
        )
        .await?
        .ok_or("Foreign role missing")?;
    assert_eq!(unaffected.permission, permission("team", "create"));
    assert_eq!(unaffected.updated_at, None);

    let deleted = call(
        &plugin,
        &ctx,
        Some(&owner.token),
        HttpMethod::Post,
        "/organization/delete-role",
        Some(json!({"organizationId":org,"roleName":"legacy-editor"})),
        &[],
    )
    .await?;
    assert_eq!(deleted.status, 200);
    assert_eq!(body::<Value>(&deleted)?, json!({"success":true}));
    assert_eq!(ctx.database.count_organization_roles(&org).await?, 0);
    assert_eq!(ctx.database.count_organization_roles(&other).await?, 1);
    let replay = call(
        &plugin,
        &ctx,
        Some(&owner.token),
        HttpMethod::Post,
        "/organization/delete-role",
        Some(json!({"organizationId":org,"roleId":(rows).first().expect("fixture contains the requested index").id})),
        &[],
    )
    .await?;
    assert_error(&replay, 400, "ROLE_NOT_FOUND")?;

    let id_only = ctx
        .database
        .create_organization_role(CreateOrganizationRole {
            organization_id: org.clone(),
            role: "another-duplicate".to_owned(),
            permission: permission("team", "create"),
        })
        .await?;
    let retained = ctx
        .database
        .create_organization_role(CreateOrganizationRole {
            organization_id: org.clone(),
            role: "another-duplicate".to_owned(),
            permission: permission("team", "create"),
        })
        .await?;
    let deleted_2 = call(
        &plugin,
        &ctx,
        Some(&owner.token),
        HttpMethod::Post,
        "/organization/delete-role",
        Some(json!({"organizationId":org,"roleId":id_only.id})),
        &[],
    )
    .await?;
    assert_eq!(deleted_2.status, 200);
    assert_eq!(ctx.database.count_organization_roles(&org).await?, 1);
    assert!(
        ctx.database
            .get_organization_role(&org, &OrganizationRoleSelector::Id(retained.id))
            .await?
            .is_some()
    );
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
async fn dynamic_role_creation_preserves_the_membership_resource_and_name_check_order() -> TestResult
{
    let plugin = OrganizationPlugin::with_config(configuration());
    let ctx = configured_context(&plugin, create_test_config()).await?;
    let (_, owner) = actor(&ctx, "name-owner").await;
    let (_, outsider) = actor(&ctx, "name-outsider").await;
    let (member, member_session) = actor(&ctx, "name-member").await;
    let org = organization(&plugin, &ctx, &owner, "native-role-name-priority").await?;
    ctx.database
        .create_member(CreateMember {
            organization_id: org.clone(),
            user_id: member.id,
            role: "member".to_owned(),
        })
        .await?;
    ctx.database
        .create_organization_role(CreateOrganizationRole {
            organization_id: org.clone(),
            role: "existing".to_owned(),
            permission: permission("team", "create"),
        })
        .await?;
    for (session, name, requested, status, code) in [
        (
            &outsider,
            "existing",
            json!({}),
            403,
            "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
        ),
        (
            &outsider,
            "OWNER",
            json!({}),
            400,
            "ROLE_NAME_IS_ALREADY_TAKEN",
        ),
        (
            &member_session,
            "existing",
            json!({}),
            403,
            "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE",
        ),
        (
            &owner,
            "existing",
            json!({"invented":["read"]}),
            400,
            "INVALID_RESOURCE",
        ),
        (
            &owner,
            "existing",
            json!({}),
            400,
            "ROLE_NAME_IS_ALREADY_TAKEN",
        ),
    ] {
        let denied = call(
            &plugin,
            &ctx,
            Some(&session.token),
            HttpMethod::Post,
            "/organization/create-role",
            Some(json!({"organizationId":org,"role":name,"permission":requested})),
            &[],
        )
        .await?;
        assert_error(&denied, status, code)?;
        assert_eq!(ctx.database.count_organization_roles(&org).await?, 1);
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
async fn assigned_role_checks_filter_the_tenant_before_the_configured_adapter_page() -> TestResult {
    let plugin = OrganizationPlugin::with_config(configuration());
    let mut config = create_test_config();
    config.advanced.database.default_find_many_limit = 1;
    let ctx = configured_context(&plugin, config).await?;
    let (_, owner) = actor(&ctx, "page-owner").await;
    let (assigned, assigned_session) = actor(&ctx, "page-assigned").await;
    let (prefix, _) = actor(&ctx, "page-prefix").await;
    let org = organization(&plugin, &ctx, &owner, "native-assigned-role-page").await?;
    let role = ctx
        .database
        .create_organization_role(CreateOrganizationRole {
            organization_id: org.clone(),
            role: "editor".to_owned(),
            permission: permission("team", "create"),
        })
        .await?;
    let member = ctx
        .database
        .create_member(CreateMember {
            organization_id: org.clone(),
            user_id: assigned.id.clone(),
            role: " member, editor ".to_owned(),
        })
        .await?;
    let denied = call(
        &plugin,
        &ctx,
        Some(&owner.token),
        HttpMethod::Post,
        "/organization/delete-role",
        Some(json!({"organizationId":org,"roleId":role.id})),
        &[],
    )
    .await?;
    assert_error(&denied, 400, "ROLE_IS_ASSIGNED_TO_MEMBERS")?;
    assert!(
        ctx.database
            .get_organization_role(&org, &OrganizationRoleSelector::Id(role.id.clone()))
            .await?
            .is_some()
    );

    ctx.database.delete_member(&member.id).await?;
    ctx.database
        .create_member(CreateMember {
            organization_id: org.clone(),
            user_id: prefix.id,
            role: "prefixeditor".to_owned(),
        })
        .await?;
    ctx.database
        .create_member(CreateMember {
            organization_id: org.clone(),
            user_id: assigned.id.clone(),
            role: "editor".to_owned(),
        })
        .await?;
    // The pinned adapter inspects the first matching page, including a prefix match
    // that is not an exact role. A later assignment does not block this deletion.
    let deleted = call(
        &plugin,
        &ctx,
        Some(&owner.token),
        HttpMethod::Post,
        "/organization/delete-role",
        Some(json!({"organizationId":org,"roleId":role.id})),
        &[],
    )
    .await?;
    assert_eq!(deleted.status, 200);
    assert_eq!(body::<Value>(&deleted)?, json!({"success":true}));
    assert!(
        ctx.database
            .get_organization_role(&org, &OrganizationRoleSelector::Id(role.id))
            .await?
            .is_none()
    );
    assert_eq!(
        ctx.database
            .get_member(&org, &assigned.id)
            .await?
            .ok_or("Assigned member missing")?
            .role,
        "editor"
    );
    let revoked = call(
        &plugin,
        &ctx,
        Some(&assigned_session.token),
        HttpMethod::Post,
        "/organization/create-team",
        Some(json!({"organizationId":org,"name":"Unavailable"})),
        &[],
    )
    .await?;
    assert_error(
        &revoked,
        403,
        "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION",
    )?;
    assert!(ctx.database.list_teams(&org).await?.is_empty());
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
async fn permission_requests_preserve_empty_legacy_xor_and_membership_wire_behavior() -> TestResult
{
    let plugin = OrganizationPlugin::with_config(configuration());
    let ctx = configured_context(&plugin, create_test_config()).await?;
    let (_, owner) = actor(&ctx, "permission-owner").await;
    let (_, outsider) = actor(&ctx, "permission-outsider").await;
    let org = organization(&plugin, &ctx, &owner, "native-role-permission-shapes").await?;
    for (request, success) in [
        (json!({"permissions":{}}), false),
        (json!({"permissions":{"team":[]}}), false),
        (json!({"permissions":{"invented":[]}}), false),
        (json!({"permission":{"team":["create"]}}), false),
        (
            json!({"permissions":{"team":["create"]},"permission":null}),
            true,
        ),
        (
            json!({"permissions":null,"permission":{"team":["create"]}}),
            false,
        ),
        (
            json!({"organizationId":"","permissions":{"team":["create"]}}),
            true,
        ),
    ] {
        let response = call(
            &plugin,
            &ctx,
            Some(&owner.token),
            HttpMethod::Post,
            "/organization/has-permission",
            Some(request),
            &[],
        )
        .await?;
        assert_eq!(response.status, 200);
        assert_eq!(
            body::<Value>(&response)?,
            json!({"error":null,"success":success})
        );
    }
    let both = call(
        &plugin,
        &ctx,
        Some(&owner.token),
        HttpMethod::Post,
        "/organization/has-permission",
        Some(json!({"permissions":{"team":["create"]},"permission":{"team":["create"]}})),
        &[],
    )
    .await?;
    assert_error(&both, 400, "VALIDATION_ERROR")?;
    assert_eq!(
        (*(body::<Value>(&both)?)
            .get("message")
            .unwrap_or(&Value::Null)),
        "[body] Invalid input: more than one option matched"
    );
    let denied = call(
        &plugin,
        &ctx,
        Some(&outsider.token),
        HttpMethod::Post,
        "/organization/has-permission",
        Some(json!({"organizationId":org,"permissions":{"team":["create"]}})),
        &[],
    )
    .await?;
    assert_error(&denied, 401, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")?;
    let invalid_without_authentication = call(
        &plugin,
        &ctx,
        None,
        HttpMethod::Post,
        "/organization/create-role",
        Some(json!({"role":123,"permission":{}})),
        &[],
    )
    .await?;
    assert_error(&invalid_without_authentication, 400, "VALIDATION_ERROR")?;
    assert_eq!(
        (*(body::<Value>(&invalid_without_authentication)?)
            .get("message")
            .unwrap_or(&Value::Null)),
        "[body.role] Invalid input: expected string, received number"
    );
    assert_eq!(ctx.database.count_organization_roles(&org).await?, 0);
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
async fn role_wire_validation_preserves_union_selection_and_rejects_null_updates_without_mutation()
-> TestResult {
    let plugin = OrganizationPlugin::with_config(configuration());
    let ctx = configured_context(&plugin, create_test_config()).await?;
    let (_, owner) = actor(&ctx, "validation-owner").await;
    let org = organization(&plugin, &ctx, &owner, "native-role-validation").await?;
    let role = ctx
        .database
        .create_organization_role(CreateOrganizationRole {
            organization_id: org.clone(),
            role: "editor".to_owned(),
            permission: permission("team", "create"),
        })
        .await?;
    for (request, message) in [
        (
            json!({"roleName":"","data":{}}),
            "[body.roleName] Too small: expected string to have >=1 characters",
        ),
        (
            json!({"roleId":"","data":{}}),
            "[body.roleId] Too small: expected string to have >=1 characters",
        ),
        (
            json!({"roleName":"","roleId":"","data":{}}),
            "[body] Invalid input",
        ),
        (json!({"roleName":123,"data":{}}), "[body] Invalid input"),
        (
            json!({"roleId":role.id,"data":{"permission":null}}),
            "[body.data.permission] Invalid input: expected record, received null",
        ),
        (
            json!({"roleId":role.id,"data":{"roleName":null}}),
            "[body.data.roleName] Invalid input: expected string, received null",
        ),
        (
            json!({"organizationId":null,"roleId":role.id,"data":{}}),
            "[body.organizationId] Invalid input: expected string, received null",
        ),
    ] {
        let response = call(
            &plugin,
            &ctx,
            Some(&owner.token),
            HttpMethod::Post,
            "/organization/update-role",
            Some(request),
            &[],
        )
        .await?;
        assert_error(&response, 400, "VALIDATION_ERROR")?;
        assert_eq!(
            (*(body::<Value>(&response)?)
                .get("message")
                .unwrap_or(&Value::Null)),
            message
        );
        let persisted = ctx
            .database
            .get_organization_role(&org, &OrganizationRoleSelector::Id(role.id.clone()))
            .await?
            .ok_or("Role missing")?;
        assert_eq!(persisted.permission, permission("team", "create"));
        assert_eq!(persisted.updated_at, None);
    }
    let selected = call(
        &plugin,
        &ctx,
        Some(&owner.token),
        HttpMethod::Post,
        "/organization/update-role",
        Some(json!({"roleName":null,"roleId":role.id,"data":{"permission":{"team":["update"]}}})),
        &[],
    )
    .await?;
    assert_eq!(selected.status, 200);
    assert_eq!(
        (*(*(body::<Value>(&selected)?)
            .get("roleData")
            .unwrap_or(&Value::Null))
        .get("id")
        .unwrap_or(&Value::Null)),
        role.id
    );
    assert_eq!(
        ctx.database
            .get_organization_role(&org, &OrganizationRoleSelector::Id(role.id.clone()))
            .await?
            .ok_or("Role missing")?
            .permission,
        permission("team", "update")
    );
    Ok(())
}

fn delegated_configuration() -> OrganizationConfig {
    let mut config = configuration();
    drop(
        config
            .access_control
            .as_mut()
            .expect("Access control configured")
            .insert(
                "apiKey".to_owned(),
                vec![
                    "create".to_owned(),
                    "read".to_owned(),
                    "update".to_owned(),
                    "delete".to_owned(),
                ],
            ),
    );
    config.roles = Some(
        [
            (
                "owner".to_owned(),
                RolePermissions {
                    organization: vec!["update".to_owned(), "delete".to_owned()],
                    member: vec![
                        "create".to_owned(),
                        "update".to_owned(),
                        "delete".to_owned(),
                    ],
                    invitation: vec!["create".to_owned(), "cancel".to_owned()],
                    team: vec![
                        "create".to_owned(),
                        "update".to_owned(),
                        "delete".to_owned(),
                    ],
                    ac: vec![
                        "create".to_owned(),
                        "read".to_owned(),
                        "update".to_owned(),
                        "delete".to_owned(),
                    ],
                    api_key: vec![
                        "create".to_owned(),
                        "read".to_owned(),
                        "update".to_owned(),
                        "delete".to_owned(),
                    ],
                    ..Default::default()
                },
            ),
            (
                "delegator".to_owned(),
                RolePermissions {
                    team: vec!["create".to_owned()],
                    ac: vec!["create".to_owned(), "read".to_owned(), "update".to_owned()],
                    ..Default::default()
                },
            ),
            (
                "auditor".to_owned(),
                RolePermissions {
                    member: vec!["update".to_owned()],
                    ..Default::default()
                },
            ),
            ("member".to_owned(), RolePermissions::default()),
        ]
        .into(),
    );
    config
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn delegation_checks_each_grant_without_unioning_full_requests_and_revokes_api_key_authority()
-> TestResult {
    let plugin = OrganizationPlugin::with_config(delegated_configuration());
    let ctx = configured_context(&plugin, create_test_config()).await?;
    let (_, owner) = actor(&ctx, "delegation-owner").await;
    let (delegate, delegate_session) = actor(&ctx, "delegation-member").await;
    let org = organization(&plugin, &ctx, &owner, "native-role-delegation").await?;
    let member = ctx
        .database
        .create_member(CreateMember {
            organization_id: org.clone(),
            user_id: delegate.id.clone(),
            role: "delegator,auditor".to_owned(),
        })
        .await?;
    let combined = call(
        &plugin,
        &ctx,
        Some(&delegate_session.token),
        HttpMethod::Post,
        "/organization/has-permission",
        Some(json!({"permissions":{"team":["create"],"member":["update"]}})),
        &[],
    )
    .await?;
    // A member may hold both grants, but one role must authorize the entire request.
    // The session still needs explicit organization selection for this direct actor.
    assert_error(&combined, 400, "NO_ACTIVE_ORGANIZATION")?;
    let combined_2 = call(
        &plugin,
        &ctx,
        Some(&delegate_session.token),
        HttpMethod::Post,
        "/organization/has-permission",
        Some(json!({"organizationId":org,"permissions":{"team":["create"],"member":["update"]}})),
        &[],
    )
    .await?;
    assert_eq!(
        body::<Value>(&combined_2)?,
        json!({"error":null,"success":false})
    );
    let denied = call(&plugin, &ctx, Some(&delegate_session.token), HttpMethod::Post,
        "/organization/create-role", Some(json!({"organizationId":org,"role":"escalated","permission":{"team":["delete","delete"],"apiKey":["create"]}})), &[]).await?;
    assert_error(&denied, 403, "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE")?;
    assert_eq!(
        (*(body::<Value>(&denied)?)
            .get("missingPermissions")
            .unwrap_or(&Value::Null)),
        json!(["team:delete", "team:delete", "apiKey:create"])
    );
    assert_eq!(ctx.database.count_organization_roles(&org).await?, 0);
    let allowed = call(&plugin, &ctx, Some(&delegate_session.token), HttpMethod::Post,
        "/organization/create-role", Some(json!({"organizationId":org,"role":"combined","permission":{"team":["create"],"member":["update"]}})), &[]).await?;
    assert_eq!(allowed.status, 200);
    assert_eq!(
        (*(body::<Value>(&allowed)?)
            .get("statements")
            .unwrap_or(&Value::Null)),
        json!({"team":["create"],"member":["update"]})
    );

    let key_role = call(&plugin, &ctx, Some(&owner.token), HttpMethod::Post,
        "/organization/create-role", Some(json!({"organizationId":org,"role":"key-editor","permission":{"apiKey":["create","read"]}})), &[]).await?;
    assert_eq!(key_role.status, 200);
    let role_id = (*(*(body::<Value>(&key_role)?)
        .get("roleData")
        .unwrap_or(&Value::Null))
    .get("id")
    .unwrap_or(&Value::Null))
    .as_str()
    .ok_or("Role ID missing")?
    .to_owned();
    drop(
        ctx.database
            .update_member_role(&member.id, "key-editor")
            .await?,
    );
    crate::plugins::helpers::require_org_api_key_permission(&ctx, &delegate.id, &org, "create")
        .await?;
    crate::plugins::helpers::require_org_api_key_permission(&ctx, &delegate.id, &org, "read")
        .await?;
    let error =
        crate::plugins::helpers::require_org_api_key_permission(&ctx, &delegate.id, &org, "delete")
            .await
            .err()
            .ok_or("Unowned key permission granted")?;
    assert_error(
        &error.to_auth_response(),
        403,
        "INSUFFICIENT_API_KEY_PERMISSIONS",
    )?;
    let changed = call(
        &plugin,
        &ctx,
        Some(&owner.token),
        HttpMethod::Post,
        "/organization/update-role",
        Some(json!({"organizationId":org,"roleId":role_id,"data":{"permission":{"apiKey":[]}}})),
        &[],
    )
    .await?;
    assert_eq!(changed.status, 200);
    let error_2 =
        crate::plugins::helpers::require_org_api_key_permission(&ctx, &delegate.id, &org, "read")
            .await
            .err()
            .ok_or("Revoked key permission granted")?;
    assert_error(
        &error_2.to_auth_response(),
        403,
        "INSUFFICIENT_API_KEY_PERMISSIONS",
    )?;
    drop(
        ctx.database
            .update_member_role(&member.id, " owner ")
            .await?,
    );
    let error_3 =
        crate::plugins::helpers::require_org_api_key_permission(&ctx, &delegate.id, &org, "read")
            .await
            .err()
            .ok_or("Whitespace role bypassed creator check")?;
    assert_error(
        &error_3.to_auth_response(),
        403,
        "INSUFFICIENT_API_KEY_PERMISSIONS",
    )?;
    drop(ctx.database.update_member_role(&member.id, "owner").await?);
    crate::plugins::helpers::require_org_api_key_permission(&ctx, &delegate.id, &org, "delete")
        .await?;
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
async fn callback_role_limits_are_scoped_and_count_rows_beyond_the_list_page() -> TestResult {
    let policies = std::sync::Arc::new(std::sync::Mutex::new(HashMap::new()));
    let mut config = configuration();
    config.dynamic_access_control.maximum_roles_per_organization = Some(99);
    config.dynamic_access_control.limit_resolver = Some(std::sync::Arc::new(RoleLimits(
        std::sync::Arc::clone(&policies),
    )));
    let plugin = OrganizationPlugin::with_config(config);
    let mut config_2 = create_test_config();
    config_2.advanced.database.default_find_many_limit = 1;
    let ctx = configured_context(&plugin, config_2).await?;
    let (_, owner) = actor(&ctx, "quota-owner").await;
    let first = organization(&plugin, &ctx, &owner, "native-role-quota-one").await?;
    let second = organization(&plugin, &ctx, &owner, "native-role-quota-two").await?;
    let _ignored_clone = policies
        .lock()
        .map_err(|_error| "Role policy unavailable")?
        .insert(first.clone(), 1);
    let _ignored_clone_2 = policies
        .lock()
        .map_err(|_error| "Role policy unavailable")?
        .insert(second.clone(), 2);
    for (org, names) in [(&first, vec!["one"]), (&second, vec!["one", "two"])] {
        for name in names {
            let created = call(
                &plugin,
                &ctx,
                Some(&owner.token),
                HttpMethod::Post,
                "/organization/create-role",
                Some(json!({"organizationId":org,"role":name,"permission":{}})),
                &[],
            )
            .await?;
            assert_eq!(created.status, 200);
        }
        let listed = call(
            &plugin,
            &ctx,
            Some(&owner.token),
            HttpMethod::Get,
            "/organization/list-roles",
            None,
            &[("organizationId", org)],
        )
        .await?;
        assert_eq!(body::<Vec<Value>>(&listed)?.len(), 1);
        let rejected = call(
            &plugin,
            &ctx,
            Some(&owner.token),
            HttpMethod::Post,
            "/organization/create-role",
            Some(json!({"organizationId":org,"role":"overflow","permission":{}})),
            &[],
        )
        .await?;
        assert_error(&rejected, 400, "TOO_MANY_ROLES")?;
    }
    assert_eq!(ctx.database.count_organization_roles(&first).await?, 1);
    assert_eq!(ctx.database.count_organization_roles(&second).await?, 2);
    let deleted = call(
        &plugin,
        &ctx,
        Some(&owner.token),
        HttpMethod::Post,
        "/organization/delete-role",
        Some(json!({"organizationId":second,"roleName":"two"})),
        &[],
    )
    .await?;
    assert_eq!(deleted.status, 200);
    let created = call(
        &plugin,
        &ctx,
        Some(&owner.token),
        HttpMethod::Post,
        "/organization/create-role",
        Some(json!({"organizationId":second,"role":"replacement","permission":{}})),
        &[],
    )
    .await?;
    assert_eq!(created.status, 200);
    assert_eq!(ctx.database.count_organization_roles(&second).await?, 2);
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn overlapping_permission_reloads_change_pending_delegation_only_in_the_selected_organization()
-> TestResult {
    for refreshed_organization in [None, Some(false), Some(true)] {
        let policy = std::sync::Arc::new(PausingRoleLimits::default());
        let mut config = configuration();
        config.dynamic_access_control.limit_resolver =
            Some(std::sync::Arc::<PausingRoleLimits>::clone(&policy));
        let plugin = OrganizationPlugin::with_config(config);
        let ctx = configured_context(&plugin, create_test_config()).await?;
        let (_, owner) = actor(&ctx, "cache-owner").await;
        let (delegate, delegated_session) = actor(&ctx, "cache-delegate").await;
        let org = organization(&plugin, &ctx, &owner, "native-pending-role-cache").await?;
        let other = organization(&plugin, &ctx, &owner, "native-unrelated-role-cache").await?;
        let manager = call(
            &plugin,
            &ctx,
            Some(&owner.token),
            HttpMethod::Post,
            "/organization/create-role",
            Some(json!({"organizationId":org,"role":"manager","permission":{"ac":["create"],"team":["create"]}})),
            &[],
        ).await?;
        assert_eq!(manager.status, 200);
        let manager_id = (*(*(body::<Value>(&manager)?)
            .get("roleData")
            .unwrap_or(&Value::Null))
        .get("id")
        .unwrap_or(&Value::Null))
        .as_str()
        .ok_or("Manager role id missing")?
        .to_owned();
        ctx.database
            .create_member(CreateMember {
                organization_id: org.clone(),
                user_id: delegate.id,
                role: "manager".to_owned(),
            })
            .await?;
        policy
            .pause
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let pending = call(
            &plugin,
            &ctx,
            Some(&delegated_session.token),
            HttpMethod::Post,
            "/organization/create-role",
            Some(json!({"organizationId":org,"role":"delegated","permission":{"team":["create"]}})),
            &[],
        );
        let revoke = async {
            policy.entered.notified().await;
            let changed = call(
                &plugin,
                &ctx,
                Some(&owner.token),
                HttpMethod::Post,
                "/organization/update-role",
                Some(json!({"organizationId":org,"roleId":manager_id,"data":{"permission":{"ac":["create"]}}})),
                &[],
            ).await?;
            assert_eq!(changed.status, 200);
            if let Some(same_organization) = refreshed_organization {
                let refreshed = call(
                    &plugin,
                    &ctx,
                    Some(&owner.token),
                    HttpMethod::Post,
                    "/organization/has-permission",
                    Some(json!({"organizationId":if same_organization { &org } else { &other },"permissions":{"team":["create"]}})),
                    &[],
                ).await?;
                assert_eq!(refreshed.status, 200);
                assert_eq!(
                    (*(body::<Value>(&refreshed)?)
                        .get("success")
                        .unwrap_or(&Value::Null)),
                    true
                );
            }
            policy.release.notify_one();
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        let (pending, revoked) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(pending, revoke)
        })
        .await?;
        revoked?;
        let pending = pending?;
        if refreshed_organization == Some(true) {
            assert_error(&pending, 403, "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE")?;
            assert_eq!(
                (*(body::<Value>(&pending)?)
                    .get("missingPermissions")
                    .unwrap_or(&Value::Null)),
                json!(["team:create"])
            );
        } else {
            assert_eq!(pending.status, 200);
        }
        let manager_2 = ctx
            .database
            .get_organization_role(&org, &OrganizationRoleSelector::Id(manager_id))
            .await?
            .ok_or("Updated manager role missing")?;
        assert_eq!(manager_2.permission, permission("ac", "create"));
        let created = ctx
            .database
            .get_organization_role(
                &org,
                &OrganizationRoleSelector::Name("delegated".to_owned()),
            )
            .await?;
        if refreshed_organization == Some(true) {
            assert!(created.is_none());
            assert_eq!(ctx.database.count_organization_roles(&org).await?, 1);
        } else {
            assert_eq!(
                created.ok_or("Delegated role missing")?.permission,
                permission("team", "create")
            );
            assert_eq!(ctx.database.count_organization_roles(&org).await?, 2);
        }
        assert_eq!(ctx.database.count_organization_roles(&other).await?, 0);
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn default_role_validation_collects_ordered_issues_before_authorization_and_persistence()
-> TestResult {
    let plugin = OrganizationPlugin::with_config(configuration());
    let ctx = configured_context(&plugin, create_test_config()).await?;
    let (_, owner) = actor(&ctx, "default-validation-owner").await;
    let org = organization(&plugin, &ctx, &owner, "native-default-role-validation").await?;
    for (transfer_encoding, length, bytes, code, message) in [
        (
            Some("chunked"),
            None,
            None,
            "VALIDATION_ERROR",
            "[body] Invalid input: expected object, received null",
        ),
        (
            None,
            Some("0"),
            None,
            "VALIDATION_ERROR",
            "[body] Invalid input: expected object, received undefined",
        ),
        (
            None,
            None,
            None,
            "VALIDATION_ERROR",
            "[body] Invalid input: expected object, received undefined",
        ),
        (
            None,
            None,
            Some(Vec::new()),
            "BAD_REQUEST",
            "Invalid JSON in request body",
        ),
        (
            None,
            None,
            Some(b"{malformed".to_vec()),
            "BAD_REQUEST",
            "Invalid JSON in request body",
        ),
    ] {
        let mut request = AuthRequest::new(HttpMethod::Post, "/organization/create-role");
        drop(
            request
                .headers
                .insert("content-type".to_owned(), "application/json".to_owned()),
        );
        if let Some(value) = transfer_encoding {
            drop(
                request
                    .headers
                    .insert("transfer-encoding".to_owned(), value.to_owned()),
            );
        }
        if let Some(value) = length {
            drop(
                request
                    .headers
                    .insert("content-length".to_owned(), value.to_owned()),
            );
        }
        request.body = bytes;
        let response = plugin
            .on_request(&request, &ctx)
            .await?
            .ok_or("Role route missing")?;
        assert_error(&response, 400, code)?;
        assert_eq!(
            (*(body::<Value>(&response)?)
                .get("message")
                .unwrap_or(&Value::Null)),
            message
        );
        assert_eq!(ctx.database.count_organization_roles(&org).await?, 0);
    }
    for (path, input, expected) in [
        (
            "/organization/create-role",
            json!({"role":"extra","permission":{},"additionalFields":null}),
            "[body.additionalFields] Invalid input: expected object, received null",
        ),
        (
            "/organization/create-role",
            json!({"role":"extra","permission":{},"additionalFields":1}),
            "[body.additionalFields] Invalid input: expected object, received number",
        ),
        (
            "/organization/create-role",
            json!({"role":"extra","permission":{},"additionalFields":[]}),
            "[body.additionalFields] Invalid input: expected object, received array",
        ),
        (
            "/organization/create-role",
            json!({"organizationId":null,"role":1,"permission":null,"additionalFields":1}),
            "[body.organizationId] Invalid input: expected string, received null; [body.role] Invalid input: expected string, received number; [body.permission] Invalid input: expected record, received null; [body.additionalFields] Invalid input: expected object, received number",
        ),
        (
            "/organization/create-role",
            json!({"role":"extra","permission":{"team":[null,1],"member":1}}),
            "[body.permission.team.0] Invalid input: expected string, received null; [body.permission.team.1] Invalid input: expected string, received number; [body.permission.member] Invalid input: expected array, received number",
        ),
        (
            "/organization/create-role",
            json!({"role":"extra","permission":{"2":[null],"1":[false],"team":[1]}}),
            "[body.permission.1.0] Invalid input: expected string, received boolean; [body.permission.2.0] Invalid input: expected string, received null; [body.permission.team.0] Invalid input: expected string, received number",
        ),
        (
            "/organization/update-role",
            json!({"organizationId":1,"roleName":"","data":{"permission":null,"roleName":1}}),
            "[body.organizationId] Invalid input: expected string, received number; [body.data.permission] Invalid input: expected record, received null; [body.data.roleName] Invalid input: expected string, received number; [body.roleName] Too small: expected string to have >=1 characters",
        ),
        (
            "/organization/has-permission",
            json!({"organizationId":null,"permissions":null,"permission":null}),
            "[body.organizationId] Invalid input: expected string, received null; [body] Invalid input",
        ),
    ] {
        for token in [Some(owner.token.as_str()), None] {
            let response = call(
                &plugin,
                &ctx,
                token,
                HttpMethod::Post,
                path,
                Some(input.clone()),
                &[],
            )
            .await?;
            assert_error(&response, 400, "VALIDATION_ERROR")?;
            assert_eq!(
                (*(body::<Value>(&response)?)
                    .get("message")
                    .unwrap_or(&Value::Null)),
                expected
            );
            assert_eq!(ctx.database.count_organization_roles(&org).await?, 0);
        }
    }
    let created = call(
        &plugin,
        &ctx,
        Some(&owner.token),
        HttpMethod::Post,
        "/organization/create-role",
        Some(json!({"role":"ΟΣ","permission":{},"additionalFields":{"ignored":"value"}})),
        &[],
    )
    .await?;
    assert_eq!(created.status, 200);
    let value = body::<Value>(&created)?;
    assert_eq!(
        (*(*(value).get("roleData").unwrap_or(&Value::Null))
            .get("role")
            .unwrap_or(&Value::Null)),
        "ος"
    );
    assert!(
        (*(value).get("roleData").unwrap_or(&Value::Null))
            .get("ignored")
            .is_none()
    );
    assert_eq!(
        (ctx.database.list_organization_roles(&org).await?)
            .first()
            .expect("fixture contains the requested index")
            .role,
        "ος"
    );
    let duplicate = call(
        &plugin,
        &ctx,
        Some(&owner.token),
        HttpMethod::Post,
        "/organization/create-role",
        Some(json!({"role":"ος","permission":{}})),
        &[],
    )
    .await?;
    assert_error(&duplicate, 400, "ROLE_NAME_IS_ALREADY_TAKEN")?;
    assert_eq!(ctx.database.count_organization_roles(&org).await?, 1);
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
async fn expired_and_revoked_role_sessions_cannot_mutate_existing_permissions() -> TestResult {
    let plugin = OrganizationPlugin::with_config(configuration());
    let ctx = configured_context(&plugin, create_test_config()).await?;
    let (user, owner) = actor(&ctx, "session-role-owner").await;
    let org = organization(&plugin, &ctx, &owner, "native-role-session-guards").await?;
    let role = ctx
        .database
        .create_organization_role(CreateOrganizationRole {
            organization_id: org.clone(),
            role: "retained".to_owned(),
            permission: permission("team", "create"),
        })
        .await?;
    for expired in [true, false] {
        let session = ctx
            .session_manager()
            .create_session(&user, None, None)
            .await?;
        if expired {
            ctx.database
                .update_session_expiry(
                    &session.token,
                    chrono::Utc::now() - chrono::Duration::seconds(1),
                )
                .await?;
        } else {
            ctx.database.delete_session(&session.token).await?;
        }
        let denied = call(&plugin, &ctx, Some(&session.token), HttpMethod::Post, "/organization/update-role",
            Some(json!({"organizationId":org,"roleId":role.id,"data":{"permission":{"team":["delete"]}}})), &[]).await?;
        assert_error(&denied, 401, "UNAUTHORIZED")?;
        let persisted = ctx
            .database
            .get_organization_role(&org, &OrganizationRoleSelector::Id(role.id.clone()))
            .await?
            .ok_or("Role missing")?;
        assert_eq!(persisted.permission, permission("team", "create"));
        assert_eq!(persisted.updated_at, None);
        assert_eq!(ctx.database.count_organization_roles(&org).await?, 1);
    }
    let allowed = call(&plugin, &ctx, Some(&owner.token), HttpMethod::Post, "/organization/update-role",
        Some(json!({"organizationId":org,"roleId":role.id,"data":{"permission":{"team":["update"]}}})), &[]).await?;
    assert_eq!(allowed.status, 200);
    assert_eq!(
        ctx.database
            .get_organization_role(&org, &OrganizationRoleSelector::Id(role.id))
            .await?
            .ok_or("Role missing")?
            .permission,
        permission("team", "update")
    );
    Ok(())
}
