use super::*;

// Upstream reference: packages/better-auth/src/plugins/access/access.test.ts and packages/better-auth/src/plugins/organization/access/statement.ts; adapted to the Rust organization RBAC helpers.
#[test]
fn test_owner_has_full_permissions() {
    let custom = HashMap::new();

    assert!(has_permission(
        "owner",
        &Resource::Organization,
        &Action::Update,
        &custom
    ));
    assert!(has_permission(
        "owner",
        &Resource::Organization,
        &Action::Delete,
        &custom
    ));
    assert!(has_permission(
        "owner",
        &Resource::Member,
        &Action::Create,
        &custom
    ));
    assert!(has_permission(
        "owner",
        &Resource::Invitation,
        &Action::Cancel,
        &custom
    ));
}

// Upstream reference: packages/better-auth/src/plugins/access/access.test.ts and packages/better-auth/src/plugins/organization/access/statement.ts; adapted to the Rust organization RBAC helpers.
#[test]
fn test_admin_cannot_delete_organization() {
    let custom = HashMap::new();

    assert!(has_permission(
        "admin",
        &Resource::Organization,
        &Action::Update,
        &custom
    ));
    assert!(!has_permission(
        "admin",
        &Resource::Organization,
        &Action::Delete,
        &custom
    ));
}

// Upstream reference: packages/better-auth/src/plugins/access/access.test.ts and packages/better-auth/src/plugins/organization/access/statement.ts; adapted to the Rust organization RBAC helpers.
#[test]
fn test_member_has_no_permissions() {
    let custom = HashMap::new();

    assert!(!has_permission(
        "member",
        &Resource::Organization,
        &Action::Update,
        &custom
    ));
    assert!(!has_permission(
        "member",
        &Resource::Member,
        &Action::Create,
        &custom
    ));
}

// Upstream reference: packages/better-auth/src/plugins/access/access.test.ts and packages/better-auth/src/plugins/organization/access/statement.ts; adapted to the Rust organization RBAC helpers.
#[test]
fn test_composite_roles() {
    let custom = HashMap::new();

    // member,admin should have admin permissions
    assert!(has_permission_any(
        "member,admin",
        &Resource::Organization,
        &Action::Update,
        &custom
    ));

    // member alone should not
    assert!(!has_permission_any(
        "member",
        &Resource::Organization,
        &Action::Update,
        &custom
    ));
}
