//! Permission helpers for the admin plugin.

use super::AdminConfig;
use crate::access::{AccessControl, create_access_control};
use std::collections::HashMap;

/// Built-in admin resources and actions, matching Better Auth's `defaultStatements`.
///
/// These declarations include `user:impersonate-admins`, which is deliberately
/// not granted by [`admin_role`]. Declaring an action does not grant it to a role.
pub const DEFAULT_STATEMENTS: &[(&str, &[&str])] = &[
    (
        "user",
        &[
            "create",
            "list",
            "set-role",
            "ban",
            "impersonate",
            "impersonate-admins",
            "delete",
            "set-password",
            "set-email",
            "get",
            "update",
        ],
    ),
    ("session", &["list", "revoke", "delete"]),
];

/// Create application-side access control from [`DEFAULT_STATEMENTS`].
#[must_use]
pub fn default_ac() -> AccessControl {
    create_access_control(
        DEFAULT_STATEMENTS
            .iter()
            .map(|(resource, actions)| {
                (
                    (*resource).to_owned(),
                    actions.iter().map(|action| (*action).to_owned()).collect(),
                )
            })
            .collect(),
    )
}

/// Role-based permission grants for the admin plugin.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RolePermissions {
    /// Resource name -> allowed actions.
    pub permissions: HashMap<String, Vec<String>>,
}

impl RolePermissions {
    /// Create an empty role definition.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow a set of actions for one resource.
    /// Replaces that resource's grants while preserving other resources.
    #[must_use]
    pub fn allow<I, S>(mut self, resource: impl Into<String>, actions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        _ = self.permissions.insert(
            resource.into(),
            actions.into_iter().map(Into::into).collect(),
        );
        self
    }

    fn allows(&self, requested: &HashMap<String, Vec<String>>) -> bool {
        use crate::access::{Connector, authorize};
        authorize(
            |resource| self.permissions.get(resource).map(Vec::as_slice),
            requested
                .iter()
                .map(|(resource, actions)| (resource.as_str(), actions.as_slice(), Connector::And)),
            Connector::And,
        )
        .success()
    }
}

/// Create the built-in admin role, ready to extend with [`RolePermissions::allow`].
///
/// Grants every action in [`DEFAULT_STATEMENTS`] except `user:impersonate-admins`.
#[must_use]
pub fn admin_role() -> RolePermissions {
    DEFAULT_STATEMENTS
        .iter()
        .fold(RolePermissions::new(), |role, (resource, actions)| {
            role.allow(
                *resource,
                actions
                    .iter()
                    .copied()
                    .filter(|action| *resource != "user" || *action != "impersonate-admins"),
            )
        })
}

/// Create the built-in user role, which grants no admin permissions.
#[must_use]
pub fn user_role() -> RolePermissions {
    RolePermissions::new()
}

/// Create the built-in role map used when [`AdminConfig::roles`] is unset.
///
/// Extend a role before passing the map to the plugin:
///
/// ```
/// use alibi_plugins::admin::{AdminPlugin, admin_role, default_roles};
///
/// let mut roles = default_roles();
/// roles.insert("admin".into(), admin_role().allow("job", ["read", "manage"]));
/// let plugin = AdminPlugin::new().roles(roles);
/// ```
#[must_use]
pub fn default_roles() -> HashMap<String, RolePermissions> {
    HashMap::from([
        ("admin".to_owned(), admin_role()),
        ("user".to_owned(), user_role()),
    ])
}

fn configured_roles(config: &AdminConfig) -> HashMap<String, RolePermissions> {
    config.roles.clone().unwrap_or_else(default_roles)
}

fn role_names<'a>(role: Option<&'a str>, default_role: &'a str) -> Vec<&'a str> {
    role.filter(|role| !role.is_empty())
        .or_else(|| (!default_role.is_empty()).then_some(default_role))
        .unwrap_or("user")
        .split(',')
        .collect()
}

pub(super) fn is_admin_user_id(user_id: Option<&str>, config: &AdminConfig) -> bool {
    user_id.is_some_and(|user_id| {
        config
            .admin_user_ids
            .as_ref()
            .is_some_and(|ids| ids.iter().any(|id| id == user_id))
    })
}

pub(super) fn has_permission(
    user_id: Option<&str>,
    role: Option<&str>,
    config: &AdminConfig,
    requested: &HashMap<String, Vec<String>>,
) -> bool {
    if is_admin_user_id(user_id, config) {
        return true;
    }

    let roles = configured_roles(config);
    role_names(role, &config.default_role)
        .into_iter()
        .filter_map(|role| roles.get(role))
        .any(|role| role.allows(requested))
}

pub(super) fn is_admin_role(role: Option<&str>, config: &AdminConfig) -> bool {
    role_names(role, &config.default_role)
        .into_iter()
        .any(|role| {
            config.admin_roles.as_ref().map_or_else(
                || role == "admin",
                |admins| admins.iter().any(|admin| admin.trim() == role),
            )
        })
}
