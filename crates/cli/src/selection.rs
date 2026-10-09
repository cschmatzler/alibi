use super::{EntityRole, ExtraEntitySchema, FieldDef, registry};
pub(crate) fn list_plugins() -> Vec<&'static str> {
    registry::plugin_schemas().iter().map(|p| p.name).collect()
}

/// Core and selected plugin fields of every generated entity.
pub(crate) struct Selection {
    pub(crate) user: Vec<FieldDef>,
    pub(crate) session: Vec<FieldDef>,
    pub(crate) extra: Vec<&'static ExtraEntitySchema>,
}

pub(crate) fn select(plugins: &[String]) -> Selection {
    let mut selection = Selection {
        user: Vec::new(),
        session: Vec::new(),
        extra: Vec::new(),
    };
    let mut selected = std::collections::HashSet::new();
    for plugin_name in plugins {
        if !selected.insert(plugin_name.as_str()) {
            continue;
        }
        if let Some(schema) = registry::plugin_schemas()
            .iter()
            .find(|p| p.name == plugin_name.as_str())
        {
            selection.user.extend_from_slice(schema.user_fields);
            selection.session.extend_from_slice(schema.session_fields);
            selection.extra.extend(schema.extra_entities.iter());
        }
    }
    selection
}

pub(crate) const CORE_ENTITIES: [(&str, &str, EntityRole); 4] = [
    ("user", "users", EntityRole::User),
    ("session", "sessions", EntityRole::Session),
    ("account", "accounts", EntityRole::Account),
    ("verification", "verifications", EntityRole::Verification),
];

pub(crate) fn role_name(role: EntityRole) -> &'static str {
    match role {
        EntityRole::User => "user",
        EntityRole::Session => "session",
        EntityRole::Account => "account",
        EntityRole::Verification => "verification",
    }
}

/// Fields of a core entity: its core fields, then the selected plugin fields.
pub(crate) fn entity_fields(selection: &Selection, role: EntityRole) -> Vec<&FieldDef> {
    let plugin: &[FieldDef] = match role {
        EntityRole::User => &selection.user,
        EntityRole::Session => &selection.session,
        EntityRole::Account | EntityRole::Verification => &[],
    };
    registry::core_fields(role).iter().chain(plugin).collect()
}
