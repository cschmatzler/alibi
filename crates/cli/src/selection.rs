use alibi_schema_registry::{self as registry, EntityRole, ExtraEntitySchema, FieldDef};
use std::collections::HashSet;

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
    let mut selected = HashSet::new();
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

/// Fields of a core entity: its core fields, then the selected plugin fields.
fn entity_fields(selection: &Selection, role: EntityRole) -> Vec<&FieldDef> {
    let plugin: &[FieldDef] = match role {
        EntityRole::User => &selection.user,
        EntityRole::Session => &selection.session,
        EntityRole::Account | EntityRole::Verification => &[],
    };
    registry::core_fields(role).iter().chain(plugin).collect()
}

pub(crate) struct SelectedEntity<'a> {
    pub(crate) module: &'static str,
    pub(crate) table: &'static str,
    pub(crate) role: Option<EntityRole>,
    pub(crate) fields: Vec<&'a FieldDef>,
}

impl Selection {
    pub(crate) fn entities(&self) -> impl Iterator<Item = SelectedEntity<'_>> {
        let core = EntityRole::ALL.into_iter().map(|role| SelectedEntity {
            module: role.as_str(),
            table: role.as_str(),
            role: Some(role),
            fields: entity_fields(self, role),
        });
        core.chain(self.extra.iter().map(|entity| SelectedEntity {
            module: entity.mod_name,
            table: entity.table_name,
            role: entity.role,
            fields: entity.fields.iter().collect(),
        }))
    }
}
