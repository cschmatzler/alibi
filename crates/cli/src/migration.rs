use crate::selection::Selection;
use alibi_schema_registry::FieldDef;

pub(crate) fn statements(selection: &Selection) -> (Vec<String>, Vec<String>) {
    let mut entities: Vec<_> = selection.entities().collect();
    entities.sort_by_key(|entity| table_order(entity.table));
    let for_dialect = |dialect| {
        entities
            .iter()
            .flat_map(|entity| migration_statements(entity.table, &entity.fields, dialect))
            .collect()
    };
    (
        for_dialect(SqlDialect::Sqlite),
        for_dialect(SqlDialect::Postgres),
    )
}

#[derive(Clone, Copy)]
enum SqlDialect {
    Sqlite,
    Postgres,
}

/// Filter the compiled TypeScript DDL to the selected plugin columns and indexes.
fn migration_statements(table: &str, fields: &[&FieldDef], dialect: SqlDialect) -> Vec<String> {
    let (auth, oauth, rate, sso) = match dialect {
        SqlDialect::Sqlite => (
            alibi_schema_registry::SQLITE_AUTH_SCHEMA,
            alibi_schema_registry::SQLITE_OAUTH_SCHEMA,
            alibi_schema_registry::SQLITE_RATE_LIMIT_SCHEMA,
            alibi_schema_registry::SQLITE_SSO_SCHEMA,
        ),
        SqlDialect::Postgres => (
            alibi_schema_registry::POSTGRES_AUTH_SCHEMA,
            alibi_schema_registry::POSTGRES_OAUTH_SCHEMA,
            alibi_schema_registry::POSTGRES_RATE_LIMIT_SCHEMA,
            alibi_schema_registry::POSTGRES_SSO_SCHEMA,
        ),
    };
    let selected: std::collections::HashSet<_> = fields
        .iter()
        .map(|field| field.column_name.unwrap_or(field.name))
        .collect();
    let prefix = format!("create table \"{table}\" (");
    let mut statements = Vec::new();
    for statement in auth
        .split(';')
        .chain(oauth.split(';'))
        .chain(rate.split(';'))
        .chain(sso.split(';'))
    {
        let statement = statement.trim();
        if let Some(start) = statement.find(&prefix) {
            let columns = statement
                .get(start + prefix.len()..)
                .unwrap_or_default()
                .trim_end_matches(')');
            let columns: Vec<_> = columns
                .split(", ")
                .filter(|column| {
                    column
                        .split('"')
                        .nth(1)
                        .is_some_and(|name| selected.contains(name))
                })
                .collect();
            statements.push(format!(
                "CREATE TABLE IF NOT EXISTS \"{table}\" ({})",
                columns.join(", ")
            ));
        } else if statement.starts_with("create ")
            && statement.contains(&format!(" on \"{table}\" ("))
        {
            let columns = statement
                .rsplit_once('(')
                .map_or("", |(_, columns)| columns.trim_end_matches(')'));
            if columns
                .split(", ")
                .all(|column| selected.contains(column.trim_matches('"')))
            {
                statements.push(statement.replacen("index ", "index IF NOT EXISTS ", 1));
            }
        }
    }
    statements
}

fn table_order(table: &str) -> usize {
    let prefix = format!("create table \"{table}\" (");
    alibi_schema_registry::SQLITE_AUTH_SCHEMA
        .find(&prefix)
        .or_else(|| {
            alibi_schema_registry::SQLITE_OAUTH_SCHEMA
                .find(&prefix)
                .map(|index| index + alibi_schema_registry::SQLITE_AUTH_SCHEMA.len())
        })
        .unwrap_or(usize::MAX)
}
