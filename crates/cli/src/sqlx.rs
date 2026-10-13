use crate::parse_type;
use crate::selection::{CORE_ENTITIES, Selection, entity_fields, role_name};
use alibi_schema_registry::{EntityRole, FieldDef};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

pub(crate) fn sqlx_schema(selection: &Selection) -> TokenStream {
    let entities = CORE_ENTITIES.iter().map(|(module, table, role)| {
        sqlx_entity(module, table, Some(*role), &entity_fields(selection, *role))
    });
    let extra = selection.extra.iter().map(|entity| {
        sqlx_entity(
            entity.mod_name,
            entity.table_name,
            entity.role,
            &entity.fields.iter().collect::<Vec<_>>(),
        )
    });
    let mut tables = CORE_ENTITIES
        .iter()
        .map(|(_, table, role)| (*table, entity_fields(selection, *role)))
        .chain(
            selection
                .extra
                .iter()
                .map(|entity| (entity.table_name, entity.fields.iter().collect())),
        )
        .collect::<Vec<_>>();
    tables.sort_by_key(|(table, _)| crate::sqlx::table_order(table));
    let sqlite = tables
        .iter()
        .flat_map(|(table, fields)| migration_statements(table, fields, SqlDialect::Sqlite));
    let postgres = tables
        .iter()
        .flat_map(|(table, fields)| migration_statements(table, fields, SqlDialect::Postgres));
    quote! {
        use alibi::AuthSchema;
        use alibi::sqlx::{Engine, SqlxPool};

        #(#entities)*
        #(#extra)*

        pub struct AppAuthSchema;

        impl AuthSchema for AppAuthSchema {
            type User = user::Model;
            type Session = session::Model;
            type Account = account::Model;
            type Verification = verification::Model;
        }

        const SQLITE_TABLES: &[&str] = &[#(#sqlite),*];
        const POSTGRES_TABLES: &[&str] = &[#(#postgres),*];

        pub async fn run_app_migrations(
            pool: &SqlxPool,
        ) -> Result<(), alibi::sqlx::sqlx::Error> {
            let statements = match pool.engine() {
                Engine::Sqlite => SQLITE_TABLES,
                Engine::Postgres => POSTGRES_TABLES,
            };
            pool.execute_batch(statements).await
        }
    }
}

pub(crate) fn sqlx_entity(
    module: &str,
    table: &str,
    role: Option<EntityRole>,
    fields: &[&FieldDef],
) -> TokenStream {
    let module = format_ident!("{}", module);
    let fields = fields.iter().map(|field| {
        let name = format_ident!("{}", field.name);
        let ty = parse_type(
            field,
            &sqlx_type(field.ty).replace(
                "i64",
                if field.name == "last_request" {
                    "i64"
                } else {
                    "alibi::sqlx::Integer"
                },
            ),
        );
        let rename = field
            .column_name
            .map(|column| quote! { #[sqlx(rename = #column)] });
        let column_kind = (table == "organization" && field.name == "metadata")
            .then(|| quote! { #[auth(column_type = "text")] });
        quote! {
            #column_kind
            #rename
            pub #name: #ty,
        }
    });
    let derive = role.map_or_else(
        || quote! { #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::SqlxModel)] #[auth(table = #table)] },
        |role| {
            let role = role_name(role);
            quote! {
                #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::AuthEntity)]
                #[auth(role = #role, table = #table)]
            }
        },
    );
    quote! {
        pub mod #module {
            #derive
            pub struct Model {
                #(#fields)*
            }
        }
    }
}

/// The `SQLx` model type for a registry type.
pub(crate) fn sqlx_type(ty: &str) -> String {
    ty.replace("DateTimeUtc", "chrono::DateTime<chrono::Utc>")
        .replace("Json", "alibi::sqlx::JsonMetadata")
        .replace("f64", "alibi::sqlx::Number")
}

#[derive(Clone, Copy)]
pub(crate) enum SqlDialect {
    Sqlite,
    Postgres,
}

/// Filter the compiled TypeScript DDL to the selected plugin columns and indexes.
pub(crate) fn migration_statements(
    table: &str,
    fields: &[&FieldDef],
    dialect: SqlDialect,
) -> Vec<String> {
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

pub(crate) fn table_order(table: &str) -> usize {
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
