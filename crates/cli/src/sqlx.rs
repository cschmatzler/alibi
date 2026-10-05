use super::*;
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
    let tables = CORE_ENTITIES
        .iter()
        .map(|(_, table, role)| (*table, entity_fields(selection, *role)))
        .chain(
            selection
                .extra
                .iter()
                .map(|entity| (entity.table_name, entity.fields.iter().collect())),
        )
        .collect::<Vec<_>>();
    let sqlite = tables
        .iter()
        .map(|(table, fields)| create_table(table, fields, SqlDialect::Sqlite));
    let postgres = tables
        .iter()
        .map(|(table, fields)| create_table(table, fields, SqlDialect::Postgres));
    quote! {
        use better_auth::AuthSchema;
        use better_auth::sqlx::{Engine, SqlxPool};

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
        ) -> Result<(), better_auth::sqlx::sqlx::Error> {
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
        let ty = parse_type(field, &sqlx_type(field.ty));
        let rename = field
            .column_name
            .map(|column| quote! { #[sqlx(rename = #column)] });
        quote! {
            #rename
            pub #name: #ty,
        }
    });
    let derive = role.map_or_else(
        || quote! { #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)] },
        |role| {
            let role = role_name(role);
            quote! {
                #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, better_auth::sqlx::AuthEntity)]
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
        .replace("Json", "better_auth::sqlx::JsonMetadata")
}

#[derive(Clone, Copy)]
pub(crate) enum SqlDialect {
    Sqlite,
    Postgres,
}

/// `CREATE TABLE IF NOT EXISTS` for a generated model, as `SeaORM` derives
/// tables from its entities: column types follow the registry types.
pub(crate) fn create_table(table: &str, fields: &[&FieldDef], dialect: SqlDialect) -> String {
    let columns = fields
        .iter()
        .map(|field| {
            let (inner, nullable) = field
                .ty
                .strip_prefix("Option<")
                .and_then(|inner| inner.strip_suffix('>'))
                .map_or((field.ty, false), |inner| (inner, true));
            let sql_type = match (inner, dialect) {
                ("bool", _) => "BOOLEAN",
                ("i64", SqlDialect::Sqlite) => "INTEGER",
                ("i64", SqlDialect::Postgres) => "BIGINT",
                ("f64", SqlDialect::Sqlite) => "REAL",
                ("f64", SqlDialect::Postgres) => "DOUBLE PRECISION",
                ("DateTimeUtc", SqlDialect::Postgres) => "TIMESTAMPTZ",
                ("Json", SqlDialect::Postgres) => "JSONB",
                _ => "TEXT",
            };
            let column = field.column_name.unwrap_or(field.name);
            let constraint = if field.is_primary_key {
                " NOT NULL PRIMARY KEY"
            } else if nullable {
                ""
            } else {
                " NOT NULL"
            };
            let default = field.default_value.map_or_else(String::new, |value| {
                format!(" DEFAULT '{}'", value.replace('\'', "''"))
            });
            format!("\"{column}\" {sql_type}{constraint}{default}")
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("CREATE TABLE IF NOT EXISTS \"{table}\" ({columns})")
}
