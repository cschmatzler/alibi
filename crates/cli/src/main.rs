use better_auth_schema_registry::{self as registry, EntityRole, ExtraEntitySchema, FieldDef};
use clap::{Parser, Subcommand, ValueEnum};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "better-auth-rs", about = "CLI tools for better-auth-rs")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// The store backend whose entity definitions are generated.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
enum Backend {
    #[default]
    Sqlx,
    Seaorm,
}

#[derive(Subcommand)]
enum Command {
    /// Generate the auth schema file with `SQLx` or `SeaORM` entity definitions.
    ///
    /// By default generates core-only entities. Use --plugins to include
    /// plugin-specific fields (e.g. username, admin ban fields).
    Generate {
        /// Store backend to generate entities for.
        #[arg(short, long, value_enum, default_value_t)]
        backend: Backend,

        /// Write output to a file instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Comma-separated list of plugins whose fields to include.
        /// Available: username, two-factor, device-authorization, api-key, admin, organization, passkey.
        /// Use "all" to include every plugin's fields.
        #[arg(short, long, value_delimiter = ',')]
        plugins: Vec<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Generate {
            backend,
            output,
            plugins,
        } => {
            let plugins = if plugins.iter().any(|p| p == "all") {
                list_plugins().into_iter().map(String::from).collect()
            } else {
                plugins
            };

            let schema = generate_schema(&plugins, backend);

            match output {
                Some(path) => {
                    if let Some(parent) = path.parent()
                        && !parent.exists()
                        && let Err(e) = fs::create_dir_all(parent)
                    {
                        drop(writeln!(
                            std::io::stderr().lock(),
                            "failed to create directory {}: {e}",
                            parent.display()
                        ));
                        return ExitCode::FAILURE;
                    }
                    if let Err(e) = fs::write(&path, &schema) {
                        drop(writeln!(
                            std::io::stderr().lock(),
                            "failed to write {}: {e}",
                            path.display()
                        ));
                        return ExitCode::FAILURE;
                    }
                    drop(writeln!(
                        std::io::stderr().lock(),
                        "wrote auth schema to {}",
                        path.display()
                    ));
                }
                None => {
                    if let Err(error) = std::io::stdout().lock().write_all(schema.as_bytes()) {
                        drop(writeln!(
                            std::io::stderr().lock(),
                            "failed to write stdout: {error}"
                        ));
                        return ExitCode::FAILURE;
                    }
                }
            }
        }
    }
    ExitCode::SUCCESS
}

fn list_plugins() -> Vec<&'static str> {
    registry::plugin_schemas().iter().map(|p| p.name).collect()
}

/// Core and selected plugin fields of every generated entity.
struct Selection {
    user: Vec<FieldDef>,
    session: Vec<FieldDef>,
    extra: Vec<&'static ExtraEntitySchema>,
}

fn select(plugins: &[String]) -> Selection {
    let mut selection = Selection {
        user: Vec::new(),
        session: Vec::new(),
        extra: Vec::new(),
    };
    for plugin_name in plugins {
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

fn generate_schema(plugins: &[String], backend: Backend) -> String {
    let selection = select(plugins);
    let tokens = match backend {
        Backend::Sqlx => sqlx_schema(&selection),
        Backend::Seaorm => seaorm_schema(&selection),
    };
    #[expect(
        clippy::expect_used,
        reason = "generated from hardcoded registry; parse failure is a bug"
    )]
    let file = syn::parse2(tokens).expect("generated code should be valid syntax");
    prettyplease::unparse(&file)
}

const CORE_ENTITIES: [(&str, &str, EntityRole); 4] = [
    ("user", "users", EntityRole::User),
    ("session", "sessions", EntityRole::Session),
    ("account", "accounts", EntityRole::Account),
    ("verification", "verifications", EntityRole::Verification),
];

fn role_name(role: EntityRole) -> &'static str {
    match role {
        EntityRole::User => "user",
        EntityRole::Session => "session",
        EntityRole::Account => "account",
        EntityRole::Verification => "verification",
    }
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

#[expect(
    clippy::panic,
    reason = "type strings come from hardcoded registry; parse failure is a bug"
)]
fn parse_type(field: &FieldDef, ty: &str) -> syn::Type {
    syn::parse_str(ty)
        .unwrap_or_else(|e| panic!("invalid type `{ty}` for field `{}`: {e}", field.name))
}

fn sqlx_schema(selection: &Selection) -> TokenStream {
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

fn sqlx_entity(
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
fn sqlx_type(ty: &str) -> String {
    ty.replace("DateTimeUtc", "chrono::DateTime<chrono::Utc>")
        .replace("Json", "better_auth::sqlx::JsonMetadata")
}

#[derive(Clone, Copy)]
enum SqlDialect {
    Sqlite,
    Postgres,
}

/// `CREATE TABLE IF NOT EXISTS` for a generated model, as `SeaORM` derives
/// tables from its entities: column types follow the registry types.
fn create_table(table: &str, fields: &[&FieldDef], dialect: SqlDialect) -> String {
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
            format!("\"{column}\" {sql_type}{constraint}")
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("CREATE TABLE IF NOT EXISTS \"{table}\" ({columns})")
}

fn seaorm_schema(selection: &Selection) -> TokenStream {
    let extra_user = &selection.user;
    let extra_session = &selection.session;
    let extra_entities = &selection.extra;

    let imports = quote! {
        use better_auth::AuthSchema;
        use better_auth::seaorm::sea_orm;
        use better_auth::seaorm::sea_orm::entity::prelude::*;
        use better_auth::seaorm::sea_orm::{ConnectionTrait, Schema};
        use better_auth::seaorm::{AuthEntity, DatabaseConnection};
    };

    let user_entity = gen_entity("user", "users", EntityRole::User, extra_user);
    let session_entity = gen_entity("session", "sessions", EntityRole::Session, extra_session);
    let account_entity = gen_entity("account", "accounts", EntityRole::Account, &[]);
    let verification_entity = gen_entity(
        "verification",
        "verifications",
        EntityRole::Verification,
        &[],
    );
    let extra_entity_tokens: Vec<TokenStream> = extra_entities
        .iter()
        .map(|entity| gen_extra_entity(entity))
        .collect();

    let schema_impl = quote! {
        pub struct AppAuthSchema;

        impl AuthSchema for AppAuthSchema {
            type User = user::Model;
            type Session = session::Model;
            type Account = account::Model;
            type Verification = verification::Model;
        }
    };

    let extra_migration_statements: Vec<TokenStream> = extra_entities
        .iter()
        .map(|entity| {
            let mod_ident = format_ident!("{}", entity.mod_name);
            quote! { schema.create_table_from_entity(#mod_ident::Entity).if_not_exists().to_owned() }
        })
        .collect();

    let migration_fn = quote! {
        pub async fn run_app_migrations(
            database: &DatabaseConnection,
        ) -> Result<(), sea_orm::DbErr> {
            let schema = Schema::new(database.get_database_backend());
            for statement in [
                schema.create_table_from_entity(user::Entity).if_not_exists().to_owned(),
                schema.create_table_from_entity(session::Entity).if_not_exists().to_owned(),
                schema.create_table_from_entity(account::Entity).if_not_exists().to_owned(),
                schema.create_table_from_entity(verification::Entity).if_not_exists().to_owned(),
                #(#extra_migration_statements,)*
            ] {
                let _ = database.execute(&statement).await?;
            }
            Ok(())
        }
    };

    quote! {
        #imports
        #user_entity
        #session_entity
        #account_entity
        #verification_entity
        #(#extra_entity_tokens)*
        #schema_impl
        #migration_fn
    }
}

fn gen_entity(
    mod_name: &str,
    table_name: &str,
    role: EntityRole,
    plugin_fields: &[FieldDef],
) -> TokenStream {
    let mod_ident = format_ident!("{}", mod_name);
    let role_str = mod_name;

    let core = registry::core_fields(role);
    let all_fields: Vec<&FieldDef> = core.iter().chain(plugin_fields.iter()).collect();

    let field_tokens: Vec<TokenStream> = all_fields
        .iter()
        .map(|f| {
            let name = format_ident!("{}", f.name);
            #[expect(
                clippy::panic,
                reason = "type strings come from hardcoded registry; parse failure is a bug"
            )]
            let ty: syn::Type = syn::parse_str(f.ty)
                .unwrap_or_else(|e| panic!("invalid type `{}` for field `{}`: {e}", f.ty, f.name));
            let column_attr = f.column_name.map(|column_name| {
                quote! { #[sea_orm(column_name = #column_name)] }
            });
            if f.is_primary_key {
                quote! {
                    #column_attr
                    #[sea_orm(primary_key, auto_increment = false)]
                    pub #name: #ty,
                }
            } else {
                quote! {
                    #column_attr
                    pub #name: #ty,
                }
            }
        })
        .collect();

    quote! {
        mod #mod_ident {
            use super::*;

            #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
            #[auth(role = #role_str)]
            #[sea_orm(table_name = #table_name)]
            pub struct Model {
                #(#field_tokens)*
            }

            #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
            pub enum Relation {}

            impl ActiveModelBehavior for ActiveModel {}
        }
    }
}

fn gen_extra_entity(entity: &ExtraEntitySchema) -> TokenStream {
    let mod_ident = format_ident!("{}", entity.mod_name);
    let table_name = entity.table_name;

    let field_tokens: Vec<TokenStream> = entity
        .fields
        .iter()
        .map(|f| {
            let name = format_ident!("{}", f.name);
            #[expect(
                clippy::panic,
                reason = "type strings come from hardcoded registry; parse failure is a bug"
            )]
            let ty: syn::Type = syn::parse_str(f.ty)
                .unwrap_or_else(|e| panic!("invalid type `{}` for field `{}`: {e}", f.ty, f.name));
            let column_attr = f.column_name.map(|column_name| {
                quote! { #[sea_orm(column_name = #column_name)] }
            });
            if f.is_primary_key {
                quote! {
                    #column_attr
                    #[sea_orm(primary_key, auto_increment = false)]
                    pub #name: #ty,
                }
            } else {
                quote! {
                    #column_attr
                    pub #name: #ty,
                }
            }
        })
        .collect();

    let derive_attrs = entity.role.map_or_else(
        || {
            quote! {
                #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
            }
        },
        |role| {
            let role_str = match role {
                EntityRole::User => "user",
                EntityRole::Session => "session",
                EntityRole::Account => "account",
                EntityRole::Verification => "verification",
            };
            quote! {
                #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
                #[auth(role = #role_str)]
            }
        },
    );

    quote! {
        mod #mod_ident {
            use super::*;

            #derive_attrs
            #[sea_orm(table_name = #table_name)]
            pub struct Model {
                #(#field_tokens)*
            }

            #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
            pub enum Relation {}

            impl ActiveModelBehavior for ActiveModel {}
        }
    }
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::{Backend, generate_schema, list_plugins};

    fn all() -> Vec<String> {
        list_plugins().into_iter().map(String::from).collect()
    }

    #[test]
    fn list_plugins_includes_passkey() {
        assert!(list_plugins().contains(&"passkey"));
    }

    #[test]
    fn seaorm_schema_with_passkey_emits_entity_and_migration() {
        let schema = generate_schema(&["passkey".to_owned()], Backend::Seaorm);

        assert!(schema.contains("mod passkey"));
        assert!(schema.contains("#[sea_orm(table_name = \"passkeys\")]"));
        assert!(schema.contains("pub credential: String"));
        assert!(schema.contains("pub aaguid: Option<String>"));
        assert!(schema.contains("schema.create_table_from_entity(passkey::Entity)"));
    }

    #[test]
    fn seaorm_schema_builtin_plugins_emit_required_entities() {
        let schema = generate_schema(
            &[
                "device-authorization".to_owned(),
                "api-key".to_owned(),
                "organization".to_owned(),
                "passkey".to_owned(),
            ],
            Backend::Seaorm,
        );

        assert!(schema.contains("mod device_code"));
        assert!(schema.contains("mod api_key"));
        assert!(schema.contains("mod organization"));
        assert!(schema.contains("mod member"));
        assert!(schema.contains("mod invitation"));
        assert!(schema.contains("#[sea_orm(column_name = \"key\")]"));
        assert!(schema.contains("schema.create_table_from_entity(device_code::Entity)"));
        assert!(schema.contains("schema.create_table_from_entity(api_key::Entity)"));
        assert!(schema.contains("schema.create_table_from_entity(organization::Entity)"));
        assert!(schema.contains("schema.create_table_from_entity(member::Entity)"));
        assert!(schema.contains("schema.create_table_from_entity(invitation::Entity)"));
    }

    #[test]
    fn sqlx_schema_with_passkey_emits_row_type_and_tables() {
        let schema = generate_schema(&["passkey".to_owned()], Backend::Sqlx);

        assert!(schema.contains("pub mod passkey"));
        assert!(schema.contains("#[auth(role = \"user\", table = \"users\")]"));
        assert!(schema.contains("pub credential: String"));
        assert!(schema.contains("pub created_at: chrono::DateTime<chrono::Utc>"));
        assert!(schema.contains("CREATE TABLE IF NOT EXISTS \\\"passkeys\\\""));
        assert!(schema.contains("\\\"created_at\\\" TIMESTAMPTZ NOT NULL"));
    }

    // The checked-in fixtures are compiled and exercised by the integration
    // tests; regenerate them with `better-auth-rs generate --plugins all`.
    #[test]
    fn generated_schemas_match_compiled_fixtures() {
        assert_eq!(
            generate_schema(&all(), Backend::Sqlx),
            include_str!("../../../tests/fixtures/cli/sqlx_all.rs")
        );
        assert_eq!(
            generate_schema(&all(), Backend::Seaorm),
            include_str!("../../../tests/fixtures/cli/seaorm_all.rs")
        );
    }
}
// LCOV_EXCL_STOP
