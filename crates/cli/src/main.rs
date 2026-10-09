mod seaorm;
mod selection;
mod sqlx;

use alibi_schema_registry::FieldDef;
use clap::{Parser, Subcommand, ValueEnum};
use seaorm::seaorm_schema;
use selection::{list_plugins, select};
use sqlx::sqlx_schema;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "alibi", about = "CLI tools for Alibi")]
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
        /// Use "all" to include every plugin's fields.
        #[arg(
            short,
            long,
            value_delimiter = ',',
            value_parser = clap::builder::PossibleValuesParser::new(
                list_plugins().into_iter().chain(["all"])
            )
        )]
        plugins: Vec<String>,
    },
}

fn main() -> ExitCode {
    let Command::Generate {
        backend,
        output,
        plugins,
    } = Cli::parse().command;
    let plugins = if plugins.iter().any(|p| p == "all") {
        list_plugins().into_iter().map(String::from).collect()
    } else {
        plugins
    };
    let schema = generate_schema(&plugins, backend);
    match write_schema(output.as_deref(), &schema) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            _ = writeln!(std::io::stderr().lock(), "{message}");
            ExitCode::FAILURE
        }
    }
}

fn write_schema(output: Option<&Path>, schema: &str) -> Result<(), String> {
    let Some(path) = output else {
        return std::io::stdout()
            .lock()
            .write_all(schema.as_bytes())
            .map_err(|error| format!("failed to write stdout: {error}"));
    };
    if let Some(parent) = path.parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create directory {}: {error}", parent.display()))?;
    }
    fs::write(path, schema)
        .map_err(|error| format!("failed to write {}: {error}", path.display()))?;
    _ = writeln!(
        std::io::stderr().lock(),
        "wrote auth schema to {}",
        path.display()
    );
    Ok(())
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

#[expect(
    clippy::panic,
    reason = "type strings come from hardcoded registry; parse failure is a bug"
)]
fn parse_type(field: &FieldDef, ty: &str) -> syn::Type {
    syn::parse_str(ty)
        .unwrap_or_else(|e| panic!("invalid type `{ty}` for field `{}`: {e}", field.name))
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::{Backend, generate_schema, list_plugins};

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
}
// LCOV_EXCL_STOP
