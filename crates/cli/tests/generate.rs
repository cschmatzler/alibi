//! Public CLI argument parsing must finish before generation or writes.
use std::process::Command;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn generate_help_advertises_and_parser_accepts_every_supported_plugin() -> TestResult {
    let output = Command::new(env!("CARGO_BIN_EXE_better-auth-rs"))
        .args(["generate", "--help"])
        .output()?;
    if !output.status.success() {
        return Err(format!("help failed: {:?}", output.stderr).into());
    }
    let help = String::from_utf8(output.stdout)?;
    for name in better_auth_schema_registry::plugin_schemas()
        .iter()
        .map(|plugin| plugin.name)
        .chain(["all"])
    {
        if !help.contains(name) {
            return Err(format!("help omitted {name}: {help}").into());
        }
        let generated = Command::new(env!("CARGO_BIN_EXE_better-auth-rs"))
            .args(["generate", "--plugins", name])
            .output()?;
        if !generated.status.success() || generated.stdout.is_empty() {
            return Err(format!(
                "failed to generate for advertised plugin {name}: {:?}",
                generated.stderr
            )
            .into());
        }
    }
    Ok(())
}

#[test]
fn unknown_plugins_fail_without_output_or_filesystem_changes() -> TestResult {
    let directory =
        std::env::temp_dir().join(format!("better-auth-cli-invalid-{}", std::process::id()));
    std::fs::create_dir(&directory)?;
    let existing = directory.join("existing.rs");
    std::fs::write(&existing, "application-owned schema")?;
    let new_output = directory.join("new-parent/schema.rs");
    for plugins in ["nonsense", "api-key,nonsense", "all,nonsense"] {
        for destination in [None, Some(&existing), Some(&new_output)] {
            let mut command = Command::new(env!("CARGO_BIN_EXE_better-auth-rs"));
            let _ = command.args(["generate", "--plugins", plugins]);
            if let Some(path) = destination {
                let _ = command.arg("--output").arg(path);
            }
            let output = command.output()?;
            if output.status.success() {
                return Err(format!("accepted unknown plugins: {plugins}").into());
            }
            if !output.stdout.is_empty() {
                return Err(format!("generated output for {plugins}").into());
            }
            if !String::from_utf8(output.stderr)?.contains("nonsense") {
                return Err(format!("diagnostic omitted the unknown plugin: {plugins}").into());
            }
            if std::fs::read_to_string(&existing)? != "application-owned schema" {
                return Err(format!("overwrote an existing schema for {plugins}").into());
            }
            if directory.join("new-parent").exists() {
                return Err(format!("created an output directory for {plugins}").into());
            }
        }
    }
    std::fs::remove_dir_all(directory)?;
    Ok(())
}

/// The executable's backend selection and filesystem output must deliver the
/// same application schemas compiled and exercised by the store integrations.
#[test]
fn generated_output_files_match_working_application_schemas() -> TestResult {
    let directory =
        std::env::temp_dir().join(format!("better-auth-cli-output-{}", std::process::id()));
    let repeated = better_auth_schema_registry::plugin_schemas()
        .iter()
        .flat_map(|plugin| [plugin.name, plugin.name])
        .collect::<Vec<_>>()
        .join(",");
    for (backend, core, all) in [
        (
            "sqlx",
            include_str!("../../../tests/fixtures/cli/sqlx_core.rs"),
            include_str!("../../../tests/fixtures/cli/sqlx_all.rs"),
        ),
        (
            "seaorm",
            include_str!("../../../tests/fixtures/cli/seaorm_core.rs"),
            include_str!("../../../tests/fixtures/cli/seaorm_all.rs"),
        ),
    ] {
        for (plugins, expected) in [
            (None, core),
            (Some("all"), all),
            (Some(repeated.as_str()), all),
        ] {
            let path = directory.join(backend).join("nested/schema.rs");
            let mut command = Command::new(env!("CARGO_BIN_EXE_better-auth-rs"));
            let _ = command
                .args(["generate", "--backend", backend, "--output"])
                .arg(&path);
            if let Some(plugins) = plugins {
                let _ = command.args(["--plugins", plugins]);
            }
            let output = command.output()?;
            if !output.status.success() {
                return Err(format!(
                    "generation failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                )
                .into());
            }
            if std::fs::read_to_string(&path)? != expected {
                return Err(
                    format!("schema differs: backend={backend}, plugins={plugins:?}").into(),
                );
            }
        }
    }
    std::fs::remove_dir_all(directory)?;
    Ok(())
}
