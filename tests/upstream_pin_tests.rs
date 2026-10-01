#![cfg(test)]
//! The compatibility target is one release of `better-auth`. Every place that
//! names, installs, or reports that release must agree, or the harness could
//! compare against one version while claiming another.
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "pin consistency checks fail fast on unreadable repository files and fixed JSON layouts"
)]

#[cfg(test)]
#[path = "upstream_pin_tests/tests.rs"]
mod tests;

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(relative: &str) -> String {
    let path = repo_root().join(relative);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} should be readable: {error}", path.display()))
}

fn read_json(relative: &str) -> serde_json::Value {
    serde_json::from_str(&read(relative))
        .unwrap_or_else(|error| panic!("{relative} should be valid JSON: {error}"))
}

/// The committed oracle release recorded with the capability inventory.
fn pinned_version() -> String {
    read_json("tests/compat/capabilities.json")["upstreamVersion"]
        .as_str()
        .expect("capabilities.json declares upstreamVersion")
        .to_owned()
}

/// Exact dependency pins declared by a Bun project manifest.
fn declared_pins(manifest: &serde_json::Value) -> Vec<(String, String)> {
    manifest["dependencies"]
        .as_object()
        .expect("package.json has dependencies")
        .iter()
        .filter(|(name, _)| *name == "better-auth" || name.starts_with("@better-auth/"))
        .map(|(name, version)| {
            (
                name.clone(),
                version
                    .as_str()
                    .expect("dependency version is a string")
                    .to_owned(),
            )
        })
        .collect()
}

/// Resolved package versions recorded by a committed Bun lockfile.
fn locked_versions(lockfile: &str, package: &str) -> Vec<String> {
    let marker = format!("\"{package}\": [\"{package}@");
    lockfile
        .lines()
        .filter_map(|line| {
            let start = line.trim_start().find(&marker)? + marker.len();
            let rest = line.trim_start().get(start..)?;
            Some(rest.split('"').next()?.to_owned())
        })
        .collect()
}

fn contains_or_panic(path: &str, needle: &str) {
    assert!(
        read(path).contains(needle),
        "{path} must mention the pinned release as `{needle}`"
    );
}

fn exists(relative: &str) -> bool {
    Path::new(&repo_root().join(relative)).exists()
}
