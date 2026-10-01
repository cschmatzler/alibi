#![cfg(test)]
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
#![allow(
    clippy::expect_used,
    reason = "doc consistency tests intentionally panic immediately when required repo files are missing"
)]

#[cfg(test)]
#[path = "public_docs_consistency_tests/tests.rs"]
mod tests;

use std::fs;
use std::path::PathBuf;

fn repo_file(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn read_repo_file(path: &str) -> String {
    fs::read_to_string(repo_file(path)).expect("repo documentation file should be readable")
}

fn crate_minor_version() -> String {
    let version = env!("CARGO_PKG_VERSION");
    let mut parts = version.split('.');
    let major = parts.next().expect("major version should exist");
    let minor = parts.next().expect("minor version should exist");
    format!("{major}.{minor}")
}
