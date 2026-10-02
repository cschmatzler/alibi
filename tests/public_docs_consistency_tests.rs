#![cfg(test)]
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
#![allow(
    clippy::expect_used,
    reason = "doc consistency tests intentionally panic immediately when required repo files are missing"
)]

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

#[cfg(test)]
mod tests {
    use super::*;

    // Rust-specific surface: the README is part of the Rust crate interface and
    // must stay aligned with the published crate version and canonical module paths.
    #[test]
    fn readme_uses_current_minor_version_and_canonical_paths() {
        let expected_minor = crate_minor_version();
        let expected_full = env!("CARGO_PKG_VERSION");

        let readme = read_repo_file("README.md");
        assert!(
            readme.contains(&format!("better-auth = \"{expected_minor}\""))
                || readme.contains(&format!("better-auth = \"{expected_full}\""))
                || readme.contains(&format!("version = \"{expected_minor}\""))
                || readme.contains(&format!("version = \"{expected_full}\"")),
            "README should use the current minor or full crate version",
        );
        assert!(!readme.contains("better_auth::handlers"));
        assert!(!readme.contains("better_auth::types"));
        assert!(readme.contains("better_auth::seaorm"));
        assert!(readme.contains("Database"));
        assert!(readme.contains("SeaOrmStore"));
        assert!(!readme.contains("better_auth::store::sea_orm::Database"));
    }
}
