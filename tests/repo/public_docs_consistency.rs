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

#[cfg(test)]
mod tests {
    use super::*;

    // The package is unreleased: installation must use the same Git repository
    // for the library and generator, not an unavailable crates.io release.
    #[test]
    fn readme_installation_matches_the_unreleased_package() {
        let readme = read_repo_file("README.md");
        let repository = env!("CARGO_PKG_REPOSITORY");
        assert!(
            readme.contains(&format!("better-auth = {{ git = \"{repository}\"")),
            "the install example must use the canonical Git repository"
        );
        assert!(readme.contains(&format!(
            "cargo install --git {repository} --locked better-auth-cli"
        )));
        assert!(readme.contains(&format!("`{}`", env!("CARGO_PKG_VERSION"))));
    }
}
