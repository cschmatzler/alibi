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

    // Installation examples must use the registry package and release version
    // for both the library and generator.
    #[test]
    fn readme_installation_matches_the_registry_release() {
        let readme = read_repo_file("README.md");
        let package = env!("CARGO_PKG_NAME");
        let version = env!("CARGO_PKG_VERSION");
        assert!(
            readme.contains(&format!("{package} = {{ version = \"{version}\"")),
            "the install example must use the registry package and release version"
        );
        assert!(readme.contains(&format!(
            "cargo install {package}-cli --version {version} --locked"
        )));
        assert!(
            !readme.contains("git = ") && !readme.contains("cargo install --git"),
            "README installation examples must use the released registry packages"
        );
        assert!(readme.contains(&format!("`{}`", env!("CARGO_PKG_VERSION"))));
    }
}
