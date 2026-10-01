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
