//! The compatibility target is one release of `better-auth`. Every place that
//! names, installs, or reports that release must agree, or the harness could
//! compare against one version while claiming another.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "pin consistency checks fail fast on unreadable repository files and fixed JSON layouts"
)]

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

#[cfg(test)]
mod tests {
    use super::*;

    // Rust-specific surface: the pinned oracle release is a repository contract;
    // a mismatch anywhere means a comparison ran against the wrong better-auth.
    #[test]
    fn every_better_auth_pin_names_the_committed_release() {
        let version = pinned_version();
        assert!(
            version.split('.').count() == 3
                && version.split('.').all(|part| part.parse::<u32>().is_ok()),
            "upstreamVersion must be an exact release, got {version}"
        );

        for project in ["client-tests", "reference-server"] {
            let manifest_path = format!("tests/compat/{project}/package.json");
            let pins = declared_pins(&read_json(&manifest_path));
            assert!(
                pins.iter().any(|(name, _)| name == "better-auth"),
                "{manifest_path} must depend on better-auth"
            );
            for (name, declared) in &pins {
                assert_eq!(
                    declared, &version,
                    "{manifest_path} pins {name} to {declared}, inventory says {version}"
                );
            }

            let lockfile_path = format!("tests/compat/{project}/bun.lock");
            let lockfile = read(&lockfile_path);
            for (name, _) in &pins {
                let resolved = locked_versions(&lockfile, name);
                assert_eq!(
                    resolved,
                    vec![version.clone()],
                    "{lockfile_path} must resolve {name} to exactly {version}, found {resolved:?}"
                );
            }
        }
    }

    // Rust-specific surface: documentation, the harness schema and the Rust fixture
    // server all restate the release; they must restate the same one.
    #[test]
    fn documentation_harness_and_fixture_server_restate_the_same_release() {
        let version = pinned_version();
        let badge = version.replace('-', "--");
        contains_or_panic("README.md", &format!("better-auth@{version}"));
        contains_or_panic("README.md", &format!("better--auth-v{badge}-blue"));
        contains_or_panic(
            "README.md",
            &format!("https://www.npmjs.com/package/better-auth/v/{version}"),
        );
        contains_or_panic("tests/compat/README.md", &format!("better-auth@{version}"));
        contains_or_panic(
            "tests/compat/client-tests/support/coverage.ts",
            &format!("z.literal(\"{version}\")"),
        );
        contains_or_panic(
            "tests/compat/client-tests/support/check-coverage.ts",
            &format!("upstreamVersion: \"{version}\""),
        );
        contains_or_panic(
            "tests/compat/reference-server/port-openapi-annotations.ts",
            &format!("plugin.version !== \"{version}\""),
        );
        contains_or_panic(
            "tests/compat/rust-server/src/main.rs",
            &format!("const UPSTREAM_VERSION: &str = \"{version}\";"),
        );
        assert_eq!(
            read_json("tests/fixtures/jwt/typescript-1.7.6-encrypted-jwk.json")["referenceVersion"],
            format!("better-auth@{version}"),
            "the imported encrypted-JWK fixture must come from the pinned release"
        );
    }

    // Rust-specific surface: the installed reference packages are what actually
    // answer comparisons; when present they must be the committed release.
    #[test]
    fn installed_reference_packages_match_the_committed_release_when_present() {
        let version = pinned_version();
        let mut checked = 0;
        for project in ["client-tests", "reference-server"] {
            for package in [
                "better-auth",
                "@better-auth/passkey",
                "@better-auth/api-key",
            ] {
                let relative =
                    format!("tests/compat/{project}/node_modules/{package}/package.json");
                if !exists(&relative) {
                    continue;
                }
                assert_eq!(
                    read_json(&relative)["version"],
                    version,
                    "{relative} is not the committed release"
                );
                checked += 1;
            }
        }
        let required = ["CI", "BETTER_AUTH_REQUIRE_REFERENCE_SERVER"]
            .iter()
            .any(|name| std::env::var(name).is_ok_and(|value| !value.is_empty() && value != "0"));
        assert!(
            checked == 6 || !required,
            "the complete gate requires both compatibility projects installed from their frozen lockfiles; found {checked} of 6 reference packages"
        );
    }
}
