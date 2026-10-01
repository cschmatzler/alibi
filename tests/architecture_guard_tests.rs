#![cfg(test)]
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "architecture guard tests intentionally fail fast on fixture traversal and string-scan assumptions"
)]

#[cfg(test)]
#[path = "architecture_guard_tests/tests.rs"]
mod tests;

use std::fs;

use std::path::{Path, PathBuf};

fn collect_files(root: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).expect("directory should be readable") {
        let entry = entry.expect("directory entry should be readable");
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(std::ffi::OsStr::to_str) == Some("target") {
                continue;
            }
            collect_files(&path, files);
            continue;
        }

        let extension = path.extension().and_then(std::ffi::OsStr::to_str);
        if matches!(extension, Some("rs" | "md" | "mdx")) {
            files.push(path);
        }
    }
}

fn collect_rust_files(root: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).expect("directory should be readable") {
        let entry = entry.expect("directory entry should be readable");
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(std::ffi::OsStr::to_str) == Some("target") {
                continue;
            }
            collect_rust_files(&path, files);
            continue;
        }

        if path.extension().and_then(std::ffi::OsStr::to_str) == Some("rs") {
            files.push(path);
        }
    }
}

fn is_behavior_marker_exempt(path: &Path) -> bool {
    let text = path.to_string_lossy();
    text.ends_with("tests/architecture_guard_tests.rs")
        || text.contains("/tests/architecture_guard_tests/")
        || text.ends_with("tests/client_compat_tests.rs")
        || text.contains("/tests/client_compat_tests/")
        || text.ends_with("tests/wire_compat_smoke_tests.rs")
        || text.contains("/tests/wire_compat_smoke_tests/")
        || text.contains("/tests/compat")
        || text.contains("/tests/compat/")
        || text.ends_with("tests/compatibility_tests.rs")
        || text.contains("/tests/compatibility_tests/")
}

fn requires_strict_behavior_markers(path: &Path) -> bool {
    let text = path.to_string_lossy();
    text.ends_with("tests/integration_tests.rs")
        || text.contains("/tests/integration_tests/")
        || text.ends_with("tests/axum_integration_tests.rs")
        || text.contains("/tests/axum_integration_tests/")
        || text.contains("/crates/api/src/plugins/email_password/")
        || text.ends_with("crates/api/tests/account_oauth_tests.rs")
        || text.contains("/crates/api/tests/account_oauth_tests/")
}

fn has_test_attribute(line: &str) -> bool {
    matches!(line.trim(), "#[test]" | "#[tokio::test]")
}
