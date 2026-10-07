#![allow(
    clippy::expect_used,
    reason = "architecture guard tests intentionally fail fast on fixture traversal and string-scan assumptions"
)]

use std::fs;
use std::path::{Path, PathBuf};

fn collect_files(root: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).expect("directory should be readable") {
        let entry = entry.expect("directory entry should be readable");
        let path = entry.path();
        if path.is_dir() {
            if is_skipped_directory(&path) {
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

/// Vendored and generated trees are not repository sources.
fn is_skipped_directory(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(std::ffi::OsStr::to_str),
        Some("target" | "node_modules" | "artifacts" | ".devenv")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_persistence_symbols_are_gone_from_tracked_sources() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let guard_file = root.join(file!());
        let banned = [
            "DatabaseAdapter",
            "AuthDatabase",
            "UserOps",
            "SessionOps",
            "AccountOps",
            "VerificationOps",
            "OrganizationOps",
            "MemberOps",
            "InvitationOps",
            "TwoFactorOps",
            "ApiKeyOps",
            "PasskeyOps",
        ];
        let mut files = Vec::new();

        for relative in ["crates", "src", "tests"] {
            collect_files(&root.join(relative), &mut files);
        }

        let mut violations = Vec::new();
        for path in files {
            if path == guard_file {
                continue;
            }
            let content = fs::read_to_string(&path).expect("source file should be readable");
            for symbol in &banned {
                if content.contains(symbol) {
                    violations.push(format!("{} -> {}", path.display(), symbol));
                }
            }
        }

        assert!(
            violations.is_empty(),
            "legacy persistence symbols remain:\n{}",
            violations.join("\n")
        );
    }

    #[test]
    fn readme_must_not_use_hidden_auth_apis() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let readme = fs::read_to_string(root.join("README.md")).expect("README should be readable");

        let banned_fragments = [
            "__private",
            "__private_core",
            "__private_test_support",
            "alibi::run_migrations",
        ];

        for fragment in &banned_fragments {
            assert!(
                !readme.contains(fragment),
                "README must not use hidden auth APIs: {fragment}",
            );
        }
    }
}
