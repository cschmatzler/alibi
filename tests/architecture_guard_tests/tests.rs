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
fn behavior_tests_must_include_behavior_source_comments() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();

    for relative in ["tests", "src", "crates/api/src", "crates/core/src"] {
        collect_rust_files(&root.join(relative), &mut files);
    }

    let mut violations = Vec::new();
    for path in files {
        if is_behavior_marker_exempt(&path) || !requires_strict_behavior_markers(&path) {
            continue;
        }

        let content = fs::read_to_string(&path).expect("source file should be readable");
        let lines: Vec<&str> = content.lines().collect();

        for (index, line) in lines.iter().enumerate() {
            if !has_test_attribute(line) {
                continue;
            }

            let mut has_marker = false;
            for candidate in lines[..index].iter().rev() {
                let trimmed = candidate.trim();
                if trimmed.is_empty() {
                    if has_marker {
                        break;
                    }
                    continue;
                }
                if trimmed.starts_with("// Upstream reference:")
                    || trimmed.starts_with("// Upstream source:")
                    || trimmed.starts_with("// Rust-specific surface:")
                {
                    has_marker = true;
                    continue;
                }
                if trimmed.starts_with("//") {
                    continue;
                }
                break;
            }

            if !has_marker {
                violations.push(format!("{}:{}", path.display(), index + 1));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "behavior tests missing source/surface comments:\n{}",
        violations.join("\n")
    );
}

#[test]
fn upstream_markers_must_not_use_broad_bundle_patterns() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();

    for relative in ["tests", "src", "crates/api/src", "crates/core/src"] {
        collect_rust_files(&root.join(relative), &mut files);
    }

    let banned_fragments = [
        "packages/better-auth/src/api/routes/{",
        "packages/better-auth/src/plugins/{",
        ".*.test.ts",
        ".test.ts and ",
    ];

    let mut violations = Vec::new();
    for path in files {
        if is_behavior_marker_exempt(&path) || !requires_strict_behavior_markers(&path) {
            continue;
        }

        let content = fs::read_to_string(&path).expect("source file should be readable");
        for (index, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if !trimmed.starts_with("// Upstream reference:")
                && !trimmed.starts_with("// Upstream source:")
            {
                continue;
            }

            for fragment in &banned_fragments {
                if trimmed.contains(fragment) {
                    violations.push(format!("{}:{} -> {}", path.display(), index + 1, trimmed));
                    break;
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "broad upstream markers remain:\n{}",
        violations.join("\n")
    );
}

#[test]
fn stale_test_drift_phrasing_is_gone() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let guard_file = root.join(file!());
    let banned = [
        "Acceptable deviation",
        "superset of the TS responses",
        "changed from DELETE",
        "in addition to GET",
    ];
    let mut files = Vec::new();

    for relative in ["tests", "src", "crates/api/src", "crates/core/src"] {
        collect_rust_files(&root.join(relative), &mut files);
    }

    let mut violations = Vec::new();
    for path in files {
        if path == guard_file {
            continue;
        }
        let content = fs::read_to_string(&path).expect("source file should be readable");
        for phrase in &banned {
            if content.contains(phrase) {
                violations.push(format!("{} -> {}", path.display(), phrase));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "stale test drift phrasing remains:\n{}",
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
        "better_auth::run_migrations",
    ];

    for fragment in &banned_fragments {
        assert!(
            !readme.contains(fragment),
            "README must not use hidden auth APIs: {fragment}",
        );
    }
}
