---
title: "Release policy"
description: "Version Rust releases independently while preserving the pinned upstream Better Auth contract."
---

## Version format

Better Auth RS uses ordinary [Semantic Versioning](https://semver.org/) independently of upstream Better Auth. Every release records its exact upstream compatibility target in the release notes and compatibility guide.

- **Patch:** compatible Rust bug fixes and performance improvements, retaining the upstream target.
- **Minor:** backward-compatible additions, including compatible upstream-target upgrades.
- **Major:** breaking changes to public Rust APIs, generated schemas, or supported contracts, including breaking upstream-target upgrades.

Choose the bump by the effect on our users. An upstream version change does not automatically determine our version bump.

For example, hypothetical Rust releases `1.0.0` and `1.0.1` could both target Better Auth `1.7.7`, with `1.0.1` fixing a Rust implementation bug. A compatible upgrade to Better Auth `1.7.8` could then ship as Rust `1.1.0`.

Stable releases have no suffix. Reserve `-alpha.N`, `-beta.N`, and `-rc.N` for actual prereleases. Never reuse a published version or move its Git tag. Release tags use `v` followed by the Rust version, for example `v1.0.1`.

The repository currently targets **Better Auth `1.7.7`** and uses the development workspace version `1.0.0-alpha.3`. These examples do not change either version or imply a published release.

## Compatibility rules

The upstream API remains the compatibility contract for every release. A Rust release can fix our implementation, improve performance, or add compatible native Rust capabilities without waiting for an upstream release.

- Preserve the targeted endpoints, request and response shapes, status and error codes, redirects, cookie attributes, and supported stored data formats.
- Fix discrepancies in our implementation to match the pinned upstream behavior. A patch release must not silently introduce behavior from a newer upstream version.
- Preserve public Rust APIs and generated schemas in patch and minor releases. Breaking changes require a major release and a documented migration.
- If a fix must intentionally depart from upstream behavior, document the reason and observable difference in the compatibility guide and release notes. Do not claim parity for that behavior; a breaking contract change cannot be shipped as a patch or minor release.
- Change the upstream compatibility target only when the reference runtime, official client, companion packages, compatibility fixtures, and documentation have been updated and the differential suite passes against that target.

The [compatibility guide](/reference/compatibility/) defines supported behavior and scope. The recorded upstream target does not imply support for upstream packages listed as out of scope.

## Workspace versions

Keep all first-party published crates on the same Rust release version and update their dependency requirements together.

The upstream compatibility target is separate release information. Do not encode a Rust fix counter using a hyphen suffix or build metadata: hyphen suffixes identify prereleases, and SemVer ignores build metadata when ordering versions.

## Release checklist

1. Confirm the exact upstream target and choose the next unpublished Rust version using the rules above. For an upstream upgrade, complete the compatibility updates before assigning the release version.
2. Update the workspace package version, first-party dependency requirements, lockfiles, and installation examples together. Keep compatibility badges and documented upstream pins aligned with the verified target.
3. Record release notes with the upstream target, Rust changes, security fixes, known compatibility exceptions, and any migration steps.
4. Run `devenv shell -- ./scripts/check.sh`, `bun run docs:check`, and `bun run docs:build`. Require the complete CI gate to pass on the release commit, including differential compatibility checks.
5. Verify publishable crate packages with `cargo publish --dry-run` in dependency order, accounting for dependencies that must be published before dependent crates can be verified against the registry.
6. Publish first-party crates in dependency order from the reviewed release commit, then create its immutable `v{rust-version}` tag and release notes. If publication is interrupted, resume with the same commit and version for unpublished crates; never overwrite an already published crate.
