# Public role operators against Better Auth 1.7.6

The public Rust `plugins::access` utility now supports AND/OR across resources
and independently within action sets. Organization and admin checks reuse its
AND evaluator and still require one assigned role to satisfy a whole request.
Organization HTTP requests remain action arrays.

## Independent Source and storage proof

`published-access.mjs` is the unmodified public utility from the published
`better-auth@1.7.6` tarball. The downloaded tarball was verified against npm's
version metadata with SHA-512 integrity:

```
sha512-WTMqOpmTTj+oBoX7zzPOzL85342Upyf+/v0IkH1kvGRA85lV4JGRFIYMIRKqvjZ6ShsuL5VX/c9C13jtoZXcKA==
```

The reproducible probe is
`tests/compat/reference-server/probes/access-operators.mjs`, run with Bun from
the repository root after installing the locked reference-server dependencies.
The installed utility was compared byte-for-byte with the extracted tarball;
no node_modules file was mutated. The installed file had 100 hard links, while
the extracted tarball copy had one, so future mutation experiments must first
replace shared files with private inodes and restore from the tarball.

`source.json` preserves the raw Source decisions and SQLite application effects.
Its output matches `tests/fixtures/access/operators-1.7.6.json` byte-for-byte.
It exercises both public constructors, plain AND requests, resource OR, action
OR, nested OR, empty requests/actions/grants, missing resources, case-sensitive
literal names, duplicates, and numeric index ordering of the first AND error.
Source constructs roles without runtime declaration-subset validation.

The native integration test loads a literal persisted organization role through
actual SQLx and SeaORM stores, consumes its grants through both public Rust
constructors, compares every decision and error with Source, and gates real team
writes in the consuming application. `native-physical.log` retains both adapter
results: zero initial teams, seven authorized writes, identical ordered physical
effects, and unchanged literal permission bytes. Denied cases leave row counts
unchanged; another organization cannot load the grants or receive writes.
This is application utility proof, not a new HTTP operator contract.

`public-before.log.gz` preserves the public consumer's failure against base
`79c2c2de`: `better_auth::plugins::access` was unavailable. The same external
consumer builds and runs after the implementation (`public-after.log`).
The saved adapter proof was reviewed without rerunning passed cases.

## Focused validation and review

The API library previously could not compile its tests because eleven existing
assertions compared `StoredOrganizationPermissions` directly with parsed maps.
Those assertions now parse stored bytes at the assertion boundary; production
storage and late consumer validation are unchanged. Ten dynamic-role tests,
one organization whole-role test, and one admin permission test pass; logs are
retained beside this document. Production API Clippy passes with `-D warnings`.
Changed Rust files pass scoped rustfmt; `git diff --check` passes.

Review traced public exports, constructors, both connector levels, empty/missing
rules, first-error ordering, admin session/permission callers, organization role
loading and tenant-scoped queries, and the shared default-AND callers. The shared
replacement preserves each caller's prior decision for typed arrays. Role names
remain literal, roles are not unioned, creator/API-key guards retain late stored
validation, and cache loading and partial-update behavior remain unchanged.
No authorization bypass was found in these changed paths.

Current main adds JWK storage only; GitHub reports this branch mergeable. No
rebase or unrelated test replay was needed. Actions are disabled. No CI success,
full-suite run, coverage result, or broad compatibility result is claimed.

## Remaining issue #220 bounds

This closes the typed public utility gap. Rust uses owned string lists and a
connector enum; it does not emulate arbitrary JavaScript values, invalid
connector strings, prototype-inherited properties, or TypeScript compile-time
resource/action subset inference. Arbitrary custom-adapter permission values
remain open under #220. Existing exclusions and comparison allowances are
unchanged. Dynamic refresh work (#411) and no-database organization work (#172)
are outside this PR.
